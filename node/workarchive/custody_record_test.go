package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodyRecordPublishesFirstChallengeWithoutReplacement(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	encoded, err := fixture.record.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCustodyRecord(encoded)
	if err != nil || decoded.Verify(fixture.manifest, fixture.receipt, fixture.policy) != nil {
		t.Fatalf("custody record decode/verify error=%v", err)
	}
	if canonical, err := decoded.CanonicalBytes(); err != nil || !bytes.Equal(canonical, encoded) {
		t.Fatalf("custody record canonical mismatch error=%v", err)
	}

	path := filepath.Join(t.TempDir(), "custody.omcr")
	committed, created, err := PublishCustodyRecordFile(
		path, fixture.record, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil || !created {
		t.Fatalf("first custody record created=%t error=%v", created, err)
	}
	committedBytes, _ := committed.CanonicalBytes()
	if !bytes.Equal(committedBytes, encoded) {
		t.Fatal("first custody record changed during publication")
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("custody record file info=%+v error=%v", info, err)
	}
	if loaded, err := LoadCustodyRecordFile(
		path, fixture.manifest, fixture.receipt, fixture.policy,
	); err != nil {
		t.Fatal(err)
	} else if loadedBytes, _ := loaded.CanonicalBytes(); !bytes.Equal(loadedBytes, encoded) {
		t.Fatal("loaded custody record differs from published bytes")
	}
	if _, created, err := PublishCustodyRecordFile(
		path, fixture.record, fixture.manifest, fixture.receipt, fixture.policy,
	); err != nil || created {
		t.Fatalf("identical custody publication created=%t error=%v", created, err)
	}

	conflicting := fixture.buildRecord(t, 132, 1_003)
	if _, _, err := PublishCustodyRecordFile(
		path, conflicting, fixture.manifest, fixture.receipt, fixture.policy,
	); !errors.Is(err, ErrCustodyRecord) {
		t.Fatalf("conflicting custody record error=%v", err)
	}
	loaded, err := LoadCustodyRecordFile(
		path, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	loadedBytes, _ := loaded.CanonicalBytes()
	if !bytes.Equal(loadedBytes, encoded) {
		t.Fatal("conflicting publication replaced the first custody record")
	}
}

func TestCustodyRecordConcurrentSameChallengeConverges(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	second := fixture.answerChallenge(t, fixture.record.Challenge, 1_003)
	path := filepath.Join(t.TempDir(), "concurrent-custody.omcr")
	type result struct {
		record  CustodyRecord
		created bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var group sync.WaitGroup
	for _, proposed := range []CustodyRecord{fixture.record, second} {
		group.Add(1)
		go func(record CustodyRecord) {
			defer group.Done()
			<-start
			committed, created, err := PublishCustodyRecordFile(
				path, record, fixture.manifest, fixture.receipt, fixture.policy,
			)
			results <- result{record: committed, created: created, err: err}
		}(proposed)
	}
	close(start)
	group.Wait()
	close(results)
	created := 0
	var winner []byte
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			created++
		}
		encoded, err := result.record.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if winner == nil {
			winner = encoded
		} else if !bytes.Equal(winner, encoded) {
			t.Fatal("same challenge race returned divergent custody records")
		}
	}
	if created != 1 {
		t.Fatalf("same challenge race created %d records", created)
	}
	loaded, err := LoadCustodyRecordFile(
		path, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	loadedBytes, _ := loaded.CanonicalBytes()
	if !bytes.Equal(loadedBytes, winner) {
		t.Fatal("same challenge race file differs from returned winner")
	}
}

func TestDurableCustodySessionRecoversResponseAfterFailedWrite(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	recordPath := filepath.Join(t.TempDir(), "restart-custody.omcr")
	config := DefaultCustodySessionConfig()
	config.Now = func() uint64 { return 1_002 }
	session, err := NewDurableCustodyReplicaSession(
		fixture.manifest, fixture.receipt, fixture.store, fixture.policy,
		fixture.replicaKey, recordPath, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	challengeBytes, _ := fixture.record.Challenge.CanonicalBytes()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(challengeBytes)))
	failing := &custodyFailWriteStream{reader: bytes.NewReader(append(prefix[:], challengeBytes...))}
	if _, err := session.Serve(
		context.Background(), failing,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("durable failed write error=%v", err)
	}
	durable, err := LoadCustodyRecordFile(
		recordPath, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}

	restartConfig := config
	restartConfig.Now = func() uint64 { return 1_003 }
	restarted, err := NewDurableCustodyReplicaSession(
		fixture.manifest, fixture.receipt, fixture.store, fixture.policy,
		fixture.replicaKey, recordPath, restartConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := NewCustodyAuditorSession(
		fixture.manifest, fixture.receipt, fixture.policy, restartConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, _, _ := runCustodyPipeSession(
		t, restarted, auditor, fixture.record.Challenge,
	)
	responseRecord := CustodyRecord{
		Version: CustodyRecordVersion0, Challenge: fixture.record.Challenge,
		Batch: response.Batch, Proof: response.Proof, RenewedReceipt: response.RenewedReceipt,
	}
	durableBytes, _ := durable.CanonicalBytes()
	responseBytes, _ := responseRecord.CanonicalBytes()
	if !bytes.Equal(durableBytes, responseBytes) {
		t.Fatal("restarted custody session did not return the durable response")
	}

	conflicting := fixture.buildRecord(t, 133, 1_003).Challenge
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, serveErr := restarted.Serve(context.Background(), server)
		done <- serveErr
	}()
	if _, _, err := auditor.Audit(
		context.Background(), client, conflicting,
	); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("restarted sibling audit error=%v", err)
	}
	if err := <-done; !errors.Is(err, ErrCustodySession) {
		t.Fatalf("restarted sibling serve error=%v", err)
	}
}

func TestCustodyRecordRejectsMutationTrailingBytesAndCorruptFile(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	encoded, _ := fixture.record.CanonicalBytes()
	if _, err := DecodeCustodyRecord(append(encoded, 0)); !errors.Is(err, ErrCustodyRecord) {
		t.Fatalf("trailing custody record error=%v", err)
	}
	mutated := append([]byte(nil), encoded...)
	mutated[len(mutated)-1] ^= 1
	if _, err := DecodeCustodyRecord(mutated); !errors.Is(err, ErrCustodyRecord) {
		t.Fatalf("mutated custody record error=%v", err)
	}
	path := filepath.Join(t.TempDir(), "corrupt-custody.omcr")
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCustodyRecordFile(
		path, fixture.manifest, fixture.receipt, fixture.policy,
	); !errors.Is(err, ErrCustodyRecord) {
		t.Fatalf("corrupt custody record file error=%v", err)
	}
	if _, err := NewDurableCustodyReplicaSession(
		fixture.manifest, fixture.receipt, fixture.store, fixture.policy,
		fixture.replicaKey, path, DefaultCustodySessionConfig(),
	); !errors.Is(err, ErrCustodyRecord) {
		t.Fatalf("corrupt durable session error=%v", err)
	}
}

func FuzzDecodeCustodyRecordNeverPanics(f *testing.F) {
	fixture := newCustodyRecordFixture(f)
	encoded, _ := fixture.record.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeCustodyRecord(input) })
}

type custodyRecordFixture struct {
	manifest   Manifest
	receipt    ReplicaReceipt
	store      *ObjectStore
	policy     CustodyPolicy
	replicaKey ed25519.PrivateKey
	auditorKey ed25519.PrivateKey
	record     CustodyRecord
}

func newCustodyRecordFixture(t testing.TB) custodyRecordFixture {
	t.Helper()
	archive := newArchiveFixture(t)
	replicas, _ := archiveReplicaFixture(t, archive, 1_000, 20_000)
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "custody-record-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveDirectory(
		replicas[0].Directory, archive.checkpoint, archive.policy, archive.base,
		archive.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	result := custodyRecordFixture{
		manifest: archive.manifest, receipt: replicas[0].Receipt, store: store,
		replicaKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize)),
		auditorKey: custodyTestKey(81),
	}
	result.policy = custodyTestPolicy(result.auditorKey)
	result.record = result.buildRecord(t, 131, 1_002)
	return result
}

func (fixture custodyRecordFixture) buildRecord(
	t testing.TB,
	nonce byte,
	respondedAt uint64,
) CustodyRecord {
	t.Helper()
	challenge, err := createCustodyChallenge(
		fixture.manifest, fixture.receipt, fixture.auditorKey,
		1_001, 60, 2, 25_000,
		bytes.NewReader(bytes.Repeat([]byte{nonce}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return fixture.answerChallenge(t, challenge, respondedAt)
}

func (fixture custodyRecordFixture) answerChallenge(
	t testing.TB,
	challenge CustodyChallenge,
	respondedAt uint64,
) CustodyRecord {
	t.Helper()
	batch, proof, err := AnswerCustodyChallenge(
		fixture.store, fixture.manifest, fixture.receipt, challenge,
		fixture.policy, fixture.replicaKey, respondedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := RenewReplicaReceipt(
		fixture.manifest, fixture.receipt, challenge, batch, proof,
		fixture.policy, fixture.replicaKey, respondedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return CustodyRecord{
		Version: CustodyRecordVersion0, Challenge: challenge, Batch: batch,
		Proof: proof, RenewedReceipt: renewed,
	}
}
