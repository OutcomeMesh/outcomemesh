package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

type custodyRebaselineFixture struct {
	custodyApplicationFixture
	evidence CustodyRebaselineEvidence
	archive  CustodyRebaselineArchive
	next     CustodyRebaselineAssignment
	key      ed25519.PrivateKey
}

func newCustodyRebaselineFixture(t testing.TB) custodyRebaselineFixture {
	t.Helper()
	f := newCustodyApplicationFixture(t)
	recovery := filepath.Join(t.TempDir(), "recovery")
	application, _, err := f.apply(t, context.Background(), recovery, DefaultCustodyJournalLimits(), custodyApplicationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	applicationID, _ := application.ID()
	a := newArchiveFixture(t) // Deterministic full archive underlying the retained custody fixture.
	id, _ := f.fixture.manifest.ID()
	if a.manifestID != id {
		t.Fatal("fixture archives differ")
	}
	key := custodyTestKey(201)
	var public [ed25519.PublicKeySize]byte
	copy(public[:], key.Public().(ed25519.PublicKey))
	return custodyRebaselineFixture{f,
		CustodyRebaselineEvidence{recovery, f.packagePath, f.aPath, f.rPath, applicationID, f.id, mustCheckpointID(t, f.a), mustCheckpointID(t, f.r)},
		CustodyRebaselineArchive{a.archivePath, a.checkpoint, a.policy, a.base, a.parameters, DefaultLimits()},
		CustodyRebaselineAssignment{custodyTestPolicy(custodyTestKey(202)), public, types.Hash{203}}, key}
}

func rebaselineTestClock(at int64) func() time.Time {
	return func() time.Time { return time.Unix(at, 0) }
}

func (f custodyRebaselineFixture) propose() (CustodyRebaselineProposal, error) {
	return createCustodyRebaselineProposal(context.Background(), f.evidence, f.archive, f.fixture.manifest, f.fixture.receipt,
		f.fixture.policy, f.next, f.key, 300, 40_000, rebaselineTestClock(30_000))
}

func (f custodyRebaselineFixture) verify(proposal CustodyRebaselineProposal, clock func() time.Time) error {
	id, _ := proposal.ID()
	return verifyCustodyRebaselineProposal(context.Background(), proposal, id, f.evidence, f.archive,
		f.fixture.manifest, f.fixture.receipt, f.fixture.policy, f.next, clock)
}

func TestCustodyRebaselineLinksFullReplayWithoutLiveAuthority(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := proposal.ID()
	const expectedID = "cdf8113c102da090a6759fe0b37bd4cf086cb402c44ab1343175e2f064e30b18"
	if id.String() != expectedID {
		t.Fatalf("rebaseline golden changed: %s", id)
	}
	encoded, err := proposal.CanonicalBytes()
	if err != nil || len(encoded) != MaximumCustodyRebaselineProposalBytes {
		t.Fatal("encoding", err)
	}
	decoded, err := DecodeCustodyRebaselineProposal(encoded)
	if err != nil || decoded != proposal {
		t.Fatal("round trip", err)
	}
	if proposal.ApplicationID != f.evidence.ApplicationID || proposal.PreviousReceiptID != f.r.ReceiptID ||
		proposal.ReplayedAt != 30_000 || proposal.ReviewUntil != 30_300 || proposal.ReplicaPublicKey == f.fixture.receipt.ReplicaPublicKey {
		t.Fatal("wrong linkage or assignment")
	}
	if err := f.verify(proposal, rebaselineTestClock(30_001)); err != nil {
		t.Fatal(err)
	}
	if again, err := f.propose(); err != nil || again != proposal {
		t.Fatal("nondeterministic replay", err)
	}
	// The proposal contains no reusable receipt signature or live journal header.
	if _, err := DecodeReplicaReceipt(encoded); err == nil {
		t.Fatal("proposal accepted as receipt")
	}
	if _, err := DecodeCustodyJournalHeader(encoded); err == nil {
		t.Fatal("proposal accepted as journal header")
	}
	if _, err := DecodeCustodyChallenge(encoded); err == nil {
		t.Fatal("proposal accepted as challenge")
	}
	forgedReceipt := ReplicaReceipt{Version: ReplicaReceiptVersion0, Binding: f.fixture.manifest.Binding,
		StatementID: proposal.StatementID, ManifestID: proposal.ManifestID, AnchorID: f.fixture.manifest.Anchor.ID,
		LocationID: proposal.LocationID, StoredAt: proposal.ReplayedAt, RetainUntil: proposal.RetainUntil,
		ReplicaPublicKey: proposal.ReplicaPublicKey, Signature: proposal.Signature}
	if _, err := forgedReceipt.CanonicalBytes(); err == nil {
		t.Fatal("proposal signature reused in live receipt domain")
	}
	if _, _, err := OpenOrCreateCustodyJournal(filepath.Join(f.evidence.Recovery, "journal"), f.fixture.manifest,
		f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
		t.Fatal("quarantine removed", err)
	}
	if err := f.verifyApplication(t, f.evidence.Recovery, f.evidence.ApplicationID); err != nil {
		t.Fatal(err)
	}
	assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
	if err := VerifyReplicaRenewal(f.fixture.manifest, f.fixture.receipt, f.fixture.record.RenewedReceipt,
		f.fixture.record.Challenge, f.fixture.record.Batch, f.fixture.record.Proof, f.fixture.policy, 30_000); err == nil {
		t.Fatal("old sampled proof refreshed")
	}
	for _, at := range []int64{0, 29_999, 30_300, 40_000} {
		if err := f.verify(proposal, rebaselineTestClock(at)); !errors.Is(err, ErrCustodyRebaselineExpired) {
			t.Fatalf("time %d: %v", at, err)
		}
	}
	if err := f.verify(proposal, rebaselineTestClock(30_299)); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := f.verify(proposal, func() time.Time {
		calls++
		if calls == 1 {
			return time.Unix(30_299, 0)
		}
		return time.Unix(30_300, 0)
	}); !errors.Is(err, ErrCustodyRebaselineExpired) || calls != 2 {
		t.Fatal("expiry during replay ignored", err)
	}
	calls = 0
	if err := f.verify(proposal, func() time.Time {
		calls++
		return time.Unix(30_200-int64(calls), 0)
	}); !errors.Is(err, ErrCustodyRebaselineExpired) || calls != 2 {
		t.Fatal("rollback inside review window ignored", err)
	}
}

func TestCustodyRebaselineRejectsWrongTrustAndReusedKeys(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*custodyRebaselineFixture){
		"application":             func(v *custodyRebaselineFixture) { v.evidence.ApplicationID[0] ^= 1 },
		"missing-application-pin": func(v *custodyRebaselineFixture) { v.evidence.ApplicationID = types.Hash{} },
		"transfer":                func(v *custodyRebaselineFixture) { v.evidence.TransferID[0] ^= 1 },
		"auditor-pin":             func(v *custodyRebaselineFixture) { v.evidence.AuditorCheckpointID[0] ^= 1 },
		"replica-pin":             func(v *custodyRebaselineFixture) { v.evidence.ReplicaCheckpointID[0] ^= 1 },
		"source-overlap":          func(v *custodyRebaselineFixture) { v.evidence.Recovery = v.evidence.AuditorBackup },
		"archive-overlap":         func(v *custodyRebaselineFixture) { v.archive.Directory = v.evidence.Recovery },
		"old-replica": func(v *custodyRebaselineFixture) {
			v.key = v.fixture.replicaKey
			v.next.ReplicaPublicKey = v.fixture.receipt.ReplicaPublicKey
		},
		"old-auditor-as-replica": func(v *custodyRebaselineFixture) {
			v.key = v.fixture.auditorKey
			copy(v.next.ReplicaPublicKey[:], v.key.Public().(ed25519.PublicKey))
		},
		"old-auditor":            func(v *custodyRebaselineFixture) { v.next.Policy = v.fixture.policy },
		"old-replica-as-auditor": func(v *custodyRebaselineFixture) { v.next.Policy = custodyTestPolicy(v.fixture.replicaKey) },
		"same-new-roles":         func(v *custodyRebaselineFixture) { v.next.Policy = custodyTestPolicy(v.key) },
		"wrong-signing-key":      func(v *custodyRebaselineFixture) { v.key = custodyTestKey(204) },
		"missing-archive":        func(v *custodyRebaselineFixture) { v.archive.Directory = filepath.Join(t.TempDir(), "absent") },
		"wrong-archive-trust":    func(v *custodyRebaselineFixture) { v.archive.Policy.RequiredAttestations = 3 },
		"wrong-consensus":        func(v *custodyRebaselineFixture) { v.archive.Parameters.NetworkID++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := f
			mutate(&changed)
			if _, err := changed.propose(); err == nil {
				t.Fatal("invalid creation accepted")
			}
			// Verification never takes its trust or new assignment from the signed candidate.
			if name != "wrong-signing-key" {
				if err := changed.verify(proposal, rebaselineTestClock(30_001)); err == nil {
					t.Fatal("invalid review accepted")
				}
			}
		})
	}
	for _, mutate := range []func(*CustodyRebaselineProposal){
		func(v *CustodyRebaselineProposal) { v.PreviousReceiptID[0] ^= 1 },
		func(v *CustodyRebaselineProposal) { v.ManifestID[0] ^= 1 },
		func(v *CustodyRebaselineProposal) { v.StatementID[0] ^= 1 },
		func(v *CustodyRebaselineProposal) { v.NextPolicyID[0] ^= 1 },
		func(v *CustodyRebaselineProposal) { v.LocationID[0] ^= 1 },
		func(v *CustodyRebaselineProposal) {
			v.RetainUntil = 24_000
			v.ReplayedAt = 1_100
			v.ReviewUntil = 1_200
		},
		func(v *CustodyRebaselineProposal) { v.ReplayedAt = 1_001; v.ReviewUntil = 1_100 },
	} {
		changed := proposal
		mutate(&changed)
		message, err := changed.signatureMessage()
		if err != nil {
			t.Fatal("test mutation malformed", err)
		}
		copy(changed.Signature[:], ed25519.Sign(f.key, message))
		if err := f.verify(changed, rebaselineTestClock(int64(changed.ReplayedAt))); err == nil {
			t.Fatal("resigned different assignment accepted")
		}
	}
}

func TestCustodyRebaselineRequiresArchiveBytesAndCompletedHistory(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	// Even the exact signed proposal and unchanged manifest cannot replace replay.
	path := filepath.Join(f.archive.Directory, chunkFileName(0))
	original := mustReadArchiveFile(t, path)
	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-1] ^= 1
	writeCheckpointTestFile(t, path, corrupt)
	if _, err := f.propose(); err == nil {
		t.Fatal("corrupt archive signed")
	}
	if err := f.verify(proposal, rebaselineTestClock(30_001)); err == nil {
		t.Fatal("corrupt archive reviewed")
	}
	writeCheckpointTestFile(t, path, original)
	marker := filepath.Join(f.evidence.Recovery, custodyApplicationFileName)
	if err := os.Rename(marker, marker+".retained"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.propose(); err == nil {
		t.Fatal("incomplete history signed")
	}
}

func TestCustodyRebaselineBoundsAndCancellation(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	for _, test := range []struct {
		at               int64
		lifetime, retain uint64
	}{
		{0, 300, 40_000}, {-1, 300, 40_000}, {1_001, 300, 40_000}, {30_000, 0, 40_000},
		{30_000, 601, 40_000}, {30_000, 300, 30_300}, {30_000, 300, ^uint64(0)},
	} {
		if _, err := createCustodyRebaselineProposal(context.Background(), f.evidence, f.archive, f.fixture.manifest,
			f.fixture.receipt, f.fixture.policy, f.next, f.key, test.lifetime, test.retain, rebaselineTestClock(test.at)); err == nil {
			t.Fatalf("bad bounds: %+v", test)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := createCustodyRebaselineProposal(ctx, f.evidence, f.archive, f.fixture.manifest, f.fixture.receipt,
		f.fixture.policy, f.next, f.key, 300, 40_000, rebaselineTestClock(30_000)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if _, err := createCustodyRebaselineProposal(ctx, f.evidence, f.archive, f.fixture.manifest, f.fixture.receipt,
		f.fixture.policy, f.next, f.key, 300, 40_000, func() time.Time { cancel(); return time.Unix(30_000, 0) }); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation ignored", err)
	}
}

func TestCustodyRebaselineCodecRejectsEveryChangedByte(t *testing.T) {
	encoded := custodyRebaselineCodecSeed(t)
	for offset := range encoded {
		bad := append([]byte(nil), encoded...)
		bad[offset] ^= 1
		if _, err := DecodeCustodyRebaselineProposal(bad); err == nil {
			t.Fatalf("changed byte %d accepted", offset)
		}
		if _, err := DecodeCustodyRebaselineProposal(encoded[:offset]); err == nil {
			t.Fatalf("truncation %d accepted", offset)
		}
	}
	if _, err := DecodeCustodyRebaselineProposal(append(encoded, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

func custodyRebaselineCodecSeed(t testing.TB) []byte {
	t.Helper()
	key := custodyTestKey(201)
	v := CustodyRebaselineProposal{ApplicationID: types.Hash{1}, PreviousReceiptID: types.Hash{2}, ManifestID: types.Hash{3},
		StatementID: types.Hash{4}, NextPolicyID: types.Hash{5}, LocationID: types.Hash{6}, ReplayedAt: 30_000, ReviewUntil: 30_300, RetainUntil: 40_000}
	copy(v.ReplicaPublicKey[:], key.Public().(ed25519.PublicKey))
	message, _ := v.signatureMessage()
	copy(v.Signature[:], ed25519.Sign(key, message))
	encoded, err := v.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func FuzzDecodeCustodyRebaselineProposal(f *testing.F) {
	f.Add(custodyRebaselineCodecSeed(f))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		v, err := DecodeCustodyRebaselineProposal(encoded)
		if err == nil {
			again, err := v.CanonicalBytes()
			if err != nil || !bytes.Equal(encoded, again) {
				t.Fatal("noncanonical decode")
			}
		}
	})
}
