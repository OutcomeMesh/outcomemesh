package workarchive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodyJournalReplaysRenewalsAcrossRotationAndRestart(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "custody-journal")
	journal, state, err := OpenOrCreateCustodyJournal(
		root, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != 0 || state.CurrentReceipt != fixture.receipt ||
		!state.HeadEntryID.IsZero() {
		t.Fatalf("initial custody journal state=%+v", state)
	}

	first, created, err := journal.Append(fixture.record)
	if err != nil || !created || first.Sequence != 1 || !first.PreviousEntryID.IsZero() {
		t.Fatalf("first custody append entry=%+v created=%t error=%v", first, created, err)
	}
	firstID, err := first.ID()
	if err != nil {
		t.Fatal(err)
	}
	secondRecord := nextCustodyJournalRecord(
		t, fixture, fixture.record.RenewedReceipt, 141, 1_004, 1_005, 30_000,
	)
	second, created, err := journal.Append(secondRecord)
	if err != nil || !created || second.Sequence != 2 || second.PreviousEntryID != firstID ||
		second.PreviousReceipt != fixture.record.RenewedReceipt {
		t.Fatalf("second custody append entry=%+v created=%t error=%v", second, created, err)
	}
	secondID, _ := second.ID()
	if rotated, err := journal.Rotate(); err != nil || !rotated {
		t.Fatalf("custody journal rotated=%t error=%v", rotated, err)
	}
	if active, err := os.ReadDir(journal.activePath()); err != nil || len(active) != 0 {
		t.Fatalf("active custody bodies=%d error=%v", len(active), err)
	}
	segments, err := os.ReadDir(journal.segmentsPath())
	if err != nil || len(segments) != 1 {
		t.Fatalf("custody journal segments=%d error=%v", len(segments), err)
	}
	segmentBodies, err := os.ReadDir(filepath.Join(journal.segmentsPath(), segments[0].Name()))
	if err != nil || len(segmentBodies) != 2 {
		t.Fatalf("sealed custody bodies=%d error=%v", len(segmentBodies), err)
	}

	restarted, recovered, err := OpenOrCreateCustodyJournal(
		root, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Sequence != 2 || recovered.HeadEntryID != secondID ||
		recovered.CurrentReceipt != secondRecord.RenewedReceipt {
		t.Fatalf("replayed custody journal state=%+v", recovered)
	}
	if rotated, err := restarted.Rotate(); err != nil || rotated {
		t.Fatalf("empty custody rotation=%t error=%v", rotated, err)
	}
	if current, err := restarted.State(); err != nil || current != recovered {
		t.Fatalf("restarted custody state=%+v error=%v", current, err)
	}
}

func TestCustodyJournalRotationWaitsForAnotherHandleAppend(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "concurrent-rotation")
	writer, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	rotator, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	bodyReady := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	appendDone := make(chan error, 1)
	go func() {
		_, _, err := writer.append(fixture.record, custodyJournalHooks{afterBody: func() {
			close(bodyReady)
			<-release
		}})
		appendDone <- err
	}()
	select {
	case <-bodyReady:
	case <-time.After(5 * time.Second):
		t.Fatal("append did not reach body publication")
	}
	rotateStarted := make(chan struct{})
	rotateDone := make(chan error, 1)
	go func() {
		close(rotateStarted)
		_, err := rotator.Rotate()
		rotateDone <- err
	}()
	<-rotateStarted
	select {
	case err := <-rotateDone:
		t.Fatalf("rotation passed an unfinished append: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	for _, done := range []<-chan error{appendDone, rotateDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("journal operation did not release its lock")
		}
	}
	state, err := rotator.State()
	if err != nil || state.Sequence != 1 || state.CurrentReceipt != fixture.record.RenewedReceipt {
		t.Fatalf("concurrent rotation state=%+v error=%v", state, err)
	}
}

func TestCustodyJournalSlotDecoderRejectsInvalidEncodings(t *testing.T) {
	slot := custodyJournalSlot{Sequence: 1, EntryID: types.DomainHash("test/journal-slot")}
	encoded, err := slot.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCustodyJournalSlot(encoded)
	if err != nil || decoded != slot {
		t.Fatalf("slot roundtrip: %v", err)
	}
	for _, input := range [][]byte{nil, append(append([]byte(nil), encoded...), 0), encoded[:len(encoded)-1]} {
		if _, err := decodeCustodyJournalSlot(input); !errors.Is(err, ErrCustodyJournal) {
			t.Fatalf("invalid slot accepted: %v", err)
		}
	}
}

func FuzzDecodeCustodyJournalSlotNeverPanics(f *testing.F) {
	slot := custodyJournalSlot{Sequence: 1, EntryID: types.DomainHash("test/journal-slot")}
	encoded, _ := slot.canonicalBytes()
	f.Add(encoded)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = decodeCustodyJournalSlot(input) })
}

func TestCustodyJournalConcurrentSlotChoosesOneChallenge(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	for _, test := range []struct {
		name      string
		records   []CustodyRecord
		wantError int
	}{
		{
			name: "same challenge",
			records: []CustodyRecord{
				fixture.record,
				fixture.answerChallenge(t, fixture.record.Challenge, 1_003),
			},
		},
		{
			name: "sibling challenges",
			records: []CustodyRecord{
				fixture.record,
				fixture.buildRecord(t, 142, 1_003),
			},
			wantError: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "race-journal")
			journals := make([]*CustodyJournal, len(test.records))
			for index := range journals {
				journal, _, err := OpenOrCreateCustodyJournal(
					root, fixture.manifest, fixture.receipt, fixture.policy,
				)
				if err != nil {
					t.Fatal(err)
				}
				journals[index] = journal
			}
			type result struct {
				entry   CustodyJournalEntry
				created bool
				err     error
			}
			start := make(chan struct{})
			results := make(chan result, len(test.records))
			var group sync.WaitGroup
			for index, record := range test.records {
				group.Add(1)
				go func(journal *CustodyJournal, proposed CustodyRecord) {
					defer group.Done()
					<-start
					entry, created, err := journal.Append(proposed)
					results <- result{entry: entry, created: created, err: err}
				}(journals[index], record)
			}
			close(start)
			group.Wait()
			close(results)
			createdCount := 0
			errorCount := 0
			var winnerID types.Hash
			for result := range results {
				if result.err != nil {
					if !errors.Is(result.err, ErrCustodyJournal) {
						t.Fatal(result.err)
					}
					errorCount++
					continue
				}
				if result.created {
					createdCount++
				}
				id, err := result.entry.ID()
				if err != nil {
					t.Fatal(err)
				}
				if winnerID.IsZero() {
					winnerID = id
				} else if id != winnerID {
					t.Fatal("same challenge race returned different slot winners")
				}
			}
			if createdCount != 1 || errorCount != test.wantError {
				t.Fatalf("created=%d errors=%d", createdCount, errorCount)
			}
			_, state, err := OpenOrCreateCustodyJournal(
				root, fixture.manifest, fixture.receipt, fixture.policy,
			)
			if err != nil || state.Sequence != 1 || state.HeadEntryID != winnerID {
				t.Fatalf("race state=%+v winner=%s error=%v", state, winnerID, err)
			}
		})
	}
}

func TestCustodyJournalCrashBoundariesRecoverWithoutMutableHead(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	for _, test := range []struct {
		name         string
		hooks        custodyJournalHooks
		wantSequence uint64
	}{
		{name: "body durable before slot", hooks: custodyJournalHooks{afterBody: panicCustodyJournalHook}},
		{name: "slot durable before return", hooks: custodyJournalHooks{afterSlot: panicCustodyJournalHook}, wantSequence: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "append-crash")
			journal, _, err := OpenOrCreateCustodyJournal(
				root, fixture.manifest, fixture.receipt, fixture.policy,
			)
			if err != nil {
				t.Fatal(err)
			}
			mustPanicCustodyJournal(t, func() { _, _, _ = journal.append(fixture.record, test.hooks) })
			restarted, state, err := OpenOrCreateCustodyJournal(
				root, fixture.manifest, fixture.receipt, fixture.policy,
			)
			if err != nil || state.Sequence != test.wantSequence {
				t.Fatalf("post-crash sequence=%d error=%v", state.Sequence, err)
			}
			entry, created, err := restarted.Append(fixture.record)
			if err != nil || created != (test.wantSequence == 0) || entry.Sequence != 1 {
				t.Fatalf("recovered append entry=%+v created=%t error=%v", entry, created, err)
			}
		})
	}

	root := filepath.Join(t.TempDir(), "rotation-crash")
	journal, _, err := OpenOrCreateCustodyJournal(
		root, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	mustPanicCustodyJournal(t, func() {
		_, _ = journal.rotate(custodyJournalHooks{afterSeal: panicCustodyJournalHook})
	})
	if _, err := os.Lstat(journal.activePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash boundary left active directory error=%v", err)
	}
	_, state, err := OpenOrCreateCustodyJournal(
		root, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil || state.Sequence != 1 || state.CurrentReceipt != fixture.record.RenewedReceipt {
		t.Fatalf("sealed crash recovery state=%+v error=%v", state, err)
	}
}

func TestJournalCustodySessionCommitsBeforeSendAndRecoversExpiredChallenge(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	journal, _, err := OpenOrCreateCustodyJournal(
		filepath.Join(t.TempDir(), "session-journal"),
		fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultCustodySessionConfig()
	config.Now = func() uint64 { return 1_002 }
	replica, err := NewJournalCustodyReplicaSession(
		journal, fixture.store, fixture.replicaKey, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := NewCustodyAuditorSession(
		fixture.manifest, fixture.receipt, fixture.policy, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, _, _ := runCustodyPipeSession(
		t, replica, auditor, fixture.record.Challenge,
	)
	state, err := journal.State()
	if err != nil || state.Sequence != 1 || state.CurrentReceipt != response.RenewedReceipt {
		t.Fatalf("journaled session state=%+v error=%v", state, err)
	}

	// The challenge expired at 1061, but both sides can complete delivery of
	// the already journaled response while its proof is still fresh.
	retryConfig := config
	retryConfig.Now = func() uint64 { return 1_100 }
	restartedReplica, err := NewJournalCustodyReplicaSession(
		journal, fixture.store, fixture.replicaKey, retryConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	restartedAuditor, err := NewCustodyAuditorSession(
		fixture.manifest, fixture.receipt, fixture.policy, retryConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	recovered, _, _ := runCustodyPipeSession(
		t, restartedReplica, restartedAuditor, fixture.record.Challenge,
	)
	recoveredBytes, _ := recovered.RenewedReceipt.CanonicalBytes()
	responseBytes, _ := response.RenewedReceipt.CanonicalBytes()
	if !bytes.Equal(recoveredBytes, responseBytes) {
		t.Fatal("expired retry did not return the exact journaled renewal")
	}
	if state, err := journal.State(); err != nil || state.Sequence != 1 {
		t.Fatalf("expired retry changed journal state=%+v error=%v", state, err)
	}
}

func TestJournalCustodySessionSurvivesFirstResponseWriteFailure(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	journal, _, err := OpenOrCreateCustodyJournal(
		filepath.Join(t.TempDir(), "failed-write-journal"),
		fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultCustodySessionConfig()
	config.Now = func() uint64 { return 1_002 }
	replica, err := NewJournalCustodyReplicaSession(
		journal, fixture.store, fixture.replicaKey, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := fixture.record.Challenge.CanonicalBytes()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(challenge)))
	stream := &custodyFailWriteStream{
		reader: bytes.NewReader(append(prefix[:], challenge...)),
	}
	if _, err := replica.Serve(context.Background(), stream); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("journal session failed write error=%v", err)
	}
	state, err := journal.State()
	if err != nil || state.Sequence != 1 || state.CurrentReceipt != fixture.record.RenewedReceipt {
		t.Fatalf("failed-write journal state=%+v error=%v", state, err)
	}
}

func TestJournalCustodySessionRejectsExpiredUnansweredAndStaleProof(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	for _, test := range []struct {
		name      string
		committed bool
		now       uint64
	}{
		{"unanswered expired challenge", false, 1_100},
		{"committed proof too old", true, 1_123},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, _, err := OpenOrCreateCustodyJournal(filepath.Join(t.TempDir(), "journal"), fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			if test.committed {
				if _, _, err := journal.Append(fixture.record); err != nil {
					t.Fatal(err)
				}
			}
			config := DefaultCustodySessionConfig()
			config.Now = func() uint64 { return test.now }
			replica, err := NewJournalCustodyReplicaSession(journal, fixture.store, fixture.replicaKey, config)
			if err != nil {
				t.Fatal(err)
			}
			auditor, err := NewCustodyAuditorSession(fixture.manifest, fixture.receipt, fixture.policy, config)
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := replica.Serve(ctx, server); done <- err }()
			if _, _, err := auditor.Audit(ctx, client, fixture.record.Challenge); err == nil {
				t.Fatal("invalid retry accepted")
			}
			if err := <-done; err == nil {
				t.Fatal("replica answered invalid retry")
			}
			state, err := journal.State()
			wantSequence := uint64(0)
			if test.committed {
				wantSequence = 1
			}
			if err != nil || state.Sequence != wantSequence {
				t.Fatalf("invalid retry changed journal: %v", err)
			}
		})
	}
}

func TestCustodyJournalRejectsGapMutationAndSymlink(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	policyRoot := filepath.Join(t.TempDir(), "policy-journal")
	if _, _, err := OpenOrCreateCustodyJournal(
		policyRoot, fixture.manifest, fixture.receipt, fixture.policy,
	); err != nil {
		t.Fatal(err)
	}
	changedPolicy := fixture.policy
	changedPolicy.MaximumProofAge--
	if _, _, err := OpenOrCreateCustodyJournal(
		policyRoot, fixture.manifest, fixture.receipt, changedPolicy,
	); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("changed custody journal policy error=%v", err)
	}

	root := filepath.Join(t.TempDir(), "invalid-journal")
	journal, _, err := OpenOrCreateCustodyJournal(
		root, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	second := nextCustodyJournalRecord(
		t, fixture, fixture.record.RenewedReceipt, 143, 1_004, 1_005, 30_000,
	)
	if _, _, err := journal.Append(second); err != nil {
		t.Fatal(err)
	}
	firstSlot := filepath.Join(journal.slotBucketPath(1), custodyJournalSlotName(1))
	if err := os.Remove(firstSlot); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenOrCreateCustodyJournal(
		root, fixture.manifest, fixture.receipt, fixture.policy,
	); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("custody slot gap error=%v", err)
	}

	mutatedRoot := filepath.Join(t.TempDir(), "mutated-journal")
	mutated, _, err := OpenOrCreateCustodyJournal(
		mutatedRoot, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	entry, _, err := mutated.Append(fixture.record)
	if err != nil {
		t.Fatal(err)
	}
	entryID, _ := entry.ID()
	bodyPath := filepath.Join(mutated.activePath(), custodyJournalBodyName(entryID))
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(bodyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenOrCreateCustodyJournal(
		mutatedRoot, fixture.manifest, fixture.receipt, fixture.policy,
	); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("mutated custody body error=%v", err)
	}

	symlinkRoot := filepath.Join(t.TempDir(), "symlink-journal")
	symlinked, _, err := OpenOrCreateCustodyJournal(
		symlinkRoot, fixture.manifest, fixture.receipt, fixture.policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(symlinked.segmentsPath(), "segment-00000000000000000000000000000000")); err != nil {
		t.Fatal(err)
	}
	if _, err := symlinked.State(); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("symlink custody segment error=%v", err)
	}
}

func TestCustodyJournalCodecsAreCanonical(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	manifestID, _ := fixture.manifest.ID()
	policyID, _ := custodyJournalPolicyID(fixture.policy)
	header := CustodyJournalHeader{
		Version: CustodyJournalHeaderVersion0, ManifestID: manifestID,
		PolicyID: policyID, InitialReceipt: fixture.receipt,
	}
	headerBytes, err := header.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decodedHeader, err := DecodeCustodyJournalHeader(headerBytes)
	if err != nil || decodedHeader != header {
		t.Fatalf("decoded custody header=%+v error=%v", decodedHeader, err)
	}
	entry := CustodyJournalEntry{
		Version: CustodyJournalEntryVersion0, Sequence: 1,
		PreviousReceipt: fixture.receipt, Record: fixture.record,
	}
	entryBytes, err := entry.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	entryID, _ := entry.ID()
	if policyID.String() != "aacfa2cbb864c0a2e1777c8db822519cbb35b7e697f897687f6869a023849e72" ||
		types.DomainHash("test/journal-header", headerBytes).String() != "05d26919935a2d0c5c769752b88d33d9412b53b12e1fbc1164d0f5c554fffe53" ||
		entryID.String() != "d9ec03991601ab65d6e0e8478f6b933585858307e31d393df7396b92f0f28933" {
		t.Fatal("custody journal v0 canonical vectors changed")
	}
	decodedEntry, err := DecodeCustodyJournalEntry(entryBytes)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := decodedEntry.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, entryBytes) {
		t.Fatalf("custody entry canonical mismatch error=%v", err)
	}
	if _, err := DecodeCustodyJournalHeader(append(headerBytes, 0)); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("trailing custody header error=%v", err)
	}
	if _, err := DecodeCustodyJournalEntry(append(entryBytes, 0)); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("trailing custody entry error=%v", err)
	}
}

func FuzzDecodeCustodyJournalHeaderNeverPanics(f *testing.F) {
	fixture := newCustodyRecordFixture(f)
	manifestID, _ := fixture.manifest.ID()
	policyID, _ := custodyJournalPolicyID(fixture.policy)
	header := CustodyJournalHeader{
		Version: CustodyJournalHeaderVersion0, ManifestID: manifestID,
		PolicyID: policyID, InitialReceipt: fixture.receipt,
	}
	encoded, _ := header.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeCustodyJournalHeader(input) })
}

func FuzzDecodeCustodyJournalEntryNeverPanics(f *testing.F) {
	fixture := newCustodyRecordFixture(f)
	entry := CustodyJournalEntry{
		Version: CustodyJournalEntryVersion0, Sequence: 1,
		PreviousReceipt: fixture.receipt, Record: fixture.record,
	}
	encoded, _ := entry.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeCustodyJournalEntry(input) })
}

func nextCustodyJournalRecord(
	t testing.TB,
	fixture custodyRecordFixture,
	previous ReplicaReceipt,
	nonce byte,
	issuedAt uint64,
	respondedAt uint64,
	renewUntil uint64,
) CustodyRecord {
	t.Helper()
	challenge, err := createCustodyChallenge(
		fixture.manifest, previous, fixture.auditorKey, issuedAt, 60, 2, renewUntil,
		bytes.NewReader(bytes.Repeat([]byte{nonce}, types.HashSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := AnswerCustodyChallenge(
		fixture.store, fixture.manifest, previous, challenge,
		fixture.policy, fixture.replicaKey, respondedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := RenewReplicaReceipt(
		fixture.manifest, previous, challenge, batch, proof,
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

func panicCustodyJournalHook() { panic("simulated custody journal crash") }

func mustPanicCustodyJournal(t testing.TB, function func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("custody journal crash hook did not panic")
		}
	}()
	function()
}
