package workarchive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func retirementTestLocal(t testing.TB, f custodyRebaselineFixture, emptyReplica bool) CustodyLocalParticipants {
	t.Helper()
	root := t.TempDir()
	local := CustodyLocalParticipants{filepath.Join(root, "auditor"), filepath.Join(root, "artifacts"), filepath.Join(root, "replica")}
	replicaSource := f.rPath
	if emptyReplica {
		replicaSource = f.aPath
	}
	for _, copy := range []struct{ from, to string }{
		{filepath.Join(f.aPath, custodyBackupJournalName), local.AuditorJournal},
		{filepath.Join(f.aPath, custodyBackupArtifactsName), local.AuditorArtifacts},
		{filepath.Join(replicaSource, custodyBackupJournalName), local.ReplicaJournal},
	} {
		if _, err := walkCustodyEvidenceTree(context.Background(), copy.from, copy.to, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths); err != nil {
			t.Fatal(err)
		}
	}
	return local
}

func (f custodyRebaselineFixture) retire(ctx context.Context, local CustodyLocalParticipants, proposal CustodyRebaselineProposal,
	clock func() time.Time, hooks custodyRetirementHooks,
) (CustodyLocalRetirementPair, bool, error) {
	id, _ := proposal.ID()
	return retireLocalCustodyParticipants(ctx, local, proposal, id, f.evidence, f.archive, f.fixture.manifest, f.fixture.receipt, f.fixture.policy, f.next, clock, hooks)
}

func (f custodyRebaselineFixture) verifyRetirement(local CustodyLocalParticipants, proposal CustodyRebaselineProposal, pair CustodyLocalRetirementPair) error {
	proposalID, _ := proposal.ID()
	pairID, _ := pair.ID()
	_, err := VerifyLocalCustodyRetirement(context.Background(), local, pairID, proposal, proposalID, f.evidence, f.archive, f.fixture.manifest,
		f.fixture.receipt, f.fixture.policy, f.next)
	return err
}

func retirementTestOpen(t testing.TB, f custodyRebaselineFixture, path string) *CustodyJournal {
	t.Helper()
	journal, _, err := OpenOrCreateCustodyJournal(path, f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestCustodyRetirementPreservesEvidenceAndRejectsStaleHandles(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	local := retirementTestLocal(t, f, false)
	auditor := retirementTestOpen(t, f, local.AuditorJournal)
	replica := retirementTestOpen(t, f, local.ReplicaJournal)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	pair, changed, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(30_001), custodyRetirementHooks{})
	if err != nil || !changed {
		t.Fatalf("retire: changed=%t %v", changed, err)
	}
	if err := f.verifyRetirement(local, proposal, pair); err != nil {
		t.Fatal(err)
	}
	id, _ := pair.ID()
	if id.String() != "e34f1c1e5801bd6bde5ed7567ba05ffe264148526c1fb9bce8ce269cb621c0a2" {
		t.Fatalf("retirement golden changed: %s", id)
	}
	for _, journal := range []*CustodyJournal{auditor, replica} {
		if _, _, err := OpenOrCreateCustodyJournal(journal.path, f.fixture.manifest, f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalRetired) {
			t.Fatal("retired open", err)
		}
		if _, _, err := journal.Append(f.fixture.record); !errors.Is(err, ErrCustodyJournalRetired) {
			t.Fatal("stale append", err)
		}
		if _, err := journal.Rotate(); !errors.Is(err, ErrCustodyJournalRetired) {
			t.Fatal("stale rotation", err)
		}
		if _, err := journal.AcquireDecision(); !errors.Is(err, ErrCustodyJournalRetired) {
			t.Fatal("stale authority", err)
		}
		if _, err := NewJournalCustodyReplicaSession(journal, f.fixture.store, f.fixture.replicaKey, DefaultCustodySessionConfig()); !errors.Is(err, ErrCustodyJournalRetired) {
			t.Fatal("stale session constructor", err)
		}
		if _, err := journal.State(); err != nil {
			t.Fatal("historical replay forbidden", err)
		}
	}
	// Completed lost-result retry neither renews time nor reopens authority.
	again, changed, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(50_000), custodyRetirementHooks{})
	if err != nil || changed || again != pair {
		t.Fatalf("expired completed retry: %t %v", changed, err)
	}
	post, err := CaptureCustodyCheckpoint(local.AuditorJournal, local.AuditorArtifacts, f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
	if err != nil || post.Journal.Paths != f.a.Journal.Paths+1 || post.Journal.Bytes != f.a.Journal.Bytes+MaximumCustodyParticipantRetirementBytes || post.Artifacts != f.a.Artifacts {
		t.Fatal("retirement delta", err)
	}
	backup := filepath.Join(t.TempDir(), "retired-backup")
	checkpoint, _, err := CreateCustodyBackup(context.Background(), backup, local.AuditorJournal, local.AuditorArtifacts, f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCustodyBackup(backup, mustCheckpointID(t, checkpoint), f.fixture.manifest, f.fixture.receipt, f.fixture.policy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenOrCreateCustodyJournal(filepath.Join(backup, "journal"), f.fixture.manifest, f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalRetired) {
		t.Fatal("backup lost retirement", err)
	}
	assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
	if err := f.verifyApplication(t, f.evidence.Recovery, f.evidence.ApplicationID); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyRetirementCrashBoundariesAndExpiredContinuation(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []string{"locked", "before-commit", "auditor-temp", "auditor", "replica-temp", "replica", "cancel"} {
		t.Run(boundary, func(t *testing.T) {
			local := retirementTestLocal(t, f, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("injected retirement failure")
			hook := func() error { return failure }
			hooks := custodyRetirementHooks{}
			switch boundary {
			case "locked":
				hooks.afterLocks = hook
			case "before-commit":
				hooks.beforeCommit = hook
			case "auditor-temp", "replica-temp":
				hooks.afterTemporary = func(role string) error {
					if role+"-temp" == boundary {
						return failure
					}
					return nil
				}
			case "auditor":
				hooks.afterAuditor = hook
			case "replica":
				hooks.afterReplica = hook
			case "cancel":
				hooks.afterAuditor = func() error { cancel(); return nil }
			}
			if _, _, err := f.retire(ctx, local, proposal, rebaselineTestClock(30_001), hooks); err == nil {
				t.Fatal("failure ignored")
			}
			a, aExists, err := loadCustodyRetirement(local.AuditorJournal)
			if err != nil {
				t.Fatal(err)
			}
			_, rExists, err := loadCustodyRetirement(local.ReplicaJournal)
			if err != nil {
				t.Fatal(err)
			}
			wantA := boundary == "auditor" || boundary == "replica-temp" || boundary == "replica" || boundary == "cancel"
			if aExists != wantA || rExists != (boundary == "replica") {
				t.Fatalf("wrong commit boundary %t/%t", aExists, rExists)
			}
			pair, _, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(50_000), custodyRetirementHooks{})
			if wantA {
				if err != nil || pair.Auditor != a || pair.Replica.DecidedAt != a.DecidedAt {
					t.Fatal("durable intent not completed exactly", err)
				}
				if err := f.verifyRetirement(local, proposal, pair); err != nil {
					t.Fatal(err)
				}
			} else {
				if !errors.Is(err, ErrCustodyRebaselineExpired) {
					t.Fatal("expired uncommitted intent accepted", err)
				}
				if _, _, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(30_002), custodyRetirementHooks{}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCustodyRetirementRefusesChangedOrPartialAuthority(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"artifact-drift", "replica-advance", "partial-advance", "rehashed-marker", "replica-only-marker", "wrong-proposal", "overlap", "missing-lock"} {
		t.Run(mode, func(t *testing.T) {
			local := retirementTestLocal(t, f, false)
			replica := retirementTestOpen(t, f, local.ReplicaJournal)
			if mode == "partial-advance" || mode == "rehashed-marker" {
				_, _, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(30_001), custodyRetirementHooks{afterAuditor: func() error { return io.ErrUnexpectedEOF }})
				if !errors.Is(err, ErrCustodyRetirementIncomplete) {
					t.Fatal(err)
				}
			}
			copyF := f
			switch mode {
			case "artifact-drift":
				writeCheckpointTestFile(t, filepath.Join(local.AuditorArtifacts, "extra"), []byte("retained"))
			case "replica-advance", "partial-advance":
				next := nextCustodyJournalRecord(t, f.fixture, f.fixture.record.RenewedReceipt, 211, 1_004, 1_005, 30_000)
				if _, _, err := replica.Append(next); err != nil {
					t.Fatal(err)
				}
			case "rehashed-marker":
				writeCheckpointTestFile(t, filepath.Join(local.AuditorJournal, "pending", ".outcomemesh-custody-journal-extra"), nil)
				marker, _, _ := loadCustodyRetirement(local.AuditorJournal)
				marker.Before.Journal, err = walkCustodyEvidenceTreeExceptRetirement(context.Background(), local.AuditorJournal, "", MaximumCustodyJournalBytes, MaximumCustodyJournalPaths, true)
				if err != nil {
					t.Fatal(err)
				}
				encoded, _ := marker.CanonicalBytes()
				writeCheckpointTestFile(t, filepath.Join(local.AuditorJournal, custodyRetirementFileName), encoded)
			case "wrong-proposal":
				copyF.evidence.ApplicationID[0] ^= 1
			case "replica-only-marker":
				proposalID, _ := proposal.ID()
				marker := CustodyParticipantRetirement{ProposalID: proposalID, Before: f.r, DecidedAt: 30_001}
				encoded, _ := marker.CanonicalBytes()
				writeCheckpointTestFile(t, filepath.Join(local.ReplicaJournal, custodyRetirementFileName), encoded)
			case "overlap":
				local.ReplicaJournal = local.AuditorJournal
			case "missing-lock":
				if err := os.Rename(filepath.Join(local.AuditorJournal, custodyJournalLockName), filepath.Join(local.AuditorJournal, "retained-lock")); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := copyF.retire(context.Background(), local, proposal, rebaselineTestClock(30_002), custodyRetirementHooks{}); err == nil {
				t.Fatal("changed authority retired")
			}
			if mode == "partial-advance" || mode == "rehashed-marker" {
				if err := requireActiveCustodyJournal(local.AuditorJournal); !errors.Is(err, ErrCustodyJournalRetired) {
					t.Fatal("partial retirement undone", err)
				}
			}
		})
	}
}

type retirementReplyStream struct {
	input       *bytes.Reader
	output      bytes.Buffer
	awaitingEOF chan struct{}
	releaseEOF  <-chan struct{}
	once        sync.Once
}

func (stream *retirementReplyStream) Read(p []byte) (int, error) {
	n, err := stream.input.Read(p)
	if errors.Is(err, io.EOF) && stream.awaitingEOF != nil {
		stream.once.Do(func() { close(stream.awaitingEOF) })
		<-stream.releaseEOF
	}
	return n, err
}
func (stream *retirementReplyStream) Write(p []byte) (int, error) { return stream.output.Write(p) }
func (stream *retirementReplyStream) Close() error                { return nil }
func (stream *retirementReplyStream) SetDeadline(time.Time) error { return nil }
func retirementTestStream(challenge CustodyChallenge) *retirementReplyStream {
	encoded, _ := challenge.CanonicalBytes()
	frame := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(frame, uint32(len(encoded)))
	copy(frame[4:], encoded)
	return &retirementReplyStream{input: bytes.NewReader(frame)}
}

func TestCustodyRetirementDrainsCachedAndRecoveredReplies(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovered", true: "cached"}[cached], func(t *testing.T) {
			f := newCustodyRebaselineFixture(t)
			local := retirementTestLocal(t, f, cached)
			replica := retirementTestOpen(t, f, local.ReplicaJournal)
			config := DefaultCustodySessionConfig()
			config.Now = func() uint64 { return 1_002 }
			session, err := NewJournalCustodyReplicaSession(replica, f.fixture.store, f.fixture.replicaKey, config)
			if err != nil {
				t.Fatal(err)
			}
			if cached {
				if _, err := session.Serve(context.Background(), retirementTestStream(f.fixture.record.Challenge)); err != nil {
					t.Fatal(err)
				}
			}
			proposal, err := f.propose()
			if err != nil {
				t.Fatal(err)
			}
			stream := retirementTestStream(f.fixture.record.Challenge)
			stream.awaitingEOF = make(chan struct{})
			releaseEOF := make(chan struct{})
			stream.releaseEOF = releaseEOF
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(releaseEOF) })
			served := make(chan error, 1)
			go func() { _, err := session.Serve(context.Background(), stream); served <- err }()
			select {
			case <-stream.awaitingEOF:
			case <-time.After(5 * time.Second):
				t.Fatal("response did not reach EOF gate")
			}
			beforeLocks := make(chan struct{})
			retired := make(chan error, 1)
			go func() {
				_, _, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(30_001), custodyRetirementHooks{beforeLocks: func() error { close(beforeLocks); return nil }})
				retired <- err
			}()
			select {
			case <-beforeLocks:
			case <-time.After(5 * time.Second):
				t.Fatal("retirement did not reach locks")
			}
			select {
			case err := <-retired:
				t.Fatalf("retired during live response: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			if _, exists, err := loadCustodyRetirement(local.AuditorJournal); err != nil || exists {
				t.Fatal("partial retirement before drain", err)
			}
			releaseOnce.Do(func() { close(releaseEOF) })
			if err := <-served; err != nil {
				t.Fatal(err)
			}
			if err := <-retired; err != nil {
				t.Fatal(err)
			}
			retry := retirementTestStream(f.fixture.record.Challenge)
			if _, err := session.Serve(context.Background(), retry); !errors.Is(err, ErrCustodyJournalRetired) || retry.output.Len() != 0 {
				t.Fatal("retired cache replied", err)
			}
		})
	}
}

func TestCustodyRetirementCodecAndClosedDecision(t *testing.T) {
	retirement := CustodyParticipantRetirement{ProposalID: types.Hash{1}, Before: checkpointGoldenFixture(), DecidedAt: 30_001}
	encoded, err := retirement.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCustodyParticipantRetirement(encoded)
	if err != nil || decoded != retirement {
		t.Fatal("codec", err)
	}
	for index := range encoded {
		if _, err := DecodeCustodyParticipantRetirement(encoded[:index]); err == nil {
			t.Fatal("truncation", index)
		}
	}
	if _, err := DecodeCustodyParticipantRetirement(append(encoded, 0)); err == nil {
		t.Fatal("trailing bytes")
	}
	f := newCustodyRebaselineFixture(t)
	local := retirementTestLocal(t, f, false)
	journal := retirementTestOpen(t, f, local.AuditorJournal)
	decision, err := journal.AcquireDecision()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decision.Head(); err != nil {
		t.Fatal(err)
	}
	if _, err := decision.Usage(); err != nil {
		t.Fatal(err)
	}
	if err := decision.Close(); err != nil {
		t.Fatal(err)
	}
	if err := decision.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decision.Append(f.fixture.record); !errors.Is(err, ErrCustodyJournal) {
		t.Fatal("closed append", err)
	}
	if _, err := decision.Rotate(); !errors.Is(err, ErrCustodyJournal) {
		t.Fatal("closed rotate", err)
	}
	if _, err := decision.State(); !errors.Is(err, ErrCustodyJournal) {
		t.Fatal("closed state", err)
	}
	if _, _, err := decision.Head(); !errors.Is(err, ErrCustodyJournal) {
		t.Fatal("closed head", err)
	}
	if _, err := decision.Usage(); !errors.Is(err, ErrCustodyJournal) {
		t.Fatal("closed usage", err)
	}
}

func FuzzDecodeCustodyParticipantRetirement(f *testing.F) {
	seed := CustodyParticipantRetirement{ProposalID: types.Hash{1}, Before: checkpointGoldenFixture(), DecidedAt: 30_001}
	encoded, _ := seed.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		value, err := DecodeCustodyParticipantRetirement(input)
		if err == nil {
			encoded, err := value.CanonicalBytes()
			if err != nil || !bytes.Equal(encoded, input) {
				t.Fatal("noncanonical retirement")
			}
		}
	})
}

func TestCustodyRetirementSerializesCompetingRequests(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	local := retirementTestLocal(t, f, false)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		pair    CustodyLocalRetirementPair
		changed bool
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			pair, changed, err := f.retire(context.Background(), local, proposal, rebaselineTestClock(30_001), custodyRetirementHooks{})
			results <- result{pair, changed, err}
		}()
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.pair != second.pair || first.changed == second.changed {
		t.Fatalf("competing retirement: %+v / %+v", first, second)
	}
	if err := f.verifyRetirement(local, proposal, first.pair); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyRetirementChecksTimeAtPublication(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	proposal, err := f.propose()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"locked", "prepared", "temporary", "rollback"} {
		t.Run(phase, func(t *testing.T) {
			local := retirementTestLocal(t, f, false)
			at := int64(30_001)
			expire := func() error { at = 30_300; return nil }
			hooks := custodyRetirementHooks{}
			switch phase {
			case "locked":
				hooks.afterLocks = expire
			case "prepared":
				hooks.beforeCommit = expire
			case "temporary":
				hooks.afterTemporary = func(string) error { return expire() }
			case "rollback":
				hooks.afterTemporary = func(string) error { at = 30_000; return nil }
			}
			if _, changed, err := f.retire(context.Background(), local, proposal, func() time.Time { return time.Unix(at, 0) }, hooks); changed || !errors.Is(err, ErrCustodyRebaselineExpired) {
				t.Fatalf("time check: %t %v", changed, err)
			}
			if err := VerifyCustodyCheckpoint(f.a, mustCheckpointID(t, f.a), local.AuditorJournal, local.AuditorArtifacts, f.fixture.manifest, f.fixture.receipt, f.fixture.policy); err != nil {
				t.Fatal("expired operation changed auditor", err)
			}
			if err := VerifyCustodyCheckpoint(f.r, mustCheckpointID(t, f.r), local.ReplicaJournal, "", f.fixture.manifest, f.fixture.receipt, f.fixture.policy); err != nil {
				t.Fatal("expired operation changed replica", err)
			}
		})
	}
}

func TestCustodyRetirementCorruptMarkerCannotBecomeLive(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	for _, kind := range []string{"empty", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			local := retirementTestLocal(t, f, false)
			journal := retirementTestOpen(t, f, local.AuditorJournal)
			marker := filepath.Join(local.AuditorJournal, custodyRetirementFileName)
			switch kind {
			case "empty":
				writeCheckpointTestFile(t, marker, nil)
			case "directory":
				if err := os.Mkdir(marker, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(local.AuditorJournal, custodyJournalHeaderName), marker); err != nil {
					t.Fatal(err)
				}
			}
			active := filepath.Join(local.AuditorJournal, "objects", "active")
			if err := os.Rename(active, filepath.Join(local.AuditorJournal, "retained-active")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenOrCreateCustodyJournal(local.AuditorJournal, f.fixture.manifest, f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalRetired) {
				t.Fatal("corrupt retirement allowed repair", err)
			}
			if _, err := os.Lstat(active); !os.IsNotExist(err) {
				t.Fatal("retired child repaired")
			}
			if _, _, err := journal.Append(f.fixture.record); !errors.Is(err, ErrCustodyJournalRetired) {
				t.Fatal("corrupt retirement allowed append", err)
			}
		})
	}
}

func TestCustodyJournalSessionRejectsAdvancedHeadBeforeCachedReply(t *testing.T) {
	f := newCustodyRebaselineFixture(t)
	local := retirementTestLocal(t, f, false)
	journal := retirementTestOpen(t, f, local.ReplicaJournal)
	config := DefaultCustodySessionConfig()
	config.Now = func() uint64 { return 1_006 }
	session, err := NewJournalCustodyReplicaSession(journal, f.fixture.store, f.fixture.replicaKey, config)
	if err != nil {
		t.Fatal(err)
	}
	next := nextCustodyJournalRecord(t, f.fixture, f.fixture.record.RenewedReceipt, 211, 1_004, 1_005, 30_000)
	if _, _, err := journal.Append(next); err != nil {
		t.Fatal(err)
	}
	stream := retirementTestStream(f.fixture.record.Challenge)
	if _, err := session.Serve(context.Background(), stream); !errors.Is(err, ErrCustodySession) || stream.output.Len() != 0 {
		t.Fatal("stale journal head replied", err)
	}
}
