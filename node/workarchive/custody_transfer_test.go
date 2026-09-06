package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

type custodyTransferFixture struct {
	fixture      custodyRecordFixture
	aPath, rPath string
	a, r         CustodyCheckpoint
	transfer     CustodyHistoricalTransfer
	id           types.Hash
}

func newCustodyTransferFixture(t testing.TB) custodyTransferFixture {
	t.Helper()
	f, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	writeReconciliationArtifacts(t, artifacts, 1, f.record, true, false, false)
	if _, _, err := replica.Append(f.record); err != nil {
		t.Fatal(err)
	}
	aPath, a := createPinTestBackup(t, f, auditor.path, artifacts)
	rPath, r := createPinTestBackup(t, f, replica.path, "")
	transfer, err := PrepareCustodyHistoricalTransfer(aPath, rPath, mustCheckpointID(t, a), mustCheckpointID(t, r), f.manifest, f.receipt, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	id, err := transfer.ID()
	if err != nil {
		t.Fatal(err)
	}
	return custodyTransferFixture{f, aPath, rPath, a, r, transfer, id}
}

func (f custodyTransferFixture) create(t testing.TB, ctx context.Context, path string, id types.Hash, hooks custodyTransferHooks) (CustodyHistoricalTransfer, bool, error) {
	t.Helper()
	return createCustodyHistoricalTransferPackage(ctx, path, id, f.aPath, f.rPath, mustCheckpointID(t, f.a), mustCheckpointID(t, f.r), f.fixture.manifest, f.fixture.receipt, f.fixture.policy, hooks)
}

func (f custodyTransferFixture) verify(t testing.TB, path string) error {
	t.Helper()
	_, err := VerifyCustodyHistoricalTransferPackage(path, f.id, f.aPath, f.rPath, mustCheckpointID(t, f.a), mustCheckpointID(t, f.r), f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
	return err
}

func TestCustodyHistoricalTransferCanonicalAndHistoricalOnly(t *testing.T) {
	f := newCustodyTransferFixture(t)
	encoded, err := f.transfer.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCustodyHistoricalTransfer(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := decoded.CanonicalBytes()
	if !bytes.Equal(got, encoded) || decoded.Entry.Record.Proof.RespondedAt != f.fixture.record.Proof.RespondedAt {
		t.Fatal("historical evidence changed")
	}
	if err := decoded.Entry.Record.Verify(f.fixture.manifest, f.fixture.receipt, f.fixture.policy); err != nil {
		t.Fatal(err)
	}
	record := decoded.Entry.Record
	if VerifyReplicaRenewal(f.fixture.manifest, f.fixture.receipt, record.RenewedReceipt, record.Challenge, record.Batch, record.Proof, f.fixture.policy, 30_000) == nil {
		t.Fatal("handoff refreshed an old proof")
	}
	for _, invalid := range [][]byte{nil, encoded[:8], encoded[:len(encoded)-1], append(append([]byte(nil), encoded...), 0)} {
		if _, err := DecodeCustodyHistoricalTransfer(invalid); err == nil {
			t.Fatal("noncanonical envelope accepted")
		}
	}
	for _, offset := range []int{0, 8, 10, 10 + MaximumCustodyCheckpointBytes} {
		bad := append([]byte(nil), encoded...)
		bad[offset] ^= 1
		if _, err := DecodeCustodyHistoricalTransfer(bad); err == nil {
			t.Fatalf("changed field at %d accepted", offset)
		}
	}
	for _, mutate := range []func(*CustodyHistoricalTransfer){
		func(v *CustodyHistoricalTransfer) { v.AuditorCheckpoint.HeaderID[0] ^= 1 },
		func(v *CustodyHistoricalTransfer) { v.AuditorCheckpoint.Sequence = ^uint64(0) },
		func(v *CustodyHistoricalTransfer) { v.ReplicaCheckpoint.Artifacts = v.AuditorCheckpoint.Artifacts },
		func(v *CustodyHistoricalTransfer) { v.Entry.PreviousEntryID[0] ^= 1 },
		func(v *CustodyHistoricalTransfer) { v.Entry.Sequence++ },
		func(v *CustodyHistoricalTransfer) { v.ReplicaCheckpoint.ReceiptID[0] ^= 1 },
	} {
		bad := f.transfer
		mutate(&bad)
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("unbound transfer shape accepted")
		}
	}
	if _, err := DecodeCustodyRecord(encoded); err == nil {
		t.Fatal("envelope accepted as live record")
	}
	if _, err := DecodeCustodyJournalEntry(encoded); err == nil {
		t.Fatal("envelope accepted as journal entry")
	}
}

func TestCustodyHistoricalTransferPreservesNonemptyRotatedPrefix(t *testing.T) {
	f, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	for _, journal := range []*CustodyJournal{auditor, replica} {
		if _, _, err := journal.Append(f.record); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Rotate(); err != nil {
			t.Fatal(err)
		}
	}
	writeReconciliationArtifacts(t, artifacts, 1, f.record, true, true, true)
	next := nextCustodyJournalRecord(t, f, f.record.RenewedReceipt, 223, 1_004, 1_005, 30_000)
	writeReconciliationArtifacts(t, artifacts, 2, next, false, true, true)
	if _, _, err := replica.Append(next); err != nil {
		t.Fatal(err)
	}
	aPath, a := createPinTestBackup(t, f, auditor.path, artifacts)
	rPath, r := createPinTestBackup(t, f, replica.path, "")
	transfer, err := PrepareCustodyHistoricalTransfer(aPath, rPath, mustCheckpointID(t, a), mustCheckpointID(t, r), f.manifest, f.receipt, f.policy)
	if err != nil || transfer.Entry.Sequence != 2 || transfer.Entry.PreviousEntryID != a.HeadEntryID {
		t.Fatalf("lost prefix: %v", err)
	}
	want, _ := next.CanonicalBytes()
	got, _ := transfer.Entry.Record.CanonicalBytes()
	if !bytes.Equal(want, got) {
		t.Fatal("response was reassembled or changed")
	}
	assertReconciliationBackupsUnchanged(t, f, aPath, a, rPath, r)
}

func TestCustodyHistoricalTransferRejectsUnresolvedEvidence(t *testing.T) {
	for _, mode := range []string{"no-intent", "unanswered", "already-aligned", "larger-gap", "diverged", "different-response", "different-challenge", "missing-history", "artifact-temp", "journal-temp", "orphan", "checkpoint-temp"} {
		t.Run(mode, func(t *testing.T) {
			f, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
			writeReconciliationArtifacts(t, artifacts, 1, f.record, true, false, false)
			if mode != "unanswered" {
				if _, _, err := replica.Append(f.record); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "no-intent":
				artifacts = filepath.Join(t.TempDir(), "empty")
				lock, err := AcquireCustodyArtifacts(artifacts)
				if err != nil {
					t.Fatal(err)
				}
				_ = lock.Close()
			case "already-aligned":
				if _, _, err := auditor.Append(f.record); err != nil {
					t.Fatal(err)
				}
				writeReconciliationArtifacts(t, artifacts, 1, f.record, true, true, true)
			case "larger-gap", "missing-history", "diverged":
				next := nextCustodyJournalRecord(t, f, f.record.RenewedReceipt, 225, 1_004, 1_005, 30_000)
				if _, _, err := replica.Append(next); err != nil {
					t.Fatal(err)
				}
				if mode != "larger-gap" {
					first := f.record
					if mode == "diverged" {
						first = f.buildRecord(t, 226, 1_003)
					}
					if _, _, err := auditor.Append(first); err != nil {
						t.Fatal(err)
					}
					writeReconciliationArtifacts(t, artifacts, 2, next, true, false, false)
				}
			case "different-response":
				writeReconciliationArtifacts(t, artifacts, 1, f.answerChallenge(t, f.record.Challenge, 1_003), false, true, false)
			case "different-challenge":
				writeReconciliationArtifacts(t, artifacts, 1, f.buildRecord(t, 227, 1_003), true, false, false)
			case "artifact-temp":
				writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000001", ".pending"), nil)
			case "journal-temp":
				writeCheckpointTestFile(t, filepath.Join(auditor.path, "pending", ".outcomemesh-custody-journal-test"), nil)
			case "orphan":
				mustPanicCustodyJournal(t, func() { _, _, _ = auditor.append(f.record, custodyJournalHooks{afterBody: panicCustodyJournalHook}) })
			}
			aPath, a := createPinTestBackup(t, f, auditor.path, artifacts)
			rPath, r := createPinTestBackup(t, f, replica.path, "")
			if mode == "checkpoint-temp" {
				encoded, _ := a.CanonicalBytes()
				writeCheckpointTestFile(t, filepath.Join(aPath, ".outcomemesh-custody-journal-checkpoint"), encoded)
			}
			if _, err := PrepareCustodyHistoricalTransfer(aPath, rPath, mustCheckpointID(t, a), mustCheckpointID(t, r), f.manifest, f.receipt, f.policy); err == nil {
				t.Fatal("unresolved evidence exported")
			}
			assertReconciliationBackupsUnchanged(t, f, aPath, a, rPath, r)
		})
	}
}

func TestCustodyTransferPackageRequiresReviewAndNeverMutatesSources(t *testing.T) {
	f := newCustodyTransferFixture(t)
	path := filepath.Join(t.TempDir(), "handoff")
	for _, wrong := range []types.Hash{{}, {9}} {
		if _, _, err := f.create(t, context.Background(), path, wrong, custodyTransferHooks{}); err == nil {
			t.Fatal("missing review accepted")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid review created destination")
		}
	}
	for index := range 2 {
		got, created, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{})
		id, _ := got.ID()
		if err != nil || created != (index == 0) || id != f.id {
			t.Fatalf("export/retry: %t %v", created, err)
		}
		if err := f.verify(t, path); err != nil {
			t.Fatal(err)
		}
	}
	assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
	if _, err := os.Lstat(filepath.Join(f.aPath, "artifacts", "cycle-00000000000000000001", "record.omcr")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("export imported response into auditor")
	}
	wrongPolicy := f.fixture.policy
	wrongPolicy.MaximumProofAge++
	if _, err := VerifyCustodyHistoricalTransferPackage(path, f.id, f.aPath, f.rPath, mustCheckpointID(t, f.a), mustCheckpointID(t, f.r), f.fixture.manifest, f.fixture.receipt, wrongPolicy); err == nil {
		t.Fatal("policy drift accepted")
	}
	writeCheckpointTestFile(t, filepath.Join(path, "unexpected"), nil)
	if err := f.verify(t, path); err == nil {
		t.Fatal("unknown package evidence ignored")
	}
	if _, _, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{}); err == nil {
		t.Fatal("changed package replaced on retry")
	}
}

func TestCustodyTransferPackageConcurrencyAndFailureBoundaries(t *testing.T) {
	f := newCustodyTransferFixture(t)
	path := filepath.Join(t.TempDir(), "concurrent")
	var wg sync.WaitGroup
	results := make(chan bool, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{})
			if err != nil {
				t.Error(err)
			}
			results <- created
		}()
	}
	wg.Wait()
	close(results)
	createdCount := 0
	for created := range results {
		if created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatal("multiple exports claimed publication")
	}
	for _, mode := range []string{"write", "cancel", "commit"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "package")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("injected transfer failure")
			hooks := custodyTransferHooks{afterWrite: func() error { return failure }}
			if mode == "cancel" {
				hooks.afterWrite = func() error { cancel(); return nil }
			}
			if mode == "commit" {
				hooks = custodyTransferHooks{afterCommit: func() error { return failure }}
			}
			_, created, err := f.create(t, ctx, path, f.id, hooks)
			if err == nil || created != (mode == "commit") {
				t.Fatalf("failure boundary: %t %v", created, err)
			}
			if mode == "commit" {
				if err := f.verify(t, path); err != nil {
					t.Fatal(err)
				}
				if _, created, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{}); err != nil || created {
					t.Fatalf("lost-result retry: %v", err)
				}
			} else {
				if !errors.Is(f.verify(t, path), ErrCustodyTransferIncomplete) {
					t.Fatal("uncommitted envelope accepted")
				}
				if _, _, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{}); !errors.Is(err, ErrCustodyTransferIncomplete) {
					t.Fatal("incomplete attempt resumed")
				}
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != 2 {
					t.Fatal("incomplete evidence deleted")
				}
			}
		})
	}
}

func TestCustodyTransferPackageRejectsUnsafePathsAndChangedEvidence(t *testing.T) {
	f := newCustodyTransferFixture(t)
	for _, path := range []string{f.aPath, filepath.Join(f.aPath, "child"), filepath.Dir(f.rPath)} {
		if _, _, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{}); err == nil {
			t.Fatal("overlapping export allowed")
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(f.aPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.create(t, context.Background(), filepath.Join(alias, "child"), f.id, custodyTransferHooks{}); err == nil {
		t.Fatal("symlink overlap allowed")
	}
	for _, ctx := range []context.Context{nil, cancelledCustodyTransferContext()} {
		path := filepath.Join(t.TempDir(), "absent")
		if _, _, err := f.create(t, ctx, path, f.id, custodyTransferHooks{}); err == nil {
			t.Fatal("invalid context accepted")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cancelled export wrote a directory")
		}
	}
	path := filepath.Join(t.TempDir(), "handoff")
	if _, _, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{}); err != nil {
		t.Fatal(err)
	}
	writeCheckpointTestFile(t, filepath.Join(f.aPath, "artifacts", "cycle-00000000000000000001", "challenge.omcc"), []byte("changed"))
	if err := f.verify(t, path); err == nil {
		t.Fatal("package verification trusted changed source")
	}
	if _, _, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{}); err == nil {
		t.Fatal("retry bypassed source verification")
	}
}

func cancelledCustodyTransferContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func FuzzDecodeCustodyHistoricalTransferNeverPanics(f *testing.F) {
	fixture := newCustodyTransferFixture(f)
	encoded, _ := fixture.transfer.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{})
	f.Add(encoded[:10])
	f.Fuzz(func(t *testing.T, input []byte) {
		transfer, err := DecodeCustodyHistoricalTransfer(input)
		if err != nil {
			return
		}
		canonical, err := transfer.CanonicalBytes()
		if err != nil || !bytes.Equal(input, canonical) {
			t.Fatal("decoder accepted a noncanonical transfer")
		}
	})
}
