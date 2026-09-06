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

type custodyApplicationFixture struct {
	custodyTransferFixture
	packagePath string
}

func newCustodyApplicationFixture(t testing.TB) custodyApplicationFixture {
	t.Helper()
	f := newCustodyTransferFixture(t)
	path := filepath.Join(t.TempDir(), "handoff")
	if _, _, err := f.create(t, context.Background(), path, f.id, custodyTransferHooks{}); err != nil {
		t.Fatal(err)
	}
	return custodyApplicationFixture{f, path}
}

func (f custodyApplicationFixture) apply(t testing.TB, ctx context.Context, destination string, limits CustodyJournalLimits, hooks custodyApplicationHooks) (CustodyHistoricalApplication, bool, error) {
	t.Helper()
	return createCustodyHistoricalApplication(ctx, destination, f.packagePath, f.id, f.aPath, f.rPath,
		mustCheckpointID(t, f.a), mustCheckpointID(t, f.r), f.fixture.manifest, f.fixture.receipt, f.fixture.policy, limits, hooks)
}

func (f custodyApplicationFixture) verifyApplication(t testing.TB, destination string, id types.Hash) error {
	t.Helper()
	_, err := VerifyCustodyHistoricalApplication(destination, id, f.packagePath, f.id, f.aPath, f.rPath,
		mustCheckpointID(t, f.a), mustCheckpointID(t, f.r), f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
	return err
}

func TestCustodyHistoricalApplicationPreservesHistoryAndRejectsLiveUse(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	destination := filepath.Join(t.TempDir(), "recovery")
	application, created, err := f.apply(t, context.Background(), destination, DefaultCustodyJournalLimits(), custodyApplicationHooks{})
	if err != nil || !created {
		t.Fatalf("apply: %t %v", created, err)
	}
	id, err := application.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verifyApplication(t, destination, id); err != nil {
		t.Fatal(err)
	}
	if application.Result.Sequence != 1 || application.Result.HeadEntryID != f.r.HeadEntryID || application.Result.ReceiptID != f.r.ReceiptID || application.Result.HeaderID == f.a.HeaderID {
		t.Fatal("incorrect linked result")
	}
	journalPath, artifacts := custodyBackupEvidencePaths(destination, true)
	headerBytes, err := os.ReadFile(filepath.Join(journalPath, custodyJournalHeaderName))
	if err != nil {
		t.Fatal(err)
	}
	header, err := DecodeCustodyJournalHeader(headerBytes)
	if err != nil || header.HistoricalTransferID != f.id || header.Version != CustodyJournalHeaderHistoricalVersion1 {
		t.Fatal("missing immutable quarantine link")
	}
	journal := &CustodyJournal{path: journalPath, header: header, manifest: f.fixture.manifest, policy: f.fixture.policy, limits: DefaultCustodyJournalLimits()}
	state, err := journal.State()
	if err != nil || state.Sequence != 1 || state.CurrentReceipt != f.fixture.record.RenewedReceipt {
		t.Fatalf("historical replay: %v", err)
	}
	before, err := CaptureCustodyCheckpoint(journalPath, artifacts, f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenOrCreateCustodyJournal(journalPath, f.fixture.manifest, f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
		t.Fatalf("live open: %v", err)
	}
	if _, _, err := journal.Append(f.fixture.record); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
		t.Fatal("historical append/retry enabled")
	}
	if _, err := journal.Rotate(); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
		t.Fatal("historical rotation enabled")
	}
	if _, err := NewJournalCustodyReplicaSession(journal, f.fixture.store, f.fixture.replicaKey, DefaultCustodySessionConfig()); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
		t.Fatal("historical serving enabled")
	}
	if err := VerifyCustodyCheckpoint(before, mustCheckpointID(t, before), journalPath, artifacts, f.fixture.manifest, f.fixture.receipt, f.fixture.policy); err != nil {
		t.Fatalf("rejected live operation changed evidence: %v", err)
	}
	recordBytes, _ := f.fixture.record.CanonicalBytes()
	recordPath := filepath.Join(artifacts, "cycle-00000000000000000001", "record.omcr")
	if got, err := os.ReadFile(recordPath); err != nil || !bytes.Equal(got, recordBytes) {
		t.Fatal("applied record changed signed bytes")
	}
	if err := VerifyReplicaRenewal(f.fixture.manifest, f.fixture.receipt, f.fixture.record.RenewedReceipt, f.fixture.record.Challenge, f.fixture.record.Batch, f.fixture.record.Proof, f.fixture.policy, 30_000); err == nil {
		t.Fatal("historical application refreshed a stale proof")
	}
	assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
	if _, err := os.Lstat(filepath.Join(f.aPath, "artifacts", "cycle-00000000000000000001", "record.omcr")); !os.IsNotExist(err) {
		t.Fatal("source auditor was changed")
	}
	// Exact retry above reduced local growth limits allocates no new evidence.
	reduced := CustodyJournalLimits{MaximumBytes: 2 * MaximumCustodyJournalHeaderBytes, MaximumPaths: 9}
	if got, created, err := f.apply(t, context.Background(), destination, reduced, custodyApplicationHooks{}); err != nil || created || got != application {
		t.Fatalf("completed retry: %t %v", created, err)
	}
	second := filepath.Join(t.TempDir(), "independent-recovery")
	again, created, err := f.apply(t, context.Background(), second, DefaultCustodyJournalLimits(), custodyApplicationHooks{})
	if err != nil || !created || again != application {
		t.Fatalf("nondeterministic reconstruction: %v", err)
	}
	assertIndependentCustodyCopy(t, journalPath, filepath.Join(second, custodyBackupJournalName))
}

func TestCustodyHistoricalApplicationRejectsIncompleteAttempts(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	for _, boundary := range []string{"header", "copy", "body", "slot", "artifacts", "before-commit", "after-commit", "cancel"} {
		t.Run(boundary, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recovery")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("injected historical application failure")
			hook := func() error { return failure }
			hooks := custodyApplicationHooks{}
			switch boundary {
			case "header":
				hooks.afterHeader = hook
			case "copy":
				hooks.afterCopy = hook
			case "body":
				hooks.afterBody = hook
			case "slot":
				hooks.afterSlot = hook
			case "artifacts":
				hooks.afterArtifacts = hook
			case "before-commit":
				hooks.beforeCommit = hook
			case "after-commit":
				hooks.afterCommit = hook
			case "cancel":
				hooks.afterCopy = func() error { cancel(); return nil }
			}
			application, created, err := f.apply(t, ctx, path, DefaultCustodyJournalLimits(), hooks)
			if err == nil || created != (boundary == "after-commit") {
				t.Fatalf("failure: %t %v", created, err)
			}
			journalPath := filepath.Join(path, custodyBackupJournalName)
			before, err := digestCustodyEvidenceTree(journalPath, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenOrCreateCustodyJournal(journalPath, f.fixture.manifest, f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
				t.Fatalf("partial recovery became live: %v", err)
			}
			after, err := digestCustodyEvidenceTree(journalPath, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			if err != nil || before != after {
				t.Fatal("live open repaired an incomplete quarantine")
			}
			if boundary == "after-commit" {
				id, _ := application.ID()
				if err := f.verifyApplication(t, path, id); err != nil {
					t.Fatal(err)
				}
				if got, created, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); err != nil || created || got != application {
					t.Fatalf("lost-result retry: %v", err)
				}
			} else {
				if err := f.verifyApplication(t, path, types.Hash{1}); !errors.Is(err, ErrCustodyApplicationIncomplete) {
					t.Fatalf("incomplete accepted: %v", err)
				}
				if _, _, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); !errors.Is(err, ErrCustodyApplicationIncomplete) {
					t.Fatalf("incomplete resumed: %v", err)
				}
			}
			assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
		})
	}
}

func TestCustodyHistoricalApplicationRejectsRehashedExtraEvidence(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	path := filepath.Join(t.TempDir(), "recovery")
	application, _, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{})
	if err != nil {
		t.Fatal(err)
	}
	originalID, _ := application.ID()
	journalPath, artifacts := custodyBackupEvidencePaths(path, true)
	extra := filepath.Join(journalPath, custodyJournalPendingName, ".outcomemesh-custody-journal-injected")
	writeCheckpointTestFile(t, extra, nil)
	// This tree still replays the same signed history. Rehashing its inventory
	// must not turn extra evidence into the reviewed, exact reconstruction.
	application.Result, err = CaptureCustodyCheckpoint(journalPath, artifacts, f.fixture.manifest, f.fixture.receipt, f.fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := application.CanonicalBytes()
	writeCheckpointTestFile(t, filepath.Join(path, custodyApplicationFileName), encoded)
	newID, _ := application.ID()
	if newID == originalID {
		t.Fatal("extra file not bound by checkpoint")
	}
	if err := f.verifyApplication(t, path, newID); err == nil {
		t.Fatal("rehashed extra evidence accepted")
	}
	if _, _, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); err == nil {
		t.Fatal("retry trusted candidate's self-reported checkpoint")
	}
	if _, err := os.Lstat(extra); err != nil {
		t.Fatal("verification removed extra evidence")
	}
}

func TestCustodyHistoricalApplicationSerializesCreationAndChecksTrustBeforeWrites(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	path := filepath.Join(t.TempDir(), "recovery")
	var wg sync.WaitGroup
	results := make(chan bool, 3)
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{})
			if err != nil {
				t.Error(err)
			}
			results <- created
		}()
	}
	wg.Wait()
	close(results)
	total := 0
	for created := range results {
		if created {
			total++
		}
	}
	if total != 1 {
		t.Fatal("multiple application publishers")
	}
	for _, destination := range []string{f.packagePath, f.aPath, filepath.Join(f.rPath, "nested")} {
		if _, _, err := f.apply(t, context.Background(), destination, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); err == nil {
			t.Fatal("overlapping destination allowed")
		}
	}
	absent := filepath.Join(t.TempDir(), "absent")
	if _, _, err := f.apply(t, cancelledCustodyTransferContext(), absent, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); err == nil {
		t.Fatal("cancelled create accepted")
	}
	if _, err := os.Lstat(absent); !os.IsNotExist(err) {
		t.Fatal("cancelled create wrote a destination")
	}
	f.id[0] ^= 1
	if _, _, err := f.apply(t, context.Background(), absent, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); err == nil {
		t.Fatal("wrong transfer ID accepted")
	}
	if _, err := os.Lstat(absent); !os.IsNotExist(err) {
		t.Fatal("wrong review wrote a destination")
	}
}

func TestCustodyHistoricalHeaderAndApplicationCodecs(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	encoded, err := os.ReadFile(filepath.Join(f.aPath, "journal", custodyJournalHeaderName))
	if err != nil {
		t.Fatal(err)
	}
	header, err := DecodeCustodyJournalHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	header.Version, header.HistoricalTransferID = CustodyJournalHeaderHistoricalVersion1, f.id
	historical, err := header.CanonicalBytes()
	if err != nil || len(historical) != len(encoded)+types.HashSize {
		t.Fatal("historical header size")
	}
	if decoded, err := DecodeCustodyJournalHeader(historical); err != nil || decoded != header {
		t.Fatal("historical header roundtrip")
	}
	for _, bad := range [][]byte{historical[:len(historical)-1], append(append([]byte(nil), historical...), 0)} {
		if _, err := DecodeCustodyJournalHeader(bad); err == nil {
			t.Fatal("malformed historical header accepted")
		}
	}
	header.Version = CustodyJournalHeaderVersion0
	if _, err := header.CanonicalBytes(); err == nil {
		t.Fatal("live header carries a hidden recovery link")
	}
	header.Version, header.HistoricalTransferID = CustodyJournalHeaderHistoricalVersion1, types.Hash{}
	if _, err := header.CanonicalBytes(); err == nil {
		t.Fatal("historical header missing link")
	}
	application := CustodyHistoricalApplication{Version: CustodyHistoricalApplicationVersion0, TransferID: f.id, Result: f.r}
	application.Result.Artifacts = f.a.Artifacts
	encoded, err = application.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCustodyHistoricalApplication(encoded)
	if err != nil || decoded != application {
		t.Fatal("application roundtrip")
	}
	for _, bad := range [][]byte{nil, encoded[:len(encoded)-1], append(append([]byte(nil), encoded...), 0)} {
		if _, err := DecodeCustodyHistoricalApplication(bad); err == nil {
			t.Fatal("malformed application accepted")
		}
	}
}

func TestCustodyHistoricalApplicationKeepsRotatedPrefixAndOldArtifacts(t *testing.T) {
	fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	for _, journal := range []*CustodyJournal{auditor, replica} {
		if _, _, err := journal.Append(fixture.record); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Rotate(); err != nil {
			t.Fatal(err)
		}
	}
	writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, true, true)
	next := nextCustodyJournalRecord(t, fixture, fixture.record.RenewedReceipt, 231, 1_004, 1_005, 30_000)
	if _, _, err := replica.Append(next); err != nil {
		t.Fatal(err)
	}
	writeReconciliationArtifacts(t, artifacts, 2, next, false, true, false)
	aPath, a := createPinTestBackup(t, fixture, auditor.path, artifacts)
	rPath, r := createPinTestBackup(t, fixture, replica.path, "")
	transfer, err := PrepareCustodyHistoricalTransfer(aPath, rPath, mustCheckpointID(t, a), mustCheckpointID(t, r), fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := transfer.ID()
	base := custodyTransferFixture{fixture, aPath, rPath, a, r, transfer, id}
	packagePath := filepath.Join(t.TempDir(), "handoff")
	if _, _, err := base.create(t, context.Background(), packagePath, id, custodyTransferHooks{}); err != nil {
		t.Fatal(err)
	}
	f := custodyApplicationFixture{base, packagePath}
	path := filepath.Join(t.TempDir(), "recovery")
	application, created, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{})
	if err != nil || !created || application.Result.Sequence != 2 {
		t.Fatalf("rotated prefix application: %v", err)
	}
	applicationID, _ := application.ID()
	if err := f.verifyApplication(t, path, applicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(path, "artifacts", "cycle-00000000000000000002", "challenge.omcc")); err != nil {
		t.Fatal("missing challenge was not restored from exact record")
	}
	assertReconciliationBackupsUnchanged(t, fixture, aPath, a, rPath, r)
	// A rehashed output must not be allowed to alter an earlier cycle.
	writeCheckpointTestFile(t, filepath.Join(path, "artifacts", "cycle-00000000000000000001", "record.omcr"), []byte("changed old evidence"))
	application.Result, err = CaptureCustodyCheckpoint(filepath.Join(path, "journal"), filepath.Join(path, "artifacts"), fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := application.CanonicalBytes()
	writeCheckpointTestFile(t, filepath.Join(path, custodyApplicationFileName), encoded)
	applicationID, _ = application.ID()
	if err := f.verifyApplication(t, path, applicationID); err == nil {
		t.Fatal("rehashed changed prefix artifact accepted")
	}
}

func TestCustodyHistoricalApplicationKeepsBudgetFailureQuarantined(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	path := filepath.Join(t.TempDir(), "recovery")
	limits := CustodyJournalLimits{MaximumBytes: 2 * MaximumCustodyJournalHeaderBytes, MaximumPaths: 9}
	if _, _, err := f.apply(t, context.Background(), path, limits, custodyApplicationHooks{}); !errors.Is(err, ErrCustodyJournalBudget) {
		t.Fatalf("growth budget bypassed: %v", err)
	}
	if _, _, err := OpenOrCreateCustodyJournal(filepath.Join(path, "journal"), f.fixture.manifest, f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
		t.Fatal("budget failure left a live journal")
	}
	if _, _, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); !errors.Is(err, ErrCustodyApplicationIncomplete) {
		t.Fatal("higher budget resumed an incomplete application")
	}
	assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
}

func TestCustodyHistoricalApplicationChecksRootBeforeCommit(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	path := filepath.Join(t.TempDir(), "recovery")
	hooks := custodyApplicationHooks{beforeCommit: func() error {
		return os.WriteFile(filepath.Join(path, "unexpected"), []byte("keep"), 0o600)
	}}
	if _, _, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), hooks); err == nil {
		t.Fatal("unexpected root entry committed")
	}
	if _, err := os.Lstat(filepath.Join(path, custodyApplicationFileName)); !os.IsNotExist(err) {
		t.Fatal("invalid root received completion marker")
	}
	if got, err := os.ReadFile(filepath.Join(path, "unexpected")); err != nil || string(got) != "keep" {
		t.Fatal("unexpected evidence was removed")
	}
}

func FuzzDecodeCustodyHistoricalApplicationNeverPanics(f *testing.F) {
	fixture := newCustodyTransferFixture(f)
	application := CustodyHistoricalApplication{Version: CustodyHistoricalApplicationVersion0, TransferID: fixture.id, Result: fixture.r}
	application.Result.Artifacts = fixture.a.Artifacts
	encoded, _ := application.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		value, err := DecodeCustodyHistoricalApplication(input)
		if err != nil {
			return
		}
		canonical, err := value.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, input) {
			t.Fatal("noncanonical application accepted")
		}
	})
}
