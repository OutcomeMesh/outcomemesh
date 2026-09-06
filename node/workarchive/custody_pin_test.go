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

func TestCustodyPinsTrackPendingIntentAndRejectOldBackup(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	oldPath, oldCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	pins := filepath.Join(t.TempDir(), "pins")
	oldID, _ := oldCheckpoint.ID()
	first, created, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, oldID, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil || !created || first.Sequence != 1 {
		t.Fatalf("initial pin: created=%t error=%v", created, err)
	}
	firstID, _ := first.ID()
	// Retain an older copy of the pin authority to test the optional third-domain
	// head receipt. The log itself is not magically immune to full rollback.
	oldPins := filepath.Join(t.TempDir(), "old-pins")
	copyCheckpointTestTree(t, pins, oldPins)
	for _, expected := range []types.Hash{{}, firstID} {
		if again, created, err := PinCustodyBackup(pins, oldPath, "", expected, oldID, fixture.manifest, fixture.receipt, fixture.policy); err != nil || created || again != first {
			t.Fatalf("initial retry: %t %v", created, err)
		}
	}
	next := nextCustodyJournalRecord(t, fixture, fixture.record.RenewedReceipt, 191, 1_004, 1_005, 30_000)
	challengeBytes, _ := next.Challenge.CanonicalBytes()
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000002", "challenge.omcc"), challengeBytes)
	newPath, newCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	newID, _ := newCheckpoint.ID()
	if newCheckpoint.Sequence != oldCheckpoint.Sequence || newID == oldID {
		t.Fatal("fixture did not change intent at the same head")
	}
	if _, _, err := PinCustodyBackup(pins, newPath, "", firstID, newID, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
		t.Fatalf("missing prior bundle accepted: %v", err)
	}
	second, created, err := PinCustodyBackup(pins, newPath, oldPath, firstID, newID, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil || !created || second.Sequence != 2 || second.PreviousPinID != firstID {
		t.Fatalf("pending intent pin: %t %v", created, err)
	}
	secondID, _ := second.ID()
	if again, created, err := PinCustodyBackup(pins, newPath, "", firstID, newID, fixture.manifest, fixture.receipt, fixture.policy); err != nil || created || again != second {
		t.Fatalf("lost-result retry: %t %v", created, err)
	}
	if _, err := VerifyPinnedCustodyBackup(pins, oldPath, types.Hash{}, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatalf("old valid backup accepted as latest: %v", err)
	}
	if head, err := VerifyPinnedCustodyBackup(pins, newPath, secondID, fixture.manifest, fixture.receipt, fixture.policy); err != nil || head != second {
		t.Fatalf("latest verification: %v", err)
	}
	if _, _, err := PinCustodyBackup(pins, oldPath, newPath, secondID, oldID, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
		t.Fatalf("same-head intent rollback accepted: %v", err)
	}
	if _, _, err := PinCustodyBackup(pins, oldPath, newPath, firstID, oldID, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
		t.Fatalf("stale publisher accepted: %v", err)
	}
	if _, err := VerifyPinnedCustodyBackup(oldPins, oldPath, secondID, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
		t.Fatalf("rolled-back pin store accepted against new receipt: %v", err)
	}
	if _, err := VerifyPinnedCustodyBackup(oldPins, oldPath, types.Hash{}, fixture.manifest, fixture.receipt, fixture.policy); err != nil {
		t.Fatalf("old store was not a valid rollback fixture: %v", err)
	}
	if head, err := ReadCustodyBackupPinHead(pins); err != nil || head != second {
		t.Fatalf("rejection changed head: %v", err)
	}
}

func TestCustodyPinsRequireRetainedBodiesAndSameHistory(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	next := nextCustodyJournalRecord(t, fixture, fixture.record.RenewedReceipt, 192, 1_004, 1_005, 30_000)
	mustPanicCustodyJournal(t, func() { _, _, _ = journal.append(next, custodyJournalHooks{afterBody: panicCustodyJournalHook}) })
	orphans, err := os.ReadDir(journal.activePath())
	if err != nil || len(orphans) != 1 {
		t.Fatalf("orphan: %v", err)
	}
	oldPath, oldCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	oldID, _ := oldCheckpoint.ID()
	pins := filepath.Join(t.TempDir(), "pins")
	first, _, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, oldID, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := first.ID()
	if err := os.Remove(filepath.Join(journal.activePath(), orphans[0].Name())); err != nil {
		t.Fatal(err)
	}
	lostPath, lostCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	lostID, _ := lostCheckpoint.ID()
	if _, _, err := PinCustodyBackup(pins, lostPath, oldPath, firstID, lostID, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
		t.Fatalf("lost orphan promoted: %v", err)
	}
	// Restore the exact response and commit it, then rotate. The orphan's path
	// changes but its content ID and all old decisions remain in the new backup.
	if _, _, err := journal.Append(next); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Rotate(); err != nil {
		t.Fatal(err)
	}
	newPath, newCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	newID, _ := newCheckpoint.ID()
	second, created, err := PinCustodyBackup(pins, newPath, oldPath, firstID, newID, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil || !created || second.Checkpoint.Sequence != 2 {
		t.Fatalf("retained rotated body rejected: %v", err)
	}
	// A separately valid sibling chain from the same header is not an extension.
	sibling, _, err := OpenOrCreateCustodyJournal(filepath.Join(t.TempDir(), "sibling"), fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	siblingRecord := fixture.buildRecord(t, 193, 1_003)
	if _, _, err := sibling.Append(siblingRecord); err != nil {
		t.Fatal(err)
	}
	siblingNext := nextCustodyJournalRecord(t, fixture, siblingRecord.RenewedReceipt, 194, 1_006, 1_007, 30_000)
	if _, _, err := sibling.Append(siblingNext); err != nil {
		t.Fatal(err)
	}
	siblingThird := nextCustodyJournalRecord(t, fixture, siblingNext.RenewedReceipt, 195, 1_009, 1_010, 35_000)
	if _, _, err := sibling.Append(siblingThird); err != nil {
		t.Fatal(err)
	}
	siblingPath, siblingCheckpoint := createPinTestBackup(t, fixture, sibling.path, artifacts)
	siblingID, _ := siblingCheckpoint.ID()
	if _, _, err := PinCustodyBackup(pins, siblingPath, newPath, mustPinID(t, second), siblingID, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
		t.Fatalf("sibling history accepted: %v", err)
	}
}

func TestCustodyPinsRejectLostOrChangedRetainedFiles(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	oldPath, oldCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	oldID, _ := oldCheckpoint.ID()
	for _, test := range []struct {
		name   string
		mutate func(string, string) error
	}{
		{name: "changed challenge", mutate: func(_, a string) error {
			return os.WriteFile(filepath.Join(a, "cycle-00000000000000000001", "challenge.omcc"), []byte("different"), 0o600)
		}},
		{name: "lost artifact", mutate: func(_, a string) error {
			return os.Remove(filepath.Join(a, "cycle-00000000000000000001", "challenge.omcc"))
		}},
		{name: "lost empty file", mutate: func(_, a string) error {
			return os.Remove(filepath.Join(a, "cycle-00000000000000000002", ".outcomemesh-work-artifact-empty"))
		}},
		{name: "lost journal temporary", mutate: func(j, _ string) error {
			return os.Remove(filepath.Join(j, "pending", ".outcomemesh-custody-journal-partial"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pins := filepath.Join(t.TempDir(), "pins")
			first, _, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, oldID, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			j, a := filepath.Join(root, "journal"), filepath.Join(root, "artifacts")
			copyCheckpointTestTree(t, journal.path, j)
			copyCheckpointTestTree(t, artifacts, a)
			if err := test.mutate(j, a); err != nil {
				t.Fatal(err)
			}
			candidate, checkpoint := createPinTestBackup(t, fixture, j, a)
			id, _ := checkpoint.ID()
			if _, _, err := PinCustodyBackup(pins, candidate, oldPath, mustPinID(t, first), id, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
				t.Fatalf("evidence loss accepted: %v", err)
			}
			if head, err := ReadCustodyBackupPinHead(pins); err != nil || head != first {
				t.Fatalf("failed promotion changed head: %v", err)
			}
		})
	}
}

func TestCustodyPinsConcurrentPublishersCannotLoseUpdates(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	oldPath, oldCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	oldID, _ := oldCheckpoint.ID()
	pins := filepath.Join(t.TempDir(), "pins")
	first, _, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, oldID, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	firstID := mustPinID(t, first)
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000002", "new"), []byte("intent"))
	newPath, newCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	newID, _ := newCheckpoint.ID()
	var group sync.WaitGroup
	type result struct {
		pin     CustodyBackupPin
		created bool
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			pin, created, err := PinCustodyBackup(pins, newPath, oldPath, firstID, newID, fixture.manifest, fixture.receipt, fixture.policy)
			results <- result{pin, created, err}
		}()
	}
	group.Wait()
	close(results)
	created := 0
	for result := range results {
		if result.err != nil || result.pin.Sequence != 2 {
			t.Fatalf("concurrent pin: %v", result.err)
		}
		if result.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created %d pins for the same update", created)
	}
}

func TestCustodyPinJournalRejectsGapsCorruptionAndMissingAuthority(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	backup, checkpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	id, _ := checkpoint.ID()
	pins := filepath.Join(t.TempDir(), "pins")
	first, _, err := PinCustodyBackup(pins, backup, "", types.Hash{}, id, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{name: "gap", mutate: func(root string) error {
			return os.Rename(filepath.Join(root, "entries", custodyPinEntryName(1)), filepath.Join(root, "entries", custodyPinEntryName(2)))
		}},
		{name: "partial pin", mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, "entries", custodyPinEntryName(1)), []byte{1}, 0o600)
		}},
		{name: "missing lock", mutate: func(root string) error { return os.Remove(filepath.Join(root, custodyPinLockName)) }},
		{name: "foreign path", mutate: func(root string) error { return os.WriteFile(filepath.Join(root, "unknown"), nil, 0o600) }},
		{name: "symlink", mutate: func(root string) error {
			return os.Symlink(backup, filepath.Join(root, "pending", ".outcomemesh-custody-journal-alias"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyPath := filepath.Join(t.TempDir(), "pins")
			copyCheckpointTestTree(t, pins, copyPath)
			if err := test.mutate(copyPath); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadCustodyBackupPinHead(copyPath); err == nil {
				t.Fatal("invalid pin journal accepted")
			}
		})
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, err := PinCustodyBackup(missing, backup, "", mustPinID(t, first), id, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPinConflict) {
		t.Fatalf("missing authority silently initialized: %v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("lost authority path created")
	}
	if _, _, err := PinCustodyBackup(filepath.Join(backup, "pins"), backup, "", types.Hash{}, id, fixture.manifest, fixture.receipt, fixture.policy); err == nil {
		t.Fatal("pin store inside backup accepted")
	}
	if _, _, err := PinCustodyBackup(pins, backup, "", types.Hash{}, types.Hash{1}, fixture.manifest, fixture.receipt, fixture.policy); err == nil {
		t.Fatal("wrong candidate ID accepted")
	}
}

func TestCustodyBackupPinCanonicalEncoding(t *testing.T) {
	pin := CustodyBackupPin{Version: CustodyBackupPinVersion0, Sequence: 2, PreviousPinID: types.Hash{12}, Checkpoint: checkpointGoldenFixture()}
	encoded, err := pin.CanonicalBytes()
	if err != nil || len(encoded) != MaximumCustodyBackupPinBytes {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeCustodyBackupPin(encoded)
	if err != nil || decoded != pin {
		t.Fatalf("round trip: %v", err)
	}
	for size := 0; size < len(encoded); size++ {
		if _, err := DecodeCustodyBackupPin(encoded[:size]); err == nil {
			t.Fatalf("truncated %d accepted", size)
		}
	}
	if _, err := DecodeCustodyBackupPin(append(encoded, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	id, _ := pin.ID()
	const expected = "0157e34ca6a01a7cd902486ea2a0e48298a1f55d40a63cba7a2104e2ee4637ad"
	if id.String() != expected {
		t.Fatalf("pin golden ID=%s", id)
	}
	for _, offset := range []int{0, 8, 18} {
		bad := bytes.Clone(encoded)
		bad[offset] ^= 0xff
		if offset == 18 { // A noninitial pin must have a nonzero predecessor.
			clear(bad[18 : 18+types.HashSize])
		}
		if _, err := DecodeCustodyBackupPin(bad); err == nil {
			t.Fatalf("invalid field at %d accepted", offset)
		}
	}
}

func FuzzDecodeCustodyBackupPinNeverPanics(f *testing.F) {
	pin := CustodyBackupPin{Version: CustodyBackupPinVersion0, Sequence: 1, Checkpoint: checkpointGoldenFixture()}
	encoded, _ := pin.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		pin, err := DecodeCustodyBackupPin(input)
		if err != nil {
			return
		}
		canonical, err := pin.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, input) {
			t.Fatal("noncanonical pin accepted")
		}
	})
}

func createPinTestBackup(t testing.TB, fixture custodyRecordFixture, journal, artifacts string) (string, CustodyCheckpoint) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backup")
	checkpoint, created, err := CreateCustodyBackup(context.Background(), path, journal, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil || !created {
		t.Fatalf("backup: %v", err)
	}
	return path, checkpoint
}

func mustPinID(t testing.TB, pin CustodyBackupPin) types.Hash {
	t.Helper()
	id, err := pin.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
