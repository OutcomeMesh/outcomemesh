package workarchive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodyPinsDifferentConcurrentUpdatesRequireFreshExpectation(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	oldPath, oldCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	oldID, _ := oldCheckpoint.ID()
	pins := filepath.Join(t.TempDir(), "pins")
	first, _, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, oldID, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	firstID := mustPinID(t, first)
	var paths [2]string
	var ids [2]types.Hash
	for index := range paths {
		writeCheckpointTestFile(t, filepath.Join(artifacts, fmt.Sprintf("extra-%d", index)), []byte("retained evidence"))
		path, checkpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
		paths[index], ids[index] = path, mustCheckpointID(t, checkpoint)
	}
	type result struct {
		pin     CustodyBackupPin
		created bool
		err     error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for index := range paths {
		go func() {
			<-start
			pin, created, err := PinCustodyBackup(pins, paths[index], oldPath, firstID, ids[index], fixture.manifest, fixture.receipt, fixture.policy)
			results <- result{pin, created, err}
		}()
	}
	close(start)
	var accepted, conflicts int
	var winner CustodyBackupPin
	for range paths {
		result := <-results
		if result.err == nil && result.created && result.pin.Sequence == 2 {
			accepted++
			winner = result.pin
		} else if errors.Is(result.err, ErrCustodyBackupPinConflict) && !result.created {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent result: %+v", result)
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatalf("accepted=%d conflicts=%d", accepted, conflicts)
	}
	if head, err := ReadCustodyBackupPinHead(pins); err != nil || head != winner {
		t.Fatalf("lost winning pin: %v", err)
	}
}

func TestCustodyPinPendingCapacityPreservesHeadAndExactRetry(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	oldPath, oldCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	oldID, _ := oldCheckpoint.ID()
	pins := filepath.Join(t.TempDir(), "pins")
	first, _, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, oldID, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	for index := range MaximumCustodyPinPendingFiles {
		writeCheckpointTestFile(t, filepath.Join(pins, "pending", fmt.Sprintf(".outcomemesh-custody-journal-retained-%d", index)), nil)
	}
	if again, created, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, oldID, fixture.manifest, fixture.receipt, fixture.policy); err != nil || created || again != first {
		t.Fatalf("retry at capacity: %v", err)
	}
	writeCheckpointTestFile(t, filepath.Join(artifacts, "new"), []byte("new evidence"))
	newPath, checkpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	if _, _, err := PinCustodyBackup(pins, newPath, oldPath, mustPinID(t, first), mustCheckpointID(t, checkpoint), fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupPin) {
		t.Fatalf("capacity bypassed: %v", err)
	}
	if head, err := ReadCustodyBackupPinHead(pins); err != nil || head != first {
		t.Fatalf("head changed at capacity: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(pins, "pending"))
	if err != nil || len(entries) != MaximumCustodyPinPendingFiles {
		t.Fatalf("pending evidence removed: %v", err)
	}
	writeCheckpointTestFile(t, filepath.Join(pins, "pending", ".outcomemesh-custody-journal-over-cap"), nil)
	if _, err := ReadCustodyBackupPinHead(pins); err == nil {
		t.Fatal("over-cap inventory accepted")
	}
}

func TestCustodyPinJournalRejectsOutOfRangeSlotsAndPartialInitialization(t *testing.T) {
	for _, sequence := range []uint64{0, MaximumCustodyBackupPins + 1} {
		pins := filepath.Join(t.TempDir(), "pins")
		if err := initializeCustodyPins(pins); err != nil {
			t.Fatal(err)
		}
		pin := CustodyBackupPin{Sequence: 1, Checkpoint: checkpointGoldenFixture()}
		encoded, _ := pin.CanonicalBytes()
		writeCheckpointTestFile(t, filepath.Join(pins, "entries", custodyPinEntryName(sequence)), encoded)
		if _, err := ReadCustodyBackupPinHead(pins); err == nil {
			t.Fatalf("out-of-range slot %d accepted", sequence)
		}
	}
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	backup, checkpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	pins := filepath.Join(t.TempDir(), "pins")
	if err := os.Mkdir(pins, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PinCustodyBackup(pins, backup, "", types.Hash{}, mustCheckpointID(t, checkpoint), fixture.manifest, fixture.receipt, fixture.policy); err == nil {
		t.Fatal("partial initialization repaired")
	}
	entries, err := os.ReadDir(pins)
	if err != nil || len(entries) != 0 {
		t.Fatalf("partial authority changed: %v", err)
	}
}

func mustCheckpointID(t testing.TB, checkpoint CustodyCheckpoint) types.Hash {
	t.Helper()
	id, err := checkpoint.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCustodyPinHistoryRejectsBrokenLinksAndScopeChanges(t *testing.T) {
	first := CustodyBackupPin{Sequence: 1, Checkpoint: checkpointGoldenFixture()}
	second := CustodyBackupPin{Sequence: 2, PreviousPinID: mustPinID(t, first), Checkpoint: first.Checkpoint}
	second.Checkpoint.Artifacts.ID[0] ^= 1
	for _, test := range []struct {
		name   string
		mutate func(*CustodyBackupPin)
	}{
		{name: "wrong link", mutate: func(pin *CustodyBackupPin) { pin.PreviousPinID[0] ^= 1 }},
		{name: "wrong sequence", mutate: func(pin *CustodyBackupPin) { pin.Sequence++ }},
		{name: "changed header", mutate: func(pin *CustodyBackupPin) { pin.Checkpoint.HeaderID[1] ^= 1 }},
		{name: "changed scope", mutate: func(pin *CustodyBackupPin) { pin.Checkpoint.Artifacts = CustodyCheckpointTree{} }},
		{name: "regressed head", mutate: func(pin *CustodyBackupPin) { pin.Checkpoint.Sequence-- }},
		{name: "sibling head", mutate: func(pin *CustodyBackupPin) { pin.Checkpoint.HeadEntryID[0] ^= 1 }},
		{name: "different receipt", mutate: func(pin *CustodyBackupPin) { pin.Checkpoint.ReceiptID[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			pins := filepath.Join(t.TempDir(), "pins")
			if err := initializeCustodyPins(pins); err != nil {
				t.Fatal(err)
			}
			for _, pin := range []CustodyBackupPin{first, second} {
				encoded, err := pin.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				writeCheckpointTestFile(t, filepath.Join(pins, "entries", custodyPinEntryName(pin.Sequence)), encoded)
			}
			if head, err := ReadCustodyBackupPinHead(pins); err != nil || head != second {
				t.Fatalf("valid chain rejected: %v", err)
			}
			bad := second
			test.mutate(&bad)
			encoded, err := bad.CanonicalBytes()
			if err != nil {
				t.Fatalf("expected structurally valid changed pin: %v", err)
			}
			writeCheckpointTestFile(t, filepath.Join(pins, "entries", custodyPinEntryName(2)), encoded)
			if _, err := ReadCustodyBackupPinHead(pins); err == nil {
				t.Fatal("broken pin history accepted")
			}
		})
	}
}
