//go:build integration

package workarchive

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodyPinProcessCrashAtomicity(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	oldPath, oldCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	writeCheckpointTestFile(t, filepath.Join(artifacts, "pending-intent"), []byte("retained pending evidence"))
	newPath, newCheckpoint := createPinTestBackup(t, fixture, journal.path, artifacts)
	newID := mustCheckpointID(t, newCheckpoint)
	for _, boundary := range []string{"before-publish", "after-publish"} {
		t.Run(boundary, func(t *testing.T) {
			pins := filepath.Join(t.TempDir(), "pins")
			first, _, err := PinCustodyBackup(pins, oldPath, "", types.Hash{}, mustCheckpointID(t, oldCheckpoint), fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			firstID := mustPinID(t, first)
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestCustodyPinCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				"OUTCOMEMESH_CUSTODY_PIN_CRASH="+boundary,
				"OUTCOMEMESH_CUSTODY_PIN_PATH="+pins,
				"OUTCOMEMESH_CUSTODY_PIN_OLD_BACKUP="+oldPath,
				"OUTCOMEMESH_CUSTODY_PIN_NEW_BACKUP="+newPath,
				"OUTCOMEMESH_CUSTODY_PIN_EXPECTED="+firstID.String(),
				"OUTCOMEMESH_CUSTODY_PIN_CHECKPOINT="+newID.String(),
				"OUTCOMEMESH_CUSTODY_PIN_MARKER="+marker)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()
			head, err := ReadCustodyBackupPinHead(pins)
			if err != nil {
				t.Fatal(err)
			}
			if boundary == "before-publish" && head != first {
				t.Fatal("uncommitted pin became current")
			}
			if boundary == "after-publish" && (head.Sequence != 2 || head.Checkpoint != newCheckpoint) {
				t.Fatal("committed pin lost after kill")
			}
			again, created, err := PinCustodyBackup(pins, newPath, oldPath, firstID, newID, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil || again.Sequence != 2 || again.Checkpoint != newCheckpoint || created != (boundary == "before-publish") {
				t.Fatalf("retry after kill: created=%t error=%v", created, err)
			}
			if _, err := VerifyPinnedCustodyBackup(pins, newPath, mustPinID(t, again), fixture.manifest, fixture.receipt, fixture.policy); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCustodyBackup(oldPath, mustCheckpointID(t, oldCheckpoint), fixture.manifest, fixture.receipt, fixture.policy); err != nil {
				t.Fatalf("previous backup changed: %v", err)
			}
		})
	}
}

func TestCustodyPinCrashHelper(t *testing.T) {
	mode := os.Getenv("OUTCOMEMESH_CUSTODY_PIN_CRASH")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	fixture := newCustodyRecordFixture(t)
	readHash := func(name string) types.Hash {
		encoded, err := hex.DecodeString(os.Getenv(name))
		if err != nil || len(encoded) != types.HashSize {
			t.Fatalf("invalid helper hash %s: %v", name, err)
		}
		var hash types.Hash
		copy(hash[:], encoded)
		return hash
	}
	expected := readHash("OUTCOMEMESH_CUSTODY_PIN_EXPECTED")
	checkpoint := readHash("OUTCOMEMESH_CUSTODY_PIN_CHECKPOINT")
	hook := func() { blockAtArchiveCrashMarker(os.Getenv("OUTCOMEMESH_CUSTODY_PIN_MARKER")) }
	hooks := custodyPinHooks{}
	switch mode {
	case "before-publish":
		hooks.beforePublish = hook
	case "after-publish":
		hooks.afterPublish = hook
	default:
		t.Fatalf("unknown pin crash boundary %q", mode)
	}
	_, _, err := pinCustodyBackup(os.Getenv("OUTCOMEMESH_CUSTODY_PIN_PATH"), os.Getenv("OUTCOMEMESH_CUSTODY_PIN_NEW_BACKUP"), os.Getenv("OUTCOMEMESH_CUSTODY_PIN_OLD_BACKUP"), expected, checkpoint, fixture.manifest, fixture.receipt, fixture.policy, hooks)
	t.Fatalf("pin crash hook returned: %v", err)
}
