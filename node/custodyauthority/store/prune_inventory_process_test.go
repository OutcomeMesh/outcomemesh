//go:build integration

package store

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestPruneInventoryProcessCrashAtomicity(t *testing.T) {
	good := archiveInventoryFixture(t, newArchivePruneFixture(t))
	id, _ := good.ID()
	policyID, _ := good.PolicyID()
	source := filepath.Join(t.TempDir(), "source.ompi")
	if err := SaveArchivePruneInventoryFile(source, good, id, policyID); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"before-file-sync", "file-synced", "inventory-published", "inventory-before-directory-sync", "inventory-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			path, marker := filepath.Join(t.TempDir(), "prepared.ompi"), filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestPruneInventoryCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "OUTCOMEMESH_INVENTORY_SOURCE="+source, "OUTCOMEMESH_INVENTORY_DEST="+path,
				"OUTCOMEMESH_INVENTORY_ID="+id.String(), "OUTCOMEMESH_INVENTORY_POLICY="+policyID.String(),
				"OUTCOMEMESH_INVENTORY_STAGE="+stage, "OUTCOMEMESH_INVENTORY_MARKER="+marker)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var exitErr error
			go func() { exitErr = command.Wait(); close(done) }()
			t.Cleanup(func() { _ = command.Process.Kill(); <-done })
			deadline := time.NewTimer(15 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
		wait:
			for {
				if _, err := os.Stat(marker); err == nil {
					break wait
				}
				select {
				case <-done:
					t.Fatal("child exited before publication boundary", exitErr, output.String())
				case <-deadline.C:
					_ = command.Process.Kill()
					<-done
					t.Fatal("publication boundary not reached", output.String())
				case <-tick.C:
				}
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-done
			if exitErr == nil {
				t.Fatal("child was not terminated")
			}
			published := stage != "before-file-sync" && stage != "file-synced"
			for range 2 {
				_, err := LoadArchivePruneInventoryFile(path, id, policyID)
				if (err == nil) != published {
					t.Fatal("reopen promoted partial or lost complete package", err)
				}
			}
			// Orphan temporary names are never interpreted as a committed file.
			if err := SaveArchivePruneInventoryFile(path, good, id, policyID); err != nil {
				t.Fatal("exact retry failed", err)
			}
			if _, err := LoadArchivePruneInventoryFile(path, id, policyID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneInventoryCrashHelper(t *testing.T) {
	source := os.Getenv("OUTCOMEMESH_INVENTORY_SOURCE")
	if source == "" {
		t.Skip("subprocess helper")
	}
	readPin := func(name string) types.Hash {
		encoded, err := hex.DecodeString(os.Getenv(name))
		if err != nil || len(encoded) != types.HashSize {
			t.Fatal("invalid independent fixture pin", name, err)
		}
		return types.Hash(encoded)
	}
	id, policyID := readPin("OUTCOMEMESH_INVENTORY_ID"), readPin("OUTCOMEMESH_INVENTORY_POLICY")
	inventory, err := LoadArchivePruneInventoryFile(source, id, policyID)
	if err != nil {
		t.Fatal(err)
	}
	hooks := storeHooks{at: func(stage string) error {
		if stage == os.Getenv("OUTCOMEMESH_INVENTORY_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_INVENTORY_MARKER"), nil)
			select {}
		}
		return nil
	}}
	if err := saveArchivePruneInventoryFile(os.Getenv("OUTCOMEMESH_INVENTORY_DEST"), inventory, id, policyID, hooks); err != nil {
		t.Fatal(err)
	}
	t.Fatal("child missed controlled publication boundary")
}
