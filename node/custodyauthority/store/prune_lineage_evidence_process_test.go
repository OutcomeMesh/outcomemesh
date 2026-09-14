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

func TestPruneLineageEvidenceProcessCrashAtomicity(t *testing.T) {
	p, inventory, evidence := lineageEvidenceFixture(t, []int{2, 1})
	id, _ := evidence.ID()
	source := filepath.Join(t.TempDir(), "source.omple")
	if err := SaveArchivePruneLineageEvidenceFile(t.Context(), source, evidence, id); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"before-file-sync", "file-synced", "lineage-evidence-published", "lineage-evidence-before-directory-sync", "lineage-evidence-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			path, marker := filepath.Join(t.TempDir(), "renewals.omple"), filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestPruneLineageEvidenceCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "OUTCOMEMESH_LINEAGE_SOURCE="+source, "OUTCOMEMESH_LINEAGE_DEST="+path,
				"OUTCOMEMESH_LINEAGE_INVENTORY="+p.inventoryPath, "OUTCOMEMESH_LINEAGE_INVENTORY_ID="+p.inventoryID.String(),
				"OUTCOMEMESH_LINEAGE_ID="+id.String(), "OUTCOMEMESH_LINEAGE_POLICY="+p.policyID.String(),
				"OUTCOMEMESH_LINEAGE_STAGE="+stage, "OUTCOMEMESH_LINEAGE_MARKER="+marker)
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
					t.Fatal("child exited before evidence boundary", exitErr, output.String())
				case <-deadline.C:
					_ = command.Process.Kill()
					<-done
					t.Fatal("evidence boundary not reached", output.String())
				case <-tick.C:
				}
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-done
			if exitErr == nil {
				t.Fatal("child was not killed")
			}
			published := stage != "before-file-sync" && stage != "file-synced"
			for range 2 {
				loaded, err := LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, p.inventoryID, p.policyID, id)
				if (err == nil) != published || (err == nil && loaded.id != id) {
					t.Fatal("reopen promoted partial or lost exact complete evidence", err)
				}
			}
			// Crashed temporary names are not commits and are never promoted.
			if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id); err != nil {
				t.Fatal("exact retry", err)
			}
			if _, err := LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, p.inventoryID, p.policyID, id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneLineageEvidenceCrashHelper(t *testing.T) {
	source := os.Getenv("OUTCOMEMESH_LINEAGE_SOURCE")
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
	id, inventoryID, policyID := readPin("OUTCOMEMESH_LINEAGE_ID"), readPin("OUTCOMEMESH_LINEAGE_INVENTORY_ID"), readPin("OUTCOMEMESH_LINEAGE_POLICY")
	inventory, err := LoadArchivePruneInventoryFile(os.Getenv("OUTCOMEMESH_LINEAGE_INVENTORY"), inventoryID, policyID)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := LoadArchivePruneLineageEvidenceFile(t.Context(), source, inventory, inventoryID, policyID, id)
	if err != nil {
		t.Fatal(err)
	}
	hooks := storeHooks{at: func(stage string) error {
		if stage == os.Getenv("OUTCOMEMESH_LINEAGE_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_LINEAGE_MARKER"), nil)
			select {}
		}
		return nil
	}}
	if err := saveArchivePruneLineageEvidenceFile(t.Context(), os.Getenv("OUTCOMEMESH_LINEAGE_DEST"), evidence, id, hooks); err != nil {
		t.Fatal(err)
	}
	t.Fatal("child missed controlled publication boundary")
}
