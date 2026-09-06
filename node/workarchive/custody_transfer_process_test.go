//go:build integration

package workarchive

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCustodyTransferProcessCrashAtomicity(t *testing.T) {
	f := newCustodyTransferFixture(t)
	for _, boundary := range []string{"before-commit", "after-commit"} {
		t.Run(boundary, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "handoff")
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestCustodyTransferCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				"OUTCOMEMESH_CUSTODY_TRANSFER_CRASH="+boundary,
				"OUTCOMEMESH_CUSTODY_TRANSFER_AUDITOR="+f.aPath,
				"OUTCOMEMESH_CUSTODY_TRANSFER_REPLICA="+f.rPath,
				"OUTCOMEMESH_CUSTODY_TRANSFER_DESTINATION="+destination,
				"OUTCOMEMESH_CUSTODY_TRANSFER_MARKER="+marker)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()
			assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
			if boundary == "after-commit" {
				if err := f.verify(t, destination); err != nil {
					t.Fatal(err)
				}
				if _, created, err := f.create(t, context.Background(), destination, f.id, custodyTransferHooks{}); err != nil || created {
					t.Fatalf("lost-result retry: %v", err)
				}
			} else {
				if err := f.verify(t, destination); !errors.Is(err, ErrCustodyTransferIncomplete) {
					t.Fatalf("incomplete result after kill: %v", err)
				}
				if _, _, err := f.create(t, context.Background(), destination, f.id, custodyTransferHooks{}); !errors.Is(err, ErrCustodyTransferIncomplete) {
					t.Fatalf("incomplete result resumed: %v", err)
				}
				entries, err := os.ReadDir(destination)
				if err != nil || len(entries) != 2 {
					t.Fatal("uncommitted evidence removed")
				}
			}
			fresh := filepath.Join(t.TempDir(), "fresh-handoff")
			if _, created, err := f.create(t, context.Background(), fresh, f.id, custodyTransferHooks{}); err != nil || !created {
				t.Fatalf("new destination after kill: %v", err)
			}
		})
	}
}

func TestCustodyTransferCrashHelper(t *testing.T) {
	mode := os.Getenv("OUTCOMEMESH_CUSTODY_TRANSFER_CRASH")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	// Fixture keys and evidence are deterministic. Independent IDs come from
	// this local fixture, never from untrusted candidate checkpoint files.
	f := newCustodyTransferFixture(t)
	hook := func() error { blockAtArchiveCrashMarker(os.Getenv("OUTCOMEMESH_CUSTODY_TRANSFER_MARKER")); return nil }
	hooks := custodyTransferHooks{}
	switch mode {
	case "before-commit":
		hooks.afterWrite = hook
	case "after-commit":
		hooks.afterCommit = hook
	default:
		t.Fatalf("unknown transfer crash boundary %q", mode)
	}
	_, _, err := createCustodyHistoricalTransferPackage(context.Background(), os.Getenv("OUTCOMEMESH_CUSTODY_TRANSFER_DESTINATION"),
		f.id, os.Getenv("OUTCOMEMESH_CUSTODY_TRANSFER_AUDITOR"), os.Getenv("OUTCOMEMESH_CUSTODY_TRANSFER_REPLICA"),
		mustCheckpointID(t, f.a), mustCheckpointID(t, f.r), f.fixture.manifest, f.fixture.receipt, f.fixture.policy, hooks)
	t.Fatalf("transfer crash hook returned: %v", err)
}
