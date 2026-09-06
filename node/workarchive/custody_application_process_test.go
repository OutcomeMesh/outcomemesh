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

func TestCustodyApplicationProcessCrashAtomicity(t *testing.T) {
	f := newCustodyApplicationFixture(t)
	for _, boundary := range []string{"header", "copy", "body", "slot", "artifacts", "before-commit", "after-commit"} {
		t.Run(boundary, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recovery")
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestCustodyApplicationCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				"OUTCOMEMESH_CUSTODY_APPLICATION_CRASH="+boundary,
				"OUTCOMEMESH_CUSTODY_APPLICATION_AUDITOR="+f.aPath,
				"OUTCOMEMESH_CUSTODY_APPLICATION_REPLICA="+f.rPath,
				"OUTCOMEMESH_CUSTODY_APPLICATION_PACKAGE="+f.packagePath,
				"OUTCOMEMESH_CUSTODY_APPLICATION_DESTINATION="+path,
				"OUTCOMEMESH_CUSTODY_APPLICATION_MARKER="+marker)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()
			journal := filepath.Join(path, custodyBackupJournalName)
			before, err := digestCustodyEvidenceTree(journal, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenOrCreateCustodyJournal(journal, f.fixture.manifest, f.fixture.receipt, f.fixture.policy); !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
				t.Fatalf("crashed construction became live: %v", err)
			}
			after, err := digestCustodyEvidenceTree(journal, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			if err != nil || before != after {
				t.Fatal("live open repaired quarantined evidence")
			}
			application, created, err := f.apply(t, context.Background(), path, DefaultCustodyJournalLimits(), custodyApplicationHooks{})
			if boundary == "after-commit" {
				if err != nil || created {
					t.Fatalf("committed retry: %v", err)
				}
				id, _ := application.ID()
				if err := f.verifyApplication(t, path, id); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrCustodyApplicationIncomplete) {
				t.Fatalf("incomplete application resumed: %v", err)
			}
			assertReconciliationBackupsUnchanged(t, f.fixture, f.aPath, f.a, f.rPath, f.r)
			// A separate fresh reconstruction remains possible after all locks
			// from the killed process have been released.
			fresh := filepath.Join(t.TempDir(), "fresh")
			if _, created, err := f.apply(t, context.Background(), fresh, DefaultCustodyJournalLimits(), custodyApplicationHooks{}); err != nil || !created {
				t.Fatalf("fresh reconstruction after kill: %v", err)
			}
		})
	}
}

func TestCustodyApplicationCrashHelper(t *testing.T) {
	mode := os.Getenv("OUTCOMEMESH_CUSTODY_APPLICATION_CRASH")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	// Deterministic local fixture supplies independent trust, not candidate IDs.
	f := newCustodyApplicationFixture(t)
	hook := func() error {
		blockAtArchiveCrashMarker(os.Getenv("OUTCOMEMESH_CUSTODY_APPLICATION_MARKER"))
		return nil
	}
	hooks := custodyApplicationHooks{}
	switch mode {
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
	default:
		t.Fatalf("unknown application crash boundary %q", mode)
	}
	_, _, err := createCustodyHistoricalApplication(context.Background(), os.Getenv("OUTCOMEMESH_CUSTODY_APPLICATION_DESTINATION"),
		os.Getenv("OUTCOMEMESH_CUSTODY_APPLICATION_PACKAGE"), f.id,
		os.Getenv("OUTCOMEMESH_CUSTODY_APPLICATION_AUDITOR"), os.Getenv("OUTCOMEMESH_CUSTODY_APPLICATION_REPLICA"),
		mustCheckpointID(t, f.a), mustCheckpointID(t, f.r), f.fixture.manifest, f.fixture.receipt, f.fixture.policy, DefaultCustodyJournalLimits(), hooks)
	t.Fatalf("application crash hook returned: %v", err)
}
