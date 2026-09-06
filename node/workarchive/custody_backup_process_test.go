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

func TestCustodyBackupProcessCrashAtomicity(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	expected, err := CaptureCustodyCheckpoint(journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := expected.ID()
	for _, boundary := range []string{"journal", "before-commit", "after-commit"} {
		t.Run(boundary, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "backup")
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestCustodyBackupCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				"OUTCOMEMESH_CUSTODY_BACKUP_CRASH="+boundary,
				"OUTCOMEMESH_CUSTODY_BACKUP_SOURCE="+journal.path,
				"OUTCOMEMESH_CUSTODY_BACKUP_ARTIFACTS="+artifacts,
				"OUTCOMEMESH_CUSTODY_BACKUP_DESTINATION="+destination,
				"OUTCOMEMESH_CUSTODY_BACKUP_MARKER="+marker)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()
			// Process death must release both source locks and the bundle lock.
			source, err := CaptureCustodyCheckpoint(journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil || source != expected {
				t.Fatalf("source changed after kill: %v", err)
			}
			got, err := VerifyCustodyBackup(destination, id, fixture.manifest, fixture.receipt, fixture.policy)
			if boundary == "after-commit" {
				if err != nil || got != expected {
					t.Fatalf("completed backup lost after kill: %v", err)
				}
				if got, created, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); err != nil || created || got != expected {
					t.Fatalf("lost-ack backup retry: created=%t err=%v", created, err)
				}
			} else {
				if !errors.Is(err, ErrCustodyBackupIncomplete) {
					t.Fatalf("incomplete backup accepted after kill: %v", err)
				}
				if _, _, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupIncomplete) {
					t.Fatalf("incomplete backup overwritten: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(destination, "journal", custodyJournalHeaderName)); err != nil {
					t.Fatalf("partial copy removed: %v", err)
				}
				fresh := filepath.Join(t.TempDir(), "fresh-backup")
				if got, created, err := CreateCustodyBackup(context.Background(), fresh, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); err != nil || !created || got != expected {
					t.Fatalf("fresh retry after crash: created=%t err=%v", created, err)
				}
			}
		})
	}
}

func TestCustodyBackupCrashHelper(t *testing.T) {
	mode := os.Getenv("OUTCOMEMESH_CUSTODY_BACKUP_CRASH")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	fixture := newCustodyRecordFixture(t)
	hook := func() error { blockAtArchiveCrashMarker(os.Getenv("OUTCOMEMESH_CUSTODY_BACKUP_MARKER")); return nil }
	hooks := custodyBackupHooks{}
	switch mode {
	case "journal":
		hooks.afterJournalCopy = hook
	case "before-commit":
		hooks.beforeCommit = hook
	case "after-commit":
		hooks.afterCommit = hook
	default:
		t.Fatalf("unknown backup crash boundary %q", mode)
	}
	_, _, err := createCustodyBackup(context.Background(), os.Getenv("OUTCOMEMESH_CUSTODY_BACKUP_DESTINATION"),
		os.Getenv("OUTCOMEMESH_CUSTODY_BACKUP_SOURCE"), os.Getenv("OUTCOMEMESH_CUSTODY_BACKUP_ARTIFACTS"),
		fixture.manifest, fixture.receipt, fixture.policy, hooks)
	t.Fatalf("backup crash hook returned: %v", err)
}
