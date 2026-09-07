//go:build integration

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedPruneProcessCrashAtomicity(t *testing.T) {
	runPinnedPruneProcessCrashAtomicity(t, newPinnedPruneFixture)
}

func TestStorageBoundPruneProcessCrashAtomicity(t *testing.T) {
	runPinnedPruneProcessCrashAtomicity(t, func(t testing.TB) *pruneFixture {
		return newPruneFixtureWithStorageID(t, testHash(91))
	})
}

func runPinnedPruneProcessCrashAtomicity(t *testing.T, fixture func(testing.TB) *pruneFixture) {
	stages := append(pinnedPrunePublicationStages(), "prune-before-effect", "prune-after-effect")
	for _, prefix := range []string{"prune", "pins"} {
		for _, stage := range []string{"before-ready", "ready-file-synced", "ready-directory-synced"} {
			stages = append(stages, prefix+"-"+stage)
		}
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := fixture(t)
			initializing := strings.Contains(stage, "ready")
			if !initializing {
				f.admit(t, !strings.Contains(stage, "admission-"))
			}
			_ = f.executor.Close()
			_ = f.coordinator.Close()
			_ = f.chain.Close()
			if initializing {
				f.executorPath = filepath.Join(t.TempDir(), "new-executor")
				f.executorPinsPath = filepath.Join(t.TempDir(), "new-pins")
			}
			killPruneExecutorChild(t, f, stage, initializing)
			if initializing {
				opened, err := OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id)
				usable := stage == "pins-ready-file-synced" || stage == "pins-ready-directory-synced"
				if !usable {
					if err == nil {
						_ = opened.Close()
						t.Fatal("partial pair opened")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if s := pruneSnapshot(t, opened); s.Stage != PrunePrepared || s.Protection.Pending != nil {
						t.Fatal("initializer executed work")
					}
					_ = opened.Close()
				}
				if raw, err := OpenPruneExecutor(f.executorPath, testAssignment(), f.id); err == nil {
					_ = raw.Close()
					t.Fatal("partial pair downgraded to raw")
				}
				if created, err := CreatePinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.request, f.id); !errors.Is(err, os.ErrExist) {
					if created != nil {
						_ = created.Close()
					}
					t.Fatal("partial pair recreated", err)
				}
				return
			}
			f.reopen(t)
			s := pruneSnapshot(t, f.executor)
			assertPinnedRecoveryStage(t, s, stage)
			f.reopen(t)
			again := pruneSnapshot(t, f.executor)
			if s.Stage != again.Stage || s.Protection.Confirmed != again.Protection.Confirmed || (s.Protection.Pending == nil) != (again.Protection.Pending == nil) || testCoordination(t, f.coordinator).Authority.Pending != 1 {
				t.Fatal("open advanced or completed work")
			}
			// Actual deletion exists only after the chain effect, never merely
			// because the independent journal retained a start transition.
			ticket, _ := f.admission.ID()
			_, found, err := f.chain.CanonicalPruneEffect(ticket)
			if err != nil || found != (strings.Contains(stage, "result-") || stage == "prune-after-effect") {
				t.Fatal("unexpected effect after process death", found, err)
			}
			settlePinnedPruneAfterFailure(t, f)
		})
	}
}
