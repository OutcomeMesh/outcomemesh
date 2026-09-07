//go:build integration

package store

import (
	"errors"
	"strings"
	"testing"
)

func TestPruneCancellationProcessCrashAtomicity(t *testing.T) {
	for _, mode := range []string{"cancel", "resume-intent", "resume-record"} {
		for _, stage := range cancellationStages() {
			if mode != "cancel" && strings.HasPrefix(stage, "pins-cancel-intent-") {
				continue
			}
			if mode == "resume-record" && !strings.HasPrefix(stage, "pins-cancel-confirm-") {
				continue
			}
			t.Run(mode+"/"+stage, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				f.admit(t, true)
				if mode != "cancel" {
					stopAt := "prune-cancel-before-write"
					if mode == "resume-record" {
						stopAt = "prune-cancel-after-apply"
					}
					fault := errors.New("prepare pending cancellation")
					f.executor.hooks.at = func(at string) error {
						if at == stopAt {
							return fault
						}
						return nil
					}
					if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, fault) {
						t.Fatal(err)
					}
				}
				_ = f.executor.Close()
				_ = f.coordinator.Close()
				_ = f.chain.Close()
				childStage := stage
				if mode != "cancel" {
					childStage = "resume/" + stage
				}
				killPruneExecutorChild(t, f, childStage, false)
				f.reopen(t)
				assertCancellationRecovery(t, f, stage)
				f.reopen(t)
				assertCancellationRecovery(t, f, stage)
				assertNoCancellationPrune(t, f)
				c := settleCancellation(t, f)
				completeCancellation(t, f, c)
				f.reopen(t)
				retained, err := f.executor.CancelBeforeStart(t.Context(), nil)
				if err != nil || retained != c {
					t.Fatal("process recovery changed terminal evidence", err)
				}
			})
		}
	}
}
