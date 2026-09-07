//go:build integration

package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestPruneCompletionProcessCrashAtomicity(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, mode := range []string{"initial", "pending-retry"} {
			for _, stage := range pruneCompletionStages() {
				if mode == "pending-retry" && strings.HasPrefix(stage, "intent-") {
					continue
				}
				t.Run(outcome+"/"+mode+"/"+stage, func(t *testing.T) {
					f := newPruneFixtureWithStorageID(t, testHash(91))
					finishPruneForCompletion(t, f, outcome)
					entry := pruneCompletionEntry(t, f)
					before, terminal := testCoordination(t, f.coordinator).Authority, pruneSnapshot(t, f.executor)
					usage, _, err := f.chain.HistoryUsage()
					if err != nil {
						t.Fatal(err)
					}
					if mode == "pending-retry" {
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
							if at == "intent-after-apply" {
								cancel()
							}
							return nil
						}})
						if _, err := f.executor.Complete(ctx, f.coordinator, entry); !errors.Is(err, ErrPendingAttempt) {
							t.Fatal("failed to prepare exact pending completion", err)
						}
					}
					_ = f.executor.Close()
					_ = f.coordinator.Close()
					_ = f.chain.Close()
					killPruneExecutorChildWithCompletion(t, f, "complete/"+stage, false, entry)
					f.reopen(t)
					decided := assertPruneCompletionRecovery(t, f, entry, before, terminal, stage)
					f.reopen(t)
					assertPruneCompletionRecovery(t, f, entry, before, terminal, stage)
					result, err := f.executor.Complete(t.Context(), f.coordinator, entry)
					if err != nil || result.Appended == decided || result.Snapshot.Pending != 0 || testCoordination(t, f.coordinator).Pending != nil {
						t.Fatal("process retry did not confirm exact completion", err)
					}
					stop := f.stop(t)
					appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
					f.reopen(t)
					if result, err := f.executor.Complete(t.Context(), f.coordinator, entry); err != nil || result.Appended || result.Snapshot.Phase != custodyauthority.Retired {
						t.Fatal("historical process retry reopened authority", err)
					}
					if after, _, err := f.chain.HistoryUsage(); err != nil || after != usage || !reflect.DeepEqual(pruneSnapshot(t, f.executor), terminal) {
						t.Fatal("completion process changed chain or executor", err)
					}
				})
			}
		}
	}
}
