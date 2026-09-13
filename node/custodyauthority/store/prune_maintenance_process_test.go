//go:build integration

package store

import (
	"reflect"
	"testing"
)

func TestPruneMaintenanceProcessRecovery(t *testing.T) {
	for _, stage := range []string{"runtime-maintenance-drained", "maintenance-reviewed", "maintenance-pins-cancel-confirm-before-publish", "maintenance-cancelled"} {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, true)
			before, authority := pruneSnapshot(t, f.executor), testCoordination(t, f.coordinator)
			usage, _, err := f.chain.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			_ = f.executor.Close()
			_ = f.coordinator.Close()
			_ = f.chain.Close()
			_, marker, stop := startPruneRuntimeChild(t, f, stage)
			waitCompletionMarker(t, marker+".reached")
			assertRuntimeOwnersBusy(t, f)
			stop()
			var retained PruneExecution
			for attempt := range 2 {
				f.reopen(t)
				state := pruneSnapshot(t, f.executor)
				if !reflect.DeepEqual(authority, testCoordination(t, f.coordinator)) {
					t.Fatal("maintenance changed authority history")
				}
				if stage == "runtime-maintenance-drained" || stage == "maintenance-reviewed" {
					if !reflect.DeepEqual(before, state) {
						t.Fatal("handoff/review executed work")
					}
				} else if state.Stage != PruneCancelled || (state.Protection.Pending != nil) != (stage == "maintenance-pins-cancel-confirm-before-publish") {
					t.Fatal("incorrect retained cancellation boundary")
				}
				if attempt == 1 && !reflect.DeepEqual(state, retained) {
					t.Fatal("reopen resumed a transition")
				}
				retained = state
				if after, _, err := f.chain.HistoryUsage(); err != nil || after != usage {
					t.Fatal("maintenance changed chain data", err)
				}
			}
			// Exact recovery of an uncertain pin transition is deliberately
			// outside the maintenance handle, through the existing explicit API.
			if retained.Protection.Pending != nil {
				if err := f.executor.ResumePinnedTransition(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			s := openTestPruneService(t, f)
			owner, err := s.EnterMaintenance(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, id := maintenanceReview(t, owner)
			cancellation, err := owner.CancelBeforeStart(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			terminalID, _ := cancellation.ID()
			if !retained.RequestID.IsZero() && retained.Cancellation != nil && *retained.Cancellation != cancellation {
				t.Fatal("recovery changed cancellation")
			}
			review, _ := maintenanceReview(t, owner)
			if review.TerminalID != terminalID {
				t.Fatal("review lost recovered terminal")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			assertNoCancellationPrune(t, f)
		})
	}
}
