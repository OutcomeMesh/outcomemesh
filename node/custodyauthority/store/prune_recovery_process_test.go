//go:build integration

package store

import (
	"errors"
	"testing"
)

func TestPruneRecoveryProcessRecovery(t *testing.T) {
	for action := PruneRecoveryAuthorityAdmission; action <= PruneRecoveryExecutorCancellation; action++ {
		publication := "confirm-before-publish"
		switch action {
		case PruneRecoveryExecutorAdmission:
			publication = "pins-admission-" + publication
		case PruneRecoveryExecutorStart:
			publication = "pins-start-" + publication
		case PruneRecoveryExecutorResult:
			publication = "pins-result-" + publication
		case PruneRecoveryExecutorCancellation:
			publication = "pins-cancel-" + publication
		}
		for _, stage := range []string{"recovery-reviewed", "recovery-" + publication, "recovery-confirmed"} {
			t.Run(action.String()+"/"+stage, func(t *testing.T) {
				f := recoveryFixture(t, action, false)
				usage, _, err := f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				s := openTestPruneService(t, f)
				owner, err := s.EnterMaintenance(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				before, beforeID := recoveryReview(t, owner)
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				if err := f.chain.Close(); err != nil {
					t.Fatal(err)
				}
				_, marker, stop := startPruneRuntimeChild(t, f, stage)
				waitCompletionMarker(t, marker+".reached")
				assertRuntimeOwnersBusy(t, f)
				stop()
				var recovered PruneRecoveryReview
				for attempt := range 2 {
					s = openTestPruneService(t, f)
					owner, err = s.EnterMaintenance(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					review, id := recoveryReview(t, owner)
					if attempt == 1 && review != recovered {
						t.Fatal("reopen advanced retained recovery")
					}
					recovered = review
					if stage == "recovery-reviewed" {
						if review != before || id != beforeID {
							t.Fatal("pre-write crash changed retained state")
						}
					} else {
						if id == beforeID {
							t.Fatal("published evidence did not invalidate old review")
						}
						if _, err := owner.Recover(t.Context(), beforeID, action); !errors.Is(err, ErrPruneRecoveryReview) {
							t.Fatal("old review accepted after publication", err)
						}
					}
					wantAction := action
					if stage == "recovery-confirmed" {
						wantAction = PruneRecoveryNone
					}
					if review.Action != wantAction {
						t.Fatal("crash lost pending/confirmed distinction", review.Action)
					}
					if attempt == 1 && review.Action != PruneRecoveryNone {
						result, err := owner.Recover(t.Context(), id, action)
						if err != nil || result.After.Action != PruneRecoveryNone {
							t.Fatal("exact fresh recovery failed", err)
						}
					}
					if err := owner.Close(); err != nil {
						t.Fatal(err)
					}
				}
				f.reopen(t)
				if after, _, err := f.chain.HistoryUsage(); err != nil || after != usage {
					t.Fatal("recovery executed chain effect", err)
				}
			})
		}
	}
}
