package store

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func recoveryFixture(t testing.TB, action PruneRecoveryAction, observed bool) *pruneFixture {
	t.Helper()
	f := newPruneFixtureWithStorageID(t, testHash(91))
	point := "intent-after-publish"
	if observed {
		point = "confirm-before-publish"
	}
	var run func() error
	switch action {
	case PruneRecoveryAuthorityAdmission:
		f.admission = pruneAdmissionEntry(t, f)
		run = func() error { _, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); return err }
	case PruneRecoveryAuthorityCompletion:
		finishPruneForCompletion(t, f, "cancelled")
		entry := pruneCompletionEntry(t, f)
		run = func() error { _, err := f.executor.Complete(t.Context(), f.coordinator, entry); return err }
	case PruneRecoveryExecutorAdmission:
		f.admit(t, false)
		point = "pins-admission-" + point
		run = func() error { return f.executor.BindAdmission(t.Context(), f.coordinator, f.admission) }
	case PruneRecoveryExecutorStart, PruneRecoveryExecutorResult:
		f.admit(t, true)
		label := "start"
		if action == PruneRecoveryExecutorResult {
			label = "result"
		}
		point = "pins-" + label + "-" + point
		run = func() error {
			_, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
			return err
		}
	case PruneRecoveryExecutorCancellation:
		f.admit(t, true)
		point = "pins-cancel-" + point
		run = func() error { _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); return err }
	default:
		t.Fatal("unsupported fixture action")
	}
	fault := errors.New("retain exact recovery intent")
	hooks := storeHooks{at: func(at string) error {
		if at == point {
			return fault
		}
		return nil
	}}
	setCoordinatorHooks(f.coordinator, hooks)
	f.executor.hooks, f.executor.pins.hooks = hooks, hooks
	if err := run(); !errors.Is(err, fault) {
		t.Fatal("fixture did not reach retained intent", point, err)
	}
	f.reopen(t)
	return f
}

func recoveryReview(t testing.TB, owner *PruneMaintenance) (PruneRecoveryReview, types.Hash) {
	t.Helper()
	r, err := owner.ReviewRecovery(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.ID()
	if err != nil || id.IsZero() {
		t.Fatal("invalid recovery review", err)
	}
	return r, id
}

func TestPruneRecoveryExactOneLayerDoesNotExecute(t *testing.T) {
	for action := PruneRecoveryAuthorityAdmission; action <= PruneRecoveryExecutorCancellation; action++ {
		for _, observed := range []bool{false, true} {
			t.Run(action.String()+map[bool]string{false: "/intent-only", true: "/record-present"}[observed], func(t *testing.T) {
				f := recoveryFixture(t, action, observed)
				before, authority := pruneSnapshot(t, f.executor), testCoordination(t, f.coordinator)
				usage, _, err := f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				s := openTestPruneService(t, f)
				owner, err := s.EnterMaintenance(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				review, id := recoveryReview(t, owner)
				if review.Action != action {
					t.Fatal("wrong action", review)
				}
				if again, againID := recoveryReview(t, owner); again != review || againID != id {
					t.Fatal("review advanced state")
				}
				if _, err := owner.Review(t.Context()); err == nil {
					t.Fatal("ordinary cancellation review accepted pending state")
				}
				for _, wrong := range []struct {
					id     types.Hash
					action PruneRecoveryAction
				}{{types.Hash{}, action}, {testHash(99), action}, {id, PruneRecoveryNone}} {
					if result, err := owner.Recover(t.Context(), wrong.id, wrong.action); !errors.Is(err, ErrPruneRecoveryReview) || result != (PruneRecoveryResult{}) {
						t.Fatal("unreviewed recovery", err)
					}
				}
				if !reflect.DeepEqual(before, pruneSnapshot(t, s.executor)) || !reflect.DeepEqual(authority, testCoordination(t, s.coordinator)) {
					t.Fatal("review/rejection wrote journals")
				}
				assertRuntimeOwnersBusy(t, f)
				result, err := owner.Recover(t.Context(), id, action)
				if err != nil || result.Before != review || result.After.Action != PruneRecoveryNone {
					t.Fatal("exact recovery failed", err)
				}
				after, afterID := recoveryReview(t, owner)
				if result.After != after || id == afterID {
					t.Fatal("recovery failed to replace review")
				}
				if action <= PruneRecoveryAuthorityCompletion {
					if after.AuthorityConfirmed.HeadID != review.AuthorityPendingID || after.AuthorityConfirmed.Sequence != review.AuthorityConfirmed.Sequence+1 || !reflect.DeepEqual(before, pruneSnapshot(t, s.executor)) {
						t.Fatal("authority recovery changed executor or wrong head")
					}
				} else if after.ExecutorConfirmed != review.ExecutorPending || !reflect.DeepEqual(authority, testCoordination(t, s.coordinator)) {
					t.Fatal("executor recovery changed authority or wrong prefix")
				}
				if _, err := owner.Recover(t.Context(), id, action); !errors.Is(err, ErrPruneRecoveryReview) {
					t.Fatal("old review reused", err)
				}
				if _, err := owner.Recover(t.Context(), afterID, PruneRecoveryNone); !errors.Is(err, ErrPruneRecoveryScope) {
					t.Fatal("no attempt was treated as recovery", err)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				f.reopen(t)
				if action == PruneRecoveryExecutorStart {
					if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); !errors.Is(err, ErrPruneOutcome) {
						t.Fatal("recovered start executed again", err)
					}
					if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, ErrPruneOutcome) {
						t.Fatal("recovered start cancelled", err)
					}
				}
				if action == PruneRecoveryAuthorityAdmission && pruneSnapshot(t, f.executor).Stage != PrunePrepared {
					t.Fatal("authority recovery inferred new binding")
				}
				if current, _, err := f.chain.HistoryUsage(); err != nil || current != usage {
					t.Fatal("recovery changed chain data", err)
				}
			})
		}
	}
}

func TestPruneRecoveryBlocksUnrelatedAndAmbiguousIntent(t *testing.T) {
	for _, kind := range []string{"stop", "foreign-admission", "wrong-completion", "two-layers"} {
		t.Run(kind, func(t *testing.T) {
			var f *pruneFixture
			if kind == "two-layers" {
				f = recoveryFixture(t, PruneRecoveryExecutorCancellation, false)
			} else {
				f = newPruneFixtureWithStorageID(t, testHash(91))
			}
			if kind == "wrong-completion" {
				finishPruneForCompletion(t, f, "cancelled")
			}
			state := testCoordination(t, f.coordinator).Authority
			var entry custodyauthority.Entry
			switch kind {
			case "foreign-admission":
				entry = testEntry(t, state, custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{})
			case "wrong-completion":
				ticket, _ := f.admission.ID()
				entry = testEntry(t, state, custodyauthority.Complete, types.Hash{}, ticket, testHash(99))
			default:
				entry = testEntry(t, state, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(99))
			}
			fault := errors.New("retain unrelated authority intent")
			setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
				if at == "intent-after-publish" {
					return fault
				}
				return nil
			}})
			if _, err := f.coordinator.Append(t.Context(), entry); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			f.reopen(t)
			before, authority := pruneSnapshot(t, f.executor), testCoordination(t, f.coordinator)
			s := openTestPruneService(t, f)
			owner, err := s.EnterMaintenance(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			review, id := recoveryReview(t, owner)
			if review.Action != PruneRecoveryBlocked {
				t.Fatal("unrelated/ambiguous state eligible", review)
			}
			if _, err := owner.Recover(t.Context(), id, PruneRecoveryBlocked); !errors.Is(err, ErrPruneRecoveryScope) {
				t.Fatal(err)
			}
			if _, err := owner.Recover(t.Context(), id, PruneRecoveryAuthorityAdmission); !errors.Is(err, ErrPruneRecoveryReview) {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, pruneSnapshot(t, s.executor)) || !reflect.DeepEqual(authority, testCoordination(t, s.coordinator)) {
				t.Fatal("blocked recovery changed state")
			}
		})
	}
}

func TestPruneRecoveryUncertaintyRequiresNewObservedReview(t *testing.T) {
	for _, point := range []string{"pins-cancel-confirm-before-publish", "recovery-confirmed"} {
		t.Run(point, func(t *testing.T) {
			f := recoveryFixture(t, PruneRecoveryExecutorCancellation, false)
			s := openTestPruneService(t, f)
			owner, err := s.EnterMaintenance(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			before, id := recoveryReview(t, owner)
			fault := errors.New("recovery interrupted")
			hooks := storeHooks{at: func(at string) error {
				if at == point {
					return fault
				}
				return nil
			}}
			s.hooks, s.executor.pins.hooks = hooks, hooks
			if result, err := owner.Recover(t.Context(), id, before.Action); !errors.Is(err, fault) || result != (PruneRecoveryResult{}) {
				t.Fatal("uncertainty returned success", err)
			}
			if _, err := owner.ReviewRecovery(t.Context()); !errors.Is(err, fault) {
				t.Fatal("sticky failure forgotten", err)
			}
			if err := owner.Close(); !errors.Is(err, fault) {
				t.Fatal("close hid failure", err)
			}
			f.reopen(t)
			s = openTestPruneService(t, f)
			owner, err = s.EnterMaintenance(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			after, afterID := recoveryReview(t, owner)
			if afterID == id || after.ExecutorObserved.Stage != PruneCancelled {
				t.Fatal("observed publication not committed by review")
			}
			if _, err := owner.Recover(t.Context(), id, before.Action); !errors.Is(err, ErrPruneRecoveryReview) {
				t.Fatal("old observation refreshed", err)
			}
			if point == "recovery-confirmed" {
				if after.Action != PruneRecoveryNone {
					t.Fatal("confirmed output failure invented another attempt")
				}
			} else if _, err := owner.Recover(t.Context(), afterID, after.Action); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneRecoverySameGuardsAndCloseDrain(t *testing.T) {
	f := recoveryFixture(t, PruneRecoveryExecutorCancellation, false)
	s := openTestPruneService(t, f)
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	review, id := recoveryReview(t, owner)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseAll := func() { once.Do(func() { close(release) }) }
	defer releaseAll()
	s.hooks.at = func(at string) error {
		if at == "recovery-reviewed" {
			close(entered)
			<-release
		}
		return nil
	}
	recovered, closed := make(chan error, 1), make(chan error, 1)
	go func() { _, err := owner.Recover(t.Context(), id, review.Action); recovered <- err }()
	<-entered
	go func() { closed <- owner.Close() }()
	select {
	case err := <-closed:
		t.Fatal("Close bypassed action", err)
	case <-time.After(20 * time.Millisecond):
	}
	assertRuntimeOwnersBusy(t, f)
	releaseAll()
	if err := <-recovered; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	if state := pruneSnapshot(t, f.executor); state.Stage != PruneCancelled || state.Protection.Pending != nil {
		t.Fatal("close lost recovery")
	}
}

func TestPruneRecoveryReviewIDAndLifecycle(t *testing.T) {
	f := recoveryFixture(t, PruneRecoveryExecutorCancellation, false)
	s := openTestPruneService(t, f)
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	review, id := recoveryReview(t, owner)
	// Every top-level field either changes the domain-separated digest or is
	// rejected as structurally inconsistent; observed prefixes are not omitted.
	value := reflect.ValueOf(review)
	for i := 0; i < value.NumField(); i++ {
		changed := review
		field := reflect.ValueOf(&changed).Elem().Field(i)
		switch field.Kind() {
		case reflect.Uint8:
			field.SetUint(field.Uint() + 1)
		case reflect.Array:
			field.Index(0).SetUint(field.Index(0).Uint() ^ 1)
		case reflect.Struct:
			for j := 0; j < field.NumField(); j++ {
				part := field.Field(j)
				if part.Kind() == reflect.Array {
					part.Index(0).SetUint(part.Index(0).Uint() ^ 1)
					break
				}
			}
		default:
			t.Fatal("uncovered review field")
		}
		if got, err := changed.ID(); err == nil && got == id {
			t.Fatal("review omitted field", value.Type().Field(i).Name)
		}
	}
	if _, err := (PruneRecoveryReview{}).ID(); !errors.Is(err, ErrPruneRecoveryReview) {
		t.Fatal(err)
	}
	copy := *owner
	for _, invalid := range []*PruneMaintenance{nil, {}, &copy} {
		if _, err := invalid.ReviewRecovery(t.Context()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if _, err := invalid.Recover(t.Context(), id, review.Action); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
	if _, err := owner.ReviewRecovery(nil); !errors.Is(err, ErrPruneRuntime) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := owner.Recover(ctx, id, review.Action); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ReviewRecovery(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
