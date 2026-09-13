package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func maintenanceReview(t testing.TB, owner *PruneMaintenance) (PruneMaintenanceReview, types.Hash) {
	t.Helper()
	r, err := owner.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.ID()
	if err != nil || id.IsZero() {
		t.Fatal("invalid review", err)
	}
	return r, id
}

func TestPruneMaintenanceOwnsRootsThroughReviewedCancellation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	s := openTestPruneService(t, f)
	runContext, cancelTransport := context.WithCancel(t.Context())
	defer cancelTransport()
	if err := s.Start(runContext, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	delivery := retainedRuntimeAdmit(t, f, s.Addresses()[0])
	if _, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery); err != nil {
		t.Fatal(err)
	}
	beforeUsage, _, err := f.chain.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	assertRuntimeOwnersBusy(t, f)
	if len(s.Addresses()) != 0 {
		t.Fatal("parked service advertised routes")
	}
	if err := s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrPruneServiceQuiesced) {
		t.Fatal(err)
	}
	if duplicate, err := s.EnterMaintenance(t.Context()); !errors.Is(err, ErrPruneServiceQuiesced) || duplicate != nil {
		t.Fatal("duplicate maintenance capability", err)
	}
	cancelTransport()
	select {
	case <-s.Done():
		t.Fatal("transport context released maintenance owners")
	default:
	}
	review, id := maintenanceReview(t, owner)
	if review.RequestID != f.id || review.StorageID != testHash(91) || review.Authority.Sequence != 1 || review.Executor.Stage != PruneAdmitted {
		t.Fatal(review)
	}
	if again, againID := maintenanceReview(t, owner); again != review || againID != id {
		t.Fatal("read-only review changed history")
	}
	copy := *owner
	if _, err := copy.Review(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal("copied capability used the owner", err)
	}
	for _, wrong := range []types.Hash{{}, testHash(99)} {
		if result, err := owner.CancelBeforeStart(t.Context(), wrong); !errors.Is(err, ErrPruneMaintenanceReview) || result != (PruneCancellation{}) {
			t.Fatal("unreviewed cancellation", err)
		}
	}
	if again, _ := maintenanceReview(t, owner); again != review {
		t.Fatal("bad review mutated state")
	}
	cancellation, err := owner.CancelBeforeStart(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	terminal, _ := cancellation.ID()
	after, afterID := maintenanceReview(t, owner)
	if after.Executor.Stage != PruneCancelled || after.TerminalID != terminal || afterID == id || after.Authority != review.Authority {
		t.Fatal("cancellation completed authority or lost terminal", after)
	}
	if _, err := owner.CancelBeforeStart(t.Context(), id); !errors.Is(err, ErrPruneMaintenanceReview) {
		t.Fatal("old review silently refreshed", err)
	}
	if retry, err := owner.CancelBeforeStart(t.Context(), afterID); err != nil || retry != cancellation {
		t.Fatal("explicit terminal review failed", err)
	}
	if usage, _, err := f.chain.HistoryUsage(); err != nil || usage != beforeUsage {
		t.Fatal("maintenance changed chain", err)
	}
	if c := testCoordination(t, s.coordinator); c.Authority.Pending != 1 || c.Authority.Sequence != 1 {
		t.Fatal("maintenance completed a ticket")
	}
	assertRuntimeOwnersBusy(t, f)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	waitPruneRuntimeDone(t, s)
	if _, err := owner.Review(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal("closed capability reused", err)
	}
	f.reopen(t)
	entry := pruneCompletionEntry(t, f)
	if _, err := f.executor.Complete(t.Context(), f.coordinator, entry); err != nil {
		t.Fatal("separate completion failed", err)
	}
}

func TestPruneMaintenanceReviewBindsStateAndRejectsUnresolvedWork(t *testing.T) {
	for _, phase := range []string{"prepared", "admitted", "started", "succeeded", "cancelled", "stopping"} {
		t.Run(phase, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, false)
			if phase == "prepared" {
				// Admission exists in authority but has not been bound to this
				// executor yet; maintenance must not infer that transition.
			} else if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "started":
				fault := errors.New("stop before chain effect")
				f.executor.hooks.at = func(at string) error {
					if at == "prune-before-effect" {
						return fault
					}
					return nil
				}
				if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); !errors.Is(err, fault) {
					t.Fatal(err)
				}
			case "succeeded":
				if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err != nil {
					t.Fatal(err)
				}
			case "stopping":
				f.stop(t)
			}
			before, authority := pruneSnapshot(t, f.executor), testCoordination(t, f.coordinator)
			s := openTestPruneService(t, f)
			owner, err := s.EnterMaintenance(t.Context()) // no listener needed
			if err != nil {
				t.Fatal(err)
			}
			_, id := maintenanceReview(t, owner)
			if got, c := pruneSnapshot(t, s.executor), testCoordination(t, s.coordinator); !reflect.DeepEqual(got, before) || !reflect.DeepEqual(c, authority) {
				t.Fatal("entry/review resumed work")
			}
			result, err := owner.CancelBeforeStart(t.Context(), id)
			allowed := phase == "admitted" || phase == "cancelled" || phase == "stopping"
			if (err == nil) != allowed {
				t.Fatal("incorrect cancellation eligibility", phase, err)
			}
			if !allowed && result != (PruneCancellation{}) {
				t.Fatal("error returned terminal")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A changed authority head must invalidate an earlier review even when
	// cancelling would still be legal in the new Stopping state.
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admit(t, false)
	if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
		t.Fatal(err)
	}
	s := openTestPruneService(t, f)
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, id := maintenanceReview(t, owner)
	runtimeFixture(f, s).stop(t) // package-private test mutation; no raw owner is exported
	if _, err := owner.CancelBeforeStart(t.Context(), id); !errors.Is(err, ErrPruneMaintenanceReview) {
		t.Fatal("changed head accepted", err)
	}
}

func TestPruneMaintenanceDrainsBeforeIssuingCapability(t *testing.T) {
	for _, stage := range []string{"confirm-before-publish", "pins-admission-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			s := openTestPruneService(t, f)
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			hook := func(at string) error {
				if at == stage {
					close(reached)
					<-release
				}
				return nil
			}
			setCoordinatorHooks(s.coordinator, storeHooks{at: hook})
			s.executor.pins.hooks.at = hook
			delivery := retainedRuntimeAdmit(t, f, startTestPruneService(t, s))
			sent := make(chan error, 1)
			go func() { _, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery); sent <- err }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("missed confirmation boundary")
			}
			type result struct {
				owner *PruneMaintenance
				err   error
			}
			parked := make(chan result, 1)
			go func() { owner, err := s.EnterMaintenance(t.Context()); parked <- result{owner, err} }()
			select {
			case <-parked:
				t.Fatal("capability escaped active handler")
			case <-time.After(20 * time.Millisecond):
			}
			assertRuntimeOwnersBusy(t, f)
			unblock()
			got := <-parked
			if got.err != nil || got.owner == nil {
				t.Fatal(got.err)
			}
			if err := <-sent; !errors.Is(err, admissionwire.ErrUnconfirmed) {
				t.Fatal("lost reply claimed success", err)
			}
			assertRuntimeOwnersBusy(t, f)
			review, _ := maintenanceReview(t, got.owner)
			wantStage := PruneAdmitted
			if stage == "confirm-before-publish" {
				// Cancellation can win before executor binding begins. Drain
				// must not turn that unfinished request into an automatic bind.
				wantStage = PrunePrepared
			}
			if review.Authority.Sequence != 1 || review.Executor.Stage != wantStage {
				t.Fatal("drain changed the retained phase", review)
			}
		})
	}
}

func TestPruneMaintenanceCloseWaitsForCancellation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admit(t, true)
	s := openTestPruneService(t, f)
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, id := maintenanceReview(t, owner)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.executor.pins.hooks.at = func(at string) error {
		if at == "pins-cancel-confirm-before-publish" {
			close(reached)
			<-release
		}
		return nil
	}
	cancelled := make(chan error, 1)
	go func() { _, err := owner.CancelBeforeStart(t.Context(), id); cancelled <- err }()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("missed cancellation confirmation")
	}
	closed := make(chan error, 2)
	go func() { closed <- owner.Close() }()
	go func() { closed <- s.Close() }()
	select {
	case <-closed:
		t.Fatal("close escaped active cancellation")
	case <-time.After(20 * time.Millisecond):
	}
	assertRuntimeOwnersBusy(t, f)
	unblock()
	if err := <-cancelled; err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(<-closed, <-closed); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	if state := pruneSnapshot(t, f.executor); state.Stage != PruneCancelled || state.Protection.Pending != nil {
		t.Fatal("close lost confirmed cancellation")
	}
}

func TestPruneMaintenanceLifecycleRaces(t *testing.T) {
	for _, mode := range []string{"start", "close", "cancelled-transport"} {
		for range 3 {
			t.Run(mode, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				s := openTestPruneService(t, f)
				if mode == "cancelled-transport" {
					ctx, cancel := context.WithCancel(t.Context())
					if err := s.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
						t.Fatal(err)
					}
					cancel()
					if owner, err := s.EnterMaintenance(t.Context()); !errors.Is(err, ErrClosed) || owner != nil {
						t.Fatal("stole cancelled lifecycle", err)
					}
					waitPruneRuntimeDone(t, s)
					return
				}
				barrier, other := make(chan struct{}), make(chan error, 1)
				go func() {
					<-barrier
					if mode == "start" {
						other <- s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig())
					} else {
						other <- s.Close()
					}
				}()
				close(barrier)
				owner, err := s.EnterMaintenance(t.Context())
				otherErr := <-other
				if mode == "start" {
					if err != nil || owner == nil || (otherErr != nil && !errors.Is(otherErr, ErrPruneServiceQuiesced)) {
						t.Fatal(err, otherErr)
					}
					assertRuntimeOwnersBusy(t, f)
				} else if otherErr != nil || (err != nil && !errors.Is(err, ErrClosed)) {
					t.Fatal(err, otherErr)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if owner != nil {
					if _, err := owner.Review(t.Context()); !errors.Is(err, ErrClosed) {
						t.Fatal("closed race escaped capability", err)
					}
				}
				waitPruneRuntimeDone(t, s)
				f.reopen(t)
			})
		}
	}
}

func TestPruneMaintenanceFailureAndCloseKeepErrors(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admit(t, false)
	if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
		t.Fatal(err)
	}
	s := openTestPruneService(t, f)
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, id := maintenanceReview(t, owner)
	fault := errors.New("cancellation confirmation unavailable")
	s.executor.pins.hooks.at = func(at string) error {
		if at == "pins-cancel-confirm-before-publish" {
			return fault
		}
		return nil
	}
	if c, err := owner.CancelBeforeStart(t.Context(), id); !errors.Is(err, fault) || c != (PruneCancellation{}) {
		t.Fatal("uncertainty returned cancellation", err)
	}
	if _, err := owner.Review(t.Context()); !errors.Is(err, fault) {
		t.Fatal("uncertainty was forgotten", err)
	}
	if err := owner.Close(); !errors.Is(err, fault) {
		t.Fatal("close hid maintenance failure", err)
	}
	waitPruneRuntimeDone(t, s)
	f.reopen(t)
	if state := pruneSnapshot(t, f.executor); state.Stage != PruneCancelled || state.Protection.Pending == nil {
		t.Fatal("reopen resumed uncertain cancellation")
	}
	s = openTestPruneService(t, f)
	owner, err = s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Review(t.Context()); !errors.Is(err, ErrPrunePinPending) {
		t.Fatal("unconfirmed executor accepted", err)
	}
	if _, err := owner.CancelBeforeStart(t.Context(), id); !errors.Is(err, ErrPrunePinPending) {
		t.Fatal("unconfirmed executor resumed", err)
	}
}

func TestPruneMaintenanceRefusesPendingAuthority(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	fault := errors.New("authority intent publication interrupted")
	setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
		if at == "intent-after-publish" {
			return fault
		}
		return nil
	}})
	if _, err := f.coordinator.Append(t.Context(), f.admission); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	f.reopen(t)
	before := testCoordination(t, f.coordinator)
	if before.Pending == nil {
		t.Fatal("missing retained intent")
	}
	s := openTestPruneService(t, f)
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := owner.Review(t.Context()); !errors.Is(err, ErrPendingAttempt) {
			t.Fatal("pending authority accepted", err)
		}
		if _, err := owner.CancelBeforeStart(t.Context(), testHash(99)); !errors.Is(err, ErrPendingAttempt) {
			t.Fatal("pending authority resumed", err)
		}
		if !reflect.DeepEqual(before, testCoordination(t, s.coordinator)) {
			t.Fatal("maintenance promoted retained intent")
		}
	}
}

func TestPruneMaintenanceCancelledHandoffStaysParked(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	s := openTestPruneService(t, f)
	startTestPruneService(t, s)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.hooks.at = func(at string) error {
		if at == "runtime-maintenance-drained" {
			cancel()
		}
		return nil
	}
	if owner, err := s.EnterMaintenance(ctx); !errors.Is(err, context.Canceled) || owner != nil {
		t.Fatal("cancelled handoff succeeded", err)
	}
	assertRuntimeOwnersBusy(t, f)
	if len(s.Addresses()) != 0 {
		t.Fatal("cancelled handoff restarted transport")
	}
	if err := s.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrPruneServiceQuiesced) {
		t.Fatal("parked service restarted", err)
	}
	owner, err := s.EnterMaintenance(t.Context()) // separately selected retry, no network restart
	if err != nil {
		t.Fatal(err)
	}
	maintenanceReview(t, owner)
}

func TestPruneMaintenanceReviewIDCommitsEveryField(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admit(t, true)
	s := openTestPruneService(t, f)
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	base, originalID := maintenanceReview(t, owner)
	for _, mutate := range []func(*PruneMaintenanceReview){
		func(r *PruneMaintenanceReview) { r.AssignmentID = testHash(90) },
		func(r *PruneMaintenanceReview) { r.RequestID = testHash(90) },
		func(r *PruneMaintenanceReview) { r.StorageID = testHash(90) },
		func(r *PruneMaintenanceReview) { r.BindingID = testHash(90) },
		func(r *PruneMaintenanceReview) { r.Authority.Sequence++ },
		func(r *PruneMaintenanceReview) { r.Authority.HeadID = testHash(90) },
		func(r *PruneMaintenanceReview) { r.Phase = custodyauthority.Stopping },
		func(r *PruneMaintenanceReview) { r.Executor.Stage = PruneStarted },
		func(r *PruneMaintenanceReview) { r.Executor.HeadID = testHash(90) },
		func(r *PruneMaintenanceReview) { r.TicketID = testHash(90) },
	} {
		changed := base
		mutate(&changed)
		id, err := changed.ID()
		if err != nil || id == originalID {
			t.Fatal("review omitted field", err)
		}
		if _, err := owner.CancelBeforeStart(t.Context(), id); !errors.Is(err, ErrPruneMaintenanceReview) {
			t.Fatal("foreign review accepted", err)
		}
	}
	base.Executor.Stage, base.TerminalID = PruneCancelled, testHash(89)
	id, _ := base.ID()
	base.TerminalID = testHash(90)
	if changed, _ := base.ID(); changed == id {
		t.Fatal("review omitted terminal")
	}
}

func TestPruneMaintenanceInvalidLifecycleAndReview(t *testing.T) {
	for _, owner := range []*PruneMaintenance{nil, {}} {
		if _, err := owner.Review(t.Context()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if _, err := owner.CancelBeforeStart(t.Context(), types.Hash{}); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*PruneCommandService{nil, {}} {
		if owner, err := s.EnterMaintenance(t.Context()); owner != nil || !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
	f := newPruneFixtureWithStorageID(t, testHash(91))
	s := openTestPruneService(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if owner, err := s.EnterMaintenance(ctx); err == nil || owner != nil {
			t.Fatal("invalid context entered maintenance")
		}
	}
	if s.quiesced {
		t.Fatal("invalid context stopped service")
	}
	owner, err := s.EnterMaintenance(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	review, _ := maintenanceReview(t, owner)
	for _, mutate := range []func(*PruneMaintenanceReview){
		func(r *PruneMaintenanceReview) { r.RequestID = types.Hash{} },
		func(r *PruneMaintenanceReview) { r.StorageID = types.Hash{} },
		func(r *PruneMaintenanceReview) { r.BindingID = types.Hash{} },
		func(r *PruneMaintenanceReview) { r.Executor.Stage = 0 },
		func(r *PruneMaintenanceReview) { r.TicketID = testHash(99) },
	} {
		bad := review
		mutate(&bad)
		if _, err := bad.ID(); err == nil {
			t.Fatal("invalid review shape")
		}
	}
	// Retained-path failures cannot be cleared by another Review or Close.
	if err := os.Rename(filepath.Join(f.executorPath, pruneRecordsName), filepath.Join(f.executorPath, "preserved-records")); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Review(t.Context()); !errors.Is(err, ErrUncertain) {
		t.Fatal("changed storage accepted", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrUncertain) {
		t.Fatal("close lost failed review", err)
	}
}
