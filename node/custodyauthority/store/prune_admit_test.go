package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func pruneAdmissionEntry(t testing.TB, f *pruneFixture) custodyauthority.Entry {
	t.Helper()
	s := testCoordination(t, f.coordinator).Authority
	c := custodyauthority.Command{AssignmentID: f.request.AssignmentID, ExpectedSequence: s.Sequence, ExpectedHead: s.HeadID,
		Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: f.id}
	c, err := c.Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	e, err := custodyauthority.SignEntry(c, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func pruneAdmissionStages() []string {
	stages := pruneCompletionStages()
	for _, stage := range pinnedPrunePublicationStages() {
		if strings.Contains(stage, "admission-") {
			stages = append(stages, stage)
		}
	}
	return stages
}

func assertPruneAdmissionRecovery(t testing.TB, f *pruneFixture, stage string) bool {
	t.Helper()
	before, err := custodyauthority.NewState(testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := before.Snapshot()
	if err := before.Apply(f.admission); err != nil {
		t.Fatal(err)
	}
	admitted, _ := before.Snapshot()
	if strings.Contains(stage, "admission-") {
		checkRecoveredCoordination(t, f.coordinator, f.admission, initial, admitted, true, true, true)
		assertPinnedRecoveryStage(t, pruneSnapshot(t, f.executor), stage)
		return true
	}
	part, suffix, _ := strings.Cut(stage, "-")
	prepared := part != "intent" || isPublishedStage(suffix)
	decided := part == "confirm" || part == "authority" && isPublishedStage(suffix)
	confirmed := part == "confirm" && isPublishedStage(suffix)
	checkRecoveredCoordination(t, f.coordinator, f.admission, initial, admitted, prepared, decided, confirmed)
	s := pruneSnapshot(t, f.executor)
	if s.Stage != PrunePrepared || s.Protection.Pending != nil || s.Protection.Confirmed.Stage != PrunePrepared {
		t.Fatal("executor advanced before authority confirmation")
	}
	return decided
}

func assertPruneAdmissionConfirmed(t testing.TB, f *pruneFixture) {
	t.Helper()
	s, c := pruneSnapshot(t, f.executor), testCoordination(t, f.coordinator)
	if s.Stage != PruneAdmitted || s.Admission == nil || *s.Admission != f.admission || s.Protection.Pending != nil || s.Protection.Confirmed.Stage != PruneAdmitted ||
		c.Pending != nil || c.Confirmed.Sequence != 1 || c.Authority.Pending != 1 {
		t.Fatal("admission escaped without both confirmations")
	}
	ticket, _ := f.admission.ID()
	if _, found, err := f.chain.CanonicalPruneEffect(ticket); err != nil || found {
		t.Fatal("admission executed effect", err)
	}
}

func TestPruneAdmissionOrdersBothConfirmationsAndHistoricalRetry(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	var actual []string
	hook := func(stage string) error { actual = append(actual, stage); return nil }
	setCoordinatorHooks(f.coordinator, storeHooks{at: hook})
	f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
	result, err := f.executor.Admit(t.Context(), f.coordinator, f.admission)
	if err != nil || !result.Appended {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, pruneAdmissionStages()) {
		t.Fatalf("unexpected durable order: %v", actual)
	}
	assertPruneAdmissionConfirmed(t, f)
	f.reopen(t)
	if result, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); err != nil || result.Appended {
		t.Fatal(err)
	}
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err != nil {
		t.Fatal(err)
	}
	entry := pruneCompletionEntry(t, f)
	if _, err := f.executor.Complete(t.Context(), f.coordinator, entry); err != nil {
		t.Fatal(err)
	}
	stop := f.stop(t)
	appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
	f.reopen(t)
	terminal := pruneSnapshot(t, f.executor)
	if result, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); err != nil || result.Appended || result.Snapshot.Phase != custodyauthority.Retired {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(terminal, pruneSnapshot(t, f.executor)) {
		t.Fatal("historical admission changed executor")
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("historical ACK granted execution"); return 200, nil }); !errors.Is(err, ErrPruneCancelled) {
		t.Fatal(err)
	}
}

func TestPruneAdmissionPublicationFailures(t *testing.T) {
	for _, stage := range pruneAdmissionStages() {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			fault := errors.New("admission publication failed")
			hook := func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}
			setCoordinatorHooks(f.coordinator, storeHooks{at: hook})
			f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
			result, err := f.executor.Admit(t.Context(), f.coordinator, f.admission)
			if !errors.Is(err, fault) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("fault asserted success", err)
			}
			if _, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain owner reused", err)
			}
			f.reopen(t)
			decided := assertPruneAdmissionRecovery(t, f, stage)
			f.reopen(t)
			assertPruneAdmissionRecovery(t, f, stage)
			if result, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); err != nil || result.Appended == decided {
				t.Fatal("exact retry failed", err)
			}
			assertPruneAdmissionConfirmed(t, f)
		})
	}
}

func TestPruneAdmissionRejectsBeforeMutation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	valid := pruneAdmissionEntry(t, f)
	before, prepared := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
	for _, field := range []string{"assignment", "operation", "consumer", "authority", "purpose", "kind", "head", "sequence", "consumer-signature", "authority-signature"} {
		t.Run(field, func(t *testing.T) {
			c, actor, authority := valid.Command, byte(4), byte(1)
			switch field {
			case "assignment":
				c.AssignmentID = testHash(95)
			case "operation":
				c.OperationID = testHash(96)
			case "consumer":
				actor = 5
				c.ActorPublicKey = [32]byte{}
			case "authority":
				authority = 6
			case "purpose":
				c.Purpose = custodyauthority.Serve
			case "kind":
				c.Kind = custodyauthority.Complete
				c.OperationID = types.Hash{}
				c.Purpose = 0
				c.TicketID = testHash(98)
				c.EvidenceID = testHash(99)
			case "head":
				c.ExpectedHead = testHash(97)
			case "sequence":
				c.ExpectedSequence++
			}
			c, err := c.Sign(testKey(actor))
			if err != nil {
				t.Fatal(err)
			}
			e, err := custodyauthority.SignEntry(c, testKey(authority))
			if err != nil {
				t.Fatal(err)
			}
			if field == "consumer-signature" {
				e.Command.Signature[0] ^= 1
			}
			if field == "authority-signature" {
				e.Signature[0] ^= 1
			}
			if r, err := f.executor.Admit(t.Context(), f.coordinator, e); err == nil || !reflect.DeepEqual(r, Commit{}) {
				t.Fatal("invalid admission succeeded", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(prepared, pruneSnapshot(t, f.executor)) {
				t.Fatal("rejected entry wrote state")
			}
		})
	}
	if _, err := f.executor.Admit(nil, f.coordinator, valid); !errors.Is(err, ErrPruneRequest) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.executor.Admit(ctx, f.coordinator, valid); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.executor.Admit(t.Context(), nil, valid); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	raw := newPruneFixture(t)
	if _, err := raw.executor.Admit(t.Context(), raw.coordinator, pruneAdmissionEntry(t, raw)); !errors.Is(err, ErrPrunePin) {
		t.Fatal(err)
	}
}

func TestPruneAdmissionCancellationRetainsExactRetry(t *testing.T) {
	for _, stage := range []string{"intent-after-apply", "confirm-after-apply", "pins-admission-intent-after-apply"} {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hook := func(at string) error {
				if at == stage {
					cancel()
				}
				return nil
			}
			setCoordinatorHooks(f.coordinator, storeHooks{at: hook})
			f.executor.pins.hooks.at = hook
			if r, err := f.executor.Admit(ctx, f.coordinator, f.admission); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(r, Commit{}) {
				t.Fatal("cancellation returned completed binding", err)
			}
			assertPruneAdmissionRecovery(t, f, stage)
			// No storage error occurred: the same owner can explicitly resume.
			setCoordinatorHooks(f.coordinator, storeHooks{})
			f.executor.pins.hooks = storeHooks{}
			if _, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); err != nil {
				t.Fatal(err)
			}
			assertPruneAdmissionConfirmed(t, f)
		})
	}
}

func TestPruneAdmissionInterruptedExecutorResume(t *testing.T) {
	for _, stage := range pruneAdmissionStages() {
		if !strings.HasPrefix(stage, "prune-admission-") && !strings.HasPrefix(stage, "pins-admission-confirm-") {
			continue
		}
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.executor.pins.hooks.at = func(at string) error {
				if at == "pins-admission-intent-after-apply" {
					cancel()
				}
				return nil
			}
			if _, err := f.executor.Admit(ctx, f.coordinator, f.admission); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			f.reopen(t)
			fault := errors.New("resume interrupted")
			hook := func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}
			f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
			if r, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); !errors.Is(err, fault) || !reflect.DeepEqual(r, Commit{}) {
				t.Fatal("resume failure acknowledged", err)
			}
			f.reopen(t)
			assertPruneAdmissionRecovery(t, f, stage)
			if r, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); err != nil || r.Appended {
				t.Fatal(err)
			}
			assertPruneAdmissionConfirmed(t, f)
		})
	}
}

func TestPruneAdmissionNeverResumesAnotherTransitionOrAuthorityAttempt(t *testing.T) {
	for _, stage := range []string{"pins-start-intent-after-publish", "pins-result-intent-after-publish", "pins-cancel-intent-after-publish", "authority-stop"} {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, true)
			fault := errors.New("retained other attempt")
			if stage == "authority-stop" {
				setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
					if at == "intent-after-publish" {
						return fault
					}
					return nil
				}})
				s := testCoordination(t, f.coordinator).Authority
				_, err := f.coordinator.Append(t.Context(), testEntry(t, s, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(90)))
				if !errors.Is(err, fault) {
					t.Fatal(err)
				}
			} else {
				f.executor.pins.hooks.at = func(at string) error {
					if at == stage {
						return fault
					}
					return nil
				}
				var err error
				if strings.Contains(stage, "cancel") {
					_, err = f.executor.CancelBeforeStart(t.Context(), f.coordinator)
				} else {
					_, err = f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
				}
				if !errors.Is(err, fault) {
					t.Fatal(err)
				}
			}
			f.reopen(t)
			before, execution := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
			want := ErrPrunePinPending
			if stage == "authority-stop" {
				want = ErrPendingAttempt
			}
			if _, err := f.executor.Admit(t.Context(), f.coordinator, f.admission); !errors.Is(err, want) {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(execution, pruneSnapshot(t, f.executor)) {
				t.Fatal("admission resumed unrelated work")
			}
		})
	}
}

func TestPruneAdmissionStopAndCompletedUnboundTicket(t *testing.T) {
	for _, mode := range []string{"stop-before", "stop-after-decision", "complete-before-bind"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			if mode != "stop-before" {
				appendCoordinated(t, f.coordinator, f.admission)
			}
			f.stop(t)
			if mode == "complete-before-bind" {
				ticket, _ := f.admission.ID()
				appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Complete, types.Hash{}, ticket, testHash(88)))
			}
			before := testCoordination(t, f.coordinator)
			r, err := f.executor.Admit(t.Context(), f.coordinator, f.admission)
			if mode == "stop-after-decision" {
				if err != nil || r.Appended || pruneSnapshot(t, f.executor).Stage != PruneAdmitted {
					t.Fatal(err)
				}
			} else if err == nil || pruneSnapshot(t, f.executor).Stage != PrunePrepared {
				t.Fatal("closed/absent ticket bound", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) {
				t.Fatal("retry changed authority")
			}
		})
	}
}

func TestPruneAdmissionConcurrentRetriesAndStopSerialization(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f.executor.pins.hooks.at = func(stage string) error {
		if stage == "pins-admission-confirm-before-publish" {
			close(entered)
			<-release
		}
		return nil
	}
	var appended atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, err := f.executor.Admit(t.Context(), f.coordinator, f.admission)
			if err != nil {
				t.Error(err)
			} else if r.Appended {
				appended.Add(1)
			}
		})
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("binding did not reach confirmation")
	}
	// Construct Stop from the already known exact successor; no snapshot can
	// acquire the authority guard while admission publication is blocked.
	id, _ := f.admission.ID()
	s := custodyauthority.Snapshot{AssignmentID: f.request.AssignmentID, Sequence: 1, HeadID: id}
	stop := testEntry(t, s, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(88))
	done := make(chan error, 1)
	go func() { _, err := f.coordinator.Append(t.Context(), stop); done <- err }()
	select {
	case err := <-done:
		t.Fatal("stop split admission binding", err)
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if appended.Load() != 1 || testCoordination(t, f.coordinator).Authority.Pending != 1 || pruneSnapshot(t, f.executor).Protection.Pending != nil {
		t.Fatal("duplicate admission or unconfirmed binding")
	}
}
