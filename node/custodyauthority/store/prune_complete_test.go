package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func finishPruneForCompletion(t testing.TB, f *pruneFixture, outcome string) {
	t.Helper()
	f.admit(t, true)
	if outcome == "cancelled" {
		if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err != nil {
			t.Fatal(err)
		}
	} else if result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); err != nil || !result.Applied {
		t.Fatal("failed to retain terminal effect", err)
	}
}

func pruneCompletionEntry(t testing.TB, f *pruneFixture) custodyauthority.Entry {
	t.Helper()
	s := pruneSnapshot(t, f.executor)
	var id types.Hash
	var err error
	if s.Cancellation != nil {
		id, err = s.Cancellation.ID()
	} else if s.Effect != nil {
		id, err = s.Effect.ID()
	} else {
		t.Fatal("test has no retained terminal outcome")
	}
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := f.admission.ID()
	return testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Complete, types.Hash{}, ticket, id)
}

func pruneCompletionStages() []string {
	var result []string
	for _, part := range []string{"intent", "authority", "confirm"} {
		for _, stage := range appendStages {
			result = append(result, part+"-"+stage)
		}
	}
	return result
}

func assertPruneCompletionRecovery(t testing.TB, f *pruneFixture, entry custodyauthority.Entry, before custodyauthority.Snapshot, terminal PruneExecution, stage string) bool {
	t.Helper()
	part, suffix, ok := strings.Cut(stage, "-")
	if !ok {
		t.Fatal("invalid completion boundary")
	}
	prepared := part != "intent" || isPublishedStage(suffix)
	decided := part == "confirm" || (part == "authority" && isPublishedStage(suffix))
	confirmed := part == "confirm" && isPublishedStage(suffix)
	model, err := custodyauthority.NewState(testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(f.admission); err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(entry); err != nil {
		t.Fatal(err)
	}
	after, err := model.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	checkRecoveredCoordination(t, f.coordinator, entry, before, after, prepared, decided, confirmed)
	if !reflect.DeepEqual(pruneSnapshot(t, f.executor), terminal) {
		t.Fatal("completion recovery changed executor evidence")
	}
	return decided
}

func TestPruneCompletionUsesOnlyConfirmedTerminalOutcome(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, mode := range []string{"unbound-pinned", "storage-bound", "position-pinned"} {
			t.Run(outcome+"/"+mode, func(t *testing.T) {
				var f *pruneFixture
				switch mode {
				case "unbound-pinned":
					f = newPinnedPruneFixture(t)
				case "storage-bound":
					f = newPruneFixtureWithStorageID(t, testHash(91))
				default:
					f = newPruneFixtureWithStoragePositions(t, testHash(91), true)
				}
				finishPruneForCompletion(t, f, outcome)
				stop := f.stop(t)
				entry := pruneCompletionEntry(t, f)
				terminal := pruneSnapshot(t, f.executor)
				usage, _, err := f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				if err := f.chain.Close(); err != nil {
					t.Fatal(err)
				}
				result, err := f.executor.Complete(t.Context(), f.coordinator, entry)
				id, _ := entry.ID()
				if err != nil || !result.Appended || result.EntryID != id || result.Snapshot.Pending != 0 || result.Snapshot.Phase != custodyauthority.Stopping {
					t.Fatal("completion did not drain the exact ticket", err)
				}
				if current := testCoordination(t, f.coordinator); current.Pending != nil || current.Confirmed != position(result.Snapshot) {
					t.Fatal("completion returned before independent confirmation")
				}
				operation := result.Snapshot.Operations[0]
				if operation.CompletionID != id || operation.EvidenceID != entry.Command.EvidenceID {
					t.Fatal("completion evidence changed")
				}
				result.Snapshot.Operations[0].EvidenceID[0] ^= 1
				appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
				f.reopen(t)
				for range 2 {
					retry, err := f.executor.Complete(t.Context(), f.coordinator, entry)
					if err != nil || retry.Appended || retry.EntryID != id || retry.Snapshot.Phase != custodyauthority.Retired || retry.Snapshot.Operations[0] != operation {
						t.Fatal("historical retry changed terminal authority", err)
					}
				}
				if after, _, err := f.chain.HistoryUsage(); err != nil || after != usage || !reflect.DeepEqual(pruneSnapshot(t, f.executor), terminal) {
					t.Fatal("completion changed chain or executor", err)
				}
			})
		}
	}
}

func TestPruneCompletionRejectsUnfinishedAndRawExecutors(t *testing.T) {
	for _, stage := range []string{"raw", "prepared", "admitted", "pins-start-intent-after-publish", "prune-before-effect", "prune-after-effect", "pins-result-confirm-before-publish", "pins-cancel-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			var f *pruneFixture
			if stage == "raw" {
				f = newPruneFixture(t)
				finishPruneForCompletion(t, f, "succeeded")
			} else {
				f = newPruneFixtureWithStorageID(t, testHash(91))
				if stage != "prepared" {
					f.admit(t, true)
				}
			}
			if strings.Contains(stage, "-") {
				fault := errors.New("incomplete execution")
				hook := func(at string) error {
					if at == stage {
						return fault
					}
					return nil
				}
				f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
				var err error
				if strings.Contains(stage, "cancel") {
					_, err = f.executor.CancelBeforeStart(t.Context(), f.coordinator)
				} else {
					_, err = f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
				}
				if !errors.Is(err, fault) {
					t.Fatal(err)
				}
				f.reopen(t)
			}
			before := testCoordination(t, f.coordinator)
			// Even a valid co-signed claim cannot substitute for the executor's
			// own independently confirmed terminal record.
			ticket, _ := f.admission.ID()
			if ticket.IsZero() {
				ticket = testHash(99)
			}
			entry := testEntry(t, before.Authority, custodyauthority.Complete, types.Hash{}, ticket, testHash(98))
			result, err := f.executor.Complete(t.Context(), f.coordinator, entry)
			want := ErrPruneStage
			if stage == "raw" {
				want = ErrPrunePin
			} else if s := pruneSnapshot(t, f.executor); s.Protection.Pending != nil {
				want = ErrPrunePinPending
			} else if s.Stage == PruneStarted {
				want = ErrPruneOutcome
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(result, Commit{}) || !reflect.DeepEqual(testCoordination(t, f.coordinator), before) {
				t.Fatal("ineligible executor changed authority", err)
			}
		})
	}
}

func TestPruneCompletionRejectsWrongSignedBindings(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "succeeded")
	valid := pruneCompletionEntry(t, f)
	before := testCoordination(t, f.coordinator)
	for _, field := range []string{"assignment", "ticket", "evidence", "consumer", "authority", "kind", "head", "sequence", "consumer-signature", "authority-signature"} {
		t.Run(field, func(t *testing.T) {
			entry, command := valid, valid.Command
			actor, authority := byte(4), byte(1)
			switch field {
			case "assignment":
				command.AssignmentID = testHash(91)
			case "ticket":
				command.TicketID = testHash(92)
			case "evidence":
				command.EvidenceID = testHash(93)
			case "consumer":
				actor = 5
			case "authority":
				authority = 6
			case "kind":
				actor, command.Kind, command.TicketID = 1, custodyauthority.Stop, types.Hash{}
			case "head":
				command.ExpectedHead = testHash(94)
			case "sequence":
				command.ExpectedSequence++
			case "consumer-signature":
				entry.Command.Signature[0] ^= 1
			case "authority-signature":
				entry.Signature[0] ^= 1
			}
			if !strings.Contains(field, "signature") {
				command.ActorPublicKey, command.Signature = [32]byte{}, [64]byte{}
				var err error
				command, err = command.Sign(testKey(actor))
				if err != nil {
					t.Fatal(err)
				}
				entry, err = custodyauthority.SignEntry(command, testKey(authority))
				if err != nil {
					t.Fatal(err)
				}
			}
			if result, err := f.executor.Complete(t.Context(), f.coordinator, entry); err == nil || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("wrong signed completion accepted", err)
			}
			if !reflect.DeepEqual(testCoordination(t, f.coordinator), before) {
				t.Fatal("invalid completion retained an authority intent")
			}
		})
	}
}

func TestPruneCompletionFaultsRequireExactRetry(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, stage := range pruneCompletionStages() {
			t.Run(outcome+"/"+stage, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				finishPruneForCompletion(t, f, outcome)
				entry := pruneCompletionEntry(t, f)
				before, terminal := testCoordination(t, f.coordinator).Authority, pruneSnapshot(t, f.executor)
				fault := errors.New("completion publication failed")
				setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
					if at == stage {
						return fault
					}
					return nil
				}})
				if result, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) || !reflect.DeepEqual(result, Commit{}) {
					t.Fatal("uncertain completion returned a decision", err)
				}
				if _, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, ErrUncertain) {
					t.Fatal("poisoned coordinator remained usable", err)
				}
				f.reopen(t)
				decided := assertPruneCompletionRecovery(t, f, entry, before, terminal, stage)
				f.reopen(t)
				assertPruneCompletionRecovery(t, f, entry, before, terminal, stage)
				result, err := f.executor.Complete(t.Context(), f.coordinator, entry)
				if err != nil || result.Appended == decided || result.Snapshot.Pending != 0 || testCoordination(t, f.coordinator).Pending != nil {
					t.Fatal("exact completion retry lost its decision", err)
				}
				if !reflect.DeepEqual(pruneSnapshot(t, f.executor), terminal) {
					t.Fatal("completion advanced the executor")
				}
			})
		}
	}
}

func TestPruneCompletionConcurrentRetriesAppendOnce(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			finishPruneForCompletion(t, f, outcome)
			entry := pruneCompletionEntry(t, f)
			var wg sync.WaitGroup
			var appended atomic.Int32
			for range 16 {
				wg.Go(func() {
					result, err := f.executor.Complete(t.Context(), f.coordinator, entry)
					if err != nil || result.Snapshot.Pending != 0 {
						t.Error(err)
					}
					if result.Appended {
						appended.Add(1)
					}
				})
			}
			wg.Wait()
			if appended.Load() != 1 || testCoordination(t, f.coordinator).Authority.Sequence != 2 {
				t.Fatal("concurrent completion repeated a decision")
			}
		})
	}
}

func TestPruneCompletionHoldsBothGuardsThroughConfirmation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "succeeded")
	entry := pruneCompletionEntry(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	setCoordinatorHooks(f.coordinator, storeHooks{at: func(stage string) error {
		if stage == "confirm-before-publish" {
			close(entered)
			<-release
		}
		return nil
	}})
	done := make(chan error, 1)
	go func() { _, err := f.executor.Complete(t.Context(), f.coordinator, entry); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("completion missed confirmation")
	}
	if f.executor.mu.TryLock() {
		f.executor.mu.Unlock()
		t.Fatal("completion released executor before confirmation")
	}
	if f.coordinator.mu.TryLock() {
		f.coordinator.mu.Unlock()
		t.Fatal("completion released authority before confirmation")
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPruneCompletionDoesNotReplacePendingStopOrRefreshSignature(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "cancelled")
	entry := pruneCompletionEntry(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	setCoordinatorHooks(f.coordinator, storeHooks{at: func(stage string) error {
		if stage == "intent-after-apply" {
			cancel()
		}
		return nil
	}})
	stop := testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(90))
	if _, err := f.coordinator.Append(ctx, stop); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal(err)
	}
	if _, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal("completion displaced retained stop", err)
	}
	setCoordinatorHooks(f.coordinator, storeHooks{})
	if _, err := f.coordinator.Resume(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, custodyauthority.ErrHead) {
		t.Fatal("completion silently refreshed its signed head", err)
	}
	if result, err := f.executor.Complete(t.Context(), f.coordinator, pruneCompletionEntry(t, f)); err != nil || !result.Appended {
		t.Fatal("separately re-signed completion could not drain stopping work", err)
	}
}

func TestPruneCompletionContextPreservesIntentAndDrainsDecision(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, stage := range []string{"intent-before-write", "intent-after-apply", "authority-before-publish", "authority-after-apply", "confirm-before-write"} {
			t.Run(outcome+"/"+stage, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				finishPruneForCompletion(t, f, outcome)
				entry := pruneCompletionEntry(t, f)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
					if at == stage {
						cancel()
					}
					return nil
				}})
				result, err := f.executor.Complete(ctx, f.coordinator, entry)
				decided := stage == "authority-after-apply" || stage == "confirm-before-write"
				if decided {
					if err != nil || !result.Appended || result.Snapshot.Pending != 0 {
						t.Fatal("caller cancellation abandoned a durable decision", err)
					}
				} else if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, Commit{}) {
					t.Fatal("caller cancellation returned a decision before publication", err)
				}
				f.reopen(t)
				current := testCoordination(t, f.coordinator)
				pending := !decided && stage != "intent-before-write"
				if (current.Pending != nil) != pending || (pending && *current.Pending != entry) {
					t.Fatal("cancellation discarded or changed a retained completion")
				}
				if result, err := f.executor.Complete(t.Context(), f.coordinator, entry); err != nil || result.Appended == decided || result.Snapshot.Pending != 0 {
					t.Fatal("completion retry after context cancellation changed the outcome", err)
				}
			})
		}
	}
}

func TestPruneCompletionDirectorySyncFailureRequiresReopen(t *testing.T) {
	for _, part := range []string{"intent", "authority", "confirm"} {
		t.Run(part, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			finishPruneForCompletion(t, f, "cancelled")
			entry := pruneCompletionEntry(t, f)
			before, terminal := testCoordination(t, f.coordinator).Authority, pruneSnapshot(t, f.executor)
			fault := errors.New("completion directory sync failed")
			setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
				if at == part+"-before-publish" {
					if part == "authority" {
						f.coordinator.authority.hooks.syncEntriesDirectory = func(string) error { return fault }
					} else {
						f.coordinator.journal.hooks.syncEntriesDirectory = func(string) error { return fault }
					}
				}
				return nil
			}})
			if result, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("sync uncertainty returned success", err)
			}
			f.reopen(t)
			decided := assertPruneCompletionRecovery(t, f, entry, before, terminal, part+"-after-publish")
			if result, err := f.executor.Complete(t.Context(), f.coordinator, entry); err != nil || result.Appended == decided || result.Snapshot.Pending != 0 {
				t.Fatal("sync recovery changed completion", err)
			}
		})
	}
}

func TestPruneCompletionRejectsMissingOwnersContextAndConflictingCompletion(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "succeeded")
	entry := pruneCompletionEntry(t, f)
	before := testCoordination(t, f.coordinator)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if result, err := f.executor.Complete(ctx, f.coordinator, entry); err == nil || !reflect.DeepEqual(result, Commit{}) {
			t.Fatal("invalid context accepted")
		}
	}
	if _, err := (*PruneExecutor)(nil).Complete(t.Context(), f.coordinator, entry); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := f.executor.Complete(t.Context(), nil, entry); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	other, _, _ := newTestCoordinator(t)
	if _, err := f.executor.Complete(t.Context(), other, entry); err == nil {
		t.Fatal("completion created an admission in another authority")
	}
	_ = other.Close()
	if _, err := f.executor.Complete(t.Context(), other, entry); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(testCoordination(t, f.coordinator), before) {
		t.Fatal("invalid completion changed the original authority")
	}
	// The low-level coordinator remains a trusted signed-command store. If a
	// caller bypassed this adapter, it must not silently overwrite that history.
	conflict := testEntry(t, before.Authority, custodyauthority.Complete, types.Hash{}, entry.Command.TicketID, testHash(95))
	appendCoordinated(t, f.coordinator, conflict)
	if _, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, custodyauthority.ErrHead) {
		t.Fatal("conflicting old completion was replaced", err)
	}
	if _, err := f.executor.Complete(t.Context(), f.coordinator, pruneCompletionEntry(t, f)); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal("completed ticket reopened with a new signature", err)
	}
	_ = f.executor.Close()
	if _, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestPruneCompletionRequiresIntactDisjointRoots(t *testing.T) {
	t.Run("overlap", func(t *testing.T) {
		f := newPruneFixtureWithStorageID(t, testHash(91))
		finishPruneForCompletion(t, f, "cancelled")
		entry := pruneCompletionEntry(t, f)
		before := testCoordination(t, f.coordinator)
		for _, destination := range []*string{&f.coordinator.authority.path, &f.coordinator.journal.path} {
			for _, source := range []string{f.executorPath, f.executorPinsPath} {
				// Substitute only the private path, not on-disk history, to
				// isolate the root check before authority access/publication.
				original := *destination
				*destination = source
				result, err := f.executor.Complete(t.Context(), f.coordinator, entry)
				*destination = original
				if !errors.Is(err, ErrRootOverlap) || !reflect.DeepEqual(result, Commit{}) || !reflect.DeepEqual(testCoordination(t, f.coordinator), before) {
					t.Fatal("overlapping completion roots reached authority", err)
				}
			}
		}
	})
	for _, root := range []string{"executor", "pins"} {
		t.Run("missing-terminal/"+root, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			finishPruneForCompletion(t, f, "cancelled")
			entry := pruneCompletionEntry(t, f)
			before := testCoordination(t, f.coordinator)
			path := filepath.Join(f.executorPath, pruneRecordsName, pruneRecordName(1, PruneCancelled))
			if root == "pins" {
				path = filepath.Join(f.executorPinsPath, confirmedName, prunePinConfirmNames[1])
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if result, err := f.executor.Complete(t.Context(), f.coordinator, entry); !errors.Is(err, ErrUncertain) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatal("missing terminal evidence completed from cached state", err)
			}
			if !reflect.DeepEqual(testCoordination(t, f.coordinator), before) {
				t.Fatal("missing executor evidence wrote an authority intent")
			}
		})
	}
}
