package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func newPinnedPruneFixture(t testing.TB) *pruneFixture {
	t.Helper()
	f := newPruneFixture(t)
	_ = f.executor.Close()
	f.executorPath = filepath.Join(t.TempDir(), "pinned-executor")
	f.executorPinsPath = filepath.Join(t.TempDir(), "independent-pins")
	var err error
	f.executor, err = CreatePinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.request, f.id)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPinnedPruneExecutorRunsOnceAndRetainsConfirmedPositions(t *testing.T) {
	f := newPinnedPruneFixture(t)
	initial := pruneSnapshot(t, f.executor)
	if initial.Protection == nil || initial.Protection.BindingID.IsZero() || initial.Protection.Confirmed != (PrunePosition{Stage: PrunePrepared, HeadID: f.id}) || initial.Protection.Pending != nil {
		t.Fatal("wrong initial protection")
	}
	f.admit(t, true)
	f.reopen(t)
	admitted := pruneSnapshot(t, f.executor)
	if admitted.Stage != PruneAdmitted || admitted.Protection.Confirmed.Stage != PruneAdmitted || admitted.Protection.Pending != nil {
		t.Fatal("admission was not independently confirmed")
	}
	var calls, applied atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) {
				calls.Add(1)
				return 200, nil
			})
			if err != nil {
				t.Error(err)
			} else if result.Applied {
				applied.Add(1)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || applied.Load() != 1 {
		t.Fatal("duplicate effect", calls.Load(), applied.Load())
	}
	finished := pruneSnapshot(t, f.executor)
	if finished.Protection.Confirmed.Stage != PruneSucceeded || finished.Protection.Pending != nil || finished.Protection.BindingID != initial.Protection.BindingID {
		t.Fatal("success escaped before pin confirmation")
	}
	f.complete(t, *finished.Effect)
	f.reopen(t)
	retained, err := f.executor.Recover(t.Context(), nil)
	if err != nil || retained.Applied || !samePruneEffect(retained.Effect, *finished.Effect) {
		t.Fatal("lost result after retirement", err)
	}
	if err := f.executor.ResumePinnedTransition(t.Context()); !errors.Is(err, ErrNoAttempt) {
		t.Fatal(err)
	}
	// Every public diagnostic is detached, including the pin's head.
	finished.Protection.Confirmed.HeadID[0] ^= 1
	if pruneSnapshot(t, f.executor).Protection.Confirmed == finished.Protection.Confirmed {
		t.Fatal("mutable pin escaped")
	}
}

func pinnedPrunePublicationStages() []string {
	var result []string
	for _, part := range []string{"admission", "start", "result"} {
		for _, prefix := range []string{"pins-" + part + "-intent", "prune-" + part, "pins-" + part + "-confirm"} {
			for _, stage := range appendStages {
				result = append(result, prefix+"-"+stage)
			}
		}
	}
	return result
}

func runPinnedPruneToStage(t testing.TB, f *pruneFixture, stage string) error {
	t.Helper()
	if strings.Contains(stage, "admission-") {
		return f.executor.BindAdmission(t.Context(), f.coordinator, f.admission)
	}
	_, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
	return err
}

func assertPinnedRecoveryStage(t testing.TB, s PruneExecution, stage string) {
	t.Helper()
	wantStage, wantConfirmed, wantPending := PruneStarted, PruneStarted, false
	for index, part := range []string{"admission", "start", "result"} {
		previous := PrunePrepared + PruneStage(index)
		if point, ok := strings.CutPrefix(stage, "pins-"+part+"-intent-"); ok {
			wantStage, wantConfirmed, wantPending = previous, previous, isPublishedStage(point)
		} else if point, ok := strings.CutPrefix(stage, "prune-"+part+"-"); ok {
			wantStage, wantConfirmed, wantPending = previous, previous, true
			if isPublishedStage(point) {
				wantStage++
			}
		} else if point, ok := strings.CutPrefix(stage, "pins-"+part+"-confirm-"); ok {
			wantStage, wantConfirmed, wantPending = previous+1, previous, true
			if isPublishedStage(point) {
				wantConfirmed++
				wantPending = false
			}
		}
	}
	if s.Stage != wantStage || s.Protection.Confirmed.Stage != wantConfirmed || (s.Protection.Pending != nil) != wantPending {
		t.Fatalf("%s: stage=%d confirmed=%d pending=%v; want stage=%d confirmed=%d pending=%v", stage, s.Stage, s.Protection.Confirmed.Stage, s.Protection.Pending, wantStage, wantConfirmed, wantPending)
	}
}

func settlePinnedPruneAfterFailure(t testing.TB, f *pruneFixture) {
	t.Helper()
	s := pruneSnapshot(t, f.executor)
	if s.Protection.Pending != nil {
		if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("unconfirmed start executed"); return 200, nil }); !errors.Is(err, ErrPrunePinPending) {
			t.Fatal("pending pin did not block execution", err)
		}
		if _, err := f.executor.Recover(t.Context(), f.chain); !errors.Is(err, ErrPrunePinPending) {
			t.Fatal("pending pin bypassed by effect recovery", err)
		}
		if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); !errors.Is(err, ErrPrunePinPending) {
			t.Fatal("pending pin bypassed by admission retry", err)
		}
		if err := f.executor.ResumePinnedTransition(t.Context()); err != nil {
			t.Fatal(err)
		}
		s = pruneSnapshot(t, f.executor)
	}
	if s.Protection.Pending != nil || s.Stage != s.Protection.Confirmed.Stage {
		t.Fatal("resume did not settle exact pin")
	}
	ticket, _ := f.admission.ID()
	effect, found, err := f.chain.CanonicalPruneEffect(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if s.Stage == PruneStarted && !found {
		if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("resumed start reran"); return 200, nil }); !errors.Is(err, ErrPruneOutcome) {
			t.Fatal(err)
		}
		if _, err := f.executor.Recover(t.Context(), f.chain); !errors.Is(err, ErrPruneOutcome) {
			t.Fatal("missing effect became success", err)
		}
		stop := f.stop(t)
		snapshot := testCoordination(t, f.coordinator).Authority
		if _, err := f.coordinator.Append(t.Context(), testEntry(t, snapshot, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)); !errors.Is(err, custodyauthority.ErrOutstanding) {
			t.Fatal("unknown start retired", err)
		}
		return
	}
	var result workchain.CanonicalPruneCommit
	if found {
		result, err = f.executor.Recover(t.Context(), f.chain)
		if err != nil || result.Applied || !samePruneEffect(effect, result.Effect) {
			t.Fatal("changed historical effect", err)
		}
	} else {
		if s.Stage == PrunePrepared {
			if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
				t.Fatal(err)
			}
		}
		result, err = f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
		if err != nil || !result.Applied {
			t.Fatal("unstarted work did not run explicitly", err)
		}
	}
	f.complete(t, result.Effect)
	f.reopen(t)
	if s := pruneSnapshot(t, f.executor); s.Protection.Pending != nil || s.Protection.Confirmed.Stage != PruneSucceeded || !samePruneEffect(*s.Effect, result.Effect) {
		t.Fatal("retirement lost confirmed result")
	}
}

func TestPinnedPruneExecutorPublicationFailures(t *testing.T) {
	for _, stage := range pinnedPrunePublicationStages() {
		t.Run(stage, func(t *testing.T) {
			f := newPinnedPruneFixture(t)
			f.admit(t, !strings.Contains(stage, "admission-"))
			injected := errors.New("retained transition publication failed")
			hooks := storeHooks{at: func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}}
			f.executor.hooks, f.executor.pins.hooks = hooks, hooks
			if err := runPinnedPruneToStage(t, f, stage); !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
				t.Fatal("failure was not poisoned", err)
			}
			if _, err := f.executor.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatal("failed writer returned a snapshot", err)
			}
			f.reopen(t)
			before := pruneSnapshot(t, f.executor)
			assertPinnedRecoveryStage(t, before, stage)
			f.reopen(t)
			after := pruneSnapshot(t, f.executor)
			if before.Stage != after.Stage || before.Protection.Confirmed != after.Protection.Confirmed || (before.Protection.Pending == nil) != (after.Protection.Pending == nil) {
				t.Fatal("open advanced a transition")
			}
			settlePinnedPruneAfterFailure(t, f)
		})
	}
}

func TestPinnedPruneExecutorRejectsPrefixRollbackAndUnexplainedExtension(t *testing.T) {
	for _, mode := range []string{"executor-admission", "executor-start", "executor-result", "pins-short", "foreign-pair", "raw-open", "pin-gap", "pin-head", "pin-intent", "missing-pin-lock", "missing-pin-ready", "extra-pin-record"} {
		t.Run(mode, func(t *testing.T) {
			f := newPinnedPruneFixture(t)
			f.admit(t, true)
			if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); err != nil {
				t.Fatal(err)
			}
			_ = f.executor.Close()
			switch mode {
			case "executor-admission", "executor-start", "executor-result":
				from := map[string]int{"executor-admission": 0, "executor-start": 1, "executor-result": 2}[mode]
				for _, name := range pruneRecordNames[from:] {
					if err := os.Remove(filepath.Join(f.executorPath, pruneRecordsName, name)); err != nil {
						t.Fatal(err)
					}
				}
			case "pins-short":
				for _, directory := range []string{intentsName, confirmedName} {
					name := pruneRecordNames[2]
					if directory == confirmedName {
						name = prunePinConfirmNames[2]
					}
					if err := os.Remove(filepath.Join(f.executorPinsPath, directory, name)); err != nil {
						t.Fatal(err)
					}
				}
			case "foreign-pair":
				other := newPinnedPruneFixture(t)
				_ = other.executor.Close()
				f.executorPinsPath = other.executorPinsPath
			case "raw-open":
				if opened, err := OpenPruneExecutor(f.executorPath, testAssignment(), f.id); err == nil {
					_ = opened.Close()
					t.Fatal("pinned executor downgraded to raw")
				}
				return
			case "pin-gap":
				if err := os.Remove(filepath.Join(f.executorPinsPath, confirmedName, prunePinConfirmNames[0])); err != nil {
					t.Fatal(err)
				}
			case "pin-head", "pin-intent":
				path := filepath.Join(f.executorPinsPath, confirmedName, prunePinConfirmNames[2])
				if mode == "pin-intent" {
					path = filepath.Join(f.executorPinsPath, intentsName, pruneRecordNames[0])
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				writeTestFile(t, path, data)
			case "missing-pin-lock":
				if err := os.Remove(filepath.Join(f.executorPinsPath, prunePinLockName)); err != nil {
					t.Fatal(err)
				}
			case "missing-pin-ready":
				if err := os.Remove(filepath.Join(f.executorPinsPath, prunePinReadyName)); err != nil {
					t.Fatal(err)
				}
			case "extra-pin-record":
				writeTestFile(t, filepath.Join(f.executorPinsPath, intentsName, "04-extra"), nil)
			}
			if opened, err := OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id); err == nil {
				_ = opened.Close()
				t.Fatal("invalid prefix/pair reopened")
			}
		})
	}
}

func TestPinnedPruneExecutorCancellationLeavesExactTransition(t *testing.T) {
	for _, stage := range []string{"pins-start-intent-before-publish", "pins-start-intent-after-apply", "prune-start-after-apply", "pins-start-confirm-after-apply", "pins-result-intent-after-apply"} {
		t.Run(stage, func(t *testing.T) {
			f := newPinnedPruneFixture(t)
			f.admit(t, true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hooks := storeHooks{at: func(at string) error {
				if at == stage {
					cancel()
				}
				return nil
			}}
			f.executor.hooks, f.executor.pins.hooks = hooks, hooks
			result, err := f.executor.Execute(ctx, f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
			if strings.Contains(stage, "result-") {
				if err != nil || !result.Applied {
					t.Fatal("cancel abandoned committed result", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatal("cancel ignored", err)
			}
			f.reopen(t)
			settlePinnedPruneAfterFailure(t, f)
		})
	}
}

func TestPinnedPruneExecutorOwnershipAndLimits(t *testing.T) {
	f := newPinnedPruneFixture(t)
	if opened, err := OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("two pin owners", err)
	}
	f.admit(t, true)
	for index := range MaximumPendingFiles {
		writeTestFile(t, filepath.Join(f.executorPinsPath, pendingName, fmt.Sprintf("entry-%d", index)), nil)
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("full pins executed work"); return 200, nil }); !errors.Is(err, custodyauthority.ErrLimit) {
		t.Fatal(err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneAdmitted || s.Protection.Pending != nil {
		t.Fatal("full journal consumed start")
	}
	path := filepath.Join(f.executorPinsPath, confirmedName, prunePinConfirmNames[0])
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(t.TempDir(), "old-pin")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, data)
	if _, err := f.executor.Snapshot(); !errors.Is(err, ErrUncertain) {
		t.Fatal("pin inode replacement undetected", err)
	}
}

func TestPinnedPruneExecutorRefusesAttachmentAndOverlappingRoots(t *testing.T) {
	r := purePruneRequest(t)
	id, _ := r.ID()
	root := t.TempDir()
	for _, pair := range [][2]string{{root, root}, {root, filepath.Join(root, "child")}} {
		if opened, err := CreatePinnedPruneExecutor(pair[0], pair[1], testAssignment(), r, id); !errors.Is(err, ErrRootOverlap) {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatal("overlap accepted", err)
		}
	}
	f := newPruneFixture(t)
	_ = f.executor.Close()
	newPins := filepath.Join(t.TempDir(), "new-pins")
	if opened, err := CreatePinnedPruneExecutor(f.executorPath, newPins, testAssignment(), f.request, f.id); !errors.Is(err, os.ErrExist) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("fresh pins attached to existing root", err)
	}
	if _, err := os.Lstat(newPins); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected attachment created pins", err)
	}
}

func TestPrunePositionCommitment(t *testing.T) {
	r := purePruneRequest(t)
	id, _ := r.ID()
	position := PrunePosition{Stage: PrunePrepared, HeadID: id}
	first := nextPrunePosition(position, []byte("record"))
	if first.Stage != PruneAdmitted || first.HeadID.IsZero() || first == nextPrunePosition(position, []byte("record!")) {
		t.Fatal("position did not bind transition")
	}
	encoded := pruneConfirmationBytes(id, first)
	if len(encoded) != 75 || !bytes.Equal(encoded[:10], []byte("OMCPPOSN\x00\x00")) {
		t.Fatal("pin envelope changed")
	}
	if first.HeadID.String() != "d372e454145b1d1c355d0e23a3e5c0a44383cd4662e56a870d51dd12b5e5916b" {
		t.Fatal("position vector changed", first.HeadID)
	}
}

func TestPinnedPruneExecutorRequiredSyncFailure(t *testing.T) {
	for _, part := range []string{"admission", "start", "result"} {
		for _, kind := range []string{"intent", "confirm"} {
			stage := "pins-" + part + "-" + kind
			t.Run(stage, func(t *testing.T) {
				f := newPinnedPruneFixture(t)
				f.admit(t, part != "admission")
				injected := errors.New("independent pin directory sync failed")
				armed := false
				f.executor.pins.hooks.at = func(at string) error {
					if at == stage+"-before-write" {
						armed = true
					}
					return nil
				}
				f.executor.pins.hooks.syncEntriesDirectory = func(path string) error {
					if armed {
						return injected
					}
					return syncDirectory(path)
				}
				if err := runPinnedPruneToStage(t, f, stage); !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
					t.Fatal("sync error exposed a result", err)
				}
				f.reopen(t)
				assertPinnedRecoveryStage(t, pruneSnapshot(t, f.executor), stage+"-after-publish")
				settlePinnedPruneAfterFailure(t, f)
			})
		}
	}
}

func TestPinnedPruneExecutorConfirmsStartAndHoldsAuthorityThroughFinalPin(t *testing.T) {
	f := newPinnedPruneFixture(t)
	f.admit(t, true)
	var checkedStart, checkedResult bool
	hook := func(stage string) error {
		if stage != "prune-before-effect" && stage != "pins-result-confirm-before-write" {
			return nil
		}
		if f.coordinator.mu.TryLock() {
			f.coordinator.mu.Unlock()
			t.Error("authority guard released before final confirmation")
		}
		if stage == "prune-before-effect" {
			checkedStart = true
			if f.executor.pins.position.Stage != PruneStarted || f.executor.pins.pending != nil {
				t.Error("chain called before independently confirmed start")
			}
		} else {
			checkedResult = true
			ticket, _ := f.admission.ID()
			if _, found, err := f.chain.CanonicalPruneEffect(ticket); err != nil || !found {
				t.Error("terminal pin before actual effect", err)
			}
		}
		return nil
	}
	f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); err != nil {
		t.Fatal(err)
	}
	if !checkedStart || !checkedResult || testCoordination(t, f.coordinator).Authority.Pending != 1 {
		t.Fatal("missing guarded boundary or automatic completion")
	}
}

func TestPinnedPruneExecutorResumeLifecycle(t *testing.T) {
	if err := (*PruneExecutor)(nil).ResumePinnedTransition(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	f := newPinnedPruneFixture(t)
	if err := f.executor.ResumePinnedTransition(nil); !errors.Is(err, ErrPruneRequest) {
		t.Fatal(err)
	}
	f.admit(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	f.executor.pins.hooks.at = func(stage string) error {
		if stage == "pins-admission-intent-after-apply" {
			cancel()
		}
		return nil
	}
	if err := f.executor.BindAdmission(ctx, f.coordinator, f.admission); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	before := pruneSnapshot(t, f.executor)
	if err := f.executor.ResumePinnedTransition(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if after := pruneSnapshot(t, f.executor); after.Stage != before.Stage || after.Protection.Pending == nil {
		t.Fatal("cancelled resume changed stage")
	}
	before.Protection.Pending.HeadID[0] ^= 1
	if *before.Protection.Pending == *pruneSnapshot(t, f.executor).Protection.Pending {
		t.Fatal("pending pin alias")
	}
	f.reopen(t)
	if err := f.executor.ResumePinnedTransition(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = f.executor.Close()
	if err := f.executor.ResumePinnedTransition(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func FuzzPrunePinTransitions(f *testing.F) {
	r := purePruneRequest(f)
	id, _ := r.ID()
	assignment := testAssignment()
	command := custodyauthority.Command{AssignmentID: r.AssignmentID, ExpectedHead: r.AssignmentID, Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: id}
	command, err := command.Sign(testKey(4))
	if err != nil {
		f.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		f.Fatal(err)
	}
	ticket, _ := entry.ID()
	a, _ := entry.CanonicalBytes()
	b := pruneStartedBytes(id, ticket)
	effect := workchain.CanonicalPruneEffect{Operation: workchain.CanonicalPruneOperation{AssignmentID: r.AssignmentID, TicketID: ticket, Boundary: r.Boundary}, VerifiedAt: 200,
		Report: workchain.CanonicalPruneReport{PreviousFloorID: testHash(30), FloorID: r.Boundary.Anchor.ID, RemovedNodes: 1, RetainedNodes: 1, AddedHistoryBytes: 1, ReleasedHistoryBytes: 1}}
	c, err := effect.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(a, b, c)
	f.Add(a, pruneInventoryStartedBytes(id, ticket, testHash(92)), c)
	cancellation, _ := (PruneCancellation{AssignmentID: r.AssignmentID, RequestID: id, TicketID: ticket, BindingID: testHash(91)}).CanonicalBytes()
	f.Add(a, cancellation, []byte{})
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, first, second, third []byte) {
		current := PruneExecution{RequestID: id, Request: r, Stage: PrunePrepared}
		position := PrunePosition{Stage: PrunePrepared, HeadID: id}
		for _, encoded := range [][]byte{first, second, third} {
			next, err := advancePruneExecution(assignment, current, encoded)
			if err != nil {
				return
			}
			var canonical []byte
			switch next.Stage {
			case PruneAdmitted:
				canonical, err = next.Admission.CanonicalBytes()
			case PruneStarted:
				retainedTicket, ticketErr := next.Admission.ID()
				err = ticketErr
				canonical = pruneInventoryStartedBytes(id, retainedTicket, next.ArchiveInventoryID)
			case PruneSucceeded:
				canonical, err = next.Effect.CanonicalBytes()
			case PruneCancelled:
				canonical, err = next.Cancellation.CanonicalBytes()
			}
			if err != nil || !bytes.Equal(canonical, encoded) {
				t.Fatal("noncanonical transition accepted", err)
			}
			position = nextPrunePosition(position, encoded)
			if position.HeadID.IsZero() || position.Stage != next.Stage {
				t.Fatal("invalid retained position")
			}
			current = next
		}
	})
}
