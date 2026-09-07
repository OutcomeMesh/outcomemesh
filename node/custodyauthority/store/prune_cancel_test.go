package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func cancellationStages() []string {
	var stages []string
	for _, prefix := range []string{"pins-cancel-intent", "prune-cancel", "pins-cancel-confirm"} {
		for _, stage := range appendStages {
			stages = append(stages, prefix+"-"+stage)
		}
	}
	return stages
}

func assertCancellationRecovery(t testing.TB, f *pruneFixture, stage string) {
	t.Helper()
	want, confirmed, pending := PruneAdmitted, PruneAdmitted, false
	if suffix, ok := strings.CutPrefix(stage, "pins-cancel-intent-"); ok {
		pending = isPublishedStage(suffix)
	}
	if suffix, ok := strings.CutPrefix(stage, "prune-cancel-"); ok {
		pending = true
		if isPublishedStage(suffix) {
			want = PruneCancelled
		}
	}
	if suffix, ok := strings.CutPrefix(stage, "pins-cancel-confirm-"); ok {
		want, pending = PruneCancelled, true
		if isPublishedStage(suffix) {
			confirmed, pending = PruneCancelled, false
		}
	}
	s := pruneSnapshot(t, f.executor)
	if s.Stage != want || s.Protection.Confirmed.Stage != confirmed || (s.Protection.Pending != nil) != pending || s.Effect != nil || (s.Cancellation != nil) != (want == PruneCancelled) {
		t.Fatalf("%s: stage=%d confirmed=%d pending=%v cancellation=%v", stage, s.Stage, s.Protection.Confirmed.Stage, s.Protection.Pending != nil, s.Cancellation != nil)
	}
	if s.Protection.Pending != nil && s.Protection.Pending.Stage != PruneCancelled {
		t.Fatal("pending cancellation became a start")
	}
}

func completeCancellation(t testing.TB, f *pruneFixture, c PruneCancellation) {
	t.Helper()
	id, err := c.ID()
	if err != nil {
		t.Fatal(err)
	}
	stop := f.stop(t)
	snapshot := testCoordination(t, f.coordinator).Authority
	if _, err := f.coordinator.Append(t.Context(), testEntry(t, snapshot, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)); !errors.Is(err, custodyauthority.ErrOutstanding) {
		t.Fatal("cancellation implicitly drained authority", err)
	}
	appendCoordinated(t, f.coordinator, testEntry(t, snapshot, custodyauthority.Complete, types.Hash{}, c.TicketID, id))
	appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
}

func assertNoCancellationPrune(t testing.TB, f *pruneFixture) {
	t.Helper()
	floor, err := f.chain.CanonicalFloor()
	if err != nil || floor.Pruned {
		t.Fatal("cancellation pruned chain", err)
	}
	ticket, _ := f.admission.ID()
	if _, found, err := f.chain.CanonicalPruneEffect(ticket); err != nil || found {
		t.Fatal("cancellation fabricated a prune result", err)
	}
	if s := testCoordination(t, f.coordinator); s.Authority.Pending != 1 {
		t.Fatal("cancellation completed authority")
	}
}

func settleCancellation(t testing.TB, f *pruneFixture) PruneCancellation {
	t.Helper()
	if s := pruneSnapshot(t, f.executor); s.Protection.Pending != nil {
		if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, ErrPrunePinPending) {
			t.Fatal("pending cancellation retried outside explicit resume", err)
		}
		if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("pending cancellation executed"); return 200, nil }); !errors.Is(err, ErrPrunePinPending) {
			t.Fatal(err)
		}
		if err := f.executor.ResumePinnedTransition(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	c, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator)
	if err != nil {
		t.Fatal(err)
	}
	s := pruneSnapshot(t, f.executor)
	if s.Stage != PruneCancelled || s.Protection.Confirmed.Stage != PruneCancelled || s.Protection.Pending != nil || s.Cancellation == nil || *s.Cancellation != c || s.Effect != nil {
		t.Fatal("unconfirmed or conflicting terminal cancellation")
	}
	assertNoCancellationPrune(t, f)
	return c
}

func TestPruneCancellationIsTerminalAndCompletionIsSeparate(t *testing.T) {
	for _, mode := range []string{"unbound-pinned", "storage-bound", "position-pinned"} {
		t.Run(mode, func(t *testing.T) {
			var f *pruneFixture
			switch mode {
			case "unbound-pinned":
				f = newPinnedPruneFixture(t)
			case "storage-bound":
				f = newPruneFixtureWithStorageID(t, testHash(91))
			default:
				f = newPruneFixtureWithStoragePositions(t, testHash(91), true)
			}
			f.admit(t, true)
			before, _, err := f.chain.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			c := settleCancellation(t, f)
			if c.RequestID != f.id || c.AssignmentID != f.request.AssignmentID || c.BindingID != pruneSnapshot(t, f.executor).Protection.BindingID {
				t.Fatal("cancellation lost request/pair binding")
			}
			snapshot := pruneSnapshot(t, f.executor)
			snapshot.Cancellation.BindingID[0] ^= 1
			if *pruneSnapshot(t, f.executor).Cancellation != c {
				t.Fatal("mutable cancellation escaped")
			}
			if _, err := f.executor.Execute(t.Context(), nil, nil, func() (uint64, error) { t.Error("cancelled work reauthorized"); return 200, nil }); !errors.Is(err, ErrPruneCancelled) {
				t.Fatal(err)
			}
			if _, err := f.executor.Recover(t.Context(), nil); !errors.Is(err, ErrPruneCancelled) {
				t.Fatal("cancellation treated as positive effect", err)
			}
			if after, _, err := f.chain.HistoryUsage(); err != nil || after != before {
				t.Fatal("cancellation changed chain accounting", err)
			}
			if mode == "position-pinned" {
				if p, err := f.chain.StorageProtection(); err != nil || p.Database.Sequence != 5 || p.Pending != nil {
					t.Fatal("cancellation wrote a database position", err)
				}
			}
			completeCancellation(t, f, c)
			f.reopen(t)
			retained, err := f.executor.CancelBeforeStart(t.Context(), nil)
			if err != nil || retained != c {
				t.Fatal("historical cancellation needs new authority", err)
			}
			if s := testCoordination(t, f.coordinator); s.Authority.Phase != custodyauthority.Retired || s.Authority.Pending != 0 {
				t.Fatal("historical retry changed authority")
			}
			if err := f.executor.ResumePinnedTransition(t.Context()); !errors.Is(err, ErrNoAttempt) {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneCancellationNeverInspectsDatabase(t *testing.T) {
	f := newPruneFixtureWithStoragePositions(t, testHash(91), true)
	f.admit(t, true)
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err != nil {
		t.Fatal("cancellation required an open database", err)
	}
	f.reopen(t)
	assertNoCancellationPrune(t, f)
}

func TestPruneCancellationRejectsMissingPinsAndAnyRetainedStart(t *testing.T) {
	raw := newPruneFixture(t)
	raw.admit(t, true)
	if _, err := raw.executor.CancelBeforeStart(t.Context(), raw.coordinator); !errors.Is(err, ErrPrunePin) {
		t.Fatal("raw cancellation allowed", err)
	}
	if pruneSnapshot(t, raw.executor).Stage != PruneAdmitted {
		t.Fatal("raw refusal changed stage")
	}
	for _, stage := range []string{"pins-start-intent-after-publish", "prune-before-effect", "prune-after-effect", "success"} {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, true)
			fault := errors.New("stop at execution boundary")
			hook := func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}
			f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
			_, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
			if stage == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, fault) {
				t.Fatal(err)
			}
			f.reopen(t)
			if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err == nil {
				t.Fatal("retained start cancelled")
			}
			if s := pruneSnapshot(t, f.executor); s.Protection.Pending != nil {
				if err := f.executor.ResumePinnedTransition(t.Context()); err != nil {
					t.Fatal(err)
				}
				if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("resumed start cancelled", err)
				}
			}
			if pruneSnapshot(t, f.executor).Cancellation != nil || testCoordination(t, f.coordinator).Authority.Pending != 1 {
				t.Fatal("unknown outcome converted to cancellation")
			}
		})
	}
}

func TestPruneCancellationRequiresCurrentPendingAdmission(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, ErrPruneStage) {
		t.Fatal("unadmitted work cancelled", err)
	}
	f.admit(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, err := f.executor.CancelBeforeStart(ctx, f.coordinator); err == nil {
			t.Fatal("invalid context allowed")
		}
	}
	if _, err := f.executor.CancelBeforeStart(t.Context(), nil); !errors.Is(err, ErrClosed) {
		t.Fatal("missing authority allowed", err)
	}
	ticket, _ := f.admission.ID()
	appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Complete, types.Hash{}, ticket, testHash(90)))
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal("completed ticket cancelled", err)
	}
	if pruneSnapshot(t, f.executor).Stage != PruneAdmitted {
		t.Fatal("invalid authority published cancellation")
	}
	_ = f.executor.Close()
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := (*PruneExecutor)(nil).CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestPruneCancellationFaultsRemainExactAndNeverExecute(t *testing.T) {
	for _, stage := range cancellationStages() {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, true)
			fault := errors.New("cancellation publication interrupted")
			hook := func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}
			f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
			if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, fault) {
				t.Fatal("missed fault", err)
			}
			f.reopen(t)
			assertCancellationRecovery(t, f, stage)
			f.reopen(t)
			assertCancellationRecovery(t, f, stage)
			assertNoCancellationPrune(t, f)
			c := settleCancellation(t, f)
			completeCancellation(t, f, c)
		})
	}
}

func TestPruneCancellationRacesExecutionWithoutTwoBranches(t *testing.T) {
	for range 8 {
		f := newPruneFixtureWithStorageID(t, testHash(91))
		f.admit(t, true)
		var wg sync.WaitGroup
		var authorized, applied atomic.Int32
		start := make(chan struct{})
		for i := range 16 {
			wg.Go(func() {
				<-start
				if i%2 == 0 {
					_, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator)
					if err != nil && !errors.Is(err, ErrPruneStage) && !errors.Is(err, ErrPruneOutcome) {
						t.Error(err)
					}
					return
				}
				result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { authorized.Add(1); return 200, nil })
				if err != nil && !errors.Is(err, ErrPruneCancelled) {
					t.Error(err)
				}
				if result.Applied {
					applied.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		s := pruneSnapshot(t, f.executor)
		switch s.Stage {
		case PruneCancelled:
			if authorized.Load() != 0 || applied.Load() != 0 || s.Cancellation == nil || s.Effect != nil {
				t.Fatal("cancel winner also pruned")
			}
		case PruneSucceeded:
			if authorized.Load() != 1 || applied.Load() != 1 || s.Cancellation != nil || s.Effect == nil {
				t.Fatal("execution winner also cancelled")
			}
		default:
			t.Fatal("race left a nonterminal operation")
		}
		if s.Protection.Pending != nil || s.Protection.Confirmed.Stage != s.Stage || testCoordination(t, f.coordinator).Authority.Pending != 1 {
			t.Fatal("race confirmed or completed incorrectly")
		}
	}
}

func TestPruneCancellationGuardHoldsThroughIndependentConfirmation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admit(t, true)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f.executor.pins.hooks.at = func(stage string) error {
		if stage == "pins-cancel-confirm-before-publish" {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation missed confirmation boundary")
	}
	if f.executor.mu.TryLock() {
		f.executor.mu.Unlock()
		t.Fatal("executor released before confirmation")
	}
	if f.coordinator.mu.TryLock() {
		f.coordinator.mu.Unlock()
		t.Fatal("authority released before confirmation")
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertNoCancellationPrune(t, f)
}

func TestPruneCancellationRejectsRollbackMixedHistoryAndWrongPair(t *testing.T) {
	for _, mode := range []string{"missing-record", "start-instead", "both-branches", "extra-after-terminal", "wrong-pair", "raw"} {
		t.Run(mode, func(t *testing.T) {
			var f *pruneFixture
			if mode == "raw" {
				f = newPruneFixture(t)
			} else {
				f = newPruneFixtureWithStorageID(t, testHash(91))
			}
			f.admit(t, true)
			ticket, _ := f.admission.ID()
			if mode != "raw" {
				if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err != nil {
					t.Fatal(err)
				}
			}
			_ = f.executor.Close()
			cancelPath := filepath.Join(f.executorPath, pruneRecordsName, pruneRecordName(1, PruneCancelled))
			write := func(path string, encoded []byte) {
				t.Helper()
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing-record":
				remove(cancelPath)
			case "start-instead":
				remove(cancelPath)
				write(filepath.Join(f.executorPath, pruneRecordsName, pruneRecordNames[1]), pruneStartedBytes(f.id, ticket))
			case "both-branches":
				write(filepath.Join(f.executorPath, pruneRecordsName, pruneRecordNames[1]), pruneStartedBytes(f.id, ticket))
			case "extra-after-terminal":
				write(filepath.Join(f.executorPath, pruneRecordsName, pruneRecordNames[2]), []byte{1})
			case "wrong-pair", "raw":
				c := PruneCancellation{AssignmentID: f.request.AssignmentID, RequestID: f.id, TicketID: ticket, BindingID: testHash(99)}
				encoded, _ := c.CanonicalBytes()
				write(cancelPath, encoded)
			}
			var opened *PruneExecutor
			var err error
			if mode == "raw" {
				opened, err = OpenPruneExecutor(f.executorPath, testAssignment(), f.id)
			} else {
				opened, err = OpenPinnedPruneExecutor(f.executorPath, f.executorPinsPath, testAssignment(), f.id)
			}
			if opened != nil || err == nil {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatal("invalid cancellation recovery opened")
			}
		})
	}
}

func TestPruneCancellationCodec(t *testing.T) {
	c := PruneCancellation{AssignmentID: testHash(1), RequestID: testHash(2), TicketID: testHash(3), BindingID: testHash(4)}
	encoded, err := c.CanonicalBytes()
	if err != nil || len(encoded) != MaximumPruneCancellationBytes {
		t.Fatal(err)
	}
	id, _ := c.ID()
	if id.String() != "de61c6a6e5adc1af6e6dc172e71599c6023c4a9d12470c44756fd54ccd3277c3" {
		t.Fatal("cancellation vector changed", id)
	}
	decoded, err := DecodePruneCancellation(encoded)
	if err != nil || decoded != c {
		t.Fatal("cancellation roundtrip", err)
	}
	for n := 0; n < len(encoded); n++ {
		if _, err := DecodePruneCancellation(encoded[:n]); err == nil {
			t.Fatal("truncation accepted", n)
		}
	}
	for _, offset := range []int{0, 8, 9} {
		bad := bytes.Clone(encoded)
		bad[offset] ^= 1
		if _, err := DecodePruneCancellation(bad); err == nil {
			t.Fatal("bad cancellation envelope")
		}
	}
	if _, err := DecodePruneCancellation(append(bytes.Clone(encoded), 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	for i := range 4 {
		bad := bytes.Clone(encoded)
		clear(bad[10+i*32 : 10+(i+1)*32])
		if _, err := DecodePruneCancellation(bad); err == nil {
			t.Fatal("zero binding accepted")
		}
	}
}

func FuzzDecodePruneCancellation(f *testing.F) {
	seed, _ := (PruneCancellation{AssignmentID: testHash(1), RequestID: testHash(2), TicketID: testHash(3), BindingID: testHash(4)}).CanonicalBytes()
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		c, err := DecodePruneCancellation(input)
		if err != nil {
			return
		}
		encoded, err := c.CanonicalBytes()
		if err != nil || !bytes.Equal(input, encoded) {
			t.Fatal("noncanonical cancellation accepted")
		}
		if id, err := c.ID(); err != nil || id.IsZero() {
			t.Fatal("invalid cancellation identity")
		}
	})
}

func TestPruneCancellationWaitsForConfirmedAuthorityThenDrainsStopping(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admit(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.coordinator.journal.hooks.at = func(stage string) error {
		if stage == "intent-after-apply" {
			cancel()
		}
		return nil
	}
	snapshot := testCoordination(t, f.coordinator).Authority
	stop := testEntry(t, snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(90))
	if _, err := f.coordinator.Append(ctx, stop); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal(err)
	}
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal("unconfirmed authority accepted cancellation", err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneAdmitted || s.Protection.Pending != nil {
		t.Fatal("denied cancellation retained a transition")
	}
	f.coordinator.journal.hooks = storeHooks{}
	if _, err := f.coordinator.Resume(t.Context()); err != nil {
		t.Fatal(err)
	}
	settleCancellation(t, f)
	if s := testCoordination(t, f.coordinator); s.Authority.Phase != custodyauthority.Stopping || s.Authority.Pending != 1 {
		t.Fatal("cancellation changed stopping authority")
	}
}

func TestPruneCancellationContextNeverDiscardsPublishedIntent(t *testing.T) {
	for _, stage := range []string{"pins-cancel-intent-before-write", "pins-cancel-intent-after-apply", "prune-cancel-after-apply", "pins-cancel-confirm-before-write"} {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hook := func(at string) error {
				if at == stage {
					cancel()
				}
				return nil
			}
			f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
			_, err := f.executor.CancelBeforeStart(ctx, f.coordinator)
			if strings.HasPrefix(stage, "pins-cancel-intent-") {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal("post-record cancellation abandoned confirmation", err)
			}
			f.reopen(t)
			s := pruneSnapshot(t, f.executor)
			if stage == "pins-cancel-intent-after-apply" && (s.Stage != PruneAdmitted || s.Protection.Pending == nil) {
				t.Fatal("published cancellation intent discarded")
			}
			if stage == "pins-cancel-intent-before-write" && s.Protection.Pending != nil {
				t.Fatal("unpublished intent promoted")
			}
			settleCancellation(t, f)
		})
	}
}

func TestPruneCancellationDirectorySyncErrorsStayRecoverable(t *testing.T) {
	for _, prefix := range []string{"pins-cancel-intent", "prune-cancel", "pins-cancel-confirm"} {
		t.Run(prefix, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, true)
			fault := errors.New("cancellation directory sync failure")
			hook := func(stage string) error {
				if stage == prefix+"-before-publish" {
					if prefix == "prune-cancel" {
						f.executor.hooks.syncEntriesDirectory = func(string) error { return fault }
					} else {
						f.executor.pins.hooks.syncEntriesDirectory = func(string) error { return fault }
					}
				}
				return nil
			}
			f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
			if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			f.reopen(t)
			assertCancellationRecovery(t, f, prefix+"-after-publish")
			settleCancellation(t, f)
		})
	}
}

func TestPruneCancellationResumeErrorsRetainExactBranch(t *testing.T) {
	for _, stage := range cancellationStages() {
		if strings.HasPrefix(stage, "pins-cancel-intent-") {
			continue
		}
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admit(t, true)
			fault := errors.New("pending cancellation failure")
			f.executor.hooks.at = func(at string) error {
				if at == "prune-cancel-before-write" {
					return fault
				}
				return nil
			}
			if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			f.reopen(t)
			hook := func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}
			f.executor.hooks.at, f.executor.pins.hooks.at = hook, hook
			if err := f.executor.ResumePinnedTransition(t.Context()); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			f.reopen(t)
			assertCancellationRecovery(t, f, stage)
			settleCancellation(t, f)
		})
	}
}
