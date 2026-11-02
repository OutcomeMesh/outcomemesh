package store

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestPruneScheduledEffectServiceRejectsIncompletePlacement(t *testing.T) {
	f := newScheduledPruneFixture(t)
	c := f.runtimeConfig(t)
	for _, mode := range []string{"authority-count", "source-count", "duplicate-authority", "duplicate-source", "unknown-source", "root-overlap", "missing-migration", "wrong-inventory", "missing-base", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			bad := c
			bad.Authorities = append([]PruneArchiveAuthorityRoots(nil), c.Authorities...)
			bad.Sources = append([]ScheduledPruneSource(nil), c.Sources...)
			ctx := t.Context()
			switch mode {
			case "authority-count":
				bad.Authorities = bad.Authorities[:1]
			case "source-count":
				bad.Sources = bad.Sources[:1]
			case "duplicate-authority":
				bad.Authorities[1] = bad.Authorities[0]
			case "duplicate-source":
				bad.Sources[1] = bad.Sources[0]
			case "unknown-source":
				bad.Sources[0].AssignmentID = testHash(222)
			case "root-overlap":
				bad.Sources[0].JournalPath = bad.ExecutorPinsPath
			case "missing-migration":
				bad.StorageMigrationID = types.Hash{}
			case "wrong-inventory":
				bad.InventoryID = testHash(223)
			case "missing-base":
				bad.Base.State = nil
			case "nil-context":
				ctx = nil
			}
			s, err := OpenScheduledPruneEffectService(ctx, bad)
			if s != nil {
				s.Close()
			}
			if err == nil {
				t.Fatal("incomplete placement accepted")
			}
			cold := openScheduledEffect(t, c)
			if scheduledEffectReview(t, cold).Executor.Stage != PruneAdmitted {
				t.Fatal("invalid placement changed original history")
			}
			if err := cold.Close(); err != nil {
				t.Fatal("partial opening leaked owners", err)
			}
		})
	}
}

func openScheduledEffect(t testing.TB, c ScheduledPruneRuntimeConfig) *ScheduledPruneEffectService {
	t.Helper()
	s, err := OpenScheduledPruneEffectService(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func scheduledEffectReview(t testing.TB, s *ScheduledPruneEffectService) ScheduledPruneReview {
	t.Helper()
	r, err := s.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assertScheduledEffectBusy(t testing.TB, f *scheduledPruneFixture, c ScheduledPruneRuntimeConfig) {
	t.Helper()
	rid, _ := f.inventory.Request.ID()
	primary := f.inventory.Replicas[0].Assignment
	for _, r := range f.inventory.Replicas {
		if id, _ := r.Assignment.ID(); id == f.inventory.Request.AssignmentID {
			primary = r.Assignment
		}
	}
	if e, err := OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, primary, rid); !errors.Is(err, ErrBusy) {
		if e != nil {
			e.Close()
		}
		t.Fatal("executor ownership escaped", err)
	}
	for _, r := range f.inventory.Replicas {
		id, _ := r.Assignment.ID()
		for _, root := range c.Authorities {
			if root.AssignmentID != id {
				continue
			}
			if owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, r.Assignment, id); !errors.Is(err, ErrBusy) {
				if owner != nil {
					owner.Close()
				}
				t.Fatal("authority ownership escaped", err)
			}
		}
		for _, source := range c.Sources {
			if source.AssignmentID != id {
				continue
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			_, _, err := workarchive.OpenScheduledCustodyJournal(ctx, source.JournalPath, r.Proof, r.Assignment, f.inventory.OriginalPolicy, source.CustodyPolicy, source.JournalLimits)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("custody writer acquired a live service journal", err)
			}
		}
	}
	chain, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(c.ChainPath, c.ChainPinsPath, c.Base, c.Parameters, c.StoragePolicy, f.inventory.Request.StorageID, c.StorageMigrationID)
	if chain != nil {
		chain.Close()
	}
	if !errors.Is(err, workchain.ErrStoragePinBusy) {
		t.Fatal("protected chain ownership escaped", err)
	}
}

func TestPruneScheduledEffectServiceOwnsBothExecutionModes(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "fenced"}[fenced], func(t *testing.T) {
			var f *scheduledPruneFixture
			if fenced {
				f = newScheduledPruneFixture(t, pruneFencePolicy())
			} else {
				f = newScheduledPruneFixture(t)
			}
			c := f.runtimeConfig(t)
			if fenced {
				w := newPruneWitnessFixture(t, f.inventory)
				c.CollectPruneClaim = w.collect
			}
			oneShot, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
			if err != nil {
				t.Fatal(err)
			}
			s := openScheduledEffect(t, c)
			before := scheduledEffectReview(t, s)
			if !reflect.DeepEqual(before, oneShot.Review) {
				t.Fatal("one-shot and held review differ")
			}
			assertScheduledEffectBusy(t, f, c)
			result, err := s.Execute(t.Context(), before.ReviewID)
			if err != nil || result.Commit == nil || !result.Commit.Applied || (result.FenceResult != nil) != fenced {
				t.Fatal("actual execution", err)
			}
			assertScheduledEffectBusy(t, f, c)
			after := scheduledEffectReview(t, s)
			if !reflect.DeepEqual(before.Authorities, after.Authorities) || !reflect.DeepEqual(before.Journals, after.Journals) {
				t.Fatal("execution released an obligation or rewrote retention")
			}
			if after.Executor.Stage != PruneSucceeded || after.Storage.Confirmed.Sequence != before.Storage.Confirmed.Sequence+1 {
				t.Fatal("wrong durable effect")
			}
			if _, err := s.Execute(t.Context(), before.ReviewID); !errors.Is(err, ErrPruneArchiveEffectReview) {
				t.Fatal("stale review repeated execution", err)
			}
			recovered, err := s.Recover(t.Context(), after.ReviewID)
			if err != nil || recovered.Commit.Applied || !reflect.DeepEqual(result.Commit.Effect, recovered.Commit.Effect) {
				t.Fatal("retained result recovery", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Review(t.Context()); !errors.Is(err, ErrClosed) {
				t.Fatal("closed service reused", err)
			}
			cold := openScheduledEffect(t, c)
			if !reflect.DeepEqual(after, scheduledEffectReview(t, cold)) {
				t.Fatal("cold open changed original state")
			}
		})
	}
}

func TestPruneScheduledEffectServiceDetachesConfigurationAndReview(t *testing.T) {
	f := newScheduledPruneFixture(t)
	c := f.runtimeConfig(t)
	s := openScheduledEffect(t, c)
	want := scheduledEffectReview(t, s)
	r := scheduledEffectReview(t, s)
	c.Authorities[0].AuthorityPath = "changed"
	c.Sources[0].JournalPath = "changed"
	c.Sources[0].CustodyPolicy.TrustedAuditors[0] = testPublic(201)
	c.Base.RecentTimestamps[0]++
	c.Base.Tip.CumulativeWork[0]++
	r.Executor.Request.Boundary.BaseID = testHash(202)
	r.Executor.Protection.Confirmed.HeadID = testHash(203)
	r.Authorities[0].Authority.Operations[0].OperationID = testHash(204)
	r.Journals[0].CurrentReceipt.Signature[0]++
	if got := scheduledEffectReview(t, s); !reflect.DeepEqual(got, want) {
		t.Fatal("caller mutation changed service scope or owners")
	}
	result, err := s.Execute(t.Context(), want.ReviewID)
	if err != nil || result.Commit == nil || !result.Commit.Applied {
		t.Fatal("detached original scope failed", err)
	}
}

func TestPruneScheduledEffectServicePartialOpenReleasesOwners(t *testing.T) {
	for _, stage := range []string{"authority", "chain", "journal", "cancelled-after-open"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneFixture(t)
			c := f.runtimeConfig(t)
			var heldClose func() error
			var heldCheck func() error
			expected := ErrBusy
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hooks := storeHooks{}
			switch stage {
			case "authority":
				r := c.Authorities[0]
				for _, v := range c.Authorities {
					if types.CompareHash(v.AssignmentID, r.AssignmentID) > 0 {
						r = v
					}
				}
				for _, v := range f.inventory.Replicas {
					if id, _ := v.Assignment.ID(); id == r.AssignmentID {
						o, err := OpenCoordinator(r.AuthorityPath, r.AuthorityPinsPath, v.Assignment, r.AssignmentID)
						if err != nil {
							t.Fatal(err)
						}
						heldClose = o.Close
						heldCheck = func() error { _, err := o.Snapshot(); return err }
					}
				}
			case "chain":
				o, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(c.ChainPath, c.ChainPinsPath, c.Base, c.Parameters, c.StoragePolicy, f.inventory.Request.StorageID, c.StorageMigrationID)
				if err != nil {
					t.Fatal(err)
				}
				heldClose = o.Close
				heldCheck = func() error { _, err := o.StorageProtection(); return err }
				expected = workchain.ErrStoragePinBusy
			case "journal":
				r := c.Sources[0]
				for _, v := range c.Sources {
					if types.CompareHash(v.AssignmentID, r.AssignmentID) > 0 {
						r = v
					}
				}
				for _, v := range f.inventory.Replicas {
					if id, _ := v.Assignment.ID(); id == r.AssignmentID {
						j, _, err := workarchive.OpenScheduledCustodyJournal(t.Context(), r.JournalPath, v.Proof, v.Assignment, f.inventory.OriginalPolicy, r.CustodyPolicy, r.JournalLimits)
						if err != nil {
							t.Fatal(err)
						}
						d, err := j.AcquireDecision()
						if err != nil {
							t.Fatal(err)
						}
						heldClose = d.Close
						heldCheck = d.CheckAccess
					}
				}
				expected = workarchive.ErrCustodyJournalBusy
			case "cancelled-after-open":
				hooks.at = func(at string) error {
					if at == "scheduled-runtime-opened" {
						cancel()
					}
					return nil
				}
				expected = context.Canceled
			}
			if heldClose != nil {
				defer heldClose()
			}
			s, err := openScheduledPruneEffectService(ctx, c, hooks)
			if s != nil || !errors.Is(err, expected) {
				if s != nil {
					s.Close()
				}
				t.Fatal("partial acquisition was accepted", err)
			}
			// Cleanup must not release or invalidate the owner acquired by someone else.
			if heldCheck != nil {
				if err := heldCheck(); err != nil {
					t.Fatal("foreign owner changed", err)
				}
			}
			if heldClose != nil {
				if err := heldClose(); err != nil {
					t.Fatal(err)
				}
			}
			reopened := openScheduledEffect(t, c)
			if scheduledEffectReview(t, reopened).Executor.Stage != PruneAdmitted {
				t.Fatal("opening changed execution stage")
			}
		})
	}
}

func TestPruneScheduledEffectServiceRejectsChangedInputsWithoutStarting(t *testing.T) {
	for _, change := range []string{"zero-review", "wrong-review", "inventory", "archive", "journal-root", "cancelled", "nil-context"} {
		t.Run(change, func(t *testing.T) {
			f := newScheduledPruneFixture(t)
			c := f.runtimeConfig(t)
			s := openScheduledEffect(t, c)
			r := scheduledEffectReview(t, s)
			id := r.ReviewID
			ctx := t.Context()
			switch change {
			case "zero-review":
				id = types.Hash{}
			case "wrong-review":
				id = testHash(210)
			case "inventory":
				writeTestFile(t, c.InventoryPath, []byte("changed"))
			case "archive":
				if err := os.Rename(c.Sources[0].Directory, c.Sources[0].Directory+".held"); err != nil {
					t.Fatal(err)
				}
			case "journal-root":
				if err := os.Rename(c.Sources[0].JournalPath, c.Sources[0].JournalPath+".held"); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			if result, err := s.Execute(ctx, id); err == nil || result.Commit != nil {
				t.Fatal("changed scope executed", err)
			}
			if state := pruneSnapshot(t, s.executor); state.Stage != PruneAdmitted || state.Protection.Pending != nil {
				t.Fatal("rejection started execution")
			}
			storage, err := s.chain.StorageProtection()
			if err != nil || !reflect.DeepEqual(storage, r.Storage) {
				t.Fatal("rejection changed storage", err)
			}
		})
	}
}

func TestPruneScheduledEffectServiceConcurrentExecutionAndDrain(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(map[bool]string{false: "duplicate", true: "close"}[closing], func(t *testing.T) {
			f := newScheduledPruneFixture(t, pruneFencePolicy())
			w := newPruneWitnessFixture(t, f.inventory)
			c := f.runtimeConfig(t)
			c.CollectPruneClaim = w.collect
			s := openScheduledEffect(t, c)
			r := scheduledEffectReview(t, s)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			s.executor.hooks.at = func(at string) error {
				if at == "scheduled-prune-before-verification" {
					close(entered)
					<-release
				}
				return nil
			}
			done := make(chan error, 1)
			go func() {
				v, e := s.Execute(t.Context(), r.ReviewID)
				if e == nil && (v.Commit == nil || !v.Commit.Applied) {
					e = errors.New("no actual effect")
				}
				done <- e
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("effect did not acquire guards")
			}
			queued, other := make(chan struct{}), make(chan error, 1)
			go func() {
				close(queued)
				if closing {
					other <- s.Close()
				} else {
					_, err := s.Execute(t.Context(), r.ReviewID)
					other <- err
				}
			}()
			<-queued
			select {
			case err := <-other:
				t.Fatal("concurrent call escaped active action", err)
			case <-time.After(30 * time.Millisecond):
			}
			assertScheduledEffectBusy(t, f, c)
			once.Do(func() { close(release) })
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("effect did not drain")
			}
			select {
			case err := <-other:
				if closing && err != nil || !closing && !errors.Is(err, ErrPruneArchiveEffectReview) {
					t.Fatal("wrong queued outcome", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("queued action did not drain")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			cold := openScheduledEffect(t, c)
			after := scheduledEffectReview(t, cold)
			if after.Storage.Confirmed.Sequence != r.Storage.Confirmed.Sequence+1 || !reflect.DeepEqual(after.Authorities, r.Authorities) {
				t.Fatal("duplicate effect or changed obligations")
			}
		})
	}
}

func TestPruneScheduledEffectServiceRetainsUncertainWrites(t *testing.T) {
	f := newScheduledPruneFixture(t)
	c := f.runtimeConfig(t)
	fault := errors.New("confirmation unavailable")
	s, err := openScheduledPruneEffectService(t.Context(), c, storeHooks{at: func(at string) error {
		if at == "pins-start-intent-after-publish" {
			return fault
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := scheduledEffectReview(t, s)
	if _, err = s.Execute(t.Context(), r.ReviewID); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) {
		t.Fatal("failed publication not retained", err)
	}
	if _, err = s.Review(t.Context()); !errors.Is(err, ErrUncertain) {
		t.Fatal("live failure cleared", err)
	}
	retainedError := err.Error()
	for range 16 {
		if _, err := s.Review(t.Context()); err == nil || err.Error() != retainedError {
			t.Fatal("failed retry changed or expanded the retained error", err)
		}
	}
	assertScheduledEffectBusy(t, f, c)
	if err = s.Close(); !errors.Is(err, ErrUncertain) {
		t.Fatal("close erased uncertainty", err)
	}
	cold := openScheduledEffect(t, c)
	after := scheduledEffectReview(t, cold)
	if after.Executor.Protection.Pending == nil || !reflect.DeepEqual(after.Authorities, r.Authorities) {
		t.Fatal("reopen resumed pending work")
	}
	if _, err = cold.Execute(t.Context(), after.ReviewID); err == nil {
		t.Fatal("pending work executed")
	}
}
