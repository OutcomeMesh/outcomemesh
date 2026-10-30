package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func (f *scheduledPruneFixture) runtimeConfig(t testing.TB) ScheduledPruneRuntimeConfig {
	t.Helper()
	p := f.archive.f
	c := ScheduledPruneRuntimeConfig{InventoryPath: f.path, InventoryID: f.id, StorageMigrationID: f.migrationID, ExecutorPath: f.executor.path, ExecutorPinsPath: f.executor.pins.path, ChainPath: p.chainPath, ChainPinsPath: p.chainPositionPinsPath, Sources: f.sources, Base: p.base, Parameters: p.parameters, StoragePolicy: p.policy, Limits: workarchive.DefaultLimits()}
	for _, op := range f.operations {
		c.Authorities = append(c.Authorities, PruneArchiveAuthorityRoots{AssignmentID: op.Binding.AssignmentID, AuthorityPath: op.Coordinator.authority.path, AuthorityPinsPath: op.Coordinator.journal.path})
		if err := op.Coordinator.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.executor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.chain.Close(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCustodyScheduledPruneOwnedReviewExecuteRecover(t *testing.T) {
	f := newScheduledPruneFixture(t)
	c := f.runtimeConfig(t)
	review, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	again, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
	if err != nil || !reflect.DeepEqual(review, again) {
		t.Fatal("review changed original owners", err)
	}
	for _, bad := range []types.Hash{{}, testHash(174)} {
		if _, err := RunScheduledPrune(t.Context(), c, "execute", bad); err == nil {
			t.Fatal("unreviewed deletion")
		}
	}
	changed := c
	changed.Limits.MaximumBytes--
	if _, err := RunScheduledPrune(t.Context(), changed, "execute", review.Review.ReviewID); err == nil {
		t.Fatal("changed policy used old review")
	}
	result, err := RunScheduledPrune(t.Context(), c, "execute", review.Review.ReviewID)
	if err != nil || result.Commit == nil || !result.Commit.Applied {
		t.Fatal("owned execution", err)
	}
	if _, err := RunScheduledPrune(t.Context(), c, "execute", review.Review.ReviewID); err == nil {
		t.Fatal("stale review executed twice")
	}
	recovery, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(recovery.Review.Authorities, review.Review.Authorities) == false {
		t.Fatal("deletion completed authority work")
	}
	recovered, err := RunScheduledPrune(t.Context(), c, "recover", recovery.Review.ReviewID)
	if err != nil || recovered.Commit.Applied || !reflect.DeepEqual(result.Commit.Effect, recovered.Commit.Effect) {
		t.Fatal("recovery did not retain exact effect", err)
	}
}

func TestCustodyScheduledPruneRejectsBeforeStarting(t *testing.T) {
	for _, name := range []string{"source-count", "source-duplicate", "journal-copy-empty", "old-directory", "missing-archive", "overlap", "operation-scope", "operation-ticket", "inventory-id", "missing-inventory", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newScheduledPruneFixture(t)
			before := pruneSnapshot(t, f.executor)
			storage, _ := f.archive.f.chain.StorageProtection()
			ctx := t.Context()
			switch name {
			case "source-count":
				f.sources = f.sources[:1]
			case "source-duplicate":
				f.sources[1] = f.sources[0]
			case "journal-copy-empty":
				f.sources[0].JournalPath = t.TempDir()
			case "old-directory":
				f.sources[0].Directory = f.archive.replicas[0].Directory
			case "missing-archive":
				f.sources[0].Directory = t.TempDir()
			case "overlap":
				f.sources[0].Directory = f.sources[0].JournalPath
			case "operation-scope":
				f.operations[1].Binding.ScheduleID = testHash(176)
			case "operation-ticket":
				f.operations[1].Binding.TicketID = testHash(177)
			case "inventory-id":
				f.id = testHash(178)
			case "missing-inventory":
				f.path = filepath.Join(t.TempDir(), "missing")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := f.execute(ctx); err == nil {
				t.Fatal("invalid source accepted")
			}
			if !reflect.DeepEqual(before, pruneSnapshot(t, f.executor)) {
				t.Fatal("rejection consumed executor stage")
			}
			after, _ := f.archive.f.chain.StorageProtection()
			if !reflect.DeepEqual(storage, after) {
				t.Fatal("rejection changed storage")
			}
		})
	}
}

func TestCustodyScheduledPruneInterruptedOutcomeCannotRepeat(t *testing.T) {
	for _, stage := range []string{"scheduled-prune-before-start", "prune-before-effect", "prune-after-effect", "prune-result-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneFixture(t)
			fault := errors.New("scheduled prune interrupted")
			hit := false
			f.executor.hooks.at = func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}
			if _, err := f.execute(t.Context()); !hit || !errors.Is(err, fault) {
				t.Fatal("fault not reached", err)
			}
			path, pins := f.executor.path, f.executor.pins.path
			f.executor.Close()
			rid, _ := f.inventory.Request.ID()
			var err error
			f.executor, err = OpenPinnedPruneExecutor(path, pins, f.inventory.Replicas[0].Assignment, rid)
			if err != nil {
				t.Fatal(err)
			}
			state := pruneSnapshot(t, f.executor)
			effect, found, err := f.archive.f.chain.CanonicalPruneEffect(f.operations[0].Binding.TicketID)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "scheduled-prune-before-start" {
				if state.Stage != PruneAdmitted || found {
					t.Fatal("pre-start failure consumed attempt")
				}
				if _, err := f.execute(t.Context()); err != nil {
					t.Fatal(err)
				}
				return
			}
			if _, err := f.execute(t.Context()); err == nil {
				t.Fatal("uncertain operation repeated")
			}
			if stage == "prune-before-effect" {
				if found || state.Stage != PruneStarted {
					t.Fatal("invented outcome")
				}
				if _, err := f.executor.Recover(t.Context(), f.archive.f.chain); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("absent effect released work", err)
				}
			} else if state.Protection.Pending == nil {
				recovered, err := f.executor.Recover(t.Context(), f.archive.f.chain)
				if !found || err != nil || recovered.Applied || !reflect.DeepEqual(effect, recovered.Effect) {
					t.Fatal("matching effect recovery", err)
				}
			}
			for _, op := range f.operations {
				if testCoordination(t, op.Coordinator).Authority.Pending != 2 {
					t.Fatal("interruption reset old and new pending work")
				}
			}
		})
	}
}

func TestCustodyScheduledPruneStorageRollbackRejected(t *testing.T) {
	f := newScheduledPruneFixture(t)
	p := f.archive.f
	if err := p.chain.Close(); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(t.TempDir(), "old-storage")
	if err := os.CopyFS(old, os.DirFS(p.chainPath)); err != nil {
		t.Fatal(err)
	}
	var err error
	p.chain, err = workchain.OpenRadixMigratedPositionPinnedWithPolicy(p.chainPath, p.chainPositionPinsPath, p.base, p.parameters, p.policy, p.request.StorageID, f.migrationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.execute(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := p.chain.Close(); err != nil {
		t.Fatal(err)
	}
	copy, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(old, p.chainPositionPinsPath, p.base, p.parameters, p.policy, p.request.StorageID, f.migrationID)
	if err == nil {
		copy.Close()
		t.Fatal("old storage accepted advanced independent pins")
	}
}
