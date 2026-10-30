package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func scheduledOutcomeFixture(t testing.TB, stage string) (*scheduledPruneFixture, []ScheduledPruneCommandConfig) {
	t.Helper()
	f := newScheduledPruneFixture(t)
	if stage != "admitted" {
		fault := errors.New("stop scheduled execution")
		hit := false
		f.executor.hooks.at = func(at string) error {
			if at == stage {
				hit = true
				return fault
			}
			return nil
		}
		_, err := f.execute(t.Context())
		if stage == "success" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !hit || !errors.Is(err, fault) {
			t.Fatal("fault not reached", stage, err)
		}
	}
	p := planFromInventory(f.inventory)
	id, _ := p.ID()
	path := filepath.Join(t.TempDir(), "plan")
	if err := SaveScheduledPrunePlan(t.Context(), path, p, id); err != nil {
		t.Fatal(err)
	}
	var configs []ScheduledPruneCommandConfig
	for _, op := range f.operations {
		configs = append(configs, ScheduledPruneCommandConfig{PlanPath: path, PlanID: id, AssignmentID: op.Binding.AssignmentID, AuthorityPath: op.Coordinator.authority.path, AuthorityPinsPath: op.Coordinator.journal.path, ExecutorPath: f.executor.path, ExecutorPinsPath: f.executor.pins.path, InventoryPath: f.path, InventoryID: f.id})
	}
	runtime := f.runtimeConfig(t)
	configs[0].Storage = &PruneRecoveryStorage{ChainPath: runtime.ChainPath, ChainPinsPath: runtime.ChainPinsPath, MigrationID: runtime.StorageMigrationID, Base: runtime.Base, Parameters: runtime.Parameters, Policy: runtime.StoragePolicy}
	return f, configs
}

func scheduledOutcomeCompletion(t testing.TB, c ScheduledPruneCommandConfig) ScheduledPruneCommandConfig {
	t.Helper()
	c.Storage = nil
	r := scheduledOperatorReview(t, c)
	p, err := LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	v, err := LoadScheduledPruneInventory(c.InventoryPath, c.InventoryID)
	if err != nil {
		t.Fatal(err)
	}
	o, err := RetainedScheduledPruneOutcome(v, r.Executor)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := BuildScheduledPruneOutcomeCompletion(p, v, o, c.AssignmentID, r.Review.Authority.Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	entry := managedCommandApplyTestSign(t, draft)
	c.EntryID, _ = entry.ID()
	c.EntryPath = filepath.Join(t.TempDir(), "completion")
	raw, _ := entry.CanonicalBytes()
	writeTestFile(t, c.EntryPath, raw)
	return c
}

func TestPruneScheduledCancellationDrainsOnlySelectedTicket(t *testing.T) {
	f, configs := scheduledOutcomeFixture(t, "admitted")
	c := configs[0]
	c.Storage = nil
	before := scheduledOperatorReview(t, c)
	// Cancellation and completion must work with source archives and journals offline.
	for _, source := range f.sources {
		for _, path := range []string{source.Directory, source.JournalPath} {
			if err := os.Rename(path, path+".offline"); err != nil {
				t.Fatal(err)
			}
		}
	}
	result, err := RunScheduledPruneCommand(t.Context(), c, "cancel-before-start", before.Review.ReviewID)
	if err != nil || result.Executor.Stage != PruneCancelled {
		t.Fatal("cancel", err)
	}
	terminal := scheduledOperatorReview(t, c)
	if !reflect.DeepEqual(before.Review.Authority, terminal.Review.Authority) {
		t.Fatal("cancellation completed work")
	}
	o, err := RetainedScheduledPruneOutcome(f.inventory, terminal.Executor)
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"request", "ticket", "binding", "assignment", "ambiguous", "empty"} {
		bad := o
		cp := *o.Cancellation
		bad.Cancellation = &cp
		switch which {
		case "request":
			cp.RequestID = testHash(241)
		case "ticket":
			cp.TicketID = testHash(241)
		case "binding":
			cp.BindingID = testHash(241)
		case "assignment":
			cp.AssignmentID = testHash(241)
		case "ambiguous":
			bad.Effect = before.Executor.Effect
			if bad.Effect == nil {
				bad.Effect = &workchain.CanonicalPruneEffect{}
			}
		case "empty":
			bad.Cancellation = nil
		}
		if _, err := bad.EvidenceID(f.inventory); err == nil {
			t.Fatal("accepted substituted", which)
		}
	}
	for i, original := range configs {
		complete := scheduledOutcomeCompletion(t, original)
		old := scheduledOperatorReview(t, complete).Review.Authority.Authority
		done := scheduledOperatorApply(t, complete)
		if done.Commit == nil || done.Commit.Snapshot.Pending != old.Pending-1 || len(done.Commit.Snapshot.Operations) != len(old.Operations) {
			t.Fatal("changed unrelated accounting")
		}
		ticket := f.operations[i].Binding.TicketID
		for _, op := range old.Operations {
			if op.TicketID == ticket {
				continue
			}
			found := false
			for _, retained := range done.Commit.Snapshot.Operations {
				if reflect.DeepEqual(op, retained) {
					found = true
				}
			}
			if !found {
				t.Fatal("unrelated obligation changed")
			}
		}
		if i == 0 && scheduledOperatorReview(t, configs[1]).Review.Authority.Authority.Pending != 2 {
			t.Fatal("completed other replica")
		}
		again := scheduledOperatorApply(t, complete)
		if again.Commit.Appended || !reflect.DeepEqual(done.Commit.Snapshot, again.Commit.Snapshot) {
			t.Fatal("completion repeated")
		}
	}
}

func TestPruneScheduledCancellationCrashRecovery(t *testing.T) {
	for _, stage := range []string{"pins-cancel-intent-after-publish", "prune-cancel-after-publish", "pins-cancel-confirm-before-publish", "pins-cancel-confirm-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := scheduledOutcomeFixture(t, "admitted")
			c := configs[0]
			c.Storage = nil
			before := scheduledOperatorReview(t, c)
			fault := errors.New("cancellation interrupted")
			hit := false
			_, err := runScheduledPruneCommand(t.Context(), c, "cancel-before-start", before.Review.ReviewID, storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}})
			if !hit || !errors.Is(err, fault) {
				t.Fatal("fault not reached", err)
			}
			cold := scheduledOperatorReview(t, c)
			if !reflect.DeepEqual(cold, scheduledOperatorReview(t, c)) {
				t.Fatal("review changed retained attempt")
			}
			if !reflect.DeepEqual(before.Review.Authority, cold.Review.Authority) {
				t.Fatal("cancellation reset obligations")
			}
			if cold.Executor.Protection.Pending != nil {
				if _, err := RunScheduledPruneCommand(t.Context(), c, "cancel-before-start", cold.Review.ReviewID); err == nil {
					t.Fatal("implicitly resumed")
				}
				if _, err := RunScheduledPruneCommand(t.Context(), c, "resume-executor", cold.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
			}
			stable := scheduledOperatorReview(t, c)
			if stable.Executor.Stage != PruneCancelled || stable.Executor.Protection.Pending != nil {
				t.Fatal("lost cancellation")
			}
			r, err := RunScheduledPruneCommand(t.Context(), c, "cancel-before-start", stable.Review.ReviewID)
			if err != nil || !reflect.DeepEqual(stable.Executor, r.Executor) {
				t.Fatal("retry changed outcome", err)
			}
		})
	}
}

func TestPruneScheduledRecoveryReadsOriginalEffectWithSourcesOffline(t *testing.T) {
	for _, stage := range []string{"prune-before-effect", "prune-after-effect", "success"} {
		t.Run(stage, func(t *testing.T) {
			f, configs := scheduledOutcomeFixture(t, stage)
			c := configs[0]
			for _, s := range f.sources {
				for _, p := range []string{s.Directory, s.JournalPath} {
					if err := os.Rename(p, p+".offline"); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := scheduledOperatorReview(t, c)
			cancel := c
			cancel.Storage = nil
			cr := scheduledOperatorReview(t, cancel)
			if _, err := RunScheduledPruneCommand(t.Context(), cancel, "cancel-before-start", cr.Review.ReviewID); err == nil {
				t.Fatal("cancelled retained start")
			}
			result, err := RunScheduledPruneCommand(t.Context(), c, "recover-effect", before.Review.ReviewID)
			if stage == "prune-before-effect" {
				if !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("missing effect released work", err)
				}
				if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
					t.Fatal("unknown outcome changed")
				}
				return
			}
			if err != nil || result.Recovered == nil || result.Recovered.Applied || result.Executor.Stage != PruneSucceeded {
				t.Fatal("recovery", err)
			}
			after := scheduledOperatorReview(t, c)
			if !reflect.DeepEqual(before.Review.Storage, after.Review.Storage) || !reflect.DeepEqual(before.Review.Authority, after.Review.Authority) {
				t.Fatal("recovery changed storage or accounting")
			}
			for _, replica := range configs {
				scheduledOperatorApply(t, scheduledOutcomeCompletion(t, replica))
			}
		})
	}
}

func TestPruneScheduledOutcomeRejectsWrongOwnersAndReviews(t *testing.T) {
	_, configs := scheduledOutcomeFixture(t, "prune-after-effect")
	c := configs[0]
	before := scheduledOperatorReview(t, c)
	for _, name := range []string{"review", "migration", "schedule", "storage-pins", "inventory", "owner", "secondary", "overlap", "policy", "context"} {
		t.Run(name, func(t *testing.T) {
			bad := c
			s := *c.Storage
			bad.Storage = &s
			expected := before.Review.ReviewID
			ctx := t.Context()
			switch name {
			case "review":
				expected = testHash(244)
			case "migration":
				s.MigrationID = testHash(244)
			case "schedule":
				s.Parameters.RadixActivationHeight++
			case "storage-pins":
				s.ChainPinsPath = t.TempDir()
			case "inventory":
				bad.InventoryID = testHash(244)
			case "owner":
				bad.AuthorityPath, bad.AuthorityPinsPath = configs[1].AuthorityPath, configs[1].AuthorityPinsPath
			case "secondary":
				bad = configs[1]
				bad.Storage = &s
			case "overlap":
				s.ChainPinsPath = c.ExecutorPinsPath
			case "policy":
				s.Policy.MaxHistoryBytes--
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := RunScheduledPruneCommand(ctx, bad, "recover-effect", expected); err == nil {
				t.Fatal("accepted", name)
			}
			if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("rejection changed original owners")
			}
		})
	}
}

func TestPruneScheduledCompletionRejectsFabricatedCancellation(t *testing.T) {
	f, configs := scheduledOutcomeFixture(t, "admitted")
	c := configs[1]
	before := scheduledOperatorReview(t, c)
	primary, _ := scheduledPrunePrimary(f.inventory)
	tid, _ := primary.ID()
	rid, _ := f.inventory.Request.ID()
	fake := PruneCancellation{AssignmentID: f.inventory.Request.AssignmentID, RequestID: rid, TicketID: tid, BindingID: f.inventory.ExecutorBindingID}
	// Static signatures cannot establish that this cancellation was retained.
	draft, err := BuildScheduledPruneOutcomeCompletion(planFromInventory(f.inventory), f.inventory, ScheduledPruneOutcome{Cancellation: &fake}, c.AssignmentID, before.Review.Authority.Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	entry := managedCommandApplyTestSign(t, draft)
	c.EntryID, _ = entry.ID()
	c.EntryPath = filepath.Join(t.TempDir(), "fabricated")
	raw, _ := entry.CanonicalBytes()
	writeTestFile(t, c.EntryPath, raw)
	if _, err := RunScheduledPruneCommand(t.Context(), c, "review", types.Hash{}); !errors.Is(err, ErrPruneOutcome) {
		t.Fatal("fabricated cancellation accepted", err)
	}
	if !reflect.DeepEqual(before, scheduledOperatorReview(t, configs[1])) {
		t.Fatal("fabricated evidence changed accounting")
	}
}

func TestPruneScheduledCancellationRejectsSecondaryAndStaleReview(t *testing.T) {
	_, configs := scheduledOutcomeFixture(t, "admitted")
	for i, c := range configs {
		c.Storage = nil
		before := scheduledOperatorReview(t, c)
		expected := before.Review.ReviewID
		if i == 0 {
			expected = testHash(245)
		}
		if _, err := RunScheduledPruneCommand(t.Context(), c, "cancel-before-start", expected); err == nil {
			t.Fatal("secondary or stale decision cancelled work")
		}
		if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
			t.Fatal("rejection changed accounting")
		}
	}
}

func TestPruneScheduledRecoveryRequiresConfirmedStoragePosition(t *testing.T) {
	_, configs := scheduledOutcomeFixture(t, "prune-after-effect")
	c := configs[0]
	before := scheduledOperatorReview(t, c)
	s := c.Storage
	directory := filepath.Join(s.ChainPinsPath, "confirmed")
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 {
		t.Fatal("missing position history", err)
	}
	last := filepath.Join(directory, entries[len(entries)-1].Name())
	retained := filepath.Join(t.TempDir(), "last-confirmation")
	if err := os.Rename(last, retained); err != nil {
		t.Fatal(err)
	}
	// Model a committed database batch whose independent confirmation was lost.
	chain, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(s.ChainPath, s.ChainPinsPath, s.Base, s.Parameters, s.Policy, before.Executor.Request.StorageID, s.MigrationID)
	if err != nil {
		t.Fatal(err)
	}
	position, err := chain.StorageProtection()
	if err != nil || position.Pending == nil || position.Database != *position.Pending {
		t.Fatal("fixture did not retain a confirmation gap", err)
	}
	if err := chain.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := RunScheduledPruneCommand(t.Context(), c, "recover-effect", before.Review.ReviewID); err == nil {
		t.Fatal("recovery silently confirmed storage")
	}
	detached := c
	detached.Storage = nil
	held := scheduledOperatorReview(t, detached)
	if !reflect.DeepEqual(held.Executor, before.Executor) || !reflect.DeepEqual(held.Review.Authority, before.Review.Authority) {
		t.Fatal("pending storage changed execution or obligations")
	}
	if err := os.Rename(retained, last); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
		t.Fatal("recovery modified original positions")
	}
}
