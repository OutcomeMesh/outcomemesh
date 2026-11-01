package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func certifiedOutcomeFixture(t testing.TB) (*scheduledPruneFixture, []ScheduledPruneCommandConfig) {
	t.Helper()
	f, configs := scheduledOutcomeFixture(t, "admitted", pruneFencePolicy())
	w := newPruneWitnessFixture(t, f.inventory)
	closure := w.closeSlot(t, pruneClosureIntent(f.inventory))
	raw, err := closure.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	c := &configs[0]
	c.Storage = nil
	c.ClosurePath = filepath.Join(t.TempDir(), "closure")
	c.ClosureID, _ = closure.ID()
	writeTestFile(t, c.ClosurePath, raw)
	return f, configs
}

func withoutPruneClosure(c ScheduledPruneCommandConfig) ScheduledPruneCommandConfig {
	c.ClosurePath, c.ClosureID = "", types.Hash{}
	return c
}

func TestPruneCertifiedOperatorReviewAndCompletion(t *testing.T) {
	f, configs := certifiedOutcomeFixture(t)
	c := configs[0]
	before := scheduledOperatorReview(t, c)
	plain := scheduledOperatorReview(t, withoutPruneClosure(c))
	if before.Review.ReviewID == plain.Review.ReviewID || before.Review.ClosureID != c.ClosureID {
		t.Fatal("review omitted closure")
	}
	for _, name := range []string{"stale-review", "missing-proof", "wrong-proof-id", "secondary", "overlap", "legacy-mode", "resume-mode", "storage"} {
		t.Run(name, func(t *testing.T) {
			bad, id, mode := c, before.Review.ReviewID, "cancel-with-closure"
			switch name {
			case "stale-review":
				id = plain.Review.ReviewID
			case "missing-proof":
				bad = withoutPruneClosure(c)
			case "wrong-proof-id":
				bad.ClosureID = testHash(211)
			case "secondary":
				bad.AssignmentID, bad.AuthorityPath, bad.AuthorityPinsPath = configs[1].AssignmentID, configs[1].AuthorityPath, configs[1].AuthorityPinsPath
			case "overlap":
				bad.ClosurePath = filepath.Join(c.ExecutorPath, "fence", "candidate")
			case "legacy-mode":
				mode = "cancel-before-start"
			case "resume-mode":
				mode = "resume-executor"
			case "storage":
				bad.Storage = &PruneRecoveryStorage{}
			}
			if _, err := RunScheduledPruneCommand(t.Context(), bad, mode, id); err == nil {
				t.Fatal("accepted invalid application")
			}
			if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("invalid application changed state")
			}
		})
	}
	// No archive or database is needed to retain a verified unclaimed closure.
	for _, s := range f.sources {
		for _, p := range []string{s.Directory, s.JournalPath} {
			if err := os.Rename(p, p+".offline"); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, p := range []string{f.archive.f.chainPath, f.archive.f.chainPositionPinsPath} {
		if err := os.Rename(p, p+".offline"); err != nil {
			t.Fatal(err)
		}
	}
	r, err := RunScheduledPruneCommand(t.Context(), c, "cancel-with-closure", before.Review.ReviewID)
	if err != nil || r.Executor.Stage != PruneCancelled {
		t.Fatal(err)
	}
	cold := scheduledOperatorReview(t, c)
	if !reflect.DeepEqual(before.Review.Authority, cold.Review.Authority) {
		t.Fatal("cancellation changed authority")
	}
	for _, cfg := range configs {
		complete := scheduledOutcomeCompletion(t, withoutPruneClosure(cfg))
		result := scheduledOperatorApply(t, complete)
		if result.Commit == nil || result.Commit.Snapshot.Pending != 1 || len(result.Commit.Snapshot.Operations) != 2 {
			t.Fatal("lost original accounting")
		}
		if again := scheduledOperatorApply(t, complete); again.Commit.Appended {
			t.Fatal("duplicate completion")
		}
	}
	// Confirmed historical observation remains possible after primary completion.
	review := scheduledOperatorReview(t, c)
	if _, err := RunScheduledPruneCommand(t.Context(), c, "cancel-with-closure", review.Review.ReviewID); err != nil {
		t.Fatal("historical retry", err)
	}
}

func TestPruneCertifiedOperatorExplicitResume(t *testing.T) {
	for _, stage := range []string{"pins-cancel-intent-after-publish", "prune-cancel-after-publish", "pins-cancel-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := certifiedOutcomeFixture(t)
			c := configs[0]
			r := scheduledOperatorReview(t, c)
			fault, hit := errors.New("stop certified cancellation"), false
			_, err := runScheduledPruneCommand(t.Context(), c, "cancel-with-closure", r.Review.ReviewID, storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}})
			if !hit || !errors.Is(err, fault) {
				t.Fatal("missed stage", err)
			}
			cold := scheduledOperatorReview(t, c)
			if cold.Executor.Protection.Pending == nil {
				t.Fatal("lost intent")
			}
			if _, err := RunScheduledPruneCommand(t.Context(), c, "cancel-with-closure", cold.Review.ReviewID); err == nil {
				t.Fatal("implicit resume")
			}
			// Once intent is retained, recovery uses its exact embedded quorum.
			if err := os.Rename(c.ClosurePath, c.ClosurePath+".offline"); err != nil {
				t.Fatal(err)
			}
			resume := withoutPruneClosure(c)
			held := scheduledOperatorReview(t, resume)
			if _, err := retainedScheduledPruneOutcomeForTest(resume, held.Executor); err == nil {
				t.Fatal("unconfirmed cancellation became outcome")
			}
			result, err := RunScheduledPruneCommand(t.Context(), resume, "resume-executor", held.Review.ReviewID)
			if err != nil || result.Executor.Stage != PruneCancelled || result.Executor.Protection.Pending != nil {
				t.Fatal("resume", err)
			}
			if !reflect.DeepEqual(r.Review.Authority, result.Review.Authority) {
				t.Fatal("resume completed accounting")
			}
			complete := scheduledOutcomeCompletion(t, withoutPruneClosure(configs[1]))
			if done := scheduledOperatorApply(t, complete); done.Commit.Snapshot.Pending != 1 {
				t.Fatal("completion")
			}
		})
	}
}

func retainedScheduledPruneOutcomeForTest(c ScheduledPruneCommandConfig, s PruneExecution) (ScheduledPruneOutcome, error) {
	v, err := LoadScheduledPruneInventory(c.InventoryPath, c.InventoryID)
	if err != nil {
		return ScheduledPruneOutcome{}, err
	}
	return RetainedScheduledPruneOutcome(v, s)
}
