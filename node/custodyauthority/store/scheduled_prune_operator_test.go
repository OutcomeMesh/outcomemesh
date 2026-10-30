package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

type scheduledPruneOperatorFixture struct {
	plan          ScheduledPrunePlan
	config        []ScheduledPruneCommandConfig
	entries       []custodyauthority.Entry
	before        []Coordination
	packageConfig ScheduledPrunePackageConfig
}

func newScheduledPruneOperatorFixture(t testing.TB) scheduledPruneOperatorFixture {
	t.Helper()
	p, sources, cp := scheduledQuorumFixture(t)
	protection, err := p.f.chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	at := p.f.request.Boundary.VerifiedAt
	plan, err := PrepareScheduledPrunePlan(t.Context(), sources, cp, p.policy.CheckpointPolicy, p.policy.ReplicaPolicy, sources[0].AssignmentID, p.f.request.StorageID, protection.PairID, testPublic(4), at, func() uint64 { return at })
	if err != nil {
		t.Fatal(err)
	}
	id, _ := plan.ID()
	path := filepath.Join(t.TempDir(), "prune.plan")
	if err := SaveScheduledPrunePlan(t.Context(), path, plan, id); err != nil {
		t.Fatal(err)
	}
	rid, _ := plan.Request.ID()
	executor, err := CreatePinnedPruneExecutor(filepath.Join(t.TempDir(), "executor"), filepath.Join(t.TempDir(), "pins"), sources[0].Assignment, plan.Request, rid)
	if err != nil {
		t.Fatal(err)
	}
	f := scheduledPruneOperatorFixture{plan: plan, packageConfig: ScheduledPrunePackageConfig{PlanPath: path, PlanID: id, ExecutorPath: executor.path, ExecutorPinsPath: executor.pins.path}}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, s := range sources {
		c := ScheduledPruneCommandConfig{PlanPath: path, PlanID: id, AssignmentID: s.AssignmentID, AuthorityPath: s.AuthorityPath, AuthorityPinsPath: s.AuthorityPinsPath, ExecutorPath: f.packageConfig.ExecutorPath, ExecutorPinsPath: f.packageConfig.ExecutorPinsPath}
		review, err := RunScheduledPruneCommand(t.Context(), c, "review", types.Hash{})
		if err != nil {
			t.Fatal(err)
		}
		f.before = append(f.before, review.Review.Authority)
		draft, err := BuildScheduledPruneAdmission(s.Assignment, s.Schedule.Proof, plan.OriginalPolicy, plan.Request, review.Review.Authority.Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		entry := managedCommandApplyTestSign(t, draft)
		c.EntryPath = filepath.Join(t.TempDir(), "entry")
		c.EntryID, _ = entry.ID()
		c.JournalPath, c.CustodyPolicy, c.JournalLimits = s.JournalPath, s.CustodyPolicy, s.JournalLimits
		raw, _ := entry.CanonicalBytes()
		writeTestFile(t, c.EntryPath, raw)
		f.config = append(f.config, c)
		f.entries = append(f.entries, entry)
		f.packageConfig.Sources = append(f.packageConfig.Sources, ScheduledPruneAdmissionSource{AssignmentID: c.AssignmentID, AuthorityPath: c.AuthorityPath, AuthorityPinsPath: c.AuthorityPinsPath, EntryPath: c.EntryPath, EntryID: c.EntryID})
	}
	return f
}
func scheduledOperatorReview(t testing.TB, c ScheduledPruneCommandConfig) ScheduledPruneCommandResult {
	t.Helper()
	r, e := RunScheduledPruneCommand(t.Context(), c, "review", types.Hash{})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func scheduledOperatorApply(t testing.TB, c ScheduledPruneCommandConfig) ScheduledPruneCommandResult {
	t.Helper()
	r := scheduledOperatorReview(t, c)
	result, e := RunScheduledPruneCommand(t.Context(), c, "apply", r.Review.ReviewID)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func TestScheduledPruneOperatorAdmissionFaultRecovery(t *testing.T) {
	stages := []string{"scheduled-command-before-apply", "intent-before-publish", "intent-after-publish", "authority-after-publish", "confirm-before-publish", "confirm-after-publish", "pins-admission-intent-after-publish", "pins-admission-confirm-before-publish", "pins-admission-confirm-after-publish"}
	for _, index := range []int{0, 1} {
		for _, stage := range stages {
			if index == 1 && strings.HasPrefix(stage, "pins-") {
				continue
			}
			t.Run(string(rune('0'+index))+"/"+stage, func(t *testing.T) {
				f := newScheduledPruneOperatorFixture(t)
				c := f.config[index]
				review := scheduledOperatorReview(t, c)
				fault := errors.New("operator publication stopped")
				hit := false
				_, err := runScheduledPruneCommand(t.Context(), c, "apply", review.Review.ReviewID, storeHooks{at: func(at string) error {
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
				again := scheduledOperatorReview(t, c)
				if !reflect.DeepEqual(cold, again) {
					t.Fatal("review changed retained attempt")
				}
				mode := "apply"
				if cold.Review.Authority.Pending != nil || cold.Executor.Protection.Pending != nil {
					mode = "resume"
					if _, err := RunScheduledPruneCommand(t.Context(), c, "apply", cold.Review.ReviewID); !errors.Is(err, ErrPendingAttempt) {
						t.Fatal("apply silently resumed", err)
					}
				}
				result, err := RunScheduledPruneCommand(t.Context(), c, mode, cold.Review.ReviewID)
				if err != nil {
					t.Fatal("exact continuation", err)
				}
				if result.Commit == nil || result.Commit.Snapshot.Pending != f.before[index].Authority.Pending+1 {
					t.Fatal("original obligations lost")
				}
				stable := scheduledOperatorReview(t, c)
				if !stable.Review.AlreadyApplied || stable.Review.Authority.Pending != nil || stable.Executor.Protection.Pending != nil {
					t.Fatal("not fully confirmed")
				}
				if _, err := RunScheduledPruneCommand(t.Context(), c, "resume", stable.Review.ReviewID); !errors.Is(err, ErrNoAttempt) {
					t.Fatal("resume invented attempt", err)
				}
				retried := scheduledOperatorApply(t, c)
				if retried.Commit.Appended || !reflect.DeepEqual(stable.Review.Authority.Authority, retried.Commit.Snapshot) {
					t.Fatal("retry consumed accounting")
				}
			})
		}
	}
}

func TestScheduledPruneOperatorAdmissionRejectsSubstitution(t *testing.T) {
	f := newScheduledPruneOperatorFixture(t)
	c := f.config[0]
	before := scheduledOperatorReview(t, c)
	for _, name := range []string{"review-id", "plan-id", "entry-id", "other-owner", "missing-journal", "journal-copy", "root-alias", "inventory", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			bad := c
			id := before.Review.ReviewID
			ctx := t.Context()
			switch name {
			case "review-id":
				id = testHash(210)
			case "plan-id":
				bad.PlanID = testHash(210)
			case "entry-id":
				bad.EntryID = testHash(210)
			case "other-owner":
				bad.AuthorityPath = f.config[1].AuthorityPath
				bad.AuthorityPinsPath = f.config[1].AuthorityPinsPath
			case "missing-journal":
				bad.JournalPath = ""
			case "journal-copy":
				bad.JournalPath = t.TempDir()
			case "root-alias":
				bad.ExecutorPinsPath = bad.AuthorityPath
			case "inventory":
				bad.InventoryID = testHash(210)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := RunScheduledPruneCommand(ctx, bad, "apply", id); err == nil {
				t.Fatal("substitution accepted")
			}
			if after := scheduledOperatorReview(t, c); !reflect.DeepEqual(before, after) {
				t.Fatal("rejection changed owner")
			}
		})
	}
	// Replace the journal after review but before append. The retained descriptor
	// must fail its identity check rather than admit against a replacement root.
	original := c.JournalPath + "-held"
	_, err := runScheduledPruneCommand(t.Context(), c, "apply", before.Review.ReviewID, storeHooks{at: func(stage string) error {
		if stage == "scheduled-command-before-apply" {
			if err := os.Rename(c.JournalPath, original); err != nil {
				return err
			}
			return os.Mkdir(c.JournalPath, 0700)
		}
		return nil
	}})
	if err == nil {
		t.Fatal("replaced journal admitted")
	}
	if err := os.Remove(c.JournalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, c.JournalPath); err != nil {
		t.Fatal(err)
	}
	if after := scheduledOperatorReview(t, c); !reflect.DeepEqual(before, after) {
		t.Fatal("journal substitution consumed admission")
	}
}

func TestScheduledPrunePackageRequiresAcceptedOriginalTickets(t *testing.T) {
	f := newScheduledPruneOperatorFixture(t)
	if _, err := PackageScheduledPruneInventory(t.Context(), f.packageConfig, "", types.Hash{}); err == nil {
		t.Fatal("signed but unapplied package accepted")
	}
	scheduledOperatorApply(t, f.config[0])
	if _, err := PackageScheduledPruneInventory(t.Context(), f.packageConfig, "", types.Hash{}); err == nil {
		t.Fatal("missing second admission accepted")
	}
	scheduledOperatorApply(t, f.config[1])
	v, err := PackageScheduledPruneInventory(t.Context(), f.packageConfig, "", types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := v.ID()
	out := filepath.Join(t.TempDir(), "inventory")
	if _, err := PackageScheduledPruneInventory(t.Context(), f.packageConfig, out, testHash(212)); err == nil {
		t.Fatal("wrong review published")
	}
	for n := 0; n < 2; n++ {
		if _, err := PackageScheduledPruneInventory(t.Context(), f.packageConfig, out, id); err != nil {
			t.Fatal("immutable publication retry", err)
		}
	}
	for _, name := range []string{"duplicate", "foreign-entry", "wrong-entry-id", "foreign-owner", "overlap"} {
		t.Run(name, func(t *testing.T) {
			bad := f.packageConfig
			bad.Sources = append([]ScheduledPruneAdmissionSource(nil), bad.Sources...)
			dest := ""
			expected := types.Hash{}
			switch name {
			case "duplicate":
				bad.Sources[1] = bad.Sources[0]
			case "foreign-entry":
				bad.Sources[1].EntryPath = bad.Sources[0].EntryPath
				bad.Sources[1].EntryID = bad.Sources[0].EntryID
			case "wrong-entry-id":
				bad.Sources[1].EntryID = testHash(213)
			case "foreign-owner":
				bad.Sources[1].AuthorityPath = t.TempDir()
			case "overlap":
				dest = filepath.Join(bad.Sources[0].AuthorityPath, "inventory")
				expected = id
			}
			if _, err := PackageScheduledPruneInventory(t.Context(), bad, dest, expected); err == nil {
				t.Fatal("invalid package accepted")
			}
		})
	}
	for i, c := range f.config {
		r := scheduledOperatorReview(t, c)
		if r.Review.Authority.Authority.Pending != f.before[i].Authority.Pending+1 {
			t.Fatal("packaging changed accounting")
		}
	}
}

// A completed scheduled executor is retained independently of each original
// owner. Exporting/signing does not itself complete either owner's ticket.
func scheduledCompletedOperatorFixture(t testing.TB) (*scheduledPruneFixture, ScheduledPruneRuntimeConfig, []ScheduledPruneCommandConfig) {
	t.Helper()
	f := newScheduledPruneFixture(t)
	if _, err := f.execute(t.Context()); err != nil {
		t.Fatal(err)
	}
	v := f.inventory
	p := planFromInventory(v)
	id, _ := p.ID()
	path := filepath.Join(t.TempDir(), "plan")
	if err := SaveScheduledPrunePlan(t.Context(), path, p, id); err != nil {
		t.Fatal(err)
	}
	var configs []ScheduledPruneCommandConfig
	for _, op := range f.operations {
		c := ScheduledPruneCommandConfig{PlanPath: path, PlanID: id, AssignmentID: op.Binding.AssignmentID, AuthorityPath: op.Coordinator.authority.path, AuthorityPinsPath: op.Coordinator.journal.path, ExecutorPath: f.executor.path, ExecutorPinsPath: f.executor.pins.path, InventoryPath: f.path, InventoryID: f.id}
		draft, err := BuildScheduledPruneCompletion(p, v, *pruneSnapshot(t, f.executor).Effect, c.AssignmentID, testCoordination(t, op.Coordinator).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		entry := managedCommandApplyTestSign(t, draft)
		c.EntryID, _ = entry.ID()
		c.EntryPath = filepath.Join(t.TempDir(), "complete")
		raw, _ := entry.CanonicalBytes()
		writeTestFile(t, c.EntryPath, raw)
		configs = append(configs, c)
	}
	runtime := f.runtimeConfig(t)
	return f, runtime, configs
}
func planFromInventory(v ScheduledPruneInventory) ScheduledPrunePlan {
	v.ExecutorBindingID = types.Hash{}
	v.Replicas = append([]ScheduledPruneReplica(nil), v.Replicas...)
	for i := range v.Replicas {
		v.Replicas[i].Admission = custodyauthority.Entry{}
	}
	return ScheduledPrunePlan(v)
}
func TestScheduledPruneOperatorCompletionFaultsRetainOtherWork(t *testing.T) {
	for _, stage := range []string{"scheduled-command-before-apply", "intent-after-publish", "authority-after-publish", "confirm-before-publish", "confirm-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, _, configs := scheduledCompletedOperatorFixture(t)
			c := configs[1]
			before := scheduledOperatorReview(t, c)
			otherBefore := scheduledOperatorReview(t, configs[0])
			fault := errors.New("completion stopped")
			hit := false
			if _, err := runScheduledPruneCommand(t.Context(), c, "apply", before.Review.ReviewID, storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}}); !hit || !errors.Is(err, fault) {
				t.Fatal("fault missed", err)
			}
			cold := scheduledOperatorReview(t, c)
			mode := "apply"
			if cold.Review.Authority.Pending != nil {
				mode = "resume"
			}
			result, err := RunScheduledPruneCommand(t.Context(), c, mode, cold.Review.ReviewID)
			if err != nil {
				t.Fatal(err)
			}
			if result.Commit == nil || result.Commit.Snapshot.Pending != 1 || len(result.Commit.Snapshot.Operations) != 2 {
				t.Fatal("completion reset original accounting")
			}
			otherAfter := scheduledOperatorReview(t, configs[0])
			if !reflect.DeepEqual(otherBefore, otherAfter) {
				t.Fatal("completion changed another owner")
			}
			done := scheduledOperatorReview(t, c)
			if !done.Review.AlreadyApplied {
				t.Fatal("completed entry not retained")
			}
			retry := scheduledOperatorApply(t, c)
			if retry.Commit.Appended || !reflect.DeepEqual(result.Commit.Snapshot, retry.Commit.Snapshot) {
				t.Fatal("exact completion repeated")
			}
		})
	}
}
func TestScheduledPruneOperatorExecutorResumeNeverExecutes(t *testing.T) {
	for _, stage := range []string{"pins-start-intent-after-publish", "pins-result-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneFixture(t)
			p := planFromInventory(f.inventory)
			id, _ := p.ID()
			path := filepath.Join(t.TempDir(), "plan")
			if err := SaveScheduledPrunePlan(t.Context(), path, p, id); err != nil {
				t.Fatal(err)
			}
			runtime := f.runtimeConfig(t)
			review, err := RunScheduledPrune(t.Context(), runtime, "review", types.Hash{})
			if err != nil {
				t.Fatal(err)
			}
			hit := false
			fault := errors.New("executor interrupted")
			_, err = runScheduledPrune(t.Context(), runtime, "execute", review.Review.ReviewID, storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}})
			if !hit || !errors.Is(err, fault) {
				t.Fatal("fault missed", err)
			}
			c := ScheduledPruneCommandConfig{PlanPath: path, PlanID: id, AssignmentID: p.Request.AssignmentID, AuthorityPath: runtime.Authorities[0].AuthorityPath, AuthorityPinsPath: runtime.Authorities[0].AuthorityPinsPath, ExecutorPath: runtime.ExecutorPath, ExecutorPinsPath: runtime.ExecutorPinsPath, InventoryPath: f.path, InventoryID: f.id}
			before := scheduledOperatorReview(t, c)
			if before.Executor.Protection.Pending == nil {
				t.Fatal("missing retained transition")
			}
			bad := c
			bad.InventoryID = testHash(211)
			if _, err := RunScheduledPruneCommand(t.Context(), bad, "resume-executor", before.Review.ReviewID); err == nil {
				t.Fatal("changed inventory resumed")
			}
			result, err := RunScheduledPruneCommand(t.Context(), c, "resume-executor", before.Review.ReviewID)
			if err != nil {
				t.Fatal(err)
			}
			if result.Executor.Protection.Pending != nil || result.Executor.ArchiveInventoryID != f.id {
				t.Fatal("exact transition not confirmed")
			}
			after := scheduledOperatorReview(t, c)
			if !reflect.DeepEqual(before.Review.Authority, after.Review.Authority) {
				t.Fatal("executor continuation released tickets")
			}
			effect, err := RunScheduledPrune(t.Context(), runtime, "review", types.Hash{})
			if err != nil {
				t.Fatal(err)
			}
			if stage == "pins-start-intent-after-publish" {
				if result.Executor.Stage != PruneStarted || result.Executor.Effect != nil {
					t.Fatal("unknown start became success")
				}
				if _, err := RunScheduledPrune(t.Context(), runtime, "execute", effect.Review.ReviewID); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("unknown start repeated", err)
				}
				if _, err := RunScheduledPrune(t.Context(), runtime, "recover", effect.Review.ReviewID); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("absence invented effect", err)
				}
			} else {
				if result.Executor.Stage != PruneSucceeded || result.Executor.Effect == nil {
					t.Fatal("recorded result lost")
				}
				recovered, err := RunScheduledPrune(t.Context(), runtime, "recover", effect.Review.ReviewID)
				if err != nil || recovered.Commit.Applied || !reflect.DeepEqual(*result.Executor.Effect, recovered.Commit.Effect) {
					t.Fatal("recovery repeated effect", err)
				}
			}
		})
	}
}
