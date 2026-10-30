package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func migratedPruneFixture(t testing.TB, outcome string) (*archivePruneFixture, []MigratedPruneConfig) {
	t.Helper()
	p := newArchivePruneFixtureWithRenewals(t, []int{1, 2})
	retainArchiveInventory(t, p)
	if outcome == "cancelled" || outcome == "cancel-pending" {
		fault := errors.New("cancellation confirmation interrupted")
		hit := false
		if outcome == "cancel-pending" {
			p.f.executor.pins.hooks.at = func(stage string) error {
				if stage == "pins-cancel-confirm-before-publish" {
					hit = true
					return fault
				}
				return nil
			}
		}
		_, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator)
		if outcome == "cancelled" && err != nil {
			t.Fatal(err)
		}
		if outcome == "cancel-pending" && (!hit || !errors.Is(err, fault)) {
			t.Fatal("missed cancellation boundary", err)
		}
	} else if outcome != "admitted" {
		fault := errors.New("interrupted old execution")
		hit := false
		if outcome != "success" {
			hook := func(stage string) error {
				if stage == outcome {
					hit = true
					return fault
				}
				return nil
			}
			p.f.executor.hooks.at, p.f.executor.pins.hooks.at = hook, hook
		}
		_, err := p.execute(t.Context())
		if outcome == "success" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !hit || !errors.Is(err, fault) {
			t.Fatal("missed old boundary", err)
		}
	}
	_, sources, cp := migratePruneFixtureOwners(t, p)
	review, err := p.f.chain.ReviewRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.f.chain.MigrateRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight, review.ID()); err != nil {
		t.Fatal(err)
	}
	storage := MigratedPruneStorage{ChainPath: p.f.chainPath, ChainPinsPath: p.f.chainPositionPinsPath, MigrationID: review.ID(), Base: p.f.base, Parameters: p.f.parameters, Policy: p.f.policy}
	storage.Parameters.RadixActivationHeight = cp.Statement.RadixActivationHeight
	var configs []MigratedPruneConfig
	for _, s := range sources {
		path := filepath.Join(t.TempDir(), "scope")
		raw, _ := s.Schedule.Proof.CanonicalBytes()
		writeTestFile(t, path, raw)
		configs = append(configs, MigratedPruneConfig{InventoryPath: p.inventoryPath, InventoryID: p.inventoryID, PolicyID: p.policyID, ProofPath: path, ScheduleID: s.Schedule.ExpectedID, ExecutorPath: p.f.executor.path, ExecutorPinsPath: p.f.executor.pins.path, AuthorityPath: s.AuthorityPath, AuthorityPinsPath: s.AuthorityPinsPath, Storage: &storage})
	}
	if err := p.f.executor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	return p, configs
}
func migratedPruneReview(t testing.TB, c MigratedPruneConfig) MigratedPruneResult {
	t.Helper()
	r, err := RunMigratedPrune(t.Context(), c, "review", types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func migratedPruneCompletionConfig(t testing.TB, c MigratedPruneConfig) MigratedPruneConfig {
	t.Helper()
	c.Storage = nil
	r := migratedPruneReview(t, c)
	v, err := LoadMigratedPruneContext(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := r.Review.Outcome.Artifact()
	if err != nil {
		t.Fatal(err)
	}
	c.OutcomePath = filepath.Join(t.TempDir(), "outcome")
	writeTestFile(t, c.OutcomePath, raw)
	c.OutcomeID, err = r.Review.Outcome.EvidenceID(v)
	if err != nil {
		t.Fatal(err)
	}
	c.OutcomeKind = "effect"
	if r.Review.Outcome.Cancellation != nil {
		c.OutcomeKind = "cancellation"
	}
	draft, err := BuildMigratedPruneCompletion(v, r.Review.Outcome, r.Review.Authority.Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	entry := managedCommandApplyTestSign(t, draft)
	raw, _ = entry.CanonicalBytes()
	c.EntryPath = filepath.Join(t.TempDir(), "entry")
	writeTestFile(t, c.EntryPath, raw)
	c.EntryID, _ = entry.ID()
	return c
}
func TestPruneMigratedTerminalCompletesOriginalTickets(t *testing.T) {
	for _, outcome := range []string{"success", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			p, configs := migratedPruneFixture(t, outcome)
			for _, config := range configs {
				c := migratedPruneCompletionConfig(t, config)
				r := migratedPruneReview(t, c)
				before := r.Review.Authority.Authority
				entryBytes, err := readRegular(c.EntryPath, custodyauthority.MaximumEntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				entry, err := custodyauthority.DecodeEntry(entryBytes)
				if err != nil {
					t.Fatal(err)
				}
				if entry.Command.TicketID != before.Operations[0].TicketID || entry.Command.ScheduleID.IsZero() {
					t.Fatal("old ticket was reissued")
				}
				result, err := RunMigratedPrune(t.Context(), c, "apply", r.Review.ReviewID)
				if err != nil {
					t.Fatal(err)
				}
				after := result.Commit.Snapshot
				if after.Pending != 0 || len(after.Operations) != 1 || after.AssignmentID != before.AssignmentID || after.Operations[0].OperationID != p.f.id || after.Operations[0].TicketID != before.Operations[0].TicketID {
					t.Fatal("old accounting changed")
				}
				cold := migratedPruneReview(t, c)
				if !cold.Review.AlreadyApplied {
					t.Fatal("missing historical completion")
				}
				retry, err := RunMigratedPrune(t.Context(), c, "apply", cold.Review.ReviewID)
				if err != nil || retry.Commit.Appended || !reflect.DeepEqual(after, retry.Commit.Snapshot) {
					t.Fatal("historical retry reset work", err)
				}
				if !reflect.DeepEqual(r.Executor, retry.Executor) {
					t.Fatal("completion changed retained outcome")
				}
			}
		})
	}
}
func TestPruneMigratedRecoveryOnlyRetainsExactOldEffect(t *testing.T) {
	for _, stage := range []string{"prune-before-effect", "prune-after-effect", "pins-start-intent-after-publish", "pins-result-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := migratedPruneFixture(t, stage)
			c := configs[0]
			r := migratedPruneReview(t, c)
			before := r.Review.Authority
			if r.Executor.Protection.Pending != nil {
				bare := c
				bare.Storage = nil
				pending := migratedPruneReview(t, bare)
				if _, err := RunMigratedPrune(t.Context(), bare, "resume-executor", pending.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
				r = migratedPruneReview(t, c)
			}
			recovered, err := RunMigratedPrune(t.Context(), c, "recover-effect", r.Review.ReviewID)
			if stage == "prune-before-effect" || stage == "pins-start-intent-after-publish" {
				if !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("absence resolved as success", err)
				}
				cold := migratedPruneReview(t, c)
				if cold.Executor.Stage != PruneStarted || cold.Review.Outcome.Effect != nil || cold.Review.Authority.Authority.Pending != 1 {
					t.Fatal("unknown outcome released work")
				}
				return
			}
			if err != nil || recovered.Recovered == nil || recovered.Recovered.Applied || recovered.Executor.Stage != PruneSucceeded {
				t.Fatal("could not retain exact old effect", err)
			}
			if !reflect.DeepEqual(before, recovered.Review.Authority) {
				t.Fatal("effect recovery completed ticket")
			}
			r = migratedPruneReview(t, c)
			again, err := RunMigratedPrune(t.Context(), c, "recover-effect", r.Review.ReviewID)
			if err != nil || again.Recovered.Applied || !reflect.DeepEqual(recovered.Recovered, again.Recovered) {
				t.Fatal("effect recovery repeated deletion", err)
			}
			complete := migratedPruneCompletionConfig(t, c)
			r = migratedPruneReview(t, complete)
			if _, err := RunMigratedPrune(t.Context(), complete, "apply", r.Review.ReviewID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPruneMigratedCompletionFaultsPreserveOtherOwners(t *testing.T) {
	for _, stage := range []string{"migrated-prune-before-complete", "intent-after-publish", "authority-after-publish", "confirm-before-publish", "confirm-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := migratedPruneFixture(t, "success")
			c := migratedPruneCompletionConfig(t, configs[1])
			r := migratedPruneReview(t, c)
			other := configs[0]
			other.Storage = nil
			before := migratedPruneReview(t, other)
			hit := false
			fault := errors.New("completion interrupted")
			_, err := runMigratedPrune(t.Context(), c, "apply", r.Review.ReviewID, storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}})
			if !hit || !errors.Is(err, fault) {
				t.Fatal("missed boundary", err)
			}
			r = migratedPruneReview(t, c)
			mode := "apply"
			if r.Review.Authority.Pending != nil {
				mode = "resume"
				if _, err := RunMigratedPrune(t.Context(), c, "apply", r.Review.ReviewID); !errors.Is(err, ErrPendingAttempt) {
					t.Fatal("implicit recovery", err)
				}
			}
			result, err := RunMigratedPrune(t.Context(), c, mode, r.Review.ReviewID)
			if err != nil || result.Commit.Snapshot.Pending != 0 || len(result.Commit.Snapshot.Operations) != 1 {
				t.Fatal("completion recovery", err)
			}
			if after := migratedPruneReview(t, other); !reflect.DeepEqual(before, after) {
				t.Fatal("secondary completion changed primary")
			}
		})
	}
}

func TestPruneMigratedRejectsSubstitutionWithoutChangingOwners(t *testing.T) {
	_, configs := migratedPruneFixture(t, "success")
	c := migratedPruneCompletionConfig(t, configs[0])
	before := migratedPruneReview(t, c)
	for _, name := range []string{"inventory", "policy", "scope", "entry", "outcome", "kind", "secondary-proof", "other-owner", "overlap", "stale-review"} {
		t.Run(name, func(t *testing.T) {
			bad := c
			id := before.Review.ReviewID
			switch name {
			case "inventory":
				bad.InventoryID = testHash(241)
			case "policy":
				bad.PolicyID = testHash(241)
			case "scope":
				bad.ScheduleID = testHash(241)
			case "entry":
				bad.EntryID = testHash(241)
			case "outcome":
				bad.OutcomeID = testHash(241)
			case "kind":
				bad.OutcomeKind = "cancellation"
			case "secondary-proof":
				bad.ProofPath = configs[1].ProofPath
				bad.ScheduleID = configs[1].ScheduleID
			case "other-owner":
				bad.AuthorityPath = configs[1].AuthorityPath
				bad.AuthorityPinsPath = configs[1].AuthorityPinsPath
			case "overlap":
				bad.ExecutorPinsPath = bad.AuthorityPath
			case "stale-review":
				id = testHash(241)
			}
			if _, err := RunMigratedPrune(t.Context(), bad, "apply", id); err == nil {
				t.Fatal("substituted completion accepted")
			}
			if after := migratedPruneReview(t, c); !reflect.DeepEqual(before, after) {
				t.Fatal("rejection changed original owners")
			}
		})
	}
	v, err := LoadMigratedPruneContext(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*MigratedPruneContext, *MigratedPruneOutcome){
		func(v *MigratedPruneContext, o *MigratedPruneOutcome) {
			v.Inventory.Policy.ExecutorBindingID = testHash(243)
		},
		func(v *MigratedPruneContext, o *MigratedPruneOutcome) { o.Effect.Operation.TicketID = testHash(243) },
		func(v *MigratedPruneContext, o *MigratedPruneOutcome) { o.Effect.Operation.StorageID = testHash(243) },
		func(v *MigratedPruneContext, o *MigratedPruneOutcome) { o.Effect.Operation.ScheduleID = v.ScheduleID },
		func(v *MigratedPruneContext, o *MigratedPruneOutcome) { o.Cancellation = &PruneCancellation{} },
	} {
		vv := v
		o := before.Review.Outcome
		effect := *o.Effect
		o.Effect = &effect
		mutate(&vv, &o)
		if _, err := BuildMigratedPruneCompletion(vv, o, before.Review.Authority.Confirmed); err == nil {
			t.Fatal("substituted evidence signed")
		}
	}
}
func TestPruneMigratedRecoveryRejectsWrongProtectedStorage(t *testing.T) {
	_, configs := migratedPruneFixture(t, "prune-after-effect")
	c := configs[0]
	before := migratedPruneReview(t, c)
	for _, name := range []string{"migration", "height", "pair", "policy", "missing", "secondary"} {
		t.Run(name, func(t *testing.T) {
			bad := c
			s := *c.Storage
			bad.Storage = &s
			switch name {
			case "migration":
				s.MigrationID = testHash(245)
			case "height":
				s.Parameters.RadixActivationHeight++
			case "pair":
				s.ChainPinsPath = t.TempDir()
			case "policy":
				s.Policy.MaxHistoryBytes--
			case "missing":
				bad.Storage = nil
			case "secondary":
				bad.AuthorityPath = configs[1].AuthorityPath
				bad.AuthorityPinsPath = configs[1].AuthorityPinsPath
				bad.ProofPath = configs[1].ProofPath
				bad.ScheduleID = configs[1].ScheduleID
			}
			if _, err := RunMigratedPrune(t.Context(), bad, "recover-effect", before.Review.ReviewID); err == nil {
				t.Fatal("wrong recovery context accepted")
			}
			if after := migratedPruneReview(t, c); !reflect.DeepEqual(before, after) {
				t.Fatal("rejected recovery mutated state")
			}
		})
	}
}

func TestPruneMigratedCancellationResumesOnlyRetainedBranch(t *testing.T) {
	_, configs := migratedPruneFixture(t, "cancel-pending")
	c := configs[0]
	c.Storage = nil
	r := migratedPruneReview(t, c)
	if r.Executor.Protection.Pending == nil || r.Review.Outcome.Cancellation != nil {
		t.Fatal("unconfirmed cancellation became evidence")
	}
	if _, err := RunMigratedPrune(t.Context(), c, "resume-executor", r.Review.ReviewID); err != nil {
		t.Fatal(err)
	}
	for _, c := range configs {
		complete := migratedPruneCompletionConfig(t, c)
		review := migratedPruneReview(t, complete)
		done, err := RunMigratedPrune(t.Context(), complete, "apply", review.Review.ReviewID)
		if err != nil || done.Commit.Snapshot.Pending != 0 {
			t.Fatal("cancelled old work did not drain", err)
		}
	}
	_, configs = migratedPruneFixture(t, "admitted")
	c = configs[0]
	c.Storage = nil
	r = migratedPruneReview(t, c)
	if _, err := r.Review.Outcome.Artifact(); err == nil {
		t.Fatal("unstarted work manufactured cancellation")
	}
	if _, err := RunMigratedPrune(t.Context(), c, "resume-executor", r.Review.ReviewID); err == nil {
		t.Fatal("resume invented cancellation branch")
	}
}

func TestPruneMigratedCancellationBeforeStartPreservesAccounting(t *testing.T) {
	for _, stage := range []string{"success", "pins-cancel-intent-after-publish", "pins-cancel-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := migratedPruneFixture(t, "admitted")
			c := configs[0]
			c.Storage = nil
			r := migratedPruneReview(t, c)
			before := r.Review.Authority
			hit := false
			fault := errors.New("migrated cancellation interrupted")
			hooks := storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}}
			result, err := runMigratedPrune(t.Context(), c, "cancel-before-start", r.Review.ReviewID, hooks)
			if stage == "success" {
				if err != nil || result.Executor.Stage != PruneCancelled {
					t.Fatal(err)
				}
			} else {
				if !hit || !errors.Is(err, fault) {
					t.Fatal("missed cancellation boundary", err)
				}
				r = migratedPruneReview(t, c)
				if _, err := RunMigratedPrune(t.Context(), c, "resume-executor", r.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
			}
			r = migratedPruneReview(t, c)
			if !reflect.DeepEqual(before, r.Review.Authority) || r.Review.Outcome.Cancellation == nil {
				t.Fatal("cancellation changed authority")
			}
			retry, err := RunMigratedPrune(t.Context(), c, "cancel-before-start", r.Review.ReviewID)
			if err != nil || !reflect.DeepEqual(r.Executor, retry.Executor) {
				t.Fatal("cancellation retry changed terminal", err)
			}
			for _, c := range configs {
				complete := migratedPruneCompletionConfig(t, c)
				r := migratedPruneReview(t, complete)
				if _, err := RunMigratedPrune(t.Context(), complete, "apply", r.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, stage := range []string{"prune-before-effect", "prune-after-effect", "pins-start-intent-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := migratedPruneFixture(t, stage)
			c := configs[0]
			c.Storage = nil
			r := migratedPruneReview(t, c)
			if _, err := RunMigratedPrune(t.Context(), c, "cancel-before-start", r.Review.ReviewID); err == nil {
				t.Fatal("retained start cancelled")
			}
			if after := migratedPruneReview(t, c); !reflect.DeepEqual(r, after) {
				t.Fatal("cancellation changed unknown outcome")
			}
		})
	}
}
