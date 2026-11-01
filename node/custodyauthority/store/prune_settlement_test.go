package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func certifyObservedProposal(t testing.TB, proposal prunefence.SettlementProposal) prunefence.Settlement {
	t.Helper()
	for _, v := range []struct {
		role string
		seed byte
	}{{"owner", 4}, {"controller", 1}} {
		review, err := proposal.ReviewID(v.role)
		if err != nil {
			t.Fatal(err)
		}
		proposal, err = proposal.Sign(v.role, review, testKey(v.seed))
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, draft, err := proposal.Draft()
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := scope.ID()
	command, err := draft.Sign(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	q := custodyfence.Certificate{Version: 1, Command: command}
	for seed := byte(70); seed < 74; seed++ {
		w, err := custodyfence.Create(filepath.Join(t.TempDir(), "decision"), scope, sid, testKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		vote, err := w.Vote(command)
		if err != nil {
			t.Fatal(err)
		}
		q.Votes = append(q.Votes, vote)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	return prunefence.Settlement{Proposal: proposal, Certificate: q}
}
func observedOutcomeFixture(t testing.TB) (*scheduledPruneFixture, []ScheduledPruneCommandConfig) {
	t.Helper()
	f, configs := scheduledOutcomeFixture(t, "prune-after-effect", pruneFencePolicy())
	c := configs[0]
	c.PrepareSettlement = true
	review := scheduledOperatorReview(t, c)
	prepared, err := RunScheduledPruneCommand(t.Context(), c, "prepare-settlement", review.Review.ReviewID)
	if err != nil || prepared.Proposal == nil {
		t.Fatal("prepare observed effect", err)
	}
	decision := certifyObservedProposal(t, *prepared.Proposal)
	c.PrepareSettlement = false
	c.SettlementPath = filepath.Join(t.TempDir(), "settlement-certificate")
	c.SettlementID, _ = decision.ID()
	raw, _ := decision.CanonicalBytes()
	writeTestFile(t, c.SettlementPath, raw)
	configs[0] = c
	return f, configs
}
func withoutPruneSettlement(c ScheduledPruneCommandConfig) ScheduledPruneCommandConfig {
	c.PrepareSettlement = false
	c.SettlementPath = ""
	c.SettlementID = types.Hash{}
	return c
}
func TestPruneSettlementObservedEffectAndReplicaCompletion(t *testing.T) {
	f, configs := observedOutcomeFixture(t)
	c := configs[0]
	before := scheduledOperatorReview(t, c)
	if before.Executor.Stage != PruneStarted || before.Executor.FenceResult != nil || before.Executor.FenceSettlement != nil {
		t.Fatal("fixture already has signed result")
	}
	plain := withoutPruneSettlement(c)
	legacy := scheduledOperatorReview(t, plain)
	if _, err := RunScheduledPruneCommand(t.Context(), plain, "recover-effect", legacy.Review.ReviewID); !errors.Is(err, ErrPruneOutcome) {
		t.Fatal("bare recovery bypass", err)
	}
	if _, err := RunScheduledPruneCommand(t.Context(), c, "settle-effect", legacy.Review.ReviewID); err == nil {
		t.Fatal("unreviewed settlement")
	}
	settled, err := RunScheduledPruneCommand(t.Context(), c, "settle-effect", before.Review.ReviewID)
	if err != nil || settled.Executor.Stage != PruneSucceeded || settled.Executor.FenceResult != nil || settled.Executor.FenceSettlement == nil {
		t.Fatal("settle", err)
	}
	after := scheduledOperatorReview(t, c)
	if !reflect.DeepEqual(before.Review.Authority, after.Review.Authority) || !reflect.DeepEqual(before.Review.Storage, after.Review.Storage) {
		t.Fatal("settlement changed accounting or storage")
	}
	outcome, err := RetainedScheduledPruneOutcome(f.inventory, after.Executor)
	if err != nil || outcome.Settlement == nil || outcome.Effect != nil {
		t.Fatal("downgraded settlement", err)
	}
	raw, _ := outcome.Artifact()
	path := filepath.Join(t.TempDir(), "outcome")
	writeTestFile(t, path, raw)
	id, _ := outcome.EvidenceID(f.inventory)
	eid, _ := after.Executor.Effect.ID()
	if id == eid {
		t.Fatal("settlement collapsed to bare effect")
	}
	if _, err := LoadScheduledPruneOutcome(path, "settlement", id); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadScheduledPruneOutcome(path, "effect", id); err == nil {
		t.Fatal("decoded as raw effect")
	}
	retry, err := RunScheduledPruneCommand(t.Context(), c, "settle-effect", after.Review.ReviewID)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := retry.Executor.FenceSettlement.CanonicalBytes()
	if !bytes.Equal(raw, again) {
		t.Fatal("retry changed certificate")
	}
	// An alternative valid quorum cannot replace the exact artifact after retain.
	certRaw, err := os.ReadFile(c.SettlementPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := prunefence.DecodeSettlement(certRaw)
	cert.Certificate.Votes = cert.Certificate.Votes[:3]
	alternate, _ := cert.CanonicalBytes()
	bad := c
	bad.SettlementPath = filepath.Join(t.TempDir(), "alternate")
	bad.SettlementID, _ = cert.ID()
	writeTestFile(t, bad.SettlementPath, alternate)
	if _, err := RunScheduledPruneCommand(t.Context(), bad, "review", types.Hash{}); err == nil {
		t.Fatal("replaced exact certificate")
	}
	// Neither detached evidence nor returned slices may mutate retained history.
	after.Executor.FenceSettlement.Decision.Certificate.Votes[0].Signature[0] ^= 1
	if _, err := RetainedScheduledPruneOutcome(f.inventory, after.Executor); err == nil {
		t.Fatal("bad detached certificate")
	}
	stable := scheduledOperatorReview(t, c)
	stableRaw, _ := stable.Executor.FenceSettlement.CanonicalBytes()
	if !bytes.Equal(raw, stableRaw) {
		t.Fatal("snapshot aliased owner")
	}
	for _, config := range configs {
		config = withoutPruneSettlement(config)
		config.Storage = nil
		r := scheduledOperatorReview(t, config)
		draft, err := BuildScheduledPruneCompletion(planFromInventory(f.inventory), f.inventory, *r.Executor.Effect, config.AssignmentID, r.Review.Authority.Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		fake := managedCommandApplyTestSign(t, draft)
		fakeConfig := config
		fakeConfig.EntryPath = filepath.Join(t.TempDir(), "bare-effect-completion")
		fakeConfig.EntryID, _ = fake.ID()
		b, _ := fake.CanonicalBytes()
		writeTestFile(t, fakeConfig.EntryPath, b)
		if _, err := RunScheduledPruneCommand(t.Context(), fakeConfig, "review", types.Hash{}); err == nil {
			t.Fatal("bare effect completed settled work")
		}
		complete := scheduledOutcomeCompletion(t, config)
		result := scheduledOperatorApply(t, complete)
		if result.Commit == nil || result.Commit.Snapshot.Pending != 1 || len(result.Commit.Snapshot.Operations) != 2 {
			t.Fatal("reset accounting")
		}
		if again := scheduledOperatorApply(t, complete); again.Commit.Appended {
			t.Fatal("duplicate completion")
		}
	}
}
func TestPruneSettlementRejectsMissingEffectAndWrongContext(t *testing.T) {
	for _, stage := range []string{"admitted", "prune-before-effect", "success"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := scheduledOutcomeFixture(t, stage, pruneFencePolicy())
			c := configs[0]
			before := scheduledOperatorReview(t, c)
			c.PrepareSettlement = true
			if _, err := RunScheduledPruneCommand(t.Context(), c, "review", types.Hash{}); err == nil {
				t.Fatal("prepared missing or already signed result")
			}
			c.PrepareSettlement = false
			if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("rejected prepare mutated owners")
			}
		})
	}
	_, configs := observedOutcomeFixture(t)
	c := configs[0]
	before := scheduledOperatorReview(t, c)
	for _, name := range []string{"missing-storage", "wrong-certificate-id", "wrong-storage-pair", "secondary", "mixed-entry", "mixed-closure", "wrong-mode", "raw-review"} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mode := "review"
			expected := types.Hash{}
			switch name {
			case "missing-storage":
				bad.Storage = nil
			case "wrong-certificate-id":
				bad.SettlementID = testHash(201)
			case "wrong-storage-pair":
				s := *bad.Storage
				s.ChainPinsPath = filepath.Join(t.TempDir(), "absent")
				bad.Storage = &s
			case "secondary":
				bad.AssignmentID = configs[1].AssignmentID
			case "mixed-entry":
				bad.EntryPath = c.SettlementPath
			case "mixed-closure":
				bad.ClosurePath = c.SettlementPath
				bad.ClosureID = c.SettlementID
			case "wrong-mode":
				mode = "recover-effect"
				expected = before.Review.ReviewID
			case "raw-review":
				mode = "settle-effect"
				bad = withoutPruneSettlement(c)
				expected = before.Review.ReviewID
			}
			if _, err := RunScheduledPruneCommand(t.Context(), bad, mode, expected); err == nil {
				t.Fatal("invalid settlement accepted")
			}
			if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("rejected settlement changed owners")
			}
		})
	}
}
func TestPruneSettlementRetainsExactIntentAcrossFailures(t *testing.T) {
	for _, stage := range []string{"prune-settlement-before-retain", "pins-result-intent-after-publish", "prune-result-after-publish", "prune-result-after-apply", "pins-result-confirm-before-publish", "pins-result-confirm-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			f, configs := observedOutcomeFixture(t)
			c := configs[0]
			review := scheduledOperatorReview(t, c)
			fault := errors.New("lost settlement response")
			hit := false
			hooks := storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}}
			if _, err := runScheduledPruneCommand(t.Context(), c, "settle-effect", review.Review.ReviewID, hooks); !hit || !errors.Is(err, fault) {
				t.Fatal("fault not reached", err)
			}
			plain := withoutPruneSettlement(c)
			plain.Storage = nil
			cold := scheduledOperatorReview(t, plain)
			if cold.Executor.Protection.Pending != nil {
				if err := os.Rename(c.SettlementPath, c.SettlementPath+".offline"); err != nil {
					t.Fatal(err)
				}
				resumed, err := RunScheduledPruneCommand(t.Context(), plain, "resume-executor", cold.Review.ReviewID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := RetainedScheduledPruneOutcome(f.inventory, resumed.Executor); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(c.SettlementPath+".offline", c.SettlementPath); err != nil {
					t.Fatal(err)
				}
			}
			stable := scheduledOperatorReview(t, c)
			done, err := RunScheduledPruneCommand(t.Context(), c, "settle-effect", stable.Review.ReviewID)
			if err != nil || done.Executor.FenceSettlement == nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(review.Review.Authority, done.Review.Authority) || !reflect.DeepEqual(review.Review.Storage, done.Review.Storage) {
				t.Fatal("recovery changed accounting/storage")
			}
		})
	}
}
func FuzzDecodePruneSettlement(fuzz *testing.F) {
	// The complete valid seed is produced by the deterministic vector fixture.
	seed := pruneSettlementVector(fuzz)
	raw, _ := seed.CanonicalBytes()
	fuzz.Add(raw)
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		s, err := DecodePruneSettlement(raw)
		if err != nil {
			return
		}
		again, err := s.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("noncanonical settlement")
		}
	})
}

func TestPruneSettlementRejectsFullySignedWrongEffect(t *testing.T) {
	_, configs := observedOutcomeFixture(t)
	c := configs[0]
	before := scheduledOperatorReview(t, c)
	raw, err := os.ReadFile(c.SettlementPath)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := prunefence.DecodeSettlement(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := decision.Proposal
	p.EffectID = testHash(205)
	p.OwnerSignature = [64]byte{}
	p.ControllerSignature = [64]byte{}
	wrong := certifyObservedProposal(t, p)
	bad := c
	bad.SettlementPath = filepath.Join(t.TempDir(), "wrong-effect")
	bad.SettlementID, _ = wrong.ID()
	encoded, _ := wrong.CanonicalBytes()
	writeTestFile(t, bad.SettlementPath, encoded)
	if _, err := RunScheduledPruneCommand(t.Context(), bad, "review", types.Hash{}); err == nil {
		t.Fatal("two signatures and votes overrode actual storage")
	}
	if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
		t.Fatal("forged storage effect changed state")
	}
}

func TestPruneSettlementConcurrentChoiceRecoveryIdentityAndDowngrade(t *testing.T) {
	f, configs := observedOutcomeFixture(t)
	c := configs[0]
	plan, err := LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := plan.Replica(c.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := plan.Request.ID()
	executor, err := OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, primary.Assignment, rid)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close()
	owner, err := OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, primary.Assignment, c.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	storage := c.Storage
	chain, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(storage.ChainPath, storage.ChainPinsPath, storage.Base, storage.Parameters, storage.Policy, f.inventory.Request.StorageID, storage.MigrationID)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	raw, err := os.ReadFile(c.SettlementPath)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := prunefence.DecodeSettlement(raw)
	second, _ := prunefence.DecodeSettlement(raw)
	second.Certificate.Votes = second.Certificate.Votes[:3]
	var firstErr, secondErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, firstErr = executor.SettleObservedEffect(t.Context(), owner, chain, f.inventory, first)
	}()
	go func() {
		defer wait.Done()
		_, secondErr = executor.SettleObservedEffect(t.Context(), owner, chain, f.inventory, second)
	}()
	wait.Wait()
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatal("concurrent attempt did not choose exactly one artifact", firstErr, secondErr)
	}
	snapshot, err := executor.Snapshot()
	if err != nil || snapshot.FenceSettlement == nil || snapshot.FenceResult != nil {
		t.Fatal(err)
	}
	id, _ := snapshot.FenceSettlement.ID()
	bare, _ := snapshot.Effect.ID()
	executor.mu.Lock()
	owner.mu.Lock()
	maintenance, me := maintenanceReviewLocked(executor, owner)
	recovery, re := recoveryReviewLocked(executor, owner)
	owner.mu.Unlock()
	executor.mu.Unlock()
	if me != nil || re != nil || maintenance.TerminalID != id || recovery.TerminalID != id || id == bare {
		t.Fatal("review downgraded terminal evidence", me, re)
	}
	outcome, err := RetainedScheduledPruneOutcome(f.inventory, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	current := testCoordination(t, owner)
	good, err := BuildScheduledPruneOutcomeCompletion(plan, f.inventory, outcome, c.AssignmentID, current.Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := BuildScheduledPruneCompletion(plan, f.inventory, *snapshot.Effect, c.AssignmentID, current.Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	executor.mu.Lock()
	goodErr := executor.validateCompletion(managedCommandApplyTestSign(t, good))
	badErr := executor.validateCompletion(managedCommandApplyTestSign(t, bad))
	executor.mu.Unlock()
	if goodErr != nil || badErr == nil {
		t.Fatal("primary completion bypass", goodErr, badErr)
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	// A copied/stale executor record cannot replace the independently pinned
	// settlement even if its bare storage effect is otherwise perfectly valid.
	effectRaw, _ := snapshot.Effect.CanonicalBytes()
	if err := os.WriteFile(filepath.Join(c.ExecutorPath, "records", "03-result.omcpfx"), effectRaw, 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, primary.Assignment, rid)
	if opened != nil {
		opened.Close()
	}
	if err == nil {
		t.Fatal("cold open accepted downgraded terminal record")
	}
}
