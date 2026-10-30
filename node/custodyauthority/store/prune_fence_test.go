package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func pruneFencePolicy() prunefence.Policy {
	return prunefence.Policy{Owner: testPublic(4), Controller: testPublic(1), Threshold: 3, Witnesses: f.Scope().Witnesses}
}

type pruneWitnessFixture struct {
	members []*custodyfence.Witness
	scope   custodyfence.Scope
}

func newPruneWitnessFixture(t testing.TB, v ScheduledPruneInventory) *pruneWitnessFixture {
	t.Helper()
	rid, _ := v.Request.ID()
	scope, err := v.FencePolicy.Scope(v.Request.AssignmentID, rid)
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := scope.ID()
	w := &pruneWitnessFixture{scope: scope}
	for seed := byte(70); seed < 74; seed++ {
		member, err := custodyfence.Create(filepath.Join(t.TempDir(), "witness"), scope, sid, testKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		w.members = append(w.members, member)
		t.Cleanup(func() { member.Close() })
	}
	return w
}
func (w *pruneWitnessFixture) collect(ctx context.Context, s custodyfence.Scope, c custodyfence.Command) (custodyfence.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return custodyfence.Certificate{}, err
	}
	have, _ := s.ID()
	want, _ := w.scope.ID()
	if have != want {
		return custodyfence.Certificate{}, prunefence.ErrFence
	}
	c, err := c.Sign(testKey(4))
	if err != nil {
		return custodyfence.Certificate{}, err
	}
	q := custodyfence.Certificate{Version: 1, Command: c}
	for _, member := range w.members {
		v, err := member.Vote(c)
		if err == nil {
			q.Votes = append(q.Votes, v)
		}
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	return q, q.Verify(s)
}
func (f *scheduledPruneFixture) executeFenced(ctx context.Context, collect PruneClaimCollector) (workchain.CanonicalPruneCommit, error) {
	return f.executor.ExecuteScheduledArchiveFenced(ctx, f.archive.f.chain, f.path, f.id, f.operations, f.sources, f.archive.f.base, f.archive.f.parameters, workarchive.DefaultLimits(), collect)
}
func pruneFenceObligations(t testing.TB, f *scheduledPruneFixture) []custodyauthority.Snapshot {
	t.Helper()
	var out []custodyauthority.Snapshot
	for _, op := range f.operations {
		out = append(out, testCoordination(t, op.Coordinator).Authority)
	}
	return out
}
func reopenPruneFence(t testing.TB, f *scheduledPruneFixture) {
	t.Helper()
	e := f.executor
	path, pins, a, id := e.path, e.pins.path, e.assignment, e.id
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.executor, err = OpenPinnedPruneExecutor(path, pins, a, id)
	if err != nil {
		t.Fatal("cold open", err)
	}
}

func TestPruneFenceScheduledExecutionAndOriginalCompletion(t *testing.T) {
	f := newScheduledPruneFixture(t, pruneFencePolicy())
	w := newPruneWitnessFixture(t, f.inventory)
	before := pruneFenceObligations(t, f)
	if _, err := f.execute(t.Context()); err == nil {
		t.Fatal("legacy scheduled path accepted fenced request")
	}
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.operations[0].Coordinator); err == nil {
		t.Fatal("local cancellation bypassed quorum")
	}
	r, err := f.executeFenced(t.Context(), w.collect)
	if err != nil || !r.Applied {
		t.Fatal("fenced deletion", err)
	}
	if !reflect.DeepEqual(before, pruneFenceObligations(t, f)) {
		t.Fatal("deletion released obligations")
	}
	s, err := f.executor.Snapshot()
	if err != nil || s.FenceResult == nil || s.Stage != PruneSucceeded {
		t.Fatal("missing signed result", err)
	}
	proof, _ := s.FenceResult.CanonicalBytes()
	rid, _ := r.Effect.ID()
	if s.FenceResult.EffectID != rid {
		t.Fatal("wrong result binding")
	}
	if _, err := RetainedScheduledPruneOutcome(f.inventory, s); err != nil {
		t.Fatal("valid detached outcome", err)
	}
	for _, missing := range []string{"claim", "signature", "effect"} {
		bad, _ := f.executor.Snapshot()
		switch missing {
		case "claim":
			bad.FenceClaim = nil
		case "signature":
			bad.FenceResult.Signature[0] ^= 1
		case "effect":
			bad.FenceResult.EffectID = testHash(249)
		}
		if _, err := RetainedScheduledPruneOutcome(f.inventory, bad); err == nil {
			t.Fatal("detached outcome accepted invalid fence", missing)
		}
	}
	reopenPruneFence(t, f)
	cold, _ := f.executor.Snapshot()
	again, _ := cold.FenceResult.CanonicalBytes()
	if !bytes.Equal(proof, again) {
		t.Fatal("cold recovery changed proof")
	}
	old, err := f.executor.Recover(t.Context(), f.archive.f.chain)
	if err != nil || old.Applied {
		t.Fatal("result recovery repeated deletion", err)
	}
	p := ScheduledPrunePlan(f.inventory)
	p.ExecutorBindingID = types.Hash{}
	p.Replicas = append([]ScheduledPruneReplica(nil), p.Replicas...)
	for i := range p.Replicas {
		p.Replicas[i].Admission = custodyauthority.Entry{}
	}
	for i, op := range f.operations {
		draft, err := BuildScheduledPruneCompletion(p, f.inventory, r.Effect, op.Binding.AssignmentID, testCoordination(t, op.Coordinator).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		entry := managedCommandApplyTestSign(t, draft)
		if _, err := f.executor.CompleteScheduledArchiveReplica(t.Context(), op.Coordinator, f.path, f.id, entry); err != nil {
			t.Fatal(err)
		}
		after := testCoordination(t, op.Coordinator).Authority
		if after.Pending != before[i].Pending-1 || len(after.Operations) != len(before[i].Operations) {
			t.Fatal("completion changed other obligations or spending")
		}
	}
}

func TestPruneFenceStorageRejectsCrossedPermit(t *testing.T) {
	f := newScheduledPruneFixture(t, pruneFencePolicy())
	s, _ := f.executor.Snapshot()
	op, err := pruneFenceOperation(s)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := op.FenceOperationID()
	w := newPruneWitnessFixture(t, f.inventory)
	b := prunefence.Binding{RequestID: s.RequestID, AssignmentID: s.Request.AssignmentID, OperationID: id, InventoryID: f.id, ExecutorBindingID: f.inventory.ExecutorBindingID, StoragePairID: testHash(248)}
	session, err := prunefence.NewSession(pruneFencePolicy(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	candidate, _ := session.Candidate()
	scope, draft, _ := candidate.Draft()
	q, err := w.collect(t.Context(), scope, draft)
	if err != nil {
		t.Fatal(err)
	}
	permit, _, err := session.Authorize(q)
	if err != nil {
		t.Fatal(err)
	}
	chain := f.archive.f.chain
	before, _ := chain.StorageProtection()
	called := false
	if _, err := chain.PruneCanonicalPrefixFenced(op, func() (uint64, error) { called = true; return 0, nil }, permit); err == nil || called {
		t.Fatal("wrong storage pair reached deletion")
	}
	after, _ := chain.StorageProtection()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("invalid permit mutated storage")
	}
	if _, found, err := chain.CanonicalPruneEffect(op.TicketID); err != nil || found {
		t.Fatal("invalid permit retained effect", err)
	}
}

func TestPruneFenceInterruptedAttemptsNeverRestartOrCancel(t *testing.T) {
	for _, stage := range []string{"prune-fence-candidate-synced", "prune-fence-quorum-before-start", "prune-before-effect", "prune-after-effect", "prune-result-after-publish", "pins-result-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneFixture(t, pruneFencePolicy())
			w := newPruneWitnessFixture(t, f.inventory)
			before := pruneFenceObligations(t, f)
			fault := errors.New("interrupted fence")
			hit := false
			hook := storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}}
			f.executor.hooks = hook
			f.executor.pins.hooks = hook
			if _, err := f.executeFenced(t.Context(), w.collect); err == nil || !hit {
				t.Fatal("fault not reached", err)
			}
			reopenPruneFence(t, f)
			s, _ := f.executor.Snapshot()
			if s.Protection.Pending != nil {
				if err := f.executor.ResumePinnedTransition(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.executeFenced(t.Context(), w.collect); err == nil {
				t.Fatal("cold owner restarted deletion")
			}
			if _, err := f.executor.CancelBeforeStart(t.Context(), f.operations[0].Coordinator); err == nil {
				t.Fatal("uncertain attempt cancelled")
			}
			s, _ = f.executor.Snapshot()
			_, err := f.executor.Recover(t.Context(), f.archive.f.chain)
			if s.Stage == PruneSucceeded {
				if err != nil || s.FenceResult == nil {
					t.Fatal("retained result not recoverable", err)
				}
			} else if err == nil {
				t.Fatal("missing signature reconstructed")
			}
			if !reflect.DeepEqual(before, pruneFenceObligations(t, f)) {
				t.Fatal("fault refunded accounting")
			}
		})
	}
}

func TestPruneFenceMissingQuorumLeavesStorageUntouched(t *testing.T) {
	f := newScheduledPruneFixture(t, pruneFencePolicy())
	w := newPruneWitnessFixture(t, f.inventory)
	before := pruneFenceObligations(t, f)
	_, err := f.executeFenced(t.Context(), func(ctx context.Context, s custodyfence.Scope, c custodyfence.Command) (custodyfence.Certificate, error) {
		q, e := w.collect(ctx, s, c)
		q.Votes = q.Votes[:2]
		return q, e
	})
	if err == nil {
		t.Fatal("minority granted deletion")
	}
	ticket, _ := f.inventory.Replicas[0].Admission.ID()
	if _, found, err := f.archive.f.chain.CanonicalPruneEffect(ticket); err != nil || found {
		t.Fatal("storage changed without quorum", err)
	}
	if !reflect.DeepEqual(before, pruneFenceObligations(t, f)) {
		t.Fatal("minority reset obligations")
	}
	reopenPruneFence(t, f)
	if _, err := f.executeFenced(t.Context(), w.collect); err == nil {
		t.Fatal("lost session replaced")
	}
}

func TestPruneFenceCompetingCopyCannotSelectAnotherSession(t *testing.T) {
	f := newScheduledPruneFixture(t, pruneFencePolicy())
	w := newPruneWitnessFixture(t, f.inventory)
	_, err := f.executeFenced(t.Context(), func(ctx context.Context, s custodyfence.Scope, c custodyfence.Command) (custodyfence.Certificate, error) {
		q, e := w.collect(ctx, s, c)
		if e != nil {
			return q, e
		}
		candidate := *f.executor.fenceCandidate
		// A copied participant may change its inventory and local executor roots,
		// but every such candidate must still contend at this request's old slot.
		candidate.Binding.ExecutorBindingID = testHash(232)
		copySession, e := prunefence.NewSession(candidate.Policy, candidate.Binding)
		if e != nil {
			t.Fatal(e)
		}
		defer copySession.Close()
		copyCandidate, _ := copySession.Candidate()
		copyScope, copyDraft, _ := copyCandidate.Draft()
		if _, e := w.collect(ctx, copyScope, copyDraft); e == nil {
			t.Fatal("copy obtained second quorum")
		}
		if _, _, e := copySession.Authorize(q); e == nil {
			t.Fatal("copy reused original quorum")
		}
		return q, nil
	})
	if err != nil {
		t.Fatal("original execution failed", err)
	}
}
