package store

import (
	"bytes"
	"context"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const MaximumPruneSettlementBytes = workchain.MaximumCanonicalPruneEffectBytes + prunefence.MaximumSettlementBytes + 32

// PruneSettlement is retained observed-effect evidence, explicitly distinct from
// a live-session result. Its ID, not the bare effect ID, binds later completion.
type PruneSettlement struct {
	Effect   workchain.CanonicalPruneEffect
	Decision prunefence.Settlement
}

func (s PruneSettlement) CanonicalBytes() ([]byte, error) {
	effect, err := s.Effect.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	id, _ := s.Effect.ID()
	op, err := s.Effect.Operation.FenceOperationID()
	if err != nil || id != s.Decision.Proposal.EffectID || op != s.Decision.Proposal.Claim.Candidate.Binding.OperationID {
		return nil, ErrPruneOutcome
	}
	decision, err := s.Decision.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumPruneSettlementBytes)
	e.Fixed([]byte("OMCPSE00"))
	e.U16(0)
	e.BytesField(effect)
	e.BytesField(decision)
	return e.Bytes(), nil
}
func (s PruneSettlement) ID() (types.Hash, error) {
	b, err := s.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-prune/settlement/id/v0", b), nil
}
func DecodePruneSettlement(raw []byte) (PruneSettlement, error) {
	var s PruneSettlement
	if len(raw) > MaximumPruneSettlementBytes {
		return s, ErrPruneOutcome
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMCPSE00" || v != 0 {
		return s, ErrPruneOutcome
	}
	effect, err := d.BytesField(workchain.MaximumCanonicalPruneEffectBytes)
	if err != nil {
		return s, err
	}
	s.Effect, err = workchain.DecodeCanonicalPruneEffect(effect)
	if err != nil {
		return s, err
	}
	decision, err := d.BytesField(prunefence.MaximumSettlementBytes)
	if err != nil {
		return s, err
	}
	s.Decision, err = prunefence.DecodeSettlement(decision)
	if err != nil {
		return s, err
	}
	b, err := s.CanonicalBytes()
	if err != nil || d.Finish() != nil || !bytes.Equal(raw, b) {
		return PruneSettlement{}, ErrPruneOutcome
	}
	return s, nil
}
func clonePruneSettlement(s PruneSettlement) PruneSettlement {
	b, _ := s.CanonicalBytes()
	copy, _ := DecodePruneSettlement(b)
	return copy
}

func verifyPruneSettlement(s PruneExecution, settlement PruneSettlement) error {
	if s.FenceClaim == nil || s.FenceResult != nil || s.Admission == nil || s.Cancellation != nil {
		return ErrPruneOutcome
	}
	if _, err := settlement.CanonicalBytes(); err != nil {
		return err
	}
	claim := settlement.Decision.Proposal.Claim
	if err := verifyPruneFenceCandidate(s, claim.Candidate); err != nil {
		return err
	}
	have, _ := claim.CanonicalBytes()
	want, err := s.FenceClaim.CanonicalBytes()
	if err != nil || !bytes.Equal(have, want) || !pruneEffectMatches(s.Request, *s.Admission, settlement.Effect) {
		return ErrPruneOutcome
	}
	return nil
}

// observedPruneSettlement reads only immutable historical evidence. No record is
// not evidence of no effect. The original executor lock excludes a still-running
// local session; this is not hardware fencing against a full-machine rollback.
func observedPruneSettlement(v ScheduledPruneInventory, s PruneExecution, chain *workchain.Store) (workchain.CanonicalPruneEffect, prunefence.SettlementProposal, error) {
	var zero workchain.CanonicalPruneEffect
	var proposal prunefence.SettlementProposal
	if chain == nil || v.validate() != nil || scheduledPruneExecutorBinding(v, s) != nil || s.Protection.Pending != nil || s.Stage != PruneStarted || s.FenceClaim == nil || s.FenceResult != nil || s.FenceSettlement != nil || s.Effect != nil || s.Cancellation != nil {
		return zero, proposal, ErrPruneOutcome
	}
	iid, _ := v.ID()
	b := s.FenceClaim.Candidate.Binding
	if s.ArchiveInventoryID != iid || b.InventoryID != iid || b.ExecutorBindingID != v.ExecutorBindingID || b.StoragePairID != v.StoragePairID {
		return zero, proposal, ErrPruneOutcome
	}
	if err := verifyPruneFenceCandidate(s, s.FenceClaim.Candidate); err != nil {
		return zero, proposal, err
	}
	primary, err := scheduledPrunePrimary(v)
	if err != nil {
		return zero, proposal, err
	}
	ticket, _ := primary.ID()
	inspection, err := chain.InspectCanonicalPrune(ticket)
	if err != nil {
		return zero, proposal, err
	}
	if inspection.Storage.StorageID != v.Request.StorageID || inspection.Storage.PairID != v.StoragePairID || inspection.Effect == nil || !pruneEffectMatches(v.Request, primary, *inspection.Effect) {
		return zero, proposal, ErrPruneOutcome
	}
	raw, err := s.FenceClaim.CanonicalBytes()
	if err != nil {
		return zero, proposal, err
	}
	claim, _ := prunefence.DecodeClaim(raw)
	id, _ := inspection.Effect.ID()
	proposal = prunefence.SettlementProposal{Claim: claim, EffectID: id}
	return *inspection.Effect, proposal, nil
}

// SettleObservedEffect retains a co-signed, witness-selected decision only after
// reading the exact committed effect from the original protected storage pair.
// It never executes work, recreates a session signature or completes an admission.
func (executor *PruneExecutor) SettleObservedEffect(ctx context.Context, coordinator *Coordinator, chain *workchain.Store, inventory ScheduledPruneInventory, decision prunefence.Settlement) (PruneSettlement, error) {
	var zero PruneSettlement
	if executor == nil || coordinator == nil || ctx == nil {
		return zero, ErrClosed
	}
	raw, err := decision.CanonicalBytes()
	if err != nil {
		return zero, err
	}
	decision, err = prunefence.DecodeSettlement(raw)
	if err != nil {
		return zero, err
	}
	// Inventory codecs detach nested caller-owned slices before any owner wait.
	inv, err := inventory.CanonicalBytes()
	if err != nil {
		return zero, err
	}
	inventory, err = DecodeScheduledPruneInventory(inv)
	if err != nil {
		return zero, err
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	s := executor.snapshot()
	if err := scheduledPruneExecutorBinding(inventory, s); err != nil {
		return zero, err
	}
	if s.Stage == PruneSucceeded {
		if s.FenceSettlement == nil {
			return zero, ErrPruneOutcome
		}
		retained, _ := s.FenceSettlement.Decision.CanonicalBytes()
		if !bytes.Equal(retained, raw) {
			return zero, ErrPruneOutcome
		}
		if _, err := RetainedScheduledPruneOutcome(inventory, s); err != nil {
			return zero, err
		}
		return clonePruneSettlement(*s.FenceSettlement), nil
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if executor.admission == nil {
		return zero, ErrPruneOutcome
	}
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil {
		return zero, err
	}
	var settlement PruneSettlement
	err = coordinator.withOperation(ctx, binding, func() error {
		if err := executor.checkAuthorityRoots(coordinator); err != nil {
			return err
		}
		if chain == nil {
			return ErrPruneOutcome
		}
		if err := chain.VerifyContext(executor.assignment.NetworkID, executor.assignment.ActivationHeight, executor.assignment.BaseID); err != nil {
			return err
		}
		effect, proposal, err := observedPruneSettlement(inventory, s, chain)
		if err != nil {
			return err
		}
		// Only the signatures differ from the owner-verified proposal.
		proposal.OwnerSignature = decision.Proposal.OwnerSignature
		proposal.ControllerSignature = decision.Proposal.ControllerSignature
		want, err := proposal.CanonicalBytes()
		have, _ := decision.Proposal.CanonicalBytes()
		if err != nil || !bytes.Equal(want, have) {
			return ErrPruneOutcome
		}
		settlement = PruneSettlement{Effect: effect, Decision: decision}
		if err := verifyPruneSettlement(s, settlement); err != nil {
			return err
		}
		encoded, err := settlement.CanonicalBytes()
		if err != nil {
			return err
		}
		if err := executor.hooks.reach("prune-settlement-before-retain"); err != nil {
			return err
		}
		if err := executor.publish(ctx, 2, encoded, "prune-result"); err != nil {
			return err
		}
		next, err := advancePruneExecution(executor.assignment, executor.execution(), encoded)
		if err != nil {
			return executor.poison(err)
		}
		executor.installExecution(next)
		return executor.applied("prune-result")
	})
	if err != nil {
		return zero, err
	}
	return clonePruneSettlement(settlement), nil
}

// VerifyScheduledPruneSettlementProposal checks pinned static context for offline
// signing. It proves neither physical storage nor current permission; application
// must still acquire the original owners and re-read the committed effect.
func VerifyScheduledPruneSettlementProposal(plan ScheduledPrunePlan, v ScheduledPruneInventory, p prunefence.SettlementProposal) error {
	if err := plan.BindInventory(v); err != nil {
		return err
	}
	if _, err := p.CanonicalBytes(); err != nil {
		return err
	}
	primary, err := scheduledPrunePrimary(v)
	if err != nil {
		return err
	}
	rid, _ := v.Request.ID()
	if err := verifyPruneFenceCandidate(PruneExecution{Request: v.Request, RequestID: rid, Admission: &primary}, p.Claim.Candidate); err != nil {
		return err
	}
	iid, _ := v.ID()
	b := p.Claim.Candidate.Binding
	if b.InventoryID != iid || b.ExecutorBindingID != v.ExecutorBindingID || b.StoragePairID != v.StoragePairID {
		return ErrPruneOutcome
	}
	return nil
}
