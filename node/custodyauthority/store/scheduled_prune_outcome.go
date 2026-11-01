package store

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// ScheduledPruneOutcome exports exactly one retained terminal artifact. An
// observed-effect settlement is distinct from an effect or pre-start cancellation.
// Export alone releases no replica ticket.
type ScheduledPruneOutcome struct {
	Effect       *workchain.CanonicalPruneEffect
	Cancellation *PruneCancellation
	Settlement   *PruneSettlement
}

func (o ScheduledPruneOutcome) EvidenceID(v ScheduledPruneInventory) (types.Hash, error) {
	if err := v.validate(); err != nil {
		return types.Hash{}, err
	}
	if o.count() != 1 {
		return types.Hash{}, ErrPruneOutcome
	}
	primary, err := scheduledPrunePrimary(v)
	if err != nil {
		return types.Hash{}, err
	}
	if o.Settlement != nil {
		rid, _ := v.Request.ID()
		claim := o.Settlement.Decision.Proposal.Claim
		state := PruneExecution{Request: v.Request, RequestID: rid, Admission: &primary, FenceClaim: &claim}
		if err := verifyPruneSettlement(state, *o.Settlement); err != nil {
			return types.Hash{}, err
		}
		iid, _ := v.ID()
		b := claim.Candidate.Binding
		if b.InventoryID != iid || b.ExecutorBindingID != v.ExecutorBindingID || b.StoragePairID != v.StoragePairID {
			return types.Hash{}, ErrPruneOutcome
		}
		return o.Settlement.ID()
	}
	if o.Effect != nil {
		if !pruneEffectMatches(v.Request, primary, *o.Effect) {
			return types.Hash{}, ErrPruneOutcome
		}
		return o.Effect.ID()
	}
	rid, _ := v.Request.ID()
	ticket, _ := primary.ID()
	c := o.Cancellation
	if c.AssignmentID != v.Request.AssignmentID || c.RequestID != rid || c.TicketID != ticket || c.BindingID != v.ExecutorBindingID || !cancellationMatches(PruneExecution{Request: v.Request, RequestID: rid, Admission: &primary}, *c) {
		return types.Hash{}, ErrPruneOutcome
	}
	return c.ID()
}

func (o ScheduledPruneOutcome) Artifact() ([]byte, error) {
	if o.count() != 1 {
		return nil, ErrPruneOutcome
	}
	if o.Settlement != nil {
		return o.Settlement.CanonicalBytes()
	}
	return (MigratedPruneOutcome{Effect: o.Effect, Cancellation: o.Cancellation}).Artifact()
}

func LoadScheduledPruneOutcome(path, kind string, id types.Hash) (ScheduledPruneOutcome, error) {
	if kind == "settlement" {
		if id.IsZero() {
			return ScheduledPruneOutcome{}, ErrPruneOutcome
		}
		raw, err := readRegular(path, MaximumPruneSettlementBytes)
		if err != nil {
			return ScheduledPruneOutcome{}, err
		}
		value, err := DecodePruneSettlement(raw)
		if err != nil {
			return ScheduledPruneOutcome{}, err
		}
		actual, _ := value.ID()
		if actual != id {
			return ScheduledPruneOutcome{}, ErrPruneOutcome
		}
		return ScheduledPruneOutcome{Settlement: &value}, nil
	}
	o, err := LoadMigratedPruneOutcome(path, kind, id)
	return ScheduledPruneOutcome{Effect: o.Effect, Cancellation: o.Cancellation}, err
}

func (o ScheduledPruneOutcome) count() int {
	n := 0
	if o.Effect != nil {
		n++
	}
	if o.Cancellation != nil {
		n++
	}
	if o.Settlement != nil {
		n++
	}
	return n
}

func scheduledPrunePrimary(v ScheduledPruneInventory) (custodyauthority.Entry, error) {
	for _, s := range v.Replicas {
		id, err := s.Assignment.ID()
		if err == nil && id == v.Request.AssignmentID {
			return s.Admission, nil
		}
	}
	return custodyauthority.Entry{}, ErrScheduledPrune
}

// RetainedScheduledPruneOutcome checks a detached snapshot. Callers publishing
// or applying it must first acquire the original owners and independent pins.
func RetainedScheduledPruneOutcome(v ScheduledPruneInventory, s PruneExecution) (ScheduledPruneOutcome, error) {
	if err := scheduledPruneExecutorBinding(v, s); err != nil {
		return ScheduledPruneOutcome{}, err
	}
	if s.Protection.Pending != nil {
		return ScheduledPruneOutcome{}, ErrPrunePinPending
	}
	id, err := v.ID()
	if err != nil {
		return ScheduledPruneOutcome{}, err
	}
	o := ScheduledPruneOutcome{Effect: s.Effect, Cancellation: s.Cancellation}
	if s.FenceSettlement != nil {
		if s.Stage != PruneSucceeded || s.Effect == nil || s.Cancellation != nil || s.FenceResult != nil || s.ArchiveInventoryID != id {
			return ScheduledPruneOutcome{}, ErrPruneOutcome
		}
		if err := verifyPruneSettlement(s, *s.FenceSettlement); err != nil {
			return ScheduledPruneOutcome{}, err
		}
		effect, err := s.Effect.ID()
		settled, se := s.FenceSettlement.Effect.ID()
		if err != nil || se != nil || effect != settled {
			return ScheduledPruneOutcome{}, ErrPruneOutcome
		}
		o = ScheduledPruneOutcome{Settlement: s.FenceSettlement}
		if _, err := o.EvidenceID(v); err != nil {
			return ScheduledPruneOutcome{}, err
		}
		return o, nil
	}
	if !v.Request.FencePolicyID.IsZero() && s.Stage == PruneCancelled {
		if s.Cancellation == nil || s.Cancellation.Closure == nil || s.FenceClaim != nil || s.FenceResult != nil {
			return ScheduledPruneOutcome{}, ErrPruneOutcome
		}
	} else if !v.Request.FencePolicyID.IsZero() {
		if s.FenceClaim == nil || s.FenceResult == nil || s.Effect == nil || s.Stage != PruneSucceeded {
			return ScheduledPruneOutcome{}, ErrPruneOutcome
		}
		raw, err := encodePruneFenceResult(*s.Effect, *s.FenceResult)
		if err != nil {
			return ScheduledPruneOutcome{}, err
		}
		if err := verifyPruneFenceCandidate(s, s.FenceClaim.Candidate); err != nil {
			return ScheduledPruneOutcome{}, err
		}
		b := s.FenceClaim.Candidate.Binding
		if b.InventoryID != id || b.ExecutorBindingID != v.ExecutorBindingID || b.StoragePairID != v.StoragePairID {
			return ScheduledPruneOutcome{}, ErrPruneOutcome
		}
		if _, _, err := decodePruneFenceResult(s, raw); err != nil {
			return ScheduledPruneOutcome{}, err
		}
	}
	if (s.Stage == PruneSucceeded && s.ArchiveInventoryID == id && o.Effect != nil && o.Cancellation == nil) || (s.Stage == PruneCancelled && s.ArchiveInventoryID.IsZero() && o.Effect == nil && o.Cancellation != nil) {
		if _, err := o.EvidenceID(v); err != nil {
			return ScheduledPruneOutcome{}, err
		}
		return o, nil
	}
	return ScheduledPruneOutcome{}, ErrPruneOutcome
}

func scheduledPruneExecutorBinding(v ScheduledPruneInventory, s PruneExecution) error {
	primary, err := scheduledPrunePrimary(v)
	rid, re := v.Request.ID()
	if err != nil || re != nil || s.Protection == nil || s.Protection.BindingID != v.ExecutorBindingID || s.RequestID != rid || !samePruneRequest(s.Request, v.Request) || s.Admission == nil || *s.Admission != primary {
		return ErrScheduledPrune
	}
	return nil
}
