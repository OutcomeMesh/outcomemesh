package store

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// ScheduledPruneOutcome reuses the original effect or pre-start cancellation
// bytes. It does not certify a missing result or release any replica ticket.
type ScheduledPruneOutcome struct {
	Effect       *workchain.CanonicalPruneEffect
	Cancellation *PruneCancellation
}

func (o ScheduledPruneOutcome) EvidenceID(v ScheduledPruneInventory) (types.Hash, error) {
	if err := v.validate(); err != nil {
		return types.Hash{}, err
	}
	if (o.Effect == nil) == (o.Cancellation == nil) {
		return types.Hash{}, ErrPruneOutcome
	}
	primary, err := scheduledPrunePrimary(v)
	if err != nil {
		return types.Hash{}, err
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
	if c.AssignmentID != v.Request.AssignmentID || c.RequestID != rid || c.TicketID != ticket || c.BindingID != v.ExecutorBindingID {
		return types.Hash{}, ErrPruneOutcome
	}
	return c.ID()
}

func (o ScheduledPruneOutcome) Artifact() ([]byte, error) {
	return MigratedPruneOutcome(o).Artifact()
}

func LoadScheduledPruneOutcome(path, kind string, id types.Hash) (ScheduledPruneOutcome, error) {
	o, err := LoadMigratedPruneOutcome(path, kind, id)
	return ScheduledPruneOutcome(o), err
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
