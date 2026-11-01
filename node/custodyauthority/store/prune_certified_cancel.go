package store

import (
	"bytes"
	"context"

	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

func verifyPruneClosure(s PruneExecution, closure prunefence.Closure) error {
	if err := closure.Verify(); err != nil {
		return err
	}
	i := closure.Intent
	policy, err := i.Policy.ID()
	if err != nil || s.Admission == nil || s.Request.FencePolicyID.IsZero() || policy != s.Request.FencePolicyID ||
		i.AssignmentID != s.Request.AssignmentID || i.RequestID != s.RequestID ||
		i.Policy.Owner != s.Request.ConsumerPublicKey || i.Policy.Controller != s.Admission.AuthorityPublicKey {
		return ErrPruneOutcome
	}
	return nil
}

func clonePruneCancellation(c PruneCancellation) PruneCancellation {
	// Called only for validated retained records. Decoding detaches every nested
	// policy/vote slice; returned evidence cannot mutate an open executor.
	raw, _ := c.CanonicalBytes()
	copy, _ := DecodePruneCancellation(raw)
	return copy
}

// CancelWithClosure retains the original controller/witness decision before
// start. It never contacts witnesses, reads storage, signs or completes tickets.
// A retained candidate survives this transition. Started and pending attempts
// stay held; a confirmed retry accepts only the exact retained certificate.
func (executor *PruneExecutor) CancelWithClosure(ctx context.Context, coordinator *Coordinator, closure prunefence.Closure) (PruneCancellation, error) {
	if executor == nil {
		return PruneCancellation{}, ErrClosed
	}
	raw, err := closure.CanonicalBytes()
	if err != nil {
		return PruneCancellation{}, err
	}
	closure, err = prunefence.DecodeClosure(raw)
	if err != nil {
		return PruneCancellation{}, err
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.preStartCancellationCheck(ctx); err != nil {
		return PruneCancellation{}, err
	}
	if err := verifyPruneClosure(executor.execution(), closure); err != nil {
		return PruneCancellation{}, err
	}
	if executor.stage == PruneCancelled {
		if executor.cancellation == nil || executor.cancellation.Closure == nil {
			return PruneCancellation{}, ErrPruneOutcome
		}
		retained, _ := executor.cancellation.Closure.CanonicalBytes()
		if !bytes.Equal(retained, raw) {
			return PruneCancellation{}, ErrPruneOutcome
		}
		return clonePruneCancellation(*executor.cancellation), nil
	}
	if coordinator == nil {
		return PruneCancellation{}, ErrClosed
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil {
		return PruneCancellation{}, err
	}
	c := PruneCancellation{AssignmentID: executor.request.AssignmentID, RequestID: executor.id, TicketID: binding.TicketID, BindingID: executor.pins.binding, Closure: &closure}
	encoded, err := c.CanonicalBytes()
	if err != nil {
		return PruneCancellation{}, err
	}
	err = coordinator.withOperation(ctx, binding, func() error {
		if err := executor.checkAuthorityRoots(coordinator); err != nil {
			return err
		}
		if err := executor.publish(ctx, 1, encoded, "prune-cancel"); err != nil {
			return err
		}
		executor.stage, executor.cancellation = PruneCancelled, &c
		return executor.applied("prune-cancel")
	})
	if err != nil {
		return PruneCancellation{}, err
	}
	return clonePruneCancellation(c), nil
}
