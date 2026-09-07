package store

import (
	"bytes"
	"context"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// Admit submits one externally co-signed prune admission for this already
// retained request, then independently confirms its executor binding before
// returning. Both lifetime owners stay locked across authority intent, decision,
// confirmation, executor intent, binding and confirmation, in that order.
// It never signs, chooses a head, starts work or completes a ticket.
//
// A retry may resume only this exact authority attempt and this exact admission
// transition. It cannot resume a start/result/cancellation, replace a request or
// clear an unrelated pending attempt. Storage uncertainty requires close/reopen.
// Open itself submits nothing. A historical success is an observation, NOT an
// execution grant: Execute still requires the original live coordinator guard.
// Commit.Appended describes only the authority decision; false may still mean
// this call finished a previously unconfirmed executor admission binding.
func (executor *PruneExecutor) Admit(ctx context.Context, coordinator *Coordinator, entry custodyauthority.Entry) (Commit, error) {
	if executor == nil || coordinator == nil {
		return Commit{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.check(); err != nil {
		return Commit{}, err
	}
	if ctx == nil {
		return Commit{}, ErrPruneRequest
	}
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	if executor.pins == nil {
		return Commit{}, ErrPrunePin
	}
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, entry)
	if err != nil {
		return Commit{}, err
	}
	encoded, _ := entry.CanonicalBytes()
	if executor.admission != nil && *executor.admission != entry {
		return Commit{}, ErrPruneStage
	}
	if executor.pins.pending != nil && (executor.pins.next.Stage != PruneAdmitted || !bytes.Equal(executor.pins.pending, encoded)) {
		return Commit{}, ErrPrunePinPending
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.authority == nil || coordinator.journal == nil {
		return Commit{}, ErrClosed
	}
	if err := executor.checkAuthorityRoots(coordinator); err != nil {
		return Commit{}, err
	}
	result, err := coordinator.append(ctx, entry)
	if err != nil {
		return Commit{}, err
	}
	// Exact retained admission intent is historical evidence, even if a trusted
	// local caller has since drained the ticket. Never resume another transition.
	if executor.pins.pending != nil {
		if err := executor.resumePinnedTransition(ctx); err != nil {
			return Commit{}, err
		}
		return result, nil
	}
	if executor.admission != nil {
		return result, nil
	}
	// No intent exists yet: bind only an actually pending ticket. Stop may have
	// occurred before this retry, but cannot interleave with this guarded section.
	err = coordinator.withOperation(ctx, binding, func() error {
		if err := executor.publish(ctx, 0, encoded, "prune-admission"); err != nil {
			return err
		}
		executor.admission, executor.stage = &entry, PruneAdmitted
		return executor.applied("prune-admission")
	})
	if err != nil {
		return Commit{}, err
	}
	return result, nil
}
