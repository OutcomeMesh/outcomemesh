package store

import (
	"context"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// OperationBinding identifies one already admitted operation, not a grant.
type OperationBinding struct {
	AssignmentID      types.Hash
	TicketID          types.Hash
	ConsumerPublicKey [32]byte
	OperationID       types.Hash
	Purpose           custodyauthority.Purpose
}

// WithOperation runs a synchronous local effect only while its exact ticket is
// pending in this private, fully confirmed authority. It holds the coordinator
// mutex until action returns, serializing against stop/completion/retirement.
// A retained uncertain authority attempt blocks entry; snapshots are not used as
// reusable permissions. Stopping allows already admitted work to drain.
//
// action must be bounded, must drain every effect before returning, must not
// re-enter this coordinator, and must not retain permission for asynchronous
// work. The caller still owns durable execution deduplication. No ticket is
// completed here, even when action succeeds, errors, panics or is cancelled.
// This is a same-process trust boundary, not a network protocol or fencing of
// copied authority roots/signing keys.
func (coordinator *Coordinator) WithOperation(ctx context.Context, binding OperationBinding, action func() error) error {
	if coordinator == nil {
		return ErrClosed
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return coordinator.withOperation(ctx, binding, action)
}

// withOperation requires the coordinator mutex, including through action.
func (coordinator *Coordinator) withOperation(ctx context.Context, binding OperationBinding, action func() error) error {
	if ctx == nil || action == nil || binding.AssignmentID.IsZero() || binding.TicketID.IsZero() ||
		binding.OperationID.IsZero() || binding.ConsumerPublicKey == [32]byte{} ||
		(binding.Purpose != custodyauthority.Audit && binding.Purpose != custodyauthority.Serve && binding.Purpose != custodyauthority.Prune) {
		return custodyauthority.ErrOperation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := coordinator.snapshot()
	if err != nil {
		return err
	}
	if current.Pending != nil {
		return ErrPendingAttempt
	}
	if current.Authority.AssignmentID != binding.AssignmentID {
		return custodyauthority.ErrAssignment
	}
	if current.Authority.Phase != custodyauthority.Accepting && current.Authority.Phase != custodyauthority.Stopping {
		return custodyauthority.ErrPhase
	}
	for _, operation := range current.Authority.Operations {
		if operation.TicketID != binding.TicketID {
			continue
		}
		if operation.ConsumerPublicKey != binding.ConsumerPublicKey || operation.OperationID != binding.OperationID ||
			operation.Purpose != binding.Purpose || !operation.CompletionID.IsZero() {
			return custodyauthority.ErrOperation
		}
		return action()
	}
	return custodyauthority.ErrOperation
}
