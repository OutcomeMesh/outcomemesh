package store

import (
	"bytes"
	"context"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// OperationBinding identifies one already admitted operation, not a grant.
type OperationBinding struct {
	AssignmentID      types.Hash
	ScheduleID        types.Hash
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
	if err := coordinator.checkOperation(binding); err != nil {
		return err
	}
	return action()
}

// checkOperation requires the coordinator mutex. It never invokes an effect.
func (coordinator *Coordinator) checkOperation(binding OperationBinding) error {
	current, err := coordinator.snapshot()
	if err != nil {
		return err
	}
	if current.Pending != nil {
		return ErrPendingAttempt
	}
	if current.Authority.Remote != nil {
		return custodyauthority.ErrRemoteActive
	}
	if current.Authority.AssignmentID != binding.AssignmentID || current.Authority.ScheduleID != binding.ScheduleID {
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
			operation.Purpose != binding.Purpose || !operation.CompletionID.IsZero() || !operation.RemoteBeginID.IsZero() {
			// A remote ticket is consumed for live execution permanently, even
			// after its drain is confirmed. Generic local Serve must not become
			// an offline fallback around the worker's sealed session. A future
			// remote completion adapter validates the drain without this guard.
			return custodyauthority.ErrOperation
		}
		return nil
	}
	return custodyauthority.ErrOperation
}

// RequiredOperation couples one local owner to an already signed admission.
// The caller must independently establish the COMPLETE required assignment set;
// this struct and any detached snapshot are not current execution permission.
type RequiredOperation struct {
	Coordinator *Coordinator
	Binding     OperationBinding
}

// withRequiredOperations locks the entire exact set before checking any ticket.
// Callers hold their executor first. No callback can acquire another coordinator;
// all multi-owner paths use assignment-ID order and release in reverse order.
func withRequiredOperations(ctx context.Context, required []RequiredOperation, action func() error) error {
	if ctx == nil || action == nil || len(required) == 0 || len(required) > custodyauthority.MaximumMembers {
		return custodyauthority.ErrOperation
	}
	ordered := append([]RequiredOperation(nil), required...)
	seen := make(map[*Coordinator]bool, len(ordered))
	for _, operation := range ordered {
		b := operation.Binding
		if operation.Coordinator == nil || seen[operation.Coordinator] || b.AssignmentID.IsZero() || b.TicketID.IsZero() ||
			b.OperationID.IsZero() || b.ConsumerPublicKey == [32]byte{} || b.Purpose != custodyauthority.Prune {
			return custodyauthority.ErrOperation
		}
		if operation.Coordinator.assignmentID != b.AssignmentID {
			return custodyauthority.ErrAssignment // never order locks by caller-relabelled owners
		}
		seen[operation.Coordinator] = true
	}
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i].Binding.AssignmentID[:], ordered[j].Binding.AssignmentID[:]) < 0
	})
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Binding.AssignmentID == ordered[i].Binding.AssignmentID {
			return custodyauthority.ErrOperation
		}
	}
	for _, operation := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		operation.Coordinator.mu.Lock()
		defer operation.Coordinator.mu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, operation := range ordered {
		if err := operation.Coordinator.checkOperation(operation.Binding); err != nil {
			return err
		}
	}
	return action()
}
