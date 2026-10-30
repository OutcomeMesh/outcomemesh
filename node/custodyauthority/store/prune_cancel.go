package store

import (
	"bytes"
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const MaximumPruneCancellationBytes = 138

var (
	ErrPruneCancelled      = errors.New("prune operation was durably cancelled before start")
	pruneCancellationMagic = []byte("OMCPCNCL\x00\x00")
)

// PruneCancellation is retained evidence that this pinned executor chose its
// terminal cancellation branch BEFORE start. It is not a signed completion,
// global no-effect certificate, storage inspection or permission to reuse work.
// Copies/shared rollback of executor roots are outside this local guarantee.
type PruneCancellation struct {
	AssignmentID types.Hash
	RequestID    types.Hash
	TicketID     types.Hash
	BindingID    types.Hash
}

func (c PruneCancellation) CanonicalBytes() ([]byte, error) {
	if c.AssignmentID.IsZero() || c.RequestID.IsZero() || c.TicketID.IsZero() || c.BindingID.IsZero() {
		return nil, ErrPruneStage
	}
	encoded := append([]byte(nil), pruneCancellationMagic...)
	for _, id := range []types.Hash{c.AssignmentID, c.RequestID, c.TicketID, c.BindingID} {
		encoded = append(encoded, id[:]...)
	}
	return encoded, nil
}

func DecodePruneCancellation(input []byte) (PruneCancellation, error) {
	var c PruneCancellation
	if len(input) != MaximumPruneCancellationBytes || !bytes.HasPrefix(input, pruneCancellationMagic) {
		return c, ErrPruneStage
	}
	for i, id := range []*types.Hash{&c.AssignmentID, &c.RequestID, &c.TicketID, &c.BindingID} {
		copy(id[:], input[10+i*types.HashSize:10+(i+1)*types.HashSize])
	}
	if _, err := c.CanonicalBytes(); err != nil {
		return PruneCancellation{}, err
	}
	return c, nil
}

func (c PruneCancellation) ID() (types.Hash, error) {
	encoded, err := c.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-prune/cancellation/id/v0", encoded), nil
}

// CancelBeforeStart irrevocably cancels an admitted but never-started operation.
// Independent executor stage pins are REQUIRED. The executor and current local
// pending-ticket guard are held through intent, terminal record and independent
// confirmation. Stopping may drain this way; completed/retired tickets cannot.
//
// No WorkChain handle is accepted and no database is queried. A retained or
// uncertain start can never take this branch, even if no chain effect is found.
// A confirmed exact retry returns historical evidence without acquiring current
// authority. Completion still requires a separate consumer-signed command and
// authority decision; this method never closes a ticket or admits replacement work.
func (executor *PruneExecutor) CancelBeforeStart(ctx context.Context, coordinator *Coordinator) (PruneCancellation, error) {
	if executor == nil {
		return PruneCancellation{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	// Preserve the historical/nil-context paths without acquiring authority.
	if err := executor.cancellationCheck(ctx); err != nil {
		return PruneCancellation{}, err
	}
	if executor.stage == PruneCancelled {
		return *executor.cancellation, nil
	}
	if coordinator == nil {
		return PruneCancellation{}, ErrClosed
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return executor.cancelBeforeStartLocked(ctx, coordinator)
}

// Both owners' mutexes must be held (unless coordinator is nil). The historical
// branch requires no live authority grant, even with a closed coordinator.
func (executor *PruneExecutor) cancelBeforeStartLocked(ctx context.Context, coordinator *Coordinator) (PruneCancellation, error) {
	if err := executor.cancellationCheck(ctx); err != nil {
		return PruneCancellation{}, err
	}
	if executor.stage == PruneCancelled {
		return *executor.cancellation, nil
	}
	if coordinator == nil {
		return PruneCancellation{}, ErrClosed
	}
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil {
		return PruneCancellation{}, err
	}
	cancellation := PruneCancellation{AssignmentID: executor.request.AssignmentID, RequestID: executor.id, TicketID: binding.TicketID, BindingID: executor.pins.binding}
	encoded, _ := cancellation.CanonicalBytes()
	err = coordinator.withOperation(ctx, binding, func() error {
		if err := executor.checkAuthorityRoots(coordinator); err != nil {
			return err
		}
		if err := executor.publish(ctx, 1, encoded, "prune-cancel"); err != nil {
			return err
		}
		executor.stage, executor.cancellation = PruneCancelled, &cancellation
		return executor.applied("prune-cancel")
	})
	if err != nil {
		return PruneCancellation{}, err
	}
	return cancellation, nil
}

// cancellationCheck requires the executor mutex, but no authority ownership.
func (executor *PruneExecutor) cancellationCheck(ctx context.Context) error {
	if !executor.request.FencePolicyID.IsZero() {
		return ErrPruneOutcome
	}
	if err := executor.operationCheck(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrPruneRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if executor.pins == nil {
		return ErrPrunePin
	}
	if executor.stage == PruneStarted {
		return ErrPruneOutcome
	}
	if executor.stage != PruneAdmitted && executor.stage != PruneCancelled {
		return ErrPruneStage
	}
	return nil
}

func pruneRecordCount(stage PruneStage) int {
	if stage == PruneCancelled {
		return 2
	}
	return int(stage - PrunePrepared)
}

func pruneRecordName(index int, next PruneStage) string {
	if index == 1 && next == PruneCancelled {
		return "02-cancelled.omcpc"
	}
	return pruneRecordNames[index]
}

func pruneTransitionLabel(index int, next PruneStage) string {
	if next == PruneCancelled {
		return "cancel"
	}
	return []string{"admission", "start", "result"}[index]
}

func cancellationMatches(current PruneExecution, c PruneCancellation) bool {
	if current.Admission == nil || c.AssignmentID != current.Request.AssignmentID || c.RequestID != current.RequestID {
		return false
	}
	ticket, err := current.Admission.ID()
	return err == nil && c.TicketID == ticket
}

func checkCancellationBinding(next PruneExecution, binding types.Hash) error {
	if next.Cancellation != nil && (binding.IsZero() || next.Cancellation.BindingID != binding) {
		return ErrPrunePin
	}
	return nil
}
