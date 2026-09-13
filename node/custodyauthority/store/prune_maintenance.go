package store

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var (
	ErrPruneServiceQuiesced   = errors.New("prune command service is parked for offline maintenance; close before reopening")
	ErrPruneMaintenanceReview = errors.New("prune maintenance review does not match the exact retained state")
)

// PruneMaintenance is a one-way, local capability after the command transport
// has drained. The original service keeps all four process locks continuously;
// its Close (or this handle's Close) invalidates the capability and releases them.
// No raw owners, WorkChain handle, Execute, signer or generic action escape.
// It does not fence copied owners or establish all-required-assignment coverage.
type PruneMaintenance struct{ service *PruneCommandService }

// PruneMaintenanceReview is detached historical state for one local cancellation
// review. The exact authority and independently confirmed executor prefixes are
// hashed together. Its ID is neither a signature nor reusable execution authority.
type PruneMaintenanceReview struct {
	AssignmentID, RequestID, StorageID, BindingID types.Hash
	Authority                                     custodyauthority.Position
	Phase                                         custodyauthority.Phase
	Executor                                      PrunePosition
	TicketID, TerminalID                          types.Hash
}

func (r PruneMaintenanceReview) ID() (types.Hash, error) {
	if r.AssignmentID.IsZero() || r.RequestID.IsZero() || r.StorageID.IsZero() || r.BindingID.IsZero() ||
		r.Authority.HeadID.IsZero() || r.Executor.HeadID.IsZero() || r.Phase < custodyauthority.Accepting || r.Phase > custodyauthority.Retired ||
		r.Executor.Stage < PrunePrepared || r.Executor.Stage > PruneCancelled ||
		(r.Executor.Stage == PrunePrepared) != r.TicketID.IsZero() ||
		(r.Executor.Stage == PruneSucceeded || r.Executor.Stage == PruneCancelled) != !r.TerminalID.IsZero() {
		return types.Hash{}, ErrPruneMaintenanceReview
	}
	encoded := []byte{0, 0, byte(r.Phase), byte(r.Executor.Stage)}
	encoded = binary.BigEndian.AppendUint64(encoded, r.Authority.Sequence)
	for _, id := range []types.Hash{r.AssignmentID, r.RequestID, r.StorageID, r.BindingID, r.Authority.HeadID, r.Executor.HeadID, r.TicketID, r.TerminalID} {
		encoded = append(encoded, id[:]...)
	}
	return types.DomainHash("OMESH/custody-prune/maintenance/cancel-review/v0", encoded), nil
}

// EnterMaintenance explicitly stops transport and drains accepted handlers while
// retaining all journal locks. It never resumes or confirms an operation. The
// transport context no longer controls ownership after this transition: callers
// must Close the handle or service. Done remains open until those owners close.
// Start cannot restart a parked service; reopen the same roots after Close.
// On error the caller still owns the original service and must Close it.
func (service *PruneCommandService) EnterMaintenance(ctx context.Context) (*PruneMaintenance, error) {
	if service == nil {
		return nil, ErrClosed
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.executor == nil || service.coordinator == nil {
		return nil, ErrClosed
	}
	if ctx == nil {
		return nil, ErrPruneRuntime
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if service.maintenance != nil {
		return nil, ErrPruneServiceQuiesced
	}
	if !service.quiesced {
		// If cancellation already scheduled Close, do not race it for a lease.
		// The callback may be waiting for mu; returning lets it finish shutdown.
		if service.stopWatch != nil && !service.stopWatch() {
			return nil, ErrClosed
		}
		service.stopWatch = nil
		service.quiesced = true
		service.gate.Lock()
		service.accepting = false
		service.gate.Unlock()
		if service.cancel != nil {
			service.cancel()
		}
		if service.host != nil {
			service.quiesceErr = service.host.Close()
		}
		service.inflight.Wait()
		service.gate.Lock()
		service.quiesceErr = errors.Join(service.quiesceErr, service.failure)
		service.gate.Unlock()
		if err := service.hooks.reach("runtime-maintenance-drained"); err != nil {
			service.quiesceErr = errors.Join(service.quiesceErr, ErrUncertain, err)
		}
	}
	if service.quiesceErr != nil {
		return nil, service.quiesceErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owner := &PruneMaintenance{service: service}
	service.maintenance = owner
	return owner, nil
}

// withOwners holds lifecycle -> executor -> coordinator through the entire
// review/action. The callback is private and synchronous; no grant escapes.
func (owner *PruneMaintenance) withOwners(ctx context.Context, action func(*PruneExecutor, *Coordinator) error) error {
	if owner == nil || owner.service == nil {
		return ErrClosed
	}
	s := owner.service
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.quiesced || s.maintenance != owner || s.executor == nil || s.coordinator == nil {
		return ErrClosed
	}
	if s.quiesceErr != nil {
		return s.quiesceErr
	}
	if ctx == nil {
		return ErrPruneRuntime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.executor.mu.Lock()
	defer s.executor.mu.Unlock()
	s.coordinator.mu.Lock()
	defer s.coordinator.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := action(s.executor, s.coordinator)
	if errors.Is(err, ErrUncertain) || errors.Is(err, ErrClosed) {
		s.quiesceErr = errors.Join(s.quiesceErr, err)
	}
	return err
}

func maintenanceReviewLocked(executor *PruneExecutor, coordinator *Coordinator) (PruneMaintenanceReview, error) {
	if err := executor.operationCheck(); err != nil {
		return PruneMaintenanceReview{}, err
	}
	if executor.pins == nil || executor.request.StorageID.IsZero() {
		return PruneMaintenanceReview{}, ErrPrunePin
	}
	state, err := coordinator.snapshot()
	if err != nil {
		return PruneMaintenanceReview{}, err
	}
	if state.Pending != nil {
		return PruneMaintenanceReview{}, ErrPendingAttempt
	}
	protection := executor.pins.protection()
	if protection.Pending != nil || protection.Confirmed.Stage != executor.stage {
		return PruneMaintenanceReview{}, ErrPrunePinPending
	}
	if state.Authority.AssignmentID != executor.request.AssignmentID {
		return PruneMaintenanceReview{}, custodyauthority.ErrAssignment
	}
	r := PruneMaintenanceReview{AssignmentID: executor.request.AssignmentID, RequestID: executor.id,
		StorageID: executor.request.StorageID, BindingID: protection.BindingID, Authority: state.Confirmed,
		Phase: state.Authority.Phase, Executor: protection.Confirmed}
	if executor.admission != nil {
		r.TicketID, err = executor.admission.ID()
		if err != nil {
			return PruneMaintenanceReview{}, err
		}
	}
	if executor.effect != nil {
		r.TerminalID, err = executor.effect.ID()
		if err != nil {
			return PruneMaintenanceReview{}, err
		}
	}
	if executor.cancellation != nil {
		r.TerminalID, err = executor.cancellation.ID()
		if err != nil {
			return PruneMaintenanceReview{}, err
		}
	}
	_, err = r.ID()
	return r, err
}

// Review validates only retained local journals; no database or live archive
// availability is inspected. Unconfirmed attempts block this boundary.
func (owner *PruneMaintenance) Review(ctx context.Context) (PruneMaintenanceReview, error) {
	var review PruneMaintenanceReview
	err := owner.withOwners(ctx, func(e *PruneExecutor, c *Coordinator) (err error) {
		review, err = maintenanceReviewLocked(e, c)
		return err
	})
	if err != nil {
		return PruneMaintenanceReview{}, err
	}
	return review, nil
}

// CancelBeforeStart compares the independently reviewed ID under the SAME
// owner guards held through the existing live pending-ticket check and durable
// cancellation. It cannot cancel Started work or complete an authority ticket.
// The review becomes stale after any history change, including cancellation.
// Re-review is explicit; there is no automatic retry, refresh or resume here.
func (owner *PruneMaintenance) CancelBeforeStart(ctx context.Context, expectedReviewID types.Hash) (PruneCancellation, error) {
	var cancellation PruneCancellation
	err := owner.withOwners(ctx, func(e *PruneExecutor, c *Coordinator) (err error) {
		review, err := maintenanceReviewLocked(e, c)
		if err != nil {
			return err
		}
		id, err := review.ID()
		if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
			return errors.Join(ErrPruneMaintenanceReview, err)
		}
		cancellation, err = e.cancelBeforeStartLocked(ctx, c)
		return err
	})
	if err != nil {
		return PruneCancellation{}, err
	}
	return cancellation, nil
}

func (owner *PruneMaintenance) Close() error {
	if owner == nil || owner.service == nil {
		return nil
	}
	return owner.service.Close()
}
