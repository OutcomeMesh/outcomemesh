package store

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var (
	ErrPruneRecoveryReview = errors.New("prune recovery requires the exact reviewed state and action")
	ErrPruneRecoveryScope  = errors.New("retained state has no single eligible prune recovery action")
)

type PruneRecoveryAction uint8

const (
	PruneRecoveryNone PruneRecoveryAction = iota
	PruneRecoveryAuthorityAdmission
	PruneRecoveryAuthorityCompletion
	PruneRecoveryExecutorAdmission
	PruneRecoveryExecutorStart
	PruneRecoveryExecutorResult
	PruneRecoveryExecutorCancellation
	PruneRecoveryBlocked
)

func (action PruneRecoveryAction) String() string {
	switch action {
	case PruneRecoveryNone:
		return "none"
	case PruneRecoveryAuthorityAdmission:
		return "authority-admission"
	case PruneRecoveryAuthorityCompletion:
		return "authority-completion"
	case PruneRecoveryExecutorAdmission:
		return "executor-admission"
	case PruneRecoveryExecutorStart:
		return "executor-start"
	case PruneRecoveryExecutorResult:
		return "executor-result"
	case PruneRecoveryExecutorCancellation:
		return "executor-cancellation"
	case PruneRecoveryBlocked:
		return "blocked"
	default:
		return "invalid"
	}
}

// PruneRecoveryReview describes BOTH independently confirmed prefixes and the
// exact retained intents/observed prefixes. AdmissionID/TerminalID describe the
// retained next executor state when pending, not a confirmed disposition. This
// local historical digest is not a signature, a chain effect or a fresh grant.
type PruneRecoveryReview struct {
	AssignmentID, RequestID, StorageID, BindingID        types.Hash
	AuthorityConfirmed, AuthorityObserved                custodyauthority.Position
	AuthorityPhase                                       custodyauthority.Phase
	AuthorityPendingID                                   types.Hash
	AuthorityPendingKind                                 custodyauthority.Kind
	ExecutorConfirmed, ExecutorObserved, ExecutorPending PrunePosition
	AdmissionID, TerminalID                              types.Hash
	Action                                               PruneRecoveryAction
}

func (review PruneRecoveryReview) ID() (types.Hash, error) {
	if review.AssignmentID.IsZero() || review.RequestID.IsZero() || review.StorageID.IsZero() || review.BindingID.IsZero() ||
		review.AuthorityConfirmed.HeadID.IsZero() || review.AuthorityObserved.HeadID.IsZero() ||
		review.AuthorityPhase < custodyauthority.Accepting || review.AuthorityPhase > custodyauthority.Retired ||
		!validPruneRecoveryPosition(review.ExecutorConfirmed) || !validPruneRecoveryPosition(review.ExecutorObserved) ||
		review.Action > PruneRecoveryBlocked {
		return types.Hash{}, ErrPruneRecoveryReview
	}
	authorityPending := !review.AuthorityPendingID.IsZero()
	executorPending := review.ExecutorPending != (PrunePosition{})
	if authorityPending {
		if review.AuthorityPendingKind < custodyauthority.Admit || review.AuthorityPendingKind > custodyauthority.Retire ||
			review.AuthorityConfirmed.Sequence == ^uint64(0) ||
			(review.AuthorityObserved != review.AuthorityConfirmed && review.AuthorityObserved != (custodyauthority.Position{Sequence: review.AuthorityConfirmed.Sequence + 1, HeadID: review.AuthorityPendingID})) {
			return types.Hash{}, ErrPruneRecoveryReview
		}
	} else if review.AuthorityPendingKind != 0 || review.AuthorityObserved != review.AuthorityConfirmed {
		return types.Hash{}, ErrPruneRecoveryReview
	}
	if executorPending {
		if !validPruneRecoveryPosition(review.ExecutorPending) ||
			(review.ExecutorPending.Stage != review.ExecutorConfirmed.Stage+1 && !(review.ExecutorConfirmed.Stage == PruneAdmitted && review.ExecutorPending.Stage == PruneCancelled)) ||
			review.ExecutorConfirmed.Stage >= PruneSucceeded ||
			(review.ExecutorObserved != review.ExecutorConfirmed && review.ExecutorObserved != review.ExecutorPending) {
			return types.Hash{}, ErrPruneRecoveryReview
		}
	} else if review.ExecutorObserved != review.ExecutorConfirmed {
		return types.Hash{}, ErrPruneRecoveryReview
	}
	retainedStage := review.ExecutorObserved.Stage
	if executorPending {
		retainedStage = review.ExecutorPending.Stage
	}
	if (retainedStage == PrunePrepared) != review.AdmissionID.IsZero() ||
		(retainedStage == PruneSucceeded || retainedStage == PruneCancelled) != !review.TerminalID.IsZero() {
		return types.Hash{}, ErrPruneRecoveryReview
	}
	switch review.Action {
	case PruneRecoveryNone:
		if authorityPending || executorPending {
			return types.Hash{}, ErrPruneRecoveryReview
		}
	case PruneRecoveryAuthorityAdmission, PruneRecoveryAuthorityCompletion:
		kind := custodyauthority.Admit
		if review.Action == PruneRecoveryAuthorityCompletion {
			kind = custodyauthority.Complete
		}
		if !authorityPending || executorPending || review.AuthorityPendingKind != kind {
			return types.Hash{}, ErrPruneRecoveryReview
		}
	case PruneRecoveryExecutorAdmission, PruneRecoveryExecutorStart, PruneRecoveryExecutorResult, PruneRecoveryExecutorCancellation:
		if authorityPending || !executorPending || executorRecoveryAction(review.ExecutorPending.Stage) != review.Action {
			return types.Hash{}, ErrPruneRecoveryReview
		}
	case PruneRecoveryBlocked:
		if !authorityPending && !executorPending {
			return types.Hash{}, ErrPruneRecoveryReview
		}
	}
	encoded := []byte{0, 0, byte(review.Action), byte(review.AuthorityPhase), byte(review.AuthorityPendingKind),
		byte(review.ExecutorConfirmed.Stage), byte(review.ExecutorObserved.Stage), byte(review.ExecutorPending.Stage)}
	encoded = binary.BigEndian.AppendUint64(encoded, review.AuthorityConfirmed.Sequence)
	encoded = binary.BigEndian.AppendUint64(encoded, review.AuthorityObserved.Sequence)
	for _, id := range []types.Hash{review.AssignmentID, review.RequestID, review.StorageID, review.BindingID,
		review.AuthorityConfirmed.HeadID, review.AuthorityObserved.HeadID, review.AuthorityPendingID,
		review.ExecutorConfirmed.HeadID, review.ExecutorObserved.HeadID, review.ExecutorPending.HeadID, review.AdmissionID, review.TerminalID} {
		encoded = append(encoded, id[:]...)
	}
	return types.DomainHash("OMESH/custody-prune/maintenance/recovery-review/v0", encoded), nil
}

func validPruneRecoveryPosition(position PrunePosition) bool {
	return position.Stage >= PrunePrepared && position.Stage <= PruneCancelled && !position.HeadID.IsZero()
}

func executorRecoveryAction(stage PruneStage) PruneRecoveryAction {
	switch stage {
	case PruneAdmitted:
		return PruneRecoveryExecutorAdmission
	case PruneStarted:
		return PruneRecoveryExecutorStart
	case PruneSucceeded:
		return PruneRecoveryExecutorResult
	case PruneCancelled:
		return PruneRecoveryExecutorCancellation
	default:
		return PruneRecoveryBlocked
	}
}

// recoveryReviewLocked requires the same lifecycle -> executor -> coordinator
// guards used by Recover. Checking accepts pending evidence but never promotes
// it. Corruption/sticky uncertainty still requires close/reopen, not a retry.
func recoveryReviewLocked(executor *PruneExecutor, coordinator *Coordinator) (PruneRecoveryReview, error) {
	if err := executor.check(); err != nil {
		return PruneRecoveryReview{}, err
	}
	if executor.pins == nil || executor.request.StorageID.IsZero() {
		return PruneRecoveryReview{}, ErrPrunePin
	}
	state, err := coordinator.snapshot()
	if err != nil {
		return PruneRecoveryReview{}, err
	}
	if err := executor.checkAuthorityRoots(coordinator); err != nil {
		return PruneRecoveryReview{}, err
	}
	if state.Authority.AssignmentID != executor.request.AssignmentID {
		return PruneRecoveryReview{}, custodyauthority.ErrAssignment
	}
	protection := executor.pins.protection()
	review := PruneRecoveryReview{AssignmentID: executor.request.AssignmentID, RequestID: executor.id,
		StorageID: executor.request.StorageID, BindingID: protection.BindingID, AuthorityConfirmed: state.Confirmed,
		AuthorityObserved: custodyauthority.Position{Sequence: state.Authority.Sequence, HeadID: state.Authority.HeadID},
		AuthorityPhase:    state.Authority.Phase, ExecutorConfirmed: protection.Confirmed, ExecutorObserved: protection.Confirmed}
	retained := executor.execution()
	if protection.Pending != nil {
		review.ExecutorPending = *protection.Pending
		if executor.stage != protection.Confirmed.Stage {
			review.ExecutorObserved = *protection.Pending
		}
		retained = executor.pins.next
		review.Action = executorRecoveryAction(protection.Pending.Stage)
	}
	if retained.Admission != nil {
		if review.AdmissionID, err = retained.Admission.ID(); err != nil {
			return PruneRecoveryReview{}, err
		}
	}
	if retained.Effect != nil {
		if review.TerminalID, err = retained.Effect.ID(); err != nil {
			return PruneRecoveryReview{}, err
		}
	}
	if retained.Cancellation != nil {
		if review.TerminalID, err = retained.Cancellation.ID(); err != nil {
			return PruneRecoveryReview{}, err
		}
	}
	if state.Pending != nil {
		review.AuthorityPendingID, err = state.Pending.ID()
		if err != nil {
			return PruneRecoveryReview{}, err
		}
		review.AuthorityPendingKind = state.Pending.Command.Kind
		review.Action = PruneRecoveryBlocked // never resume unrelated, Stop/Retire, or two-layer ambiguity
		if protection.Pending == nil {
			switch state.Pending.Command.Kind {
			case custodyauthority.Admit:
				if executor.stage == PrunePrepared {
					if _, err := pruneAdmissionBinding(executor.assignment, executor.request, *state.Pending); err == nil {
						review.Action = PruneRecoveryAuthorityAdmission
					}
				}
			case custodyauthority.Complete:
				if err := executor.validateCompletion(*state.Pending); err == nil {
					review.Action = PruneRecoveryAuthorityCompletion
				}
			}
		}
	}
	_, err = review.ID()
	return review, err
}

func (owner *PruneMaintenance) ReviewRecovery(ctx context.Context) (PruneRecoveryReview, error) {
	var review PruneRecoveryReview
	err := owner.withOwners(ctx, func(e *PruneExecutor, c *Coordinator) (err error) {
		review, err = recoveryReviewLocked(e, c)
		return err
	})
	if err != nil {
		return PruneRecoveryReview{}, err
	}
	return review, nil
}

type PruneRecoveryResult struct {
	Before, After PruneRecoveryReview
}

// Recover finishes ONE already retained intent, selected by an explicit action
// and exact recovery-review ID under the same owner guards. It never creates a
// replacement intent, fills a missing binding, signs, executes WorkChain or
// chains into the next operation. A recovered start remains Started/unknown.
// The old review becomes stale even if the resulting stdout/reply is lost.
func (owner *PruneMaintenance) Recover(ctx context.Context, expected types.Hash, action PruneRecoveryAction) (PruneRecoveryResult, error) {
	var result PruneRecoveryResult
	err := owner.withOwners(ctx, func(e *PruneExecutor, c *Coordinator) error {
		before, err := recoveryReviewLocked(e, c)
		if err != nil {
			return err
		}
		id, err := before.ID()
		if err != nil || expected.IsZero() || expected != id || action != before.Action {
			return errors.Join(ErrPruneRecoveryReview, err)
		}
		if action == PruneRecoveryNone || action == PruneRecoveryBlocked {
			return ErrPruneRecoveryScope
		}
		if err := owner.service.hooks.reach("recovery-reviewed"); err != nil {
			return err
		}
		switch action {
		case PruneRecoveryAuthorityAdmission, PruneRecoveryAuthorityCompletion:
			_, err = c.resume(ctx)
		default:
			err = e.resumePinnedTransition(ctx)
		}
		if err != nil {
			return err
		}
		after, err := recoveryReviewLocked(e, c)
		if err != nil {
			return errors.Join(ErrUncertain, err)
		}
		if after.Action != PruneRecoveryNone {
			return ErrUncertain
		}
		if err := owner.service.hooks.reach("recovery-confirmed"); err != nil {
			return errors.Join(ErrUncertain, err)
		}
		result = PruneRecoveryResult{Before: before, After: after}
		return nil
	})
	if err != nil {
		return PruneRecoveryResult{}, err
	}
	return result, nil
}
