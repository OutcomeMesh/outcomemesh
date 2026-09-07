package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

var (
	ErrPrunePin        = errors.New("prune executor history does not match independent stage pins")
	ErrPrunePinPending = errors.New("prune stage transition is retained but unconfirmed; resume that exact transition first")
)

// PrunePosition commits an exact local journal prefix, not authority or storage
// freshness. The initial Prepared head is the independently selected request ID.
type PrunePosition struct {
	Stage  PruneStage
	HeadID types.Hash
}

// PruneProtection is detached diagnostic evidence. BindingID prevents accidental
// pairing of independently initialized roots; it is not a physical storage ID.
type PruneProtection struct {
	BindingID types.Hash
	Confirmed PrunePosition
	Pending   *PrunePosition
}

func advancePruneExecution(assignment custodyauthority.Assignment, current PruneExecution, encoded []byte) (PruneExecution, error) {
	if len(encoded) > workchain.MaximumCanonicalPruneEffectBytes {
		return PruneExecution{}, ErrPruneStage
	}
	next := current
	next.Protection = nil
	switch current.Stage {
	case PrunePrepared:
		admission, err := custodyauthority.DecodeEntry(encoded)
		if err != nil {
			return PruneExecution{}, err
		}
		if _, err := pruneAdmissionBinding(assignment, current.Request, admission); err != nil {
			return PruneExecution{}, err
		}
		next.Admission = &admission
	case PruneAdmitted:
		if current.Admission == nil {
			return PruneExecution{}, ErrPruneStage
		}
		if bytes.HasPrefix(encoded, pruneCancellationMagic) {
			cancellation, err := DecodePruneCancellation(encoded)
			if err != nil || !cancellationMatches(current, cancellation) {
				return PruneExecution{}, ErrPruneStage
			}
			next.Stage, next.Cancellation = PruneCancelled, &cancellation
			return next, nil
		}
		ticket, err := current.Admission.ID()
		if err != nil || !bytes.Equal(encoded, pruneStartedBytes(current.RequestID, ticket)) {
			return PruneExecution{}, ErrPruneStage
		}
	case PruneStarted:
		if current.Admission == nil {
			return PruneExecution{}, ErrPruneStage
		}
		effect, err := workchain.DecodeCanonicalPruneEffect(encoded)
		if err != nil || !pruneEffectMatches(current.Request, *current.Admission, effect) {
			return PruneExecution{}, errors.Join(ErrPruneOutcome, err)
		}
		next.Effect = &effect
	default:
		return PruneExecution{}, ErrPruneStage
	}
	next.Stage++
	return next, nil
}

func nextPrunePosition(previous PrunePosition, encoded []byte) PrunePosition {
	stage := previous.Stage + 1
	if previous.Stage == PruneAdmitted && bytes.HasPrefix(encoded, pruneCancellationMagic) {
		stage = PruneCancelled
	}
	return PrunePosition{Stage: stage, HeadID: types.DomainHash("OMESH/custody-prune/position/id/v0", previous.HeadID[:], []byte{byte(stage)}, encoded)}
}

// CreatePinnedPruneExecutor initializes TWO NEW disjoint roots, locking the pin
// journal before the executor. It never attaches fresh pins to existing work.
// Protect the independently configured pin root against the executor's failure/
// rollback domain. Two local paths alone do not establish that independence.
func CreatePinnedPruneExecutor(path, pinPath string, assignment custodyauthority.Assignment, request PruneRequest, expectedID types.Hash) (*PruneExecutor, error) {
	return createPinnedPruneExecutor(path, pinPath, assignment, request, expectedID, storeHooks{}, storeHooks{})
}

func createPinnedPruneExecutor(path, pinPath string, assignment custodyauthority.Assignment, request PruneRequest, expectedID types.Hash, hooks, pinHooks storeHooks) (_ *PruneExecutor, err error) {
	if err := validatePruneRequest(assignment, request, expectedID); err != nil {
		return nil, err
	}
	path, pinPath, err = coordinatorPaths(path, pinPath)
	if err != nil {
		return nil, err
	}
	// Reject either existing root before creating anything. No migration, reset,
	// or pin attachment is inferred from an empty-looking existing history.
	for _, root := range []string{path, pinPath} {
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(os.ErrExist, err)
		}
	}
	var binding types.Hash
	if _, err := rand.Read(binding[:]); err != nil {
		return nil, err
	}
	if binding.IsZero() {
		return nil, ErrPrunePin
	}
	var executor *PruneExecutor
	defer func() {
		if err != nil && executor != nil {
			err = errors.Join(err, executor.Close())
		}
	}()
	pins, err := createPrunePinJournal(pinPath, assignment, request, expectedID, binding, func() error {
		var createErr error
		executor, createErr = createPruneExecutorBound(path, assignment, request, expectedID, binding, hooks)
		return createErr
	}, pinHooks)
	if err != nil {
		return nil, err
	}
	executor.pins = pins
	if err := executor.check(); err != nil {
		return nil, err
	}
	return executor, nil
}

// OpenPinnedPruneExecutor loads independent intent/confirmation history FIRST.
// It accepts the exact confirmed executor prefix or its one exact retained next
// transition. It never publishes, confirms, starts pruning or completes a ticket.
// A version-1 pinned executor cannot be opened through OpenPruneExecutor.
func OpenPinnedPruneExecutor(path, pinPath string, assignment custodyauthority.Assignment, expectedID types.Hash) (_ *PruneExecutor, err error) {
	if expectedID.IsZero() {
		return nil, ErrPruneRequest
	}
	if _, err := assignment.ID(); err != nil {
		return nil, err
	}
	path, pinPath, err = coordinatorPaths(path, pinPath)
	if err != nil {
		return nil, err
	}
	pins, err := openPrunePinJournal(pinPath, assignment, expectedID)
	if err != nil {
		return nil, err
	}
	executor, err := openPruneExecutorBound(path, assignment, expectedID, pins.binding, storeHooks{})
	if err != nil {
		return nil, errors.Join(err, pins.lock.Close())
	}
	executor.pins = pins
	if err := executor.check(); err != nil {
		return nil, errors.Join(err, executor.Close())
	}
	return executor, nil
}

// ResumePinnedTransition only retains/confirms the ONE exact attempted journal
// transition. It never calls WorkChain, obtains authority, or signs completion.
// Resuming a start leaves Started, even if no effect has occurred: Execute cannot
// retry it. Resuming a result retains evidence already obtained before its intent
// was written. Absence of a chain result is never used to invent a disposition.
// Resuming a cancellation only finishes the exact pre-start terminal choice;
// an existing start intent can never be replaced by cancellation.
func (executor *PruneExecutor) ResumePinnedTransition(ctx context.Context) error {
	if executor == nil {
		return ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.resumePinnedTransition(ctx)
}

// resumePinnedTransition requires the executor mutex.
func (executor *PruneExecutor) resumePinnedTransition(ctx context.Context) error {
	if err := executor.check(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrPruneRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pins := executor.pins
	if pins == nil || pins.pending == nil {
		return ErrNoAttempt
	}
	if executor.stage == pins.position.Stage {
		index := pruneRecordCount(executor.stage)
		prefix := "prune-" + pruneTransitionLabel(index, pins.next.Stage)
		if err := executor.publishRecord(ctx, index, pins.pending, prefix); err != nil {
			return err
		}
		executor.installExecution(pins.next)
		return executor.applied(prefix)
	}
	if err := pins.confirm(executor); err != nil {
		return executor.poison(err)
	}
	return nil
}

func (pins *prunePinJournal) protection() PruneProtection {
	result := PruneProtection{BindingID: pins.binding, Confirmed: pins.position}
	if pins.pending != nil {
		next := nextPrunePosition(pins.position, pins.pending)
		result.Pending = &next
	}
	return result
}

func (pins *prunePinJournal) verifyExecutor(executor *PruneExecutor) error {
	if err := pins.check(); err != nil {
		return err
	}
	if executor.id != pins.state.RequestID || (executor.stage != pins.state.Stage &&
		(pins.pending == nil || executor.stage != pins.next.Stage)) {
		return ErrPrunePin
	}
	// A confirmed missing record is never reconstructed from intent bytes. Only
	// an UNCONFIRMED exact next transition may be absent or present at open.
	for index := 0; index < pruneRecordCount(executor.stage); index++ {
		var expected []byte
		if index < len(pins.records) {
			expected = pins.records[index]
		} else {
			expected = pins.pending
		}
		actual, err := readRegular(filepath.Join(executor.path, pruneRecordsName, pruneRecordName(index, executor.stage)), workchain.MaximumCanonicalPruneEffectBytes)
		if err != nil || !bytes.Equal(expected, actual) {
			return errors.Join(ErrPrunePin, err)
		}
	}
	return nil
}
