package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var ErrPruneCompletion = errors.New("prune completion does not match the retained terminal outcome")

// Complete explicitly submits an externally consumer-signed, authority-co-signed
// Complete entry for this executor's independently confirmed terminal outcome.
// It never signs a command, chooses an authority head, queries WorkChain, executes
// an effect or turns missing evidence into a no-effect disposition. Raw journals
// and unconfirmed transitions are ineligible. Started must first be resolved to
// an actual retained result; it cannot complete merely because execution stopped.
//
// The executor and coordinator mutexes remain held through the coordinator's
// durable intent, decision and independent confirmation. Open submits nothing;
// explicit retry of the same entry resumes its retained attempt or returns the
// exact historical decision. A different pending authority attempt must be
// resolved separately. No extra executor transition or completion format is added.
//
// This is a trusted one-assignment local adapter, not remote authority transport,
// proof that copied consumers drained, or a replacement for live archive policy.
func (executor *PruneExecutor) Complete(ctx context.Context, coordinator *Coordinator, entry custodyauthority.Entry) (Commit, error) {
	if executor == nil || coordinator == nil {
		return Commit{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
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
	var evidence types.Hash
	var err error
	switch executor.stage {
	case PruneSucceeded:
		evidence, err = executor.effect.ID()
	case PruneCancelled:
		evidence, err = executor.cancellation.ID()
	case PruneStarted:
		return Commit{}, ErrPruneOutcome
	default:
		return Commit{}, ErrPruneStage
	}
	if err != nil {
		return Commit{}, err
	}
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil {
		return Commit{}, err
	}
	if _, err := entry.CanonicalBytes(); err != nil {
		return Commit{}, err
	}
	command := entry.Command
	if entry.AuthorityPublicKey != executor.assignment.AuthorityPublicKey || command.Kind != custodyauthority.Complete ||
		command.AssignmentID != binding.AssignmentID || command.ActorPublicKey != binding.ConsumerPublicKey ||
		command.TicketID != binding.TicketID || command.EvidenceID != evidence {
		return Commit{}, ErrPruneCompletion
	}
	// Lock order matches BindAdmission/Execute/CancelBeforeStart. Keeping this
	// guard through append prevents Close/Stop/Retire from splitting validation
	// and the completion decision. The signed compare-and-append still decides
	// whether the exact command is current, pending, historical, or conflicting.
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.authority == nil || coordinator.journal == nil {
		return Commit{}, ErrClosed
	}
	if err := executor.checkAuthorityRoots(coordinator); err != nil {
		return Commit{}, err
	}
	return coordinator.append(ctx, entry)
}
