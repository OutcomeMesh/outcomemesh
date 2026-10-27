package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// BuildRemoteCustodyNegativeAuditCompleteCommand closes only the auditor's
// administrative observation. The original Serve ticket MUST remain pending:
// it carries the unresolved execution/retention obligation even for Unseen.
// This draft does not establish current ownership or authorize application.
func BuildRemoteCustodyNegativeAuditCompleteCommand(scope RemoteCustodyScope, n RemoteCustodyNegative, position custodyauthority.Position) (custodyauthority.Command, error) {
	if err := n.Validate(scope); err != nil {
		return custodyauthority.Command{}, err
	}
	drain, _ := n.Drained.ID()
	sequence := n.Drained.Command.ExpectedSequence + 1
	if position.Sequence < sequence || (position.Sequence == sequence) != (position.HeadID == drain) ||
		position.HeadID.IsZero() || position.Sequence >= custodyauthority.MaximumEntries(scope.Worker.Assignment) {
		return custodyauthority.Command{}, custodyauthority.ErrHead
	}
	ticket, _ := n.AuditAdmission.ID()
	evidence, _ := n.ID()
	return custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: scope.Worker.Plan.AssignmentID,
		ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID, Kind: custodyauthority.Complete,
		TicketID: ticket, EvidenceID: evidence, ActorPublicKey: n.AuditAdmission.Command.ActorPublicKey}, nil
}

func (r *RemoteCustodyAuditRuntime) ApplyNegativeAuditComplete(ctx context.Context, n RemoteCustodyNegative, entry custodyauthority.Entry) (Commit, error) {
	return r.applyNegativeAuditComplete(ctx, n, entry, false)
}

// ResumeNegativeAuditComplete retries only the retained exact pending entry.
// It never infers that an unknown effect was cancelled or starts another one.
func (r *RemoteCustodyAuditRuntime) ResumeNegativeAuditComplete(ctx context.Context, n RemoteCustodyNegative, entry custodyauthority.Entry) (Commit, error) {
	return r.applyNegativeAuditComplete(ctx, n, entry, true)
}

func (r *RemoteCustodyAuditRuntime) applyNegativeAuditComplete(ctx context.Context, n RemoteCustodyNegative, entry custodyauthority.Entry, resume bool) (commit Commit, returnErr error) {
	b, err := n.CanonicalBytes()
	if err != nil {
		return commit, err
	}
	n, err = DecodeRemoteCustodyNegative(b)
	if err != nil {
		return commit, err
	}
	err = r.action(ctx, func(run context.Context) (returnErr error) {
		if _, err := entry.CanonicalBytes(); err != nil {
			return err
		}
		c := entry.Command
		draft, err := BuildRemoteCustodyNegativeAuditCompleteCommand(r.scope, n, custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead})
		if err != nil {
			return err
		}
		draft.Signature = c.Signature
		if c != draft || entry.AuthorityPublicKey != r.scope.Worker.Assignment.AuthorityPublicKey {
			return ErrRemoteCustody
		}
		current, err := r.life.owner.snapshot()
		if err != nil {
			return err
		}
		if resume {
			if current.Pending == nil {
				return ErrNoAttempt
			}
			if *current.Pending != entry {
				return ErrPendingAttempt
			}
		} else if current.Pending != nil {
			return ErrPendingAttempt
		}
		d, err := r.journal.AcquireDecision()
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, d.Close()) }()
		if err := n.Validate(r.scope); err != nil {
			return err
		}
		if err := r.checkNegativeDispositionLocked(n, d, true, resume); err != nil {
			return err
		}
		if err := run.Err(); err != nil {
			return err
		}
		if resume {
			commit, err = r.life.owner.resume(run)
		} else {
			commit, err = r.life.owner.append(run, entry)
		}
		return err
	})
	return commit, err
}
