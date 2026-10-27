package store

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func ValidateRemoteCustodyCommandChallenge(scope CustodyCommandScope, challenge workarchive.CustodyChallenge) error {
	if err := ValidateRemoteCustodyCommandScope(scope); err != nil {
		return err
	}
	if !custodyIntentMatchesChallenge(scope.Intent, challenge) {
		return ErrCustodyCommandScope
	}
	return challenge.Verify(scope.Manifest, scope.PreviousReceipt, scope.CustodyPolicy, challenge.ExpiresAt)
}

// BuildRemoteCustodyAdmitCommand prepares a fixed V1 consumer draft before a
// remote session exists. It opens no owner and signs no challenge.
func BuildRemoteCustodyAdmitCommand(scope CustodyCommandScope, purpose custodyauthority.Purpose, consumer [32]byte, position custodyauthority.Position, challenge workarchive.CustodyChallenge) (custodyauthority.Command, error) {
	if err := ValidateRemoteCustodyCommandScope(scope); err != nil {
		return custodyauthority.Command{}, err
	}
	var operation types.Hash
	var err error
	switch purpose {
	case custodyauthority.Audit:
		if consumer != scope.Intent.ConsumerPublicKey || !emptyCustodyChallenge(challenge) {
			return custodyauthority.Command{}, ErrCustodyCommandScope
		}
		operation, err = scope.Intent.ID()
	case custodyauthority.Serve:
		if err = ValidateRemoteCustodyCommandChallenge(scope, challenge); err == nil {
			operation, err = challenge.ID()
		}
	default:
		err = ErrCustodyCommandScope
	}
	if err != nil {
		return custodyauthority.Command{}, err
	}
	draft := custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: scope.AssignmentID,
		ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID, Kind: custodyauthority.Admit,
		Purpose: purpose, OperationID: operation, ActorPublicKey: consumer}
	_, err = custodyauthority.V1CustodyCommandReviewID(scope.Assignment, draft, purpose)
	return draft, err
}

// ValidateRemoteCustodyPlan verifies the full historical preparation before a
// Begin exists, including exact intent/challenge and predecessor continuity.
func ValidateRemoteCustodyPlan(scope CustodyCommandScope, plan remoteworker.Plan, challenge workarchive.CustodyChallenge) error {
	if err := plan.Validate(scope.Assignment); err != nil {
		return err
	}
	i := scope.Intent
	if plan.AssignmentID != scope.AssignmentID || plan.PriorSequence != i.PriorSequence || plan.PriorHeadID != i.PriorHeadID || plan.PriorReceiptID != i.PriorReceiptID {
		return ErrCustodyCommandScope
	}
	c := plan.Admission.Command
	draft, err := BuildRemoteCustodyAdmitCommand(scope, custodyauthority.Serve, c.ActorPublicKey,
		custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead}, challenge)
	c.Signature = [64]byte{}
	if err != nil {
		return err
	}
	if c != draft || plan.Admission.AuthorityPublicKey != scope.Assignment.AuthorityPublicKey {
		return ErrCustodyCommandScope
	}
	return nil
}
