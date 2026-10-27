package store

import (
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestRemoteCustodyPreparationPinsIntentChallengeAndPlan(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	s := f.scope
	scope := CustodyCommandScope{Assignment: s.Worker.Assignment, AssignmentID: s.Worker.Plan.AssignmentID, Manifest: s.Manifest,
		InitialReceipt: s.InitialReceipt, PreviousReceipt: s.PreviousReceipt, CustodyPolicy: s.CustodyPolicy, Intent: f.intent}
	if err := ValidateRemoteCustodyCommandScope(scope); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCustodyCommandScope(scope); err == nil {
		t.Fatal("V0 scope accepted V1")
	}
	for _, e := range []custodyauthority.Entry{f.audit, s.Worker.Plan.Admission} {
		c := e.Command
		var challenge workarchive.CustodyChallenge
		if c.Purpose == custodyauthority.Serve {
			challenge = s.Challenge
		}
		draft, err := BuildRemoteCustodyAdmitCommand(scope, c.Purpose, c.ActorPublicKey, custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead}, challenge)
		c.Signature = [64]byte{}
		if err != nil || draft != c {
			t.Fatal("admission changed", err)
		}
	}
	if err := ValidateRemoteCustodyPlan(scope, s.Worker.Plan, s.Challenge); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CustodyCommandScope){
		func(c *CustodyCommandScope) { c.Intent.AssignmentID = testHash(252) },
		func(c *CustodyCommandScope) { c.Intent.Nonce = testHash(252) },
		func(c *CustodyCommandScope) { c.Intent.PriorReceiptID = testHash(252) },
		func(c *CustodyCommandScope) { c.Intent.ReplicaPeerID = testHash(252) },
		func(c *CustodyCommandScope) { c.CustodyPolicy.MaximumProofAge++ },
		func(c *CustodyCommandScope) { c.Intent.RenewUntil = c.InitialReceipt.RetainUntil },
	} {
		changed := scope
		mutate(&changed)
		if err := ValidateRemoteCustodyPlan(changed, s.Worker.Plan, s.Challenge); err == nil {
			t.Fatal("accepted substituted scope")
		}
	}
	p := s.Worker.Plan
	p.PriorSequence, p.PriorHeadID = 1, types.Hash{1}
	if err := ValidateRemoteCustodyPlan(scope, p, s.Challenge); err == nil {
		t.Fatal("accepted another predecessor")
	}
	p = s.Worker.Plan
	p.AuthorityTransportPublicKey = scope.Assignment.AuthorityPublicKey
	if err := ValidateRemoteCustodyPlan(scope, p, s.Challenge); err == nil {
		t.Fatal("reused authority key as transport")
	}
}
