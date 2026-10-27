package store

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var ErrRemoteCustody = errors.New("remote custody scope, owner or result does not match its fixed session")

// RemoteCustodyScope is independently pinned preparation. Only the original A
// coordinator can turn its Begin proposal into a confirmed remote obligation.
// It carries public evidence, not another host's authority or private journal.
type RemoteCustodyScope struct {
	Worker          remoteworker.Config
	Manifest        workarchive.Manifest
	InitialReceipt  workarchive.ReplicaReceipt
	PreviousReceipt workarchive.ReplicaReceipt
	CustodyPolicy   workarchive.CustodyPolicy
	Challenge       workarchive.CustodyChallenge
}

func validateRemoteCustodyScope(scope RemoteCustodyScope) error {
	w := scope.Worker
	a := w.Assignment
	if a.Version != custodyauthority.Version1 || w.Plan.Validate(a) != nil {
		return ErrRemoteCustody
	}
	planID, err := w.Plan.ID()
	if err != nil || w.PlanID.IsZero() || planID != w.PlanID {
		return errors.Join(ErrRemoteCustody, err)
	}
	beginID, err := w.Begin.ID()
	if err != nil || w.BeginID.IsZero() || beginID != w.BeginID || w.Begin.AuthorityPublicKey != a.AuthorityPublicKey {
		return errors.Join(ErrRemoteCustody, err)
	}
	c := w.Begin.Command
	draft, err := custodyauthority.BuildRemoteBeginCommand(a, w.Plan.Admission, planID,
		custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead})
	c.Signature = [ed25519.SignatureSize]byte{}
	if err != nil || c != draft {
		return errors.Join(ErrRemoteCustody, err)
	}
	derived, err := workarchive.CreateRemoteCustodyAuthorityAssignment(scope.Manifest, scope.InitialReceipt, scope.CustodyPolicy,
		a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending,
		a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
	if err != nil {
		return errors.Join(ErrRemoteCustody, err)
	}
	id, err := derived.ID()
	if err != nil || id != w.Plan.AssignmentID {
		return errors.Join(ErrRemoteCustody, err)
	}
	p, initial := scope.PreviousReceipt, scope.InitialReceipt
	previousID, err := p.ID()
	if err != nil || previousID != w.Plan.PriorReceiptID || p.ManifestID != initial.ManifestID || p.StatementID != initial.StatementID ||
		p.Binding != initial.Binding || p.AnchorID != initial.AnchorID || p.LocationID != initial.LocationID || p.ReplicaPublicKey != initial.ReplicaPublicKey ||
		(w.Plan.PriorSequence == 0 && p != initial) || (w.Plan.PriorSequence != 0 && p.Version != workarchive.ReplicaReceiptVersion1) {
		return errors.Join(ErrRemoteCustody, err)
	}
	challengeID, err := scope.Challenge.ID()
	if err != nil || challengeID != w.Plan.Admission.Command.OperationID ||
		scope.Challenge.Verify(scope.Manifest, p, scope.CustodyPolicy, scope.Challenge.ExpiresAt) != nil {
		return errors.Join(ErrRemoteCustody, err)
	}
	return nil
}

func freezeRemoteCustodyScope(scope RemoteCustodyScope) (RemoteCustodyScope, error) {
	if err := validateRemoteCustodyScope(scope); err != nil {
		return RemoteCustodyScope{}, err
	}
	b, _ := scope.Worker.Assignment.CanonicalBytes()
	var err error
	if scope.Worker.Assignment, err = custodyauthority.DecodeAssignment(b); err != nil {
		return RemoteCustodyScope{}, err
	}
	b, _ = scope.Worker.Plan.CanonicalBytes()
	if scope.Worker.Plan, err = remoteworker.DecodePlan(b); err != nil {
		return RemoteCustodyScope{}, err
	}
	b, _ = scope.Manifest.CanonicalBytes()
	if scope.Manifest, err = workarchive.DecodeManifest(b); err != nil {
		return RemoteCustodyScope{}, err
	}
	b, _ = scope.Challenge.CanonicalBytes()
	if scope.Challenge, err = workarchive.DecodeCustodyChallenge(b); err != nil {
		return RemoteCustodyScope{}, err
	}
	scope.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), scope.CustodyPolicy.TrustedAuditors...)
	return scope, validateRemoteCustodyScope(scope)
}

func validateRemoteAuditScope(scope RemoteCustodyScope, intent workarchive.CustodyAuditIntent, admission custodyauthority.Entry) error {
	if err := validateRemoteCustodyScope(scope); err != nil {
		return err
	}
	w, a := scope.Worker, scope.Worker.Assignment
	if intent.Validate() != nil || intent.AssignmentID != w.Plan.AssignmentID || intent.PriorSequence != w.Plan.PriorSequence ||
		intent.PriorHeadID != w.Plan.PriorHeadID || intent.PriorReceiptID != w.Plan.PriorReceiptID || !custodyIntentMatchesChallenge(intent, scope.Challenge) {
		return ErrRemoteCustody
	}
	peer, err := transport.PeerIDFromPublicKey(a.RemoteTransportPublicKey[:])
	if err != nil || peer != intent.ReplicaPeerID {
		return errors.Join(ErrRemoteCustody, err)
	}
	trusted, consumer := false, false
	for _, key := range a.Auditors {
		trusted = trusted || key == intent.AuditorPublicKey
	}
	for _, member := range a.Consumers {
		consumer = consumer || member.PublicKey == intent.ConsumerPublicKey && member.Purposes&custodyauthority.Audit != 0
	}
	intentID, err := intent.ID()
	c := admission.Command
	if _, e := admission.ID(); e != nil || err != nil || !trusted || !consumer || admission.Version != custodyauthority.Version1 ||
		c.Version != custodyauthority.Version1 || admission.AuthorityPublicKey != a.AuthorityPublicKey || c.AssignmentID != w.Plan.AssignmentID ||
		c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Audit || c.ActorPublicKey != intent.ConsumerPublicKey || c.OperationID != intentID ||
		(c.ExpectedSequence == 0) != (c.ExpectedHead == w.Plan.AssignmentID) || c.ExpectedSequence >= w.Begin.Command.ExpectedSequence {
		return errors.Join(ErrRemoteCustody, err)
	}
	policy, p := scope.CustodyPolicy, scope.PreviousReceipt
	if intent.ExpiresAt-intent.IssuedAt > policy.MaximumChallengeLifetime || intent.IssuedAt < p.StoredAt ||
		intent.ExpiresAt >= p.RetainUntil || intent.RenewUntil <= p.RetainUntil || intent.RenewUntil-intent.IssuedAt > policy.MaximumRenewalTerm {
		return ErrRemoteCustody
	}
	return nil
}

// ValidateRemoteCustodyDrain checks historical signatures and the exact sealed
// branch. Live application still requires the original confirmed A owner.
// RetainedResult is a journal-entry commitment, never proof of A acceptance.
func ValidateRemoteCustodyDrain(scope RemoteCustodyScope, seal remoteworker.Seal, command custodyauthority.Command) error {
	if err := validateRemoteCustodyScope(scope); err != nil {
		return err
	}
	w := scope.Worker
	sealID, err := seal.ID()
	if err != nil || seal.PlanID != w.PlanID || seal.BeginID != w.BeginID {
		return errors.Join(ErrRemoteCustody, err)
	}
	draft, err := custodyauthority.BuildRemoteDrainedCommand(w.Assignment, w.Begin, sealID,
		custodyauthority.Position{Sequence: w.Begin.Command.ExpectedSequence + 1, HeadID: w.BeginID})
	if err != nil {
		return err
	}
	if _, err := command.CanonicalBytes(); err != nil {
		return errors.Join(ErrRemoteCustody, err)
	}
	command.Signature = [64]byte{}
	if command != draft {
		return ErrRemoteCustody
	}
	return nil
}
