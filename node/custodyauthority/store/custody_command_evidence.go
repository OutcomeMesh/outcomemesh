package store

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var ErrCustodyCommandScope = errors.New("custody command scope does not match its pinned archive, intent or admission")

// CustodyCommandScope is static, independently pinned preparation. It grants no
// authority and opens no owner or journal. PreviousReceipt is the intent's exact
// predecessor; current source continuity is checked separately under a decision.
type CustodyCommandScope struct {
	Assignment      custodyauthority.Assignment
	AssignmentID    types.Hash
	Manifest        workarchive.Manifest
	InitialReceipt  workarchive.ReplicaReceipt
	CustodyPolicy   workarchive.CustodyPolicy
	Intent          workarchive.CustodyAuditIntent
	PreviousReceipt workarchive.ReplicaReceipt
}

func ValidateCustodyCommandScope(scope CustodyCommandScope) error {
	return validateCustodyCommandScopeVersion(scope, custodyauthority.Version0)
}

// ValidateRemoteCustodyCommandScope is static V1 preparation before Plan/Begin
// exist. It deliberately does not widen the legacy V0 workflow.
func ValidateRemoteCustodyCommandScope(scope CustodyCommandScope) error {
	return validateCustodyCommandScopeVersion(scope, custodyauthority.Version1)
}

func validateCustodyCommandScopeVersion(scope CustodyCommandScope, version uint16) error {
	id, err := scope.Assignment.ID()
	if err != nil || scope.Assignment.Version != version || scope.AssignmentID.IsZero() || id != scope.AssignmentID || scope.Intent.AssignmentID != id || scope.Intent.Validate() != nil {
		return errors.Join(ErrCustodyCommandScope, err)
	}
	a := scope.Assignment
	derived, err := workarchive.CreateCustodyAuthorityAssignment(scope.Manifest, scope.InitialReceipt, scope.CustodyPolicy,
		a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending)
	if version == custodyauthority.Version1 && err == nil {
		derived, err = custodyauthority.WithRemoteParticipant(derived, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
		peer, peerErr := transport.PeerIDFromPublicKey(a.RemoteTransportPublicKey[:])
		if peerErr != nil || peer != scope.Intent.ReplicaPeerID {
			return errors.Join(ErrCustodyCommandScope, peerErr)
		}
	}
	if err != nil {
		return errors.Join(ErrCustodyCommandScope, err)
	}
	derivedID, err := derived.ID()
	previousID, previousErr := scope.PreviousReceipt.ID()
	p, initial, intent := scope.PreviousReceipt, scope.InitialReceipt, scope.Intent
	if err != nil || previousErr != nil || derivedID != id || previousID != intent.PriorReceiptID ||
		p.ManifestID != initial.ManifestID || p.StatementID != initial.StatementID || p.Binding != initial.Binding ||
		p.AnchorID != initial.AnchorID || p.LocationID != initial.LocationID || p.ReplicaPublicKey != initial.ReplicaPublicKey ||
		(intent.PriorSequence == 0 && p != initial) || (intent.PriorSequence != 0 && p.Version != workarchive.ReplicaReceiptVersion1) {
		return errors.Join(ErrCustodyCommandScope, err, previousErr)
	}
	trusted := false
	for _, key := range a.Auditors {
		trusted = trusted || key == intent.AuditorPublicKey
	}
	consumer := false
	for _, member := range a.Consumers {
		consumer = consumer || member.PublicKey == intent.ConsumerPublicKey && member.Purposes&custodyauthority.Audit != 0
	}
	if !trusted || !consumer || managedCustodyAuditorPeer(a, intent.ReplicaPeerID) != nil {
		return ErrCustodyCommandScope
	}
	// Check policy/time/receipt constraints before a challenge is ever signed.
	policy := scope.CustodyPolicy
	if intent.ExpiresAt-intent.IssuedAt > policy.MaximumChallengeLifetime || intent.IssuedAt < p.StoredAt ||
		intent.ExpiresAt >= p.RetainUntil || intent.RenewUntil <= p.RetainUntil ||
		intent.RenewUntil-intent.IssuedAt > policy.MaximumRenewalTerm {
		return ErrCustodyCommandScope
	}
	return nil
}

// ValidateCustodyCommandChallenge verifies the signed challenge against the
// exact unsigned intent, predecessor and trusted policy at its original time.
func ValidateCustodyCommandChallenge(scope CustodyCommandScope, challenge workarchive.CustodyChallenge) error {
	if err := ValidateCustodyCommandScope(scope); err != nil {
		return err
	}
	if !custodyIntentMatchesChallenge(scope.Intent, challenge) {
		return ErrCustodyCommandScope
	}
	if err := challenge.Verify(scope.Manifest, scope.PreviousReceipt, scope.CustodyPolicy, challenge.ExpiresAt); err != nil {
		return errors.Join(ErrCustodyCommandScope, err)
	}
	return nil
}

func custodyIntentMatchesChallenge(intent workarchive.CustodyAuditIntent, challenge workarchive.CustodyChallenge) bool {
	return challenge.ReceiptID == intent.PriorReceiptID && challenge.AuditorPublicKey == intent.AuditorPublicKey &&
		challenge.Nonce == intent.Nonce && challenge.IssuedAt == intent.IssuedAt && challenge.ExpiresAt == intent.ExpiresAt &&
		challenge.RenewUntil == intent.RenewUntil && challenge.RequestedSamples == intent.RequestedSamples
}

// BuildCustodyAdmitCommand creates an unsigned exact-position draft. Audit
// binds IntentID before challenge signing and requires an empty challenge;
// Serve binds the independently signed challenge after full scope verification.
func BuildCustodyAdmitCommand(scope CustodyCommandScope, purpose custodyauthority.Purpose, consumer [32]byte, position custodyauthority.Position, challenge workarchive.CustodyChallenge) (custodyauthority.Command, error) {
	if err := ValidateCustodyCommandScope(scope); err != nil {
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
		if err = ValidateCustodyCommandChallenge(scope, challenge); err == nil {
			operation, err = challenge.ID()
		}
	default:
		err = ErrCustodyCommandScope
	}
	if err != nil {
		return custodyauthority.Command{}, err
	}
	draft := custodyauthority.Command{Version: custodyauthority.Version0, AssignmentID: scope.AssignmentID,
		ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID, Kind: custodyauthority.Admit, Purpose: purpose,
		OperationID: operation, ActorPublicKey: consumer}
	if _, err := CustodyCommandReviewID(scope.Assignment, draft, purpose); err != nil {
		return custodyauthority.Command{}, err
	}
	return draft, nil
}

func emptyCustodyChallenge(challenge workarchive.CustodyChallenge) bool {
	return challenge.Version == 0 && challenge.StatementID.IsZero() && challenge.ManifestID.IsZero() && challenge.ReceiptID.IsZero() &&
		challenge.IssuedAt == 0 && challenge.ExpiresAt == 0 && challenge.RenewUntil == 0 && challenge.Nonce.IsZero() &&
		challenge.RequestedSamples == 0 && len(challenge.IDs) == 0 && challenge.AuditorPublicKey == [32]byte{} && challenge.Signature == [64]byte{}
}

func validateCustodyAdmission(scope CustodyCommandScope, admission custodyauthority.Entry, challenge workarchive.CustodyChallenge) error {
	if _, err := admission.ID(); err != nil {
		return errors.Join(ErrCustodyCommandScope, err)
	}
	c := admission.Command
	if c.Kind != custodyauthority.Admit || c.AssignmentID != scope.AssignmentID || admission.AuthorityPublicKey != scope.Assignment.AuthorityPublicKey {
		return ErrCustodyCommandScope
	}
	var supplied workarchive.CustodyChallenge
	if c.Purpose == custodyauthority.Serve {
		supplied = challenge
	}
	want, err := BuildCustodyAdmitCommand(scope, c.Purpose, c.ActorPublicKey,
		custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead}, supplied)
	if err != nil {
		return err
	}
	want.Signature = c.Signature
	if want != c {
		return ErrCustodyCommandScope
	}
	return nil
}

// BuildCustodyCompleteCommand commits the full selected terminal envelope,
// including its exact admission, rather than merely committing a receipt ID.
// It preserves the historical response and never selects a newer position.
func BuildCustodyCompleteCommand(scope CustodyCommandScope, admission custodyauthority.Entry, terminal CustodyTerminal, position custodyauthority.Position) (custodyauthority.Command, error) {
	if err := terminal.Validate(scope); err != nil {
		return custodyauthority.Command{}, err
	}
	if admission != terminal.Admission {
		return custodyauthority.Command{}, ErrCustodyCommandScope
	}
	ticket, err := admission.ID()
	if err != nil {
		return custodyauthority.Command{}, err
	}
	// Completion must follow this admission. The admission ID is the authority
	// head only at its own sequence; no static builder may invent a later head.
	admissionSequence := admission.Command.ExpectedSequence + 1
	if position.Sequence < admissionSequence || (position.Sequence == admissionSequence) != (position.HeadID == ticket) {
		return custodyauthority.Command{}, custodyauthority.ErrHead
	}
	evidence, err := terminal.ID()
	if err != nil {
		return custodyauthority.Command{}, err
	}
	draft := custodyauthority.Command{Version: custodyauthority.Version0, AssignmentID: scope.AssignmentID,
		ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID, Kind: custodyauthority.Complete,
		TicketID: ticket, EvidenceID: evidence, ActorPublicKey: admission.Command.ActorPublicKey}
	if _, err := CustodyCommandReviewID(scope.Assignment, draft, admission.Command.Purpose); err != nil {
		return custodyauthority.Command{}, err
	}
	return draft, nil
}

// These aliases retain the scope-facing API while the exact existing signature
// messages are implemented next to the authority codecs.
func CustodyCommandReviewID(a custodyauthority.Assignment, c custodyauthority.Command, p custodyauthority.Purpose) (types.Hash, error) {
	return custodyauthority.CustodyCommandReviewID(a, c, p)
}
func CustodyEntryReviewID(a custodyauthority.Assignment, c custodyauthority.Command, p custodyauthority.Purpose) (types.Hash, error) {
	return custodyauthority.CustodyEntryReviewID(a, c, p)
}
func SignReviewedCustodyCommand(a custodyauthority.Assignment, c custodyauthority.Command, p custodyauthority.Purpose, id types.Hash, key ed25519.PrivateKey) (custodyauthority.Command, error) {
	return custodyauthority.SignReviewedCustodyCommand(a, c, p, id, key)
}
func CosignReviewedCustodyCommand(a custodyauthority.Assignment, c custodyauthority.Command, p custodyauthority.Purpose, id types.Hash, key ed25519.PrivateKey) (custodyauthority.Entry, error) {
	return custodyauthority.CosignReviewedCustodyCommand(a, c, p, id, key)
}
