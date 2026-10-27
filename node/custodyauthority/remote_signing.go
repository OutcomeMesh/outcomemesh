package custodyauthority

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

var ErrRemoteReview = errors.New("remote signing review does not match the exact version-1 offer or drain acknowledgement")

// BuildRemoteBeginCommand prepares a static offer for one exact Serve ticket.
// It does not establish that the ticket is pending, that position is current,
// that A persisted a hold, or that B may execute. A live managed remote protocol
// must separately enforce those conditions; this foundation starts no work.
func BuildRemoteBeginCommand(assignment Assignment, serve Entry, planID types.Hash, position Position) (Command, error) {
	id, err := assignment.ID()
	if err != nil || assignment.Version != Version1 || planID.IsZero() {
		return Command{}, errors.Join(ErrRemoteReview, err)
	}
	ticket, err := serve.ID()
	c := serve.Command
	if err != nil || serve.Version != Version1 || c.Version != Version1 || c.AssignmentID != id ||
		serve.AuthorityPublicKey != assignment.AuthorityPublicKey || c.Kind != Admit || c.Purpose != Serve {
		return Command{}, errors.Join(ErrRemoteReview, err)
	}
	allowed := false
	for _, consumer := range assignment.Consumers {
		allowed = allowed || consumer.PublicKey == c.ActorPublicKey && consumer.Purposes&Serve != 0
	}
	if !allowed {
		return Command{}, ErrActor
	}
	if (c.ExpectedSequence == 0) != (c.ExpectedHead == id) {
		return Command{}, ErrHead
	}
	if c.ExpectedSequence >= position.Sequence {
		return Command{}, ErrHead
	}
	admissionSequence := c.ExpectedSequence + 1
	if (position.Sequence == admissionSequence) != (position.HeadID == ticket) {
		return Command{}, ErrHead
	}
	draft := Command{Version: Version1, AssignmentID: id, ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID,
		Kind: RemoteBegin, Purpose: Serve, OperationID: planID, TicketID: ticket, EvidenceID: c.OperationID, ActorPublicKey: assignment.RemoteControlPublicKey}
	if _, err := RemoteCommandReviewID(assignment, draft); err != nil {
		return Command{}, err
	}
	return draft, nil
}

// BuildRemoteDrainedCommand fixes the deterministic position immediately after
// the signed Begin. A signature alone does not establish a closed B journal.
// B must durably seal its exact session and drain all effects BEFORE publishing
// this acknowledgement; neither this builder nor review performs that work.
func BuildRemoteDrainedCommand(assignment Assignment, begin Entry, tombstoneID types.Hash, position Position) (Command, error) {
	id, err := assignment.ID()
	if err != nil || assignment.Version != Version1 || tombstoneID.IsZero() {
		return Command{}, errors.Join(ErrRemoteReview, err)
	}
	beginID, err := begin.ID()
	c := begin.Command
	if err != nil || begin.Version != Version1 || c.Version != Version1 || begin.AuthorityPublicKey != assignment.AuthorityPublicKey ||
		c.AssignmentID != id || c.Kind != RemoteBegin || c.ActorPublicKey != assignment.RemoteControlPublicKey {
		return Command{}, errors.Join(ErrRemoteReview, err)
	}
	if err := validateRemoteReviewedCommand(assignment, c); err != nil {
		return Command{}, err
	}
	if position.Sequence != c.ExpectedSequence+1 || position.HeadID != beginID {
		return Command{}, ErrHead
	}
	draft := Command{Version: Version1, AssignmentID: id, ExpectedSequence: position.Sequence, ExpectedHead: position.HeadID,
		Kind: RemoteDrained, OperationID: beginID, TicketID: c.TicketID, EvidenceID: tombstoneID, ActorPublicKey: assignment.RemoteControlPublicKey}
	if _, err := RemoteCommandReviewID(assignment, draft); err != nil {
		return Command{}, err
	}
	return draft, nil
}

// RemoteCommandReviewID is the exact v1 signature message for a static unsigned
// B offer/drain draft. It is not an entry ID or remote execution permission.
func RemoteCommandReviewID(assignment Assignment, draft Command) (types.Hash, error) {
	if draft.Signature != [64]byte{} {
		return types.Hash{}, ErrRemoteReview
	}
	if err := validateRemoteReviewedCommand(assignment, draft); err != nil {
		return types.Hash{}, err
	}
	unsigned, err := draft.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(authorityDomain(Version1, "command/signature"), unsigned), nil
}

func SignReviewedRemoteCommand(assignment Assignment, draft Command, expectedReviewID types.Hash, key ed25519.PrivateKey) (Command, error) {
	id, err := RemoteCommandReviewID(assignment, draft)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Command{}, errors.Join(ErrRemoteReview, err)
	}
	if !validKey(key) || [32]byte(key.Public().(ed25519.PublicKey)) != assignment.RemoteControlPublicKey {
		return Command{}, ErrActor
	}
	return draft.Sign(key)
}

// RemoteEntryReviewID binds B's verified signature to A's separately pinned
// authority. Publishing a co-signature still does not durably accept a hold.
func RemoteEntryReviewID(assignment Assignment, command Command) (types.Hash, error) {
	if err := validateRemoteReviewedCommand(assignment, command); err != nil {
		return types.Hash{}, err
	}
	entry := Entry{Version: Version1, Command: command, AuthorityPublicKey: assignment.AuthorityPublicKey}
	unsigned, err := entry.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(authorityDomain(Version1, "entry/signature"), unsigned), nil
}

func CosignReviewedRemoteCommand(assignment Assignment, command Command, expectedReviewID types.Hash, key ed25519.PrivateKey) (Entry, error) {
	id, err := RemoteEntryReviewID(assignment, command)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Entry{}, errors.Join(ErrRemoteReview, err)
	}
	if !validKey(key) || [32]byte(key.Public().(ed25519.PublicKey)) != assignment.AuthorityPublicKey {
		return Entry{}, ErrActor
	}
	return SignEntry(command, key)
}

func validateRemoteReviewedCommand(assignment Assignment, command Command) error {
	if assignment.Version != Version1 || command.Version != Version1 {
		return ErrRemoteReview
	}
	id, err := assignment.ID()
	if err != nil || command.AssignmentID != id {
		return errors.Join(ErrAssignment, err)
	}
	if err := command.validateShape(); err != nil {
		return err
	}
	if command.Kind != RemoteBegin && command.Kind != RemoteDrained {
		return ErrRemoteReview
	}
	if command.ActorPublicKey != assignment.RemoteControlPublicKey {
		return ErrActor
	}
	if command.ExpectedSequence == 0 || command.ExpectedHead == id {
		return ErrHead
	}
	if command.Kind == RemoteDrained && command.ExpectedSequence < 2 {
		return ErrHead
	}
	// Reserve an exact subsequent drain even at admission-budget exhaustion.
	limit := MaximumEntries(assignment)
	if command.ExpectedSequence >= limit || command.Kind == RemoteBegin && command.ExpectedSequence >= limit-1 {
		return ErrLimit
	}
	return nil
}
