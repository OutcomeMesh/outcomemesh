package custodyauthority

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// ErrCustodyReview identifies an Audit/Serve command that differs from the
// explicitly reviewed signing message. These helpers never consult live state.
var ErrCustodyReview = errors.New("custody signing review does not match the exact command")

// CustodyCommandReviewID returns the existing command signature message for an
// unsigned Audit/Serve draft. Complete carries no purpose on the wire: purpose
// must independently come from the selected admission and terminal evidence.
// This static check cannot establish that a ticket or position is current.
func CustodyCommandReviewID(assignment Assignment, draft Command, purpose Purpose) (types.Hash, error) {
	if draft.Signature != [ed25519.SignatureSize]byte{} {
		return types.Hash{}, ErrCustodyReview
	}
	if err := validateReviewedCustodyCommand(assignment, draft, purpose); err != nil {
		return types.Hash{}, err
	}
	unsigned, err := draft.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/command/signature/v0", unsigned), nil
}

// SignReviewedCustodyCommand signs one exact draft, without inferring actor,
// replacing a signature, refreshing a head or granting execution permission.
func SignReviewedCustodyCommand(assignment Assignment, draft Command, purpose Purpose, expectedReviewID types.Hash, key ed25519.PrivateKey) (Command, error) {
	id, err := CustodyCommandReviewID(assignment, draft, purpose)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Command{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || draft.ActorPublicKey != [32]byte(key.Public().(ed25519.PublicKey)) {
		return Command{}, ErrActor
	}
	return draft.Sign(key)
}

// CustodyEntryReviewID binds the verified consumer signature to the exact
// assignment authority using the existing entry signature message.
func CustodyEntryReviewID(assignment Assignment, command Command, purpose Purpose) (types.Hash, error) {
	if err := validateReviewedCustodyCommand(assignment, command, purpose); err != nil {
		return types.Hash{}, err
	}
	entry := Entry{Version: Version0, Command: command, AuthorityPublicKey: assignment.AuthorityPublicKey}
	unsigned, err := entry.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/entry/signature/v0", unsigned), nil
}

// CosignReviewedCustodyCommand co-signs only the independently retained exact
// consumer command. The resulting entry is not an accepted ticket.
func CosignReviewedCustodyCommand(assignment Assignment, command Command, purpose Purpose, expectedReviewID types.Hash, key ed25519.PrivateKey) (Entry, error) {
	id, err := CustodyEntryReviewID(assignment, command, purpose)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Entry{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || assignment.AuthorityPublicKey != [32]byte(key.Public().(ed25519.PublicKey)) {
		return Entry{}, ErrActor
	}
	return SignEntry(command, key)
}

func validateReviewedCustodyCommand(assignment Assignment, command Command, purpose Purpose) error {
	if purpose != Audit && purpose != Serve {
		return ErrCustodyReview
	}
	id, err := assignment.ID()
	if err != nil || id != command.AssignmentID {
		return errors.Join(ErrAssignment, err)
	}
	if err := command.validateShape(); err != nil {
		return err
	}
	if (command.ExpectedSequence == 0) != (command.ExpectedHead == id) {
		return ErrHead
	}
	switch command.Kind {
	case Admit:
		if command.Purpose != purpose {
			return ErrCommand
		}
		if command.ExpectedSequence > 2*(uint64(assignment.MaximumOperations)-1) {
			return ErrLimit
		}
	case Complete:
		if command.ExpectedSequence == 0 || command.ExpectedSequence > 2*uint64(assignment.MaximumOperations) {
			return ErrLimit
		}
	default:
		return ErrCommand
	}
	for _, consumer := range assignment.Consumers {
		if consumer.PublicKey == command.ActorPublicKey && consumer.Purposes&purpose != 0 {
			return nil
		}
	}
	return ErrActor
}
