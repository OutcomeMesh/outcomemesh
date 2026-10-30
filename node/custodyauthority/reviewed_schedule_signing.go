package custodyauthority

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// ScheduledCustodyCommandReviewID returns the version-2 command signature message for an
// unsigned Audit/Serve draft. Complete carries no purpose on the wire: purpose
// must independently come from the selected admission and terminal evidence.
// This static check cannot establish that a ticket or position is current.
func ScheduledCustodyCommandReviewID(assignment Assignment, draft Command, purpose Purpose) (types.Hash, error) {
	if draft.Signature != [ed25519.SignatureSize]byte{} {
		return types.Hash{}, ErrCustodyReview
	}
	if err := validateReviewedScheduledCustodyCommand(assignment, draft, purpose); err != nil {
		return types.Hash{}, err
	}
	unsigned, err := draft.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/command/signature/v2", unsigned), nil
}

// SignReviewedScheduledCustodyCommand signs one exact draft, without inferring actor,
// replacing a signature, refreshing a head or granting execution permission.
func SignReviewedScheduledCustodyCommand(assignment Assignment, draft Command, purpose Purpose, expectedReviewID types.Hash, key ed25519.PrivateKey) (Command, error) {
	id, err := ScheduledCustodyCommandReviewID(assignment, draft, purpose)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Command{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || draft.ActorPublicKey != [32]byte(key.Public().(ed25519.PublicKey)) {
		return Command{}, ErrActor
	}
	return draft.Sign(key)
}

// ScheduledCustodyEntryReviewID binds the verified consumer signature to the exact
// assignment authority using the version-2 entry signature message.
func ScheduledCustodyEntryReviewID(assignment Assignment, command Command, purpose Purpose) (types.Hash, error) {
	if err := validateReviewedScheduledCustodyCommand(assignment, command, purpose); err != nil {
		return types.Hash{}, err
	}
	entry := Entry{Version: ScheduleVersion2, Command: command, AuthorityPublicKey: assignment.AuthorityPublicKey}
	unsigned, err := entry.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/entry/signature/v2", unsigned), nil
}

// CosignReviewedScheduledCustodyCommand co-signs only the independently retained exact
// consumer command. The resulting entry is not an accepted ticket.
func CosignReviewedScheduledCustodyCommand(assignment Assignment, command Command, purpose Purpose, expectedReviewID types.Hash, key ed25519.PrivateKey) (Entry, error) {
	id, err := ScheduledCustodyEntryReviewID(assignment, command, purpose)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Entry{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || assignment.AuthorityPublicKey != [32]byte(key.Public().(ed25519.PublicKey)) {
		return Entry{}, ErrActor
	}
	return SignEntry(command, key)
}

func validateReviewedScheduledCustodyCommand(assignment Assignment, command Command, purpose Purpose) error {
	// Local Audit/Serve admissions and completions retain the original budget.
	if assignment.Version != Version0 || command.Version != ScheduleVersion2 {
		return ErrCustodyReview
	}
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
		if command.ExpectedSequence < 1 || command.ExpectedSequence > 2*uint64(assignment.MaximumOperations)-1 {
			return ErrLimit
		}
	case Complete:
		if command.ExpectedSequence < 2 || command.ExpectedSequence > 2*uint64(assignment.MaximumOperations)+1 {
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
