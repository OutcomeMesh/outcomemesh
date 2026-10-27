package custodyauthority

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// ErrPruneReview means the supplied draft or independently reviewed signature
// message does not match this exact signing attempt. No signature is returned.
var ErrPruneReview = errors.New("prune signing review does not match the exact command")

// PruneCommandReviewID returns the existing command-signature message hash for
// an unsigned, explicitly attributed prune draft. It never refreshes a head,
// checks live state, or establishes terminal evidence. The caller must separately
// bind OperationID or TicketID/EvidenceID to independently reviewed artifacts.
func PruneCommandReviewID(assignment Assignment, draft Command) (types.Hash, error) {
	if draft.Signature != [ed25519.SignatureSize]byte{} {
		return types.Hash{}, ErrPruneReview
	}
	if err := validateReviewedPruneCommand(assignment, draft); err != nil {
		return types.Hash{}, err
	}
	unsigned, err := draft.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/command/signature/v0", unsigned), nil
}

// SignReviewedPruneCommand signs only after matching the independently retained
// review ID. It does not admit, publish, or execute the command. A populated
// signature is never silently replaced, and the actor is never inferred from key.
func SignReviewedPruneCommand(assignment Assignment, draft Command, expectedReviewID types.Hash, key ed25519.PrivateKey) (Command, error) {
	id, err := PruneCommandReviewID(assignment, draft)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Command{}, errors.Join(ErrPruneReview, err)
	}
	if !validKey(key) || draft.ActorPublicKey != [ed25519.PublicKeySize]byte(key.Public().(ed25519.PublicKey)) {
		return Command{}, ErrActor
	}
	return draft.Sign(key)
}

// PruneEntryReviewID returns the existing authority-entry signature message
// hash, binding the exact verified consumer signature and assignment authority.
// A co-signature alone is not an accepted ticket or a current execution grant.
func PruneEntryReviewID(assignment Assignment, command Command) (types.Hash, error) {
	if err := validateReviewedPruneCommand(assignment, command); err != nil {
		return types.Hash{}, err
	}
	entry := Entry{Version: Version0, Command: command, AuthorityPublicKey: assignment.AuthorityPublicKey}
	unsigned, err := entry.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/entry/signature/v0", unsigned), nil
}

// CosignReviewedPruneCommand co-signs one consumer-signed command with its exact
// independently reviewed message hash. It cannot choose or refresh a position.
func CosignReviewedPruneCommand(assignment Assignment, command Command, expectedReviewID types.Hash, key ed25519.PrivateKey) (Entry, error) {
	id, err := PruneEntryReviewID(assignment, command)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Entry{}, errors.Join(ErrPruneReview, err)
	}
	if !validKey(key) || assignment.AuthorityPublicKey != [ed25519.PublicKeySize]byte(key.Public().(ed25519.PublicKey)) {
		return Entry{}, ErrActor
	}
	return SignEntry(command, key)
}

func validateReviewedPruneCommand(assignment Assignment, command Command) error {
	if assignment.Version != Version0 || command.Version != Version0 {
		return ErrPruneReview
	}
	id, err := assignment.ID()
	if err != nil || id != command.AssignmentID {
		return errors.Join(ErrAssignment, err)
	}
	if err := command.validateShape(); err != nil {
		return err
	}
	// The initial assignment ID cannot also be a later history head. These
	// static impossibility checks make no claim that any later head is current.
	if (command.ExpectedSequence == 0) != (command.ExpectedHead == id) {
		return ErrHead
	}
	switch command.Kind {
	case Admit:
		if command.Purpose != Prune {
			return ErrCommand
		}
		if command.ExpectedSequence > 2*(uint64(assignment.MaximumOperations)-1) {
			return ErrLimit
		}
	case Complete:
		// At most N admissions, N-1 earlier completions and one Stop may
		// precede the last completion. Retirement can never precede it.
		if command.ExpectedSequence == 0 || command.ExpectedSequence > 2*uint64(assignment.MaximumOperations) {
			return ErrLimit
		}
	default:
		return ErrCommand
	}
	for _, consumer := range assignment.Consumers {
		if consumer.PublicKey == command.ActorPublicKey && consumer.Purposes&Prune != 0 {
			return nil
		}
	}
	return ErrActor
}
