package custodyauthority

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// ScheduledPruneCommandReviewID returns the version-2 command signature message for an
// unsigned Prune draft. Completion evidence is separately bound by the caller.
// This static check cannot establish that a ticket or position is current.
func ScheduledPruneCommandReviewID(assignment Assignment, draft Command) (types.Hash, error) {
	if draft.Signature != [ed25519.SignatureSize]byte{} {
		return types.Hash{}, ErrCustodyReview
	}
	if err := validateReviewedScheduledCommand(assignment, draft, Prune); err != nil {
		return types.Hash{}, err
	}
	unsigned, err := draft.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/command/signature/v2", unsigned), nil
}

// SignReviewedScheduledPruneCommand signs one exact draft, without inferring actor,
// replacing a signature, refreshing a head or granting execution permission.
func SignReviewedScheduledPruneCommand(assignment Assignment, draft Command, expectedReviewID types.Hash, key ed25519.PrivateKey) (Command, error) {
	id, err := ScheduledPruneCommandReviewID(assignment, draft)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Command{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || draft.ActorPublicKey != [32]byte(key.Public().(ed25519.PublicKey)) {
		return Command{}, ErrActor
	}
	return draft.Sign(key)
}

// ScheduledPruneEntryReviewID binds the verified consumer signature to the exact
// assignment authority using the version-2 entry signature message.
func ScheduledPruneEntryReviewID(assignment Assignment, command Command) (types.Hash, error) {
	if err := validateReviewedScheduledCommand(assignment, command, Prune); err != nil {
		return types.Hash{}, err
	}
	entry := Entry{Version: ScheduleVersion2, Command: command, AuthorityPublicKey: assignment.AuthorityPublicKey}
	unsigned, err := entry.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/entry/signature/v2", unsigned), nil
}

// CosignReviewedScheduledPruneCommand co-signs only the independently retained exact
// consumer command. The resulting entry is not an accepted ticket.
func CosignReviewedScheduledPruneCommand(assignment Assignment, command Command, expectedReviewID types.Hash, key ed25519.PrivateKey) (Entry, error) {
	id, err := ScheduledPruneEntryReviewID(assignment, command)
	if err != nil || expectedReviewID.IsZero() || id != expectedReviewID {
		return Entry{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || assignment.AuthorityPublicKey != [32]byte(key.Public().(ed25519.PublicKey)) {
		return Entry{}, ErrActor
	}
	return SignEntry(command, key)
}
