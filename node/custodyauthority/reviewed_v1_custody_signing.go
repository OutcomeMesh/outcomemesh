package custodyauthority

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// V1CustodyCommandReviewID reviews only ordinary Audit/Serve commands in a
// fresh V1 assignment. Remote Begin/Drained have their separate review API.
// Complete's purpose must come from independently verified terminal evidence.
// These static checks neither inspect a live owner nor grant execution.
func V1CustodyCommandReviewID(a Assignment, draft Command, purpose Purpose) (types.Hash, error) {
	if draft.Signature != [64]byte{} {
		return types.Hash{}, ErrCustodyReview
	}
	if err := validateV1CustodyCommand(a, draft, purpose); err != nil {
		return types.Hash{}, err
	}
	b, err := draft.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(authorityDomain(Version1, "command/signature"), b), nil
}

func SignReviewedV1CustodyCommand(a Assignment, draft Command, purpose Purpose, expected types.Hash, key ed25519.PrivateKey) (Command, error) {
	id, err := V1CustodyCommandReviewID(a, draft, purpose)
	if err != nil || expected.IsZero() || id != expected {
		return Command{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || [32]byte(key.Public().(ed25519.PublicKey)) != draft.ActorPublicKey {
		return Command{}, ErrActor
	}
	return draft.Sign(key)
}

func V1CustodyEntryReviewID(a Assignment, command Command, purpose Purpose) (types.Hash, error) {
	if err := validateV1CustodyCommand(a, command, purpose); err != nil {
		return types.Hash{}, err
	}
	e := Entry{Version: Version1, Command: command, AuthorityPublicKey: a.AuthorityPublicKey}
	b, err := e.unsignedBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(authorityDomain(Version1, "entry/signature"), b), nil
}

func CosignReviewedV1CustodyCommand(a Assignment, command Command, purpose Purpose, expected types.Hash, key ed25519.PrivateKey) (Entry, error) {
	id, err := V1CustodyEntryReviewID(a, command, purpose)
	if err != nil || expected.IsZero() || id != expected {
		return Entry{}, errors.Join(ErrCustodyReview, err)
	}
	if !validKey(key) || [32]byte(key.Public().(ed25519.PublicKey)) != a.AuthorityPublicKey {
		return Entry{}, ErrActor
	}
	return SignEntry(command, key)
}

func validateV1CustodyCommand(a Assignment, c Command, purpose Purpose) error {
	if a.Version != Version1 || c.Version != Version1 || (purpose != Audit && purpose != Serve) {
		return ErrCustodyReview
	}
	id, err := a.ID()
	if err != nil || c.AssignmentID != id {
		return errors.Join(ErrAssignment, err)
	}
	if err := c.validateShape(); err != nil {
		return err
	}
	if (c.ExpectedSequence == 0) != (c.ExpectedHead == id) {
		return ErrHead
	}
	// Reserve the final Stop/Retire positions. Sequence alone cannot prove
	// remaining admission capacity; the live state machine checks that later.
	limit := 4 * uint64(a.MaximumOperations)
	switch c.Kind {
	case Admit:
		if c.Purpose != purpose {
			return ErrCommand
		}
		if c.ExpectedSequence >= limit {
			return ErrLimit
		}
	case Complete:
		if c.ExpectedSequence == 0 || c.ExpectedSequence >= limit {
			return ErrLimit
		}
	default:
		return ErrCommand
	}
	for _, member := range a.Consumers {
		if member.PublicKey == c.ActorPublicKey && member.Purposes&purpose != 0 {
			return nil
		}
	}
	return ErrActor
}
