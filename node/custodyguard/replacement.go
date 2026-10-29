//go:build linux || darwin

package custodyguard

import (
	"context"
	"crypto/ed25519"
	"os"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func newStoreState(root string, id Identity, c Config, cb []byte, key ed25519.PrivateKey, lock *os.File) *Store {
	return &Store{root: root, identity: id, config: c, configBytes: cb, key: append(ed25519.PrivateKey(nil), key...), lock: lock,
		choices: make(map[types.Hash]wire.Request), revoked: make(map[[32]byte]revokedSubject), replacements: make(map[[32]byte]wire.Replacement), successors: make(map[[32]byte][32]byte)}
}

// ValidateReplacementDraft checks immutable public authorization. The live
// store additionally requires its retained revocation and exact current cursor.
func ValidateReplacementDraft(c Config, id Identity, q wire.Replacement) error {
	if ValidateIdentity(c, id) != nil || q.ValidateDraft() != nil || c.Replacer == ([32]byte{}) || q.Authority != c.Replacer || q.GuardID != id.ID() || q.Successor == id.PublicKey || q.Successor == c.Revoker || q.Successor == c.Replacer {
		return ErrStore
	}
	found := false
	for _, key := range c.Subjects {
		if key == q.Successor {
			return ErrStore
		}
		found = found || key == q.Subject
	}
	if !found {
		return ErrStore
	}
	return nil
}

func (s *Store) replacementAllowed(q wire.Replacement) bool {
	if ValidateReplacementDraft(s.config, s.identity, q) != nil {
		return false
	}
	prior, ok := s.revoked[q.Subject]
	if !ok {
		return false
	}
	id, err := prior.Request.ID()
	if err != nil || id != q.RevocationID {
		return false
	}
	if original, used := s.successors[q.Successor]; used {
		return original == q.Subject && s.replacements[q.Subject] == q
	}
	return true
}

// slotID deliberately resolves to the original key. Neither the successor nor
// the replacement receipt opens a new namespace, budget or operation slot.
func (s *Store) slotID(q wire.Request) (types.Hash, error) {
	if original, ok := s.successors[q.Subject]; ok {
		q.Subject = original
	}
	return q.SlotID()
}
func (s *Store) sameChoice(a, b wire.Request) bool {
	if a.Subject == b.Subject {
		return a == b
	}
	sa, e1 := s.slotID(a)
	sb, e2 := s.slotID(b)
	return e1 == nil && e2 == nil && sa == sb && a.Choice == b.Choice
}

func (s *Store) validAttempt(b []byte) bool {
	switch len(b) {
	case wire.RequestBytes:
		q, err := wire.DecodeRequest(b)
		return err == nil && s.allowed(q)
	case wire.RevocationBytes:
		q, err := wire.DecodeRevocation(b)
		return err == nil && s.revocationAllowed(q)
	case wire.ReplacementBytes:
		q, err := wire.DecodeReplacement(b)
		return err == nil && s.replacementAllowed(q)
	default:
		return false
	}
}
func RecoverReplacement(root string, id Identity, p Position, attempt wire.Replacement) (*Store, error) {
	b, err := attempt.CanonicalBytes()
	if err != nil || attempt.GuardID != id.ID() || attempt.Before != p {
		return nil, ErrStore
	}
	return open(root, id, p, b)
}

// Replace appends an irreversible alias after revocation. It never edits a
// choice, participant history, accounting, source record or retention deadline.
// Exact retries return the historical receipt, even after later revocation.
func (s *Store) Replace(ctx context.Context, q wire.Replacement) (wire.ReplacementReceipt, error) {
	var zero wire.ReplacementReceipt
	if ctx == nil {
		return zero, ErrStore
	}
	b, err := q.CanonicalBytes()
	if err != nil {
		return zero, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = s.check(); err != nil {
		return zero, err
	}
	if !s.replacementAllowed(q) {
		return zero, wire.ErrGuard
	}
	prior, exists := s.replacements[q.Subject]
	if exists && prior != q {
		return zero, wire.ErrGuard
	}
	if !exists {
		if q.Before != s.position {
			return zero, wire.ErrGuard
		}
		if err = s.appendEvent(b); err != nil {
			return zero, err
		}
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = s.check(); err != nil {
		return zero, err
	}
	if s.replacementObserver != nil {
		if err = s.replacementObserver(s.position, q); err != nil {
			return zero, err
		}
	}
	return (wire.ReplacementReceipt{Request: q, Guard: s.identity.PublicKey}).Sign(s.key)
}
func (s *Store) SetReplacementObserver(f func(Position, wire.Replacement) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replacementObserver = f
}

// ValidateSuccessorRevocation checks the public enrollment proof before an
// offline successor revocation. The store independently resolves its own roster.
func ValidateSuccessorRevocation(c Config, id Identity, q wire.Revocation, r wire.ReplacementReceipt) error {
	if ValidateReplacementDraft(c, id, r.Request) != nil || r.Verify(id.PublicKey, id.ID(), r.Request) != nil || q.Subject != r.Request.Successor || q.GuardID != id.ID() || q.Authority != c.Revoker {
		return ErrStore
	}
	_, err := q.CanonicalBytes()
	return err
}
