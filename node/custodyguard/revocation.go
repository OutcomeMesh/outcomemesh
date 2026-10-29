//go:build linux || darwin

package custodyguard

import (
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func (id Identity) ID() types.Hash {
	if types.Hash(id.PublicKey).IsZero() || id.RootID.IsZero() || id.ConfigID.IsZero() {
		return types.Hash{}
	}
	return types.DomainHash(wire.Domain+"identity", id.PublicKey[:], id.RootID[:], id.ConfigID[:])
}

// ValidateIdentity validates public immutable configuration without opening a
// private guard root. Omitting Revoker preserves legacy ConfigID bytes.
func ValidateIdentity(c Config, id Identity) error {
	b, err := json.Marshal(c)
	if err != nil || c.validate() != nil || id.ID().IsZero() || c.Revoker == id.PublicKey || types.DomainHash(wire.Domain+"config", b) != id.ConfigID {
		return ErrStore
	}
	for _, k := range c.Subjects {
		if k == id.PublicKey {
			return ErrStore
		}
	}
	return nil
}

func ValidateRevocation(c Config, id Identity, q wire.Revocation) error {
	if ValidateIdentity(c, id) != nil {
		return ErrStore
	}
	s := Store{config: c, identity: id}
	if _, err := q.CanonicalBytes(); err != nil || !s.revocationAllowed(q) {
		return ErrStore
	}
	return nil
}

func (s *Store) revocationAllowed(q wire.Revocation) bool {
	return !types.Hash(s.config.Revoker).IsZero() && q.Authority == s.config.Revoker && q.GuardID == s.identity.ID() && s.allowed(wire.Request{Subject: q.Subject})
}

// replay applies a single authenticated event, rejecting any choice signed
// after a revocation, duplicate records, or use of reserved revocation slots.
func (s *Store) replay(b []byte) error {
	if len(b) == wire.RequestBytes {
		q, err := wire.DecodeRequest(b)
		if _, revoked := s.revoked[q.Subject]; err != nil || !s.allowed(q) || revoked || len(s.choices) >= int(s.config.Limit) {
			return ErrStore
		}
		slot, _ := q.SlotID()
		if _, exists := s.choices[slot]; exists {
			return ErrStore
		}
		s.choices[slot] = q
		return nil
	}
	q, err := wire.DecodeRevocation(b)
	if err != nil || !s.revocationAllowed(q) {
		return ErrStore
	}
	if _, exists := s.revoked[q.Subject]; exists {
		return ErrStore
	}
	s.revoked[q.Subject] = revokedSubject{Request: q, Before: s.position}
	return nil
}

// appendEvent runs under mu. Any ambiguous write poisons this instance; only
// cold recovery against an independently retained cursor may reopen it.
func (s *Store) appendEvent(b []byte) error {
	s.poisoned = true
	if s.hook != nil {
		if err := s.hook("before-persist"); err != nil {
			return err
		}
	}
	if err := publish(filepath.Join(s.root, "events", eventName(len(s.records)+1)), b); err != nil {
		return err
	}
	if s.hook != nil {
		if err := s.hook("after-persist"); err != nil {
			return err
		}
	}
	if err := s.replay(b); err != nil {
		return err
	}
	s.records = append(s.records, b)
	s.position = next(s.position, b)
	s.poisoned = false
	return nil
}

// Revoke is permanent. It neither changes retained choices nor releases work,
// funds, or capacity. All subsequent Choose calls for this subject are refused,
// including exact retries. Previously returned seals remain historical proofs.
func (s *Store) Revoke(ctx context.Context, q wire.Revocation) (wire.RevocationReceipt, error) {
	var zero wire.RevocationReceipt
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
	if !s.revocationAllowed(q) {
		return zero, wire.ErrGuard
	}
	prior, exists := s.revoked[q.Subject]
	if exists && prior.Request != q {
		return zero, wire.ErrGuard
	}
	if !exists {
		if err = s.appendEvent(b); err != nil {
			return zero, err
		}
		prior = s.revoked[q.Subject]
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = s.check(); err != nil {
		return zero, err
	}
	if s.revocationObserver != nil {
		if err = s.revocationObserver(s.position, q); err != nil {
			return zero, err
		}
	}
	return (wire.RevocationReceipt{Request: q, Before: prior.Before, Guard: s.identity.PublicKey}).Sign(s.key)
}

func (s *Store) SetRevocationObserver(f func(Position, wire.Revocation) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revocationObserver = f
}
