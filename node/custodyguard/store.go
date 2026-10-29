//go:build linux || darwin

// Package custodyguard retains one irreversible choice per subject/namespace/
// slot. It is an external trust boundary, not a software replacement for an HSM.
package custodyguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const MaximumConfigBytes = 8 << 10
const MaximumChoices = 4096
const MaximumSubjects = 32

type Config struct {
	Subjects [][32]byte
	Limit    uint32
	Revoker  [32]byte `json:",omitzero"`
}
type Identity struct {
	PublicKey        [32]byte
	RootID, ConfigID types.Hash
}
type Position = wire.Position

type revokedSubject struct {
	Request wire.Revocation
	Before  Position
}
type Store struct {
	observer           func(Position, wire.Request) error
	revocationObserver func(Position, wire.Revocation) error
	mu                 sync.Mutex
	root               string
	identity           Identity
	config             Config
	configBytes        []byte
	key                ed25519.PrivateKey
	lock               *os.File
	position           Position
	records            [][]byte
	choices            map[types.Hash]wire.Request
	revoked            map[[32]byte]revokedSubject
	poisoned           bool
	hook               func(string) error
}

func (c Config) validate() error {
	if c.Limit == 0 || c.Limit > MaximumChoices || len(c.Subjects) == 0 || len(c.Subjects) > MaximumSubjects {
		return ErrStore
	}
	for i, k := range c.Subjects {
		if types.Hash(k).IsZero() || k == c.Revoker || i > 0 && bytes.Compare(c.Subjects[i-1][:], k[:]) >= 0 {
			return ErrStore
		}
	}
	return nil
}
func rootID(root string) (types.Hash, error) {
	var raw []byte
	for i, p := range []string{root, filepath.Join(root, "key"), filepath.Join(root, "lock")} {
		h, e := PlacementID(p, i == 0)
		if e != nil {
			return types.Hash{}, e
		}
		raw = append(raw, h[:]...)
	}
	return types.DomainHash(wire.Domain+"root", raw), nil
}
func Create(root string, c Config) (s *Store, err error) {
	if c.validate() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrStore
	}
	if err = os.Mkdir(root, 0700); err != nil {
		return nil, err
	}
	if _, err = PlacementID(root, true); err != nil {
		return nil, err
	}
	if err = publish(filepath.Join(root, "lock"), nil); err != nil {
		return nil, err
	}
	lock, err := lockExisting(filepath.Join(root, "lock"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if err = publish(filepath.Join(root, "key"), key); err != nil {
		return nil, err
	}
	if bytes.Equal(c.Revoker[:], pub) {
		return nil, ErrStore
	}
	for _, k := range c.Subjects {
		if bytes.Equal(k[:], pub) {
			return nil, ErrStore
		}
	}
	c.Subjects = append([][32]byte(nil), c.Subjects...)
	cb, _ := json.Marshal(c)
	if err = publish(filepath.Join(root, "config"), cb); err != nil {
		return nil, err
	}
	if err = os.Mkdir(filepath.Join(root, "events"), 0700); err != nil {
		return nil, err
	}
	rid, err := rootID(root)
	if err != nil {
		return nil, err
	}
	id := Identity{RootID: rid, ConfigID: types.DomainHash(wire.Domain+"config", cb)}
	copy(id.PublicKey[:], pub)
	ib, _ := json.Marshal(id)
	if err = publish(filepath.Join(root, "identity"), ib); err != nil {
		return nil, err
	}
	if err = syncDir(root); err != nil {
		return nil, err
	}
	if err = syncDir(filepath.Dir(root)); err != nil {
		return nil, err
	}
	s = &Store{root: root, identity: id, config: c, configBytes: cb, key: append(ed25519.PrivateKey(nil), key...), lock: lock, choices: make(map[types.Hash]wire.Request), revoked: make(map[[32]byte]revokedSubject)}
	return s, nil
}
func (s *Store) Identity() Identity { return s.identity }
func (s *Store) Position() (Position, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(); e != nil {
		return Position{}, e
	}
	return s.position, nil
}
func eventName(n int) string { return fmt.Sprintf("%08d.choice", n) }
func next(p Position, b []byte) Position {
	return Position{Sequence: p.Sequence + 1, Head: types.DomainHash(wire.Domain+"event", p.Head[:], b)}
}

// Open accepts the externally retained exact cursor, or precisely one matching
// attempted request after it. It never adopts a tip or repairs partial evidence.
func Open(root string, id Identity, p Position, attempt *wire.Request) (*Store, error) {
	var raw []byte
	if attempt != nil {
		var err error
		raw, err = attempt.CanonicalBytes()
		if err != nil {
			return nil, err
		}
	}
	return open(root, id, p, raw)
}

func RecoverRevocation(root string, id Identity, p Position, attempt wire.Revocation) (*Store, error) {
	raw, err := attempt.CanonicalBytes()
	if err != nil || attempt.GuardID != id.ID() {
		return nil, ErrStore
	}
	return open(root, id, p, raw)
}

func open(root string, id Identity, p Position, attempt []byte) (s *Store, err error) {
	if !p.Valid() || id.ID().IsZero() {
		return nil, ErrStore
	}
	lock, err := lockExisting(filepath.Join(root, "lock"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			lock.Close()
			if s != nil {
				clear(s.key)
			}
		}
	}()
	raw, err := privateRead(filepath.Join(root, "identity"), 2048)
	if err != nil {
		return nil, err
	}
	var stored Identity
	if strictJSON(raw, &stored) != nil || stored != id {
		return nil, ErrStore
	}
	rid, err := rootID(root)
	if err != nil || rid != id.RootID {
		return nil, ErrStore
	}
	key, err := privateRead(filepath.Join(root, "key"), 64)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if len(key) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) || !bytes.Equal(key[32:], id.PublicKey[:]) {
		return nil, ErrStore
	}
	cb, err := privateRead(filepath.Join(root, "config"), MaximumConfigBytes)
	if err != nil {
		return nil, err
	}
	var c Config
	if strictJSON(cb, &c) != nil || c.validate() != nil || c.Revoker == id.PublicKey || types.DomainHash(wire.Domain+"config", cb) != id.ConfigID {
		return nil, ErrStore
	}
	s = &Store{root: root, identity: id, config: c, configBytes: cb, key: append(ed25519.PrivateKey(nil), key...), lock: lock, choices: make(map[types.Hash]wire.Request), revoked: make(map[[32]byte]revokedSubject)}
	// Recovery attempts are authenticated even when no extra event was written.
	if len(attempt) != 0 {
		if len(attempt) == wire.RevocationBytes {
			q, e := wire.DecodeRevocation(attempt)
			if e != nil || !s.revocationAllowed(q) {
				return s, ErrStore
			}
		} else {
			q, e := wire.DecodeRequest(attempt)
			if e != nil || !s.allowed(q) {
				return s, ErrStore
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "events"))
	limit := int(c.Limit)
	if !types.Hash(c.Revoker).IsZero() {
		limit += len(c.Subjects)
	}
	if err != nil || len(entries) > limit {
		return s, ErrStore
	}
	var beforeLast Position
	var last []byte
	for i, ent := range entries {
		if ent.Name() != eventName(i+1) {
			return s, ErrStore
		}
		b, e := privateRead(filepath.Join(root, "events", ent.Name()), wire.RevocationBytes)
		if e != nil {
			return s, e
		}
		beforeLast = s.position
		last = b
		if e = s.replay(b); e != nil {
			return s, e
		}
		s.position = next(s.position, b)
		s.records = append(s.records, b)
	}
	if s.position != p {
		if len(attempt) == 0 || beforeLast != p || s.position.Sequence != p.Sequence+1 || !bytes.Equal(last, attempt) {
			return s, ErrStore
		}
	}
	if err = s.check(); err != nil {
		return s, err
	}
	return s, nil
}
func (s *Store) allowed(q wire.Request) bool {
	for _, k := range s.config.Subjects {
		if q.Subject == k && k != s.identity.PublicKey {
			return true
		}
	}
	return false
}
func (s *Store) check() error {
	if s.poisoned || s.lock == nil {
		return ErrStore
	}
	rid, e := rootID(s.root)
	if e != nil || rid != s.identity.RootID {
		return ErrStore
	}
	st, e := os.Lstat(filepath.Join(s.root, "lock"))
	lt, e2 := s.lock.Stat()
	if e != nil || e2 != nil || !os.SameFile(st, lt) {
		return ErrStore
	}
	cb, e := privateRead(filepath.Join(s.root, "config"), MaximumConfigBytes)
	if e != nil || !bytes.Equal(cb, s.configBytes) {
		return ErrStore
	}
	kb, e := privateRead(filepath.Join(s.root, "key"), 64)
	defer clear(kb)
	if e != nil || !bytes.Equal(kb, s.key) {
		return ErrStore
	}
	if _, e = PlacementID(filepath.Join(s.root, "events"), true); e != nil {
		return e
	}
	ents, e := os.ReadDir(filepath.Join(s.root, "events"))
	if e != nil || len(ents) != len(s.records) {
		return ErrStore
	}
	for i, ent := range ents {
		if ent.Name() != eventName(i+1) {
			return ErrStore
		}
		b, e := privateRead(filepath.Join(s.root, "events", ent.Name()), wire.RevocationBytes)
		if e != nil || !bytes.Equal(b, s.records[i]) {
			return ErrStore
		}
	}
	return nil
}
func (s *Store) Choose(ctx context.Context, q wire.Request) (seal [64]byte, err error) {
	if ctx == nil {
		return seal, ErrStore
	}
	b, e := q.CanonicalBytes()
	if e != nil {
		return seal, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return
	}
	if err = s.check(); err != nil {
		return
	}
	if _, revoked := s.revoked[q.Subject]; !s.allowed(q) || revoked {
		return seal, wire.ErrGuard
	}
	slot, _ := q.SlotID()
	prior, ok := s.choices[slot]
	if ok && prior != q {
		return seal, wire.ErrGuard
	}
	if !ok {
		if len(s.choices) >= int(s.config.Limit) {
			return seal, ErrStore
		}
		if err = s.appendEvent(b); err != nil {
			return
		}
	}
	if err = ctx.Err(); err != nil {
		return
	}
	if err = s.check(); err != nil {
		return
	}
	if s.observer != nil {
		if err = s.observer(s.position, q); err != nil {
			return
		}
	}
	h, _ := q.SealDigest()
	copy(seal[:], ed25519.Sign(s.key, h[:]))
	return seal, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	if s.lock == nil {
		return nil
	}
	e := s.lock.Close()
	s.lock = nil
	return e
}

func ValidateConfig(c Config) error { return c.validate() }
func (s *Store) SetObserver(f func(Position, wire.Request) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = f
}
