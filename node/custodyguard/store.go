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
}
type Identity struct {
	PublicKey        [32]byte
	RootID, ConfigID types.Hash
}
type Position struct {
	Sequence uint32
	Head     types.Hash
}
type Store struct {
	observer    func(Position, wire.Request) error
	mu          sync.Mutex
	root        string
	identity    Identity
	config      Config
	configBytes []byte
	key         ed25519.PrivateKey
	lock        *os.File
	position    Position
	records     [][]byte
	choices     map[types.Hash]wire.Request
	poisoned    bool
	hook        func(string) error
}

func (c Config) validate() error {
	if c.Limit == 0 || c.Limit > MaximumChoices || len(c.Subjects) == 0 || len(c.Subjects) > MaximumSubjects {
		return ErrStore
	}
	for i, k := range c.Subjects {
		if types.Hash(k).IsZero() || i > 0 && bytes.Compare(c.Subjects[i-1][:], k[:]) >= 0 {
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
	s = &Store{root: root, identity: id, config: c, configBytes: cb, key: append(ed25519.PrivateKey(nil), key...), lock: lock, choices: make(map[types.Hash]wire.Request)}
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
func Open(root string, id Identity, p Position, attempt *wire.Request) (s *Store, err error) {
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
	if strictJSON(cb, &c) != nil || c.validate() != nil || types.DomainHash(wire.Domain+"config", cb) != id.ConfigID {
		return nil, ErrStore
	}
	s = &Store{root: root, identity: id, config: c, configBytes: cb, key: append(ed25519.PrivateKey(nil), key...), lock: lock, choices: make(map[types.Hash]wire.Request)}
	entries, err := os.ReadDir(filepath.Join(root, "events"))
	if err != nil || len(entries) > int(c.Limit) {
		return s, ErrStore
	}
	var beforeLast Position
	var last wire.Request
	for i, ent := range entries {
		if ent.Name() != eventName(i+1) {
			return s, ErrStore
		}
		b, e := privateRead(filepath.Join(root, "events", ent.Name()), wire.RequestBytes)
		if e != nil {
			return s, e
		}
		q, e := wire.DecodeRequest(b)
		if e != nil || !s.allowed(q) {
			return s, ErrStore
		}
		slot, _ := q.SlotID()
		if _, ok := s.choices[slot]; ok {
			return s, ErrStore
		}
		beforeLast = s.position
		last = q
		s.position = next(s.position, b)
		s.records = append(s.records, b)
		s.choices[slot] = q
	}
	if s.position != p {
		if attempt == nil || beforeLast != p || s.position.Sequence != p.Sequence+1 || last != *attempt {
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
		b, e := privateRead(filepath.Join(s.root, "events", ent.Name()), wire.RequestBytes)
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
	if !s.allowed(q) {
		return seal, wire.ErrGuard
	}
	slot, _ := q.SlotID()
	prior, ok := s.choices[slot]
	if ok && prior != q {
		return seal, wire.ErrGuard
	}
	if !ok {
		if len(s.records) >= int(s.config.Limit) {
			return seal, ErrStore
		}
		s.poisoned = true
		if s.hook != nil {
			if err = s.hook("before-persist"); err != nil {
				return
			}
		}
		if err = publish(filepath.Join(s.root, "events", eventName(len(s.records)+1)), b); err != nil {
			return
		}
		if s.hook != nil {
			if err = s.hook("after-persist"); err != nil {
				return
			}
		}
		s.records = append(s.records, b)
		s.choices[slot] = q
		s.position = next(s.position, b)
		s.poisoned = false
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
