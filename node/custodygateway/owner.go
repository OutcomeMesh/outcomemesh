//go:build linux || darwin

// Package custodygateway owns a fresh key and original sealed storage behind a
// separate operating-system identity. Host administrators remain trusted.
package custodygateway

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
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const MaximumConfigBytes = 2*(v2.MaximumAdmissionGenesisBytes+v2.MaximumEnrollmentBindingBytes) + 1<<20

type Identity struct {
	RootID    types.Hash
	PublicKey [32]byte
}
type Config struct {
	Descriptor          []byte
	Genesis, Enrollment []byte
	Pins                cut.SourceHandoffPins
	Source              cut.SourceLocation
	Objects             string
}
type Owner struct {
	mu                sync.Mutex
	root              string
	identity          Identity
	descriptor        wire.Descriptor
	config            Config
	configHash        types.Hash
	g                 v2.AdmissionGenesis
	b                 v2.EnrollmentBinding
	handoff           workarchive.CustodySourceHandoff
	key               ed25519.PrivateKey
	lock              *os.File
	position          wire.Position
	tip               []byte
	revoked, poisoned bool
	journalBytes      int
	// Test fault injection is private and never exposed over RPC or CLI.
	beforeCommit func() error
	afterCommit  func() error
}

func rootID(root string) (types.Hash, error) {
	var all []byte
	for _, v := range []struct {
		name string
		dir  bool
	}{{root, true}, {filepath.Join(root, "owner.lock"), false}, {filepath.Join(root, "key"), false}} {
		id, e := PlacementID(v.name, v.dir)
		if e != nil {
			return types.Hash{}, e
		}
		all = append(all, id[:]...)
	}
	return types.DomainHash(wire.Domain+"root/id", all), nil
}
func CreateIdentity(root string) (Identity, error) {
	var id Identity
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return id, ErrOwner
	}
	if e := os.Mkdir(root, 0700); e != nil {
		return id, e
	}
	if _, e := PlacementID(root, true); e != nil {
		return id, e
	}
	if e := publish(filepath.Join(root, "owner.lock"), nil); e != nil {
		return id, e
	}
	lock, e := lockExisting(filepath.Join(root, "owner.lock"))
	if e != nil {
		return id, e
	}
	defer lock.Close()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return id, e
	}
	defer clear(key)
	if e = publish(filepath.Join(root, "key"), key); e != nil {
		return id, e
	}
	id.RootID, e = rootID(root)
	if e != nil {
		return id, e
	}
	copy(id.PublicKey[:], pub)
	raw, e := json.Marshal(id)
	if e != nil {
		return id, e
	}
	if e = publish(filepath.Join(root, "identity"), raw); e != nil {
		return id, e
	}
	return id, syncDir(filepath.Dir(root))
}
func ReadIdentity(root string) (Identity, error) {
	var id Identity
	raw, e := privateRead(filepath.Join(root, "identity"), 1024)
	if e != nil {
		return id, e
	}
	if e = strictJSON(raw, &id); e != nil {
		return id, e
	}
	actual, e := rootID(root)
	if e != nil || actual != id.RootID {
		return Identity{}, ErrOwner
	}
	return id, nil
}
func validate(c Config, id Identity) (wire.Descriptor, v2.AdmissionGenesis, v2.EnrollmentBinding, workarchive.CustodySourceHandoff, error) {
	var g v2.AdmissionGenesis
	var b v2.EnrollmentBinding
	var h workarchive.CustodySourceHandoff
	d, e := wire.DecodeDescriptor(c.Descriptor)
	if e != nil {
		return d, g, b, h, e
	}
	if d.RootID != id.RootID || d.Gateway != id.PublicKey || d.OwnerUID != uint32(os.Geteuid()) {
		return d, g, b, h, ErrOwner
	}
	for _, path := range append([]string{c.Source.Journal, c.Source.Authority, c.Source.AuthorityPins}, c.Source.Workers...) {
		if path != "" {
			if _, e := PlacementID(path, true); e != nil {
				return d, g, b, h, e
			}
		}
	}
	g, e = v2.DecodeAdmissionGenesis(c.Genesis)
	if e != nil {
		return d, g, b, h, e
	}
	b, e = v2.DecodeEnrollmentBinding(c.Enrollment)
	if e != nil {
		return d, g, b, h, e
	}
	h, e = cut.ReviewSourceHandoff(g, b, c.Pins, c.Source.Role)
	if e != nil {
		return d, g, b, h, e
	}
	hid, e := h.ID()
	if e != nil || hid != d.SourceID || d.GenesisID != c.Pins.GenesisID || d.GenesisDescriptorID != c.Pins.GenesisDescriptorID || d.EnrollmentID != c.Pins.EnrollmentID || d.Issuer != b.Registry.Issuer {
		return d, g, b, h, ErrOwner
	}
	if c.Source.Role == cut.Target {
		oid, e := PlacementID(c.Objects, true)
		if e != nil || oid != d.ObjectsID {
			return d, g, b, h, ErrOwner
		}
	} else if c.Objects != "" || !d.ObjectsID.IsZero() {
		return d, g, b, h, ErrOwner
	}
	// The freshly generated service identity cannot reuse any participant or
	// witness key from either the retired assignment or selected successor.
	a := g.Assignment.Base
	old := g.Import.Evidence.Assignment
	roles := [][32]byte{a.AuthorityPublicKey, a.RemoteControlPublicKey, a.RemoteTransportPublicKey, a.ReplicaPublicKey, old.AuthorityPublicKey, old.RemoteControlPublicKey, old.RemoteTransportPublicKey, old.ReplicaPublicKey}
	roles = append(roles, b.Registry.Witnesses...)
	roles = append(roles, g.Assignment.Policy.Witnesses...)
	roles = append(roles, a.Auditors...)
	roles = append(roles, old.Auditors...)
	roles = append(roles, g.CustodyPolicy.TrustedAuditors...)
	for _, v := range a.Consumers {
		roles = append(roles, v.PublicKey)
	}
	for _, v := range old.Consumers {
		roles = append(roles, v.PublicKey)
	}
	for _, k := range roles {
		if d.Gateway == k {
			return d, g, b, h, ErrOwner
		}
	}
	return d, g, b, h, nil
}
func Configure(ctx context.Context, root string, c Config) error {
	if ctx == nil {
		return ErrOwner
	}
	frozen, e := json.Marshal(c)
	if e != nil || len(frozen) > MaximumConfigBytes {
		return ErrOwner
	}
	c, e = DecodeConfig(frozen)
	if e != nil {
		return e
	}
	lock, e := lockExisting(filepath.Join(root, "owner.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	id, e := ReadIdentity(root)
	if e != nil {
		return e
	}
	_, g, b, _, e := validate(c, id)
	if e != nil {
		return e
	}
	if _, e = cut.InspectSourceHandoff(ctx, g, b, c.Pins, c.Source); e != nil {
		return e
	}
	if c.Objects != "" {
		if _, e = workarchive.OpenExistingObjectStoreContext(ctx, c.Objects, workarchive.DefaultObjectStorePolicy()); e != nil {
			return e
		}
	}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > MaximumConfigBytes {
		return ErrOwner
	}
	if e = os.Mkdir(filepath.Join(root, "events"), 0700); e != nil {
		return e
	}
	if e = syncDir(root); e != nil {
		return e
	}
	if e = publish(filepath.Join(root, "config"), raw); e != nil {
		return e
	}
	hash := types.DomainHash(wire.Domain+"config/id", raw)
	return publish(filepath.Join(root, "configured"), hash[:])
}

// Open requires an independently retained exact position. Recovery permits only
// the exact attempted request at that before-position, never arbitrary tip adoption.
func Open(root string, descriptorID types.Hash, pin wire.Position, recoverRequest *wire.Request) (opened *Owner, err error) {
	if descriptorID.IsZero() || !pin.Valid() {
		return nil, ErrOwner
	}
	o := &Owner{root: root}
	o.lock, err = lockExisting(filepath.Join(root, "owner.lock"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			o.Close()
		}
	}()
	o.identity, err = ReadIdentity(root)
	if err != nil {
		return nil, err
	}
	raw, err := privateRead(filepath.Join(root, "config"), MaximumConfigBytes)
	if err != nil {
		return nil, err
	}
	if err = strictJSON(raw, &o.config); err != nil {
		return nil, err
	}
	o.configHash = types.DomainHash(wire.Domain+"config/id", raw)
	mark, e := privateRead(filepath.Join(root, "configured"), 32)
	if e != nil || !bytes.Equal(mark, o.configHash[:]) {
		return nil, ErrOwner
	}
	o.descriptor, o.g, o.b, o.handoff, err = validate(o.config, o.identity)
	if err != nil {
		return nil, err
	}
	actual, _ := o.descriptor.ID()
	if actual != descriptorID {
		return nil, ErrOwner
	}
	o.key, err = privateRead(filepath.Join(root, "key"), ed25519.PrivateKeySize)
	if err != nil || len(o.key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(o.key[:32]), o.key) || !bytes.Equal(o.key.Public().(ed25519.PublicKey), o.identity.PublicKey[:]) {
		return nil, ErrOwner
	}
	if _, err = PlacementID(filepath.Join(root, "events"), true); err != nil {
		return nil, err
	}
	entries, e := os.ReadDir(filepath.Join(root, "events"))
	if e != nil || len(entries) > int(o.descriptor.EventLimit) {
		return nil, ErrOwner
	}
	for i, entry := range entries {
		if entry.Name() != eventName(uint64(i+1)) || entry.IsDir() || o.revoked {
			return nil, ErrOwner
		}
		raw, e := privateRead(filepath.Join(root, "events", entry.Name()), wire.MaximumResponseBytes)
		if e != nil {
			return nil, e
		}
		r, e := wire.DecodeResponse(raw)
		if e != nil || r.Request.Before != o.position || r.Verify(o.descriptor, r.Request) != nil {
			return nil, ErrOwner
		}
		o.position, _ = r.Position()
		o.revoked = r.Request.Kind == wire.Revoke
		o.tip = raw
		o.journalBytes += len(raw)
		if o.journalBytes > wire.MaximumJournalBytes {
			return nil, ErrOwner
		}
	}
	if recoverRequest != nil && recoverRequest.Authorize(o.descriptor) != nil {
		return nil, ErrOwner
	}
	if o.position != pin {
		if recoverRequest == nil || recoverRequest.Before != pin || o.position.Sequence != pin.Sequence+1 {
			return nil, ErrOwner
		}
		tip, e := wire.DecodeResponse(o.tip)
		want, e2 := recoverRequest.CanonicalBytes()
		got, e3 := tip.Request.CanonicalBytes()
		if e != nil || e2 != nil || e3 != nil || !bytes.Equal(want, got) {
			return nil, ErrOwner
		}
	} else if recoverRequest != nil && recoverRequest.Before != pin {
		return nil, ErrOwner
	}
	if err = o.check(); err != nil {
		return nil, err
	}
	return o, nil
}
func eventName(n uint64) string { return fmt.Sprintf("%08d.response", n) }
func (o *Owner) check() error {
	if o.lock == nil || o.poisoned {
		return ErrOwner
	}
	id, e := ReadIdentity(o.root)
	if e != nil || id != o.identity {
		return ErrOwner
	}
	a, e := o.lock.Stat()
	b, e2 := os.Lstat(filepath.Join(o.root, "owner.lock"))
	if e != nil || e2 != nil || !os.SameFile(a, b) {
		return ErrOwner
	}
	raw, e := privateRead(filepath.Join(o.root, "config"), MaximumConfigBytes)
	if e != nil || types.DomainHash(wire.Domain+"config/id", raw) != o.configHash {
		return ErrOwner
	}
	mark, e := privateRead(filepath.Join(o.root, "configured"), 32)
	if e != nil || !bytes.Equal(mark, o.configHash[:]) {
		return ErrOwner
	}
	key, e := privateRead(filepath.Join(o.root, "key"), ed25519.PrivateKeySize)
	defer clear(key)
	if e != nil || !bytes.Equal(key, o.key) {
		return ErrOwner
	}
	if _, e = PlacementID(filepath.Join(o.root, "events"), true); e != nil {
		return e
	}
	entries, e := os.ReadDir(filepath.Join(o.root, "events"))
	if e != nil || len(entries) != int(o.position.Sequence) {
		return ErrOwner
	}
	for i, entry := range entries {
		if entry.Name() != eventName(uint64(i+1)) || entry.IsDir() {
			return ErrOwner
		}
	}
	if len(o.tip) > 0 {
		raw, e := privateRead(filepath.Join(o.root, "events", eventName(o.position.Sequence)), wire.MaximumResponseBytes)
		if e != nil || !bytes.Equal(raw, o.tip) {
			return ErrOwner
		}
	}
	if o.config.Objects != "" {
		id, e := PlacementID(o.config.Objects, true)
		if e != nil || id != o.descriptor.ObjectsID {
			return ErrOwner
		}
	}
	return nil
}
func (o *Owner) Descriptor() wire.Descriptor {
	o.mu.Lock()
	defer o.mu.Unlock()
	d := o.descriptor
	d.Clients = append([][32]byte(nil), d.Clients...)
	return d
}
func (o *Owner) Position() (wire.Position, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.position, o.revoked
}

// Execute completes the effect while holding the same owner lock that excludes
// revocation. No portable pre-authorization or arbitrary-signing API exists.
func (o *Owner) Execute(ctx context.Context, q wire.Request) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil {
		return nil, ErrOwner
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := o.check(); e != nil {
		o.poisoned = true
		return nil, e
	}
	if e := q.Authorize(o.descriptor); e != nil {
		return nil, e
	}
	if len(o.tip) > 0 {
		tip, e := wire.DecodeResponse(o.tip)
		a, e2 := q.CanonicalBytes()
		b, e3 := tip.Request.CanonicalBytes()
		if e == nil && e2 == nil && e3 == nil && bytes.Equal(a, b) && (!o.revoked || q.Kind == wire.Revoke) {
			return append([]byte(nil), o.tip...), nil
		}
	}
	if o.revoked || q.Before != o.position {
		return nil, wire.ErrAccess
	}
	// Reserve one final revocation slot and a bounded empty revocation response.
	if q.Kind != wire.Revoke && (o.position.Sequence+1 >= uint64(o.descriptor.EventLimit) || o.journalBytes+wire.MaximumResponseBytes+1024 > wire.MaximumJournalBytes) {
		return nil, wire.ErrAccess
	}
	var data []byte
	var e error
	switch q.Kind {
	case wire.Inspect:
		var h workarchive.CustodySourceHandoff
		h, e = cut.InspectSourceHandoff(ctx, o.g, o.b, o.config.Pins, o.config.Source)
		if e == nil {
			data, e = h.CanonicalBytes()
		}
	case wire.ReadChunk:
		if o.config.Source.Role != cut.Target {
			return nil, wire.ErrAccess
		}
		_, data, e = cut.InspectSourceHandoffChunk(ctx, o.g, o.b, o.config.Pins, o.config.Source, o.config.Objects, q.ChunkID)
	case wire.Revoke: // Always possible even if the source itself has become unreadable.
	default:
		return nil, wire.ErrAccess
	}
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = o.check(); e != nil {
		return nil, e
	}
	r, e := (wire.Response{Request: q, SourceID: o.descriptor.SourceID, Data: data}).Sign(o.descriptor, o.key)
	if e != nil {
		return nil, e
	}
	raw, e := r.CanonicalBytes()
	if e != nil || o.journalBytes+len(raw) > wire.MaximumJournalBytes {
		return nil, ErrOwner
	}
	if o.beforeCommit != nil {
		if e = o.beforeCommit(); e != nil {
			return nil, e
		}
	}
	// Once publication starts, any error is an unknown outcome. Only exact cold
	// recovery can reopen; no caller sees a signature before durability succeeds.
	o.poisoned = true
	if e = publish(filepath.Join(o.root, "events", eventName(o.position.Sequence+1)), raw); e != nil {
		return nil, e
	}
	if o.afterCommit != nil {
		if e = o.afterCommit(); e != nil {
			return nil, e
		}
	}
	o.position, _ = r.Position()
	o.revoked = q.Kind == wire.Revoke
	o.tip = raw
	o.journalBytes += len(raw)
	o.poisoned = false
	return append([]byte(nil), raw...), nil
}
func (o *Owner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.key)
	o.poisoned = true
	if o.lock == nil {
		return nil
	}
	e := o.lock.Close()
	o.lock = nil
	return e
}

// DecodeConfig rejects unknown fields and oversized public preparation input.
func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	if len(raw) > MaximumConfigBytes {
		return c, ErrOwner
	}
	e := strictJSON(raw, &c)
	return c, e
}

// DraftDescriptor derives public IDs from complete selected evidence and local
// metadata. It neither opens a source owner nor loads the service private key.
// Issuer signing and Configure are separate reviewed steps.
func DraftDescriptor(root string, c Config, participantUID uint32, clients [][32]byte, eventLimit uint32) (wire.Descriptor, error) {
	var d wire.Descriptor
	id, e := ReadIdentity(root)
	if e != nil {
		return d, e
	}
	g, e := v2.DecodeAdmissionGenesis(c.Genesis)
	if e != nil {
		return d, e
	}
	b, e := v2.DecodeEnrollmentBinding(c.Enrollment)
	if e != nil {
		return d, e
	}
	h, e := cut.ReviewSourceHandoff(g, b, c.Pins, c.Source.Role)
	if e != nil {
		return d, e
	}
	hid, e := h.ID()
	if e != nil {
		return d, e
	}
	var objectsID types.Hash
	if c.Source.Role == cut.Target {
		objectsID, e = PlacementID(c.Objects, true)
		if e != nil {
			return d, e
		}
	} else if c.Objects != "" {
		return d, ErrOwner
	}
	d = wire.Descriptor{RootID: id.RootID, SourceID: hid, GenesisID: c.Pins.GenesisID, GenesisDescriptorID: c.Pins.GenesisDescriptorID, EnrollmentID: c.Pins.EnrollmentID, ObjectsID: objectsID, Gateway: id.PublicKey, Issuer: b.Registry.Issuer, Clients: append([][32]byte(nil), clients...), OwnerUID: uint32(os.Geteuid()), ParticipantUID: participantUID, EventLimit: eventLimit}
	return d, nil
}
