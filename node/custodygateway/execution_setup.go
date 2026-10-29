//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const MaximumExecutionStoreBytes = 256 << 20
const maximumExecutionProofBytes = 8 << 20

var ErrExecution = errors.New("protected profile-5 execution refused; retain original intent and state")

type DeploymentPreparation struct{ Genesis, Enrollment, Pair, A, B []byte }

func PrepareDeployment(p DeploymentPreparation) (wire.Deployment, error) {
	var d wire.Deployment
	g, e := v2.DecodeAdmissionGenesis(p.Genesis)
	if e != nil {
		return d, e
	}
	b, e := v2.DecodeEnrollmentBinding(p.Enrollment)
	if e != nil {
		return d, e
	}
	pair, e := cut.DecodeSourceHandoffPair(p.Pair)
	if e != nil {
		return d, e
	}
	d.A, e = wire.DecodeDescriptor(p.A)
	if e != nil {
		return d, e
	}
	d.B, e = wire.DecodeDescriptor(p.B)
	if e != nil {
		return d, e
	}
	gid, _ := g.ID()
	gdid, _ := g.DescriptorID()
	bid, _ := b.ID()
	ap := cut.SourceHandoffPins{GenesisID: gid, GenesisDescriptorID: gdid, EnrollmentID: bid, PlacementID: pair.A.PlacementID}
	bp := ap
	bp.PlacementID = pair.B.PlacementID
	if e = pair.Verify(g, b, ap, bp); e != nil {
		return d, e
	}
	aid, _ := pair.A.ID()
	bbid, _ := pair.B.ID()
	pid, _ := pair.ID()
	if d.A.SourceID != aid || d.B.SourceID != bbid || d.A.Issuer != b.Registry.Issuer || d.B.Issuer != b.Registry.Issuer {
		return d, ErrExecution
	}
	d.GenesisID = gid
	d.GenesisDescriptorID = gdid
	d.EnrollmentID = bid
	d.ImportID = g.Assignment.Policy.ImportID
	d.PairID = pid
	d.MinimumRetainUntil = pair.A.RetainUntil
	d.Authority = g.Assignment.Base.AuthorityPublicKey
	d.Control = g.Assignment.Base.RemoteControlPublicKey
	_, e = d.CanonicalBytes()
	return d, e
}
func EncodeEndorsement(d wire.Deployment, pair cut.SourceHandoffPair) ([]byte, error) {
	a, e := d.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	b, e := pair.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(a) + len(b) + 32)
	out.BytesField(a)
	out.Fixed(b)
	return out.Bytes(), nil
}
func decodeEndorsement(raw []byte) (wire.Deployment, cut.SourceHandoffPair, error) {
	var pair cut.SourceHandoffPair
	var dep wire.Deployment
	d := codec.NewDecoder(raw)
	b, e := d.BytesField(wire.MaximumDeploymentBytes)
	if e != nil {
		return dep, pair, e
	}
	dep, e = wire.DecodeDeployment(b)
	if e != nil {
		return dep, pair, e
	}
	b, e = d.Fixed(cut.SourceHandoffPairBytes)
	if e != nil || d.Finish() != nil {
		return dep, pair, ErrExecution
	}
	pair, e = cut.DecodeSourceHandoffPair(b)
	return dep, pair, e
}
func (o *Owner) verifyDeployment(d wire.Deployment, pair cut.SourceHandoffPair) error {
	gb, _ := o.g.CanonicalBytes()
	eb, _ := o.b.CanonicalBytes()
	pb, _ := pair.CanonicalBytes()
	ab, _ := d.A.CanonicalBytes()
	bb, _ := d.B.CanonicalBytes()
	expected, e := PrepareDeployment(DeploymentPreparation{gb, eb, pb, ab, bb})
	if e != nil {
		return e
	}
	id, e := expected.ID()
	actual, e2 := d.ID()
	if e != nil || e2 != nil || id != actual {
		return ErrExecution
	}
	mine := d.A
	if o.config.Source.Role == cut.Target {
		mine = d.B
	}
	mid, _ := mine.ID()
	my, _ := o.descriptor.ID()
	if mid != my {
		return ErrExecution
	}
	return nil
}
func (o *Owner) endorse(ctx context.Context, raw []byte) ([]byte, error) {
	d, pair, e := decodeEndorsement(raw)
	if e != nil {
		return nil, e
	}
	if e = o.verifyDeployment(d, pair); e != nil {
		return nil, e
	}
	if d.IssuerSignature == ([64]byte{}) || d.AuthoritySignature == ([64]byte{}) || d.ControlSignature == ([64]byte{}) {
		return nil, ErrExecution
	}
	if _, e = cut.InspectSourceHandoff(ctx, o.g, o.b, o.config.Pins, o.config.Source); e != nil {
		return nil, e
	}
	id, _ := d.ID()
	path := filepath.Join(o.root, "deployment-choice")
	if b, e := privateRead(path, 32); e == nil {
		if !bytes.Equal(b, id[:]) {
			return nil, ErrExecution
		}
	} else if errors.Is(e, os.ErrNotExist) {
		if e = publish(path, id[:]); e != nil {
			o.poisoned = true
			return nil, e
		}
	} else {
		return nil, e
	}
	role := "a"
	if o.config.Source.Role == cut.Target {
		role = "b"
	}
	d, e = d.Sign(role, o.key)
	if e != nil {
		return nil, e
	}
	return d.CanonicalBytes()
}

type ExecutionKeys struct{ Replica, Control, Authority ed25519.PrivateKey }
type ExecutionConfig struct{ Deployment, Pair []byte }
type ExecutionSetup struct {
	ExecutionConfig
	ReplicaKeyPath, ControlKeyPath, AuthorityKeyPath string
}
type executionRuntime struct {
	jobs       map[types.Hash]validatedExecutionJob
	config     ExecutionConfig
	deployment wire.Deployment
	pair       cut.SourceHandoffPair
	keys       ExecutionKeys
	sessions   map[types.Hash]*liveExecution
	configHash types.Hash
}
type liveExecution struct {
	key       ed25519.PrivateKey
	candidate v2.Candidate
}

func ConfigureExecution(ctx context.Context, root string, c ExecutionConfig, keys ExecutionKeys) error {
	if ctx == nil {
		return ErrExecution
	}
	l, e := lockExisting(filepath.Join(root, "owner.lock"))
	if e != nil {
		return e
	}
	defer l.Close()
	id, e := ReadIdentity(root)
	if e != nil {
		return e
	}
	raw, e := privateRead(filepath.Join(root, "config"), MaximumConfigBytes)
	if e != nil {
		return e
	}
	base, e := DecodeConfig(raw)
	if e != nil {
		return e
	}
	d, g, b, h, e := validate(base, id)
	if e != nil {
		return e
	}
	_ = b
	_ = h
	dep, e := wire.DecodeDeployment(c.Deployment)
	if e != nil || dep.Verify() != nil {
		return ErrExecution
	}
	pair, e := cut.DecodeSourceHandoffPair(c.Pair)
	if e != nil {
		return e
	}
	o := &Owner{root: root, identity: id, descriptor: d, config: base, g: g, b: b, handoff: h}
	if e = o.verifyDeployment(dep, pair); e != nil {
		return e
	}
	did, _ := dep.ID()
	choice, e := privateRead(filepath.Join(root, "deployment-choice"), 32)
	if e != nil || !bytes.Equal(choice, did[:]) {
		return ErrExecution
	}
	if _, e = cut.InspectSourceHandoff(ctx, g, b, base.Pins, base.Source); e != nil {
		return e
	}
	match := func(k ed25519.PrivateKey, pub [32]byte) bool {
		return len(k) == 64 && bytes.Equal(ed25519.NewKeyFromSeed(k[:32]), k) && bytes.Equal(k.Public().(ed25519.PublicKey), pub[:])
	}
	files := map[string]ed25519.PrivateKey{}
	if base.Source.Role == cut.Target {
		if !match(keys.Replica, g.Assignment.Base.ReplicaPublicKey) || !match(keys.Control, g.Assignment.Base.RemoteControlPublicKey) || len(keys.Authority) != 0 {
			return ErrExecution
		}
		files["replica.key"] = keys.Replica
		files["control.key"] = keys.Control
	} else {
		if !match(keys.Authority, g.Assignment.Base.AuthorityPublicKey) || len(keys.Replica) != 0 || len(keys.Control) != 0 {
			return ErrExecution
		}
		files["authority.key"] = keys.Authority
	}
	path := filepath.Join(root, "execution")
	if e = os.Mkdir(path, 0700); e != nil {
		return e
	}
	if e = syncDir(root); e != nil {
		return e
	}
	if e = os.Mkdir(filepath.Join(path, "jobs"), 0700); e != nil {
		return e
	}
	if e = os.Mkdir(filepath.Join(path, "calls"), 0700); e != nil {
		return e
	}
	for name, key := range files {
		if e = publish(filepath.Join(path, name), key); e != nil {
			return e
		}
	}
	raw, e = json.Marshal(c)
	if e != nil {
		return e
	}
	if e = publish(filepath.Join(path, "config"), raw); e != nil {
		return e
	}
	hash := types.DomainHash(wire.Domain+"execution-config/id", raw)
	return publish(filepath.Join(path, "ready"), hash[:])
}
func (o *Owner) openExecution() error {
	path := filepath.Join(o.root, "execution")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	if _, e := PlacementID(path, true); e != nil {
		return e
	}
	raw, e := privateRead(filepath.Join(path, "config"), wire.MaximumDeploymentBytes*4)
	if e != nil {
		return e
	}
	var c ExecutionConfig
	if e = strictJSON(raw, &c); e != nil {
		return e
	}
	hash := types.DomainHash(wire.Domain+"execution-config/id", raw)
	mark, e := privateRead(filepath.Join(path, "ready"), 32)
	if e != nil || !bytes.Equal(mark, hash[:]) {
		return ErrExecution
	}
	d, e := wire.DecodeDeployment(c.Deployment)
	if e != nil || d.Verify() != nil {
		return ErrExecution
	}
	pair, e := cut.DecodeSourceHandoffPair(c.Pair)
	if e != nil {
		return e
	}
	if e = o.verifyDeployment(d, pair); e != nil {
		return e
	}
	did, _ := d.ID()
	choice, e := privateRead(filepath.Join(o.root, "deployment-choice"), 32)
	if e != nil || !bytes.Equal(choice, did[:]) {
		return ErrExecution
	}
	r := &executionRuntime{config: c, deployment: d, pair: pair, sessions: map[types.Hash]*liveExecution{}, jobs: map[types.Hash]validatedExecutionJob{}, configHash: hash}
	readKey := func(name string, pub [32]byte) (ed25519.PrivateKey, error) {
		key, e := privateRead(filepath.Join(path, name), 64)
		if e != nil || len(key) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) || !bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), pub[:]) {
			clear(key)
			return nil, ErrExecution
		}
		return key, nil
	}
	if o.config.Source.Role == cut.Target {
		r.keys.Replica, e = readKey("replica.key", o.g.Assignment.Base.ReplicaPublicKey)
		if e == nil {
			r.keys.Control, e = readKey("control.key", o.g.Assignment.Base.RemoteControlPublicKey)
		}
	} else {
		r.keys.Authority, e = readKey("authority.key", o.g.Assignment.Base.AuthorityPublicKey)
	}
	if e != nil {
		clear(r.keys.Replica)
		clear(r.keys.Control)
		clear(r.keys.Authority)
		return e
	}
	o.execution = r
	return o.checkExecution()
}
