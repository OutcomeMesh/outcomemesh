package gatewaywire

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const Runtime uint8 = 4
const MaximumDeploymentBytes = 4096
const MaximumEffectBytes = EffectBytes + guard.SealBytes
const EffectBytes = 8 + 1 + 5*32 + 8 + 32 + 8 + 32 + 64
const MaximumRuntimePayloadBytes = 16 << 20
const MaximumServiceRequestBytes = MaximumRuntimePayloadBytes + MaximumRequestBytes + 32

// Deployment fixes both private service identities in a job's signed Plan5.
// Its ID excludes signatures so five independent endorsements do not recurse.
// A partial canonical draft never passes Verify and cannot authorize execution.
type Deployment struct {
	// Guard is a separately pinned external signer. Zero preserves legacy profile 5.
	Guard                                                                         [32]byte
	A, B                                                                          Descriptor
	GenesisID, GenesisDescriptorID, EnrollmentID, ImportID, PairID                types.Hash
	MinimumRetainUntil                                                            uint64
	Authority, Control                                                            [32]byte
	IssuerSignature, AuthoritySignature, ControlSignature, ASignature, BSignature [64]byte
}

func (p Deployment) body() ([]byte, error) {
	a, e := p.A.CanonicalBytes()
	b, e2 := p.B.CanonicalBytes()
	if e != nil || e2 != nil || p.A.Gateway == p.B.Gateway || p.A.RootID == p.B.RootID || p.A.SourceID == p.B.SourceID || !p.A.ObjectsID.IsZero() || p.B.ObjectsID.IsZero() || p.A.Issuer != p.B.Issuer || types.Hash(p.Authority).IsZero() || types.Hash(p.Control).IsZero() || p.Authority == p.Control || p.Authority == p.A.Gateway || p.Authority == p.B.Gateway || p.Control == p.A.Gateway || p.Control == p.B.Gateway || p.Authority == p.A.Issuer || p.Control == p.A.Issuer {
		return nil, ErrArtifact
	}
	for _, d := range []Descriptor{p.A, p.B} {
		if d.GenesisID != p.GenesisID || d.GenesisDescriptorID != p.GenesisDescriptorID || d.EnrollmentID != p.EnrollmentID {
			return nil, ErrArtifact
		}
	}
	if p.MinimumRetainUntil == 0 || p.ImportID.IsZero() || p.PairID.IsZero() {
		return nil, ErrArtifact
	}
	e3 := codec.NewEncoder(2048)
	if p.Guard == ([32]byte{}) {
		e3.Fixed([]byte("OMCGDEP5"))
	} else {
		for _, k := range append(append([][32]byte{p.A.Gateway, p.B.Gateway, p.Authority, p.Control, p.A.Issuer}, p.A.Clients...), p.B.Clients...) {
			if k == p.Guard {
				return nil, ErrArtifact
			}
		}
		e3.Fixed([]byte("OMCGDG01"))
		e3.Fixed(p.Guard[:])
	}
	e3.BytesField(a)
	e3.BytesField(b)
	for _, h := range []types.Hash{p.GenesisID, p.GenesisDescriptorID, p.EnrollmentID, p.ImportID, p.PairID} {
		e3.Fixed(h[:])
	}
	e3.U64(p.MinimumRetainUntil)
	e3.Fixed(p.Authority[:])
	e3.Fixed(p.Control[:])
	return e3.Bytes(), nil
}
func (p Deployment) roles() []struct {
	name string
	key  [32]byte
	sig  [64]byte
} {
	return []struct {
		name string
		key  [32]byte
		sig  [64]byte
	}{{"issuer", p.A.Issuer, p.IssuerSignature}, {"authority", p.Authority, p.AuthoritySignature}, {"control", p.Control, p.ControlSignature}, {"a", p.A.Gateway, p.ASignature}, {"b", p.B.Gateway, p.BSignature}}
}
func (p Deployment) Sign(role string, key ed25519.PrivateKey) (Deployment, error) {
	if len(key) != 64 {
		return Deployment{}, ErrArtifact
	}
	b, e := p.body()
	if e != nil {
		return Deployment{}, e
	}
	var expected [32]byte
	var target *[64]byte
	switch role {
	case "issuer":
		expected = p.A.Issuer
		target = &p.IssuerSignature
	case "authority":
		expected = p.Authority
		target = &p.AuthoritySignature
	case "control":
		expected = p.Control
		target = &p.ControlSignature
	case "a":
		expected = p.A.Gateway
		target = &p.ASignature
	case "b":
		expected = p.B.Gateway
		target = &p.BSignature
	default:
		return Deployment{}, ErrArtifact
	}
	if !bytes.Equal(expected[:], key.Public().(ed25519.PublicKey)) {
		return Deployment{}, ErrArtifact
	}
	h := types.DomainHash(Domain+"deployment/"+role+"/sign", b)
	copy(target[:], ed25519.Sign(key, h[:]))
	return p, nil
}
func (p Deployment) CanonicalBytes() ([]byte, error) {
	b, e := p.body()
	if e != nil {
		return nil, e
	}
	body := append([]byte(nil), b...)
	for _, r := range p.roles() {
		if r.sig != ([64]byte{}) {
			h := types.DomainHash(Domain+"deployment/"+r.name+"/sign", body)
			if !ed25519.Verify(r.key[:], h[:], r.sig[:]) {
				return nil, ErrArtifact
			}
		}
		b = append(b, r.sig[:]...)
	}
	if len(b) > MaximumDeploymentBytes {
		return nil, ErrArtifact
	}
	return b, nil
}
func (p Deployment) ID() (types.Hash, error) {
	b, e := p.body()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(Domain+"deployment/id", b), nil
}
func (p Deployment) Verify() error {
	if _, e := p.CanonicalBytes(); e != nil {
		return e
	}
	for _, r := range p.roles() {
		if r.sig == ([64]byte{}) {
			return ErrArtifact
		}
	}
	return nil
}
func DecodeDeployment(b []byte) (Deployment, error) {
	var p Deployment
	if len(b) > MaximumDeploymentBytes {
		return p, ErrArtifact
	}
	d := codec.NewDecoder(b)
	magic, e := d.Fixed(8)
	if e != nil || (string(magic) != "OMCGDEP5" && string(magic) != "OMCGDG01") {
		return p, ErrArtifact
	}
	if string(magic) == "OMCGDG01" {
		k, err := d.Fixed(32)
		if err != nil {
			return p, err
		}
		copy(p.Guard[:], k)
		if p.Guard == ([32]byte{}) {
			return p, ErrArtifact
		}
	}
	a, e := d.BytesField(MaximumDescriptorBytes)
	if e != nil {
		return p, e
	}
	p.A, e = DecodeDescriptor(a)
	if e != nil {
		return p, e
	}
	a, e = d.BytesField(MaximumDescriptorBytes)
	if e != nil {
		return p, e
	}
	p.B, e = DecodeDescriptor(a)
	if e != nil {
		return p, e
	}
	r := reader{d: d}
	for _, h := range []*types.Hash{&p.GenesisID, &p.GenesisDescriptorID, &p.EnrollmentID, &p.ImportID, &p.PairID} {
		r.fixed(h[:])
	}
	p.MinimumRetainUntil = r.u64()
	r.fixed(p.Authority[:])
	r.fixed(p.Control[:])
	for _, sig := range []*[64]byte{&p.IssuerSignature, &p.AuthoritySignature, &p.ControlSignature, &p.ASignature, &p.BSignature} {
		r.fixed(sig[:])
	}
	raw, e := p.CanonicalBytes()
	if r.err != nil || e != nil || !bytes.Equal(raw, b) {
		return Deployment{}, ErrArtifact
	}
	return p, nil
}

// Effect is historical evidence of one completed typed operation. A fresh
// service signature, job and full admission binding exclude bare old role keys.
type Effect struct {
	GuardSeal                                                 [64]byte
	Kind                                                      uint8
	DeploymentID, ScopeID, AdmissionID, BindingID, ArtifactID types.Hash
	SourceSequence                                            uint64
	SourceHead                                                types.Hash
	CheckedAt                                                 uint64
	Signer                                                    [32]byte
	Signature                                                 [64]byte
}

const EffectExecute uint8 = 1
const EffectAccept uint8 = 2
const EffectServeA uint8 = 3
const EffectServeB uint8 = 4

func (e Effect) body() ([]byte, error) {
	if e.Kind < EffectExecute || e.Kind > EffectServeB || e.CheckedAt == 0 || types.Hash(e.Signer).IsZero() || (e.SourceSequence == 0) != e.SourceHead.IsZero() {
		return nil, ErrArtifact
	}
	out := codec.NewEncoder(EffectBytes)
	out.Fixed([]byte("OMCGEFF5"))
	out.U8(e.Kind)
	for _, h := range []types.Hash{e.DeploymentID, e.ScopeID, e.AdmissionID, e.BindingID, e.ArtifactID} {
		if h.IsZero() {
			return nil, ErrArtifact
		}
		out.Fixed(h[:])
	}
	out.U64(e.SourceSequence)
	out.Fixed(e.SourceHead[:])
	out.U64(e.CheckedAt)
	out.Fixed(e.Signer[:])
	return out.Bytes(), nil
}
func (e Effect) Sign(key ed25519.PrivateKey) (Effect, error) {
	if len(key) != 64 {
		return Effect{}, ErrArtifact
	}
	copy(e.Signer[:], key.Public().(ed25519.PublicKey))
	b, err := e.body()
	if err != nil {
		return Effect{}, err
	}
	h := types.DomainHash(Domain+"effect/sign", b)
	copy(e.Signature[:], ed25519.Sign(key, h[:]))
	return e, nil
}
func (e Effect) CanonicalBytes() ([]byte, error) {
	b, err := e.body()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(Domain+"effect/sign", b)
	if !ed25519.Verify(e.Signer[:], h[:], e.Signature[:]) {
		return nil, ErrArtifact
	}
	raw := append(b, e.Signature[:]...)
	if e.GuardSeal != ([64]byte{}) {
		copy(raw[:8], []byte("OMCGEFG1"))
		raw = append(raw, e.GuardSeal[:]...)
	}
	return raw, nil
}
func DecodeEffect(raw []byte) (Effect, error) {
	var e Effect
	if len(raw) != EffectBytes && len(raw) != MaximumEffectBytes {
		return e, ErrArtifact
	}
	r := reader{d: codec.NewDecoder(raw)}
	var magic [8]byte
	r.fixed(magic[:])
	e.Kind = r.u8()
	for _, h := range []*types.Hash{&e.DeploymentID, &e.ScopeID, &e.AdmissionID, &e.BindingID, &e.ArtifactID} {
		r.fixed(h[:])
	}
	e.SourceSequence = r.u64()
	r.fixed(e.SourceHead[:])
	e.CheckedAt = r.u64()
	r.fixed(e.Signer[:])
	r.fixed(e.Signature[:])
	if string(magic[:]) == "OMCGEFG1" {
		r.fixed(e.GuardSeal[:])
		if e.GuardSeal == ([64]byte{}) {
			return Effect{}, ErrArtifact
		}
	} else if string(magic[:]) != "OMCGEFF5" {
		return Effect{}, ErrArtifact
	}
	b, err := e.CanonicalBytes()
	if r.err != nil || err != nil || !bytes.Equal(b, raw) {
		return Effect{}, ErrArtifact
	}
	return e, nil
}
func RuntimePayloadID(b []byte) types.Hash { return types.DomainHash(Domain+"runtime-payload/id", b) }
func EncodeRuntimeRequest(q Request, payload []byte) ([]byte, error) {
	if q.Kind != Runtime || len(payload) == 0 || len(payload) > MaximumRuntimePayloadBytes || q.ChunkID != RuntimePayloadID(payload) {
		return nil, ErrArtifact
	}
	b, e := q.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(payload) + 300)
	out.Fixed([]byte("OMCGXRQ5"))
	out.Fixed(b)
	out.BytesField(payload)
	return out.Bytes(), nil
}
func DecodeRuntimeRequest(raw []byte) (Request, []byte, error) {
	var q Request
	if len(raw) > MaximumServiceRequestBytes {
		return q, nil, ErrArtifact
	}
	d := codec.NewDecoder(raw)
	m, e := d.Fixed(8)
	if e != nil || string(m) != "OMCGXRQ5" {
		return q, nil, ErrArtifact
	}
	b, e := d.Fixed(MaximumRequestBytes)
	if e != nil {
		return q, nil, e
	}
	q, e = DecodeRequest(b)
	if e != nil {
		return q, nil, e
	}
	payload, e := d.BytesField(MaximumRuntimePayloadBytes)
	if e != nil {
		return q, nil, e
	}
	again, e := EncodeRuntimeRequest(q, payload)
	if e != nil || !bytes.Equal(again, raw) {
		return Request{}, nil, ErrArtifact
	}
	return q, payload, nil
}

// GuardRequest seals the entire already-signed effect, including original
// admission binding, source head, checked time and typed operation.
func (e Effect) GuardRequest() (guard.Request, error) {
	e.GuardSeal = [64]byte{}
	raw, err := e.CanonicalBytes()
	if err != nil {
		return guard.Request{}, err
	}
	return guard.Request{Kind: guard.Effect, Subject: e.Signer, Namespace: e.ScopeID, Slot: uint64(e.Kind), Choice: types.DomainHash(guard.Domain+"effect", raw)}, nil
}
func (e Effect) VerifyGuard(key [32]byte) error {
	if key == ([32]byte{}) {
		if e.GuardSeal != ([64]byte{}) {
			return ErrArtifact
		}
		return nil
	}
	q, err := e.GuardRequest()
	if err != nil {
		return err
	}
	return q.VerifySeal(key, e.GuardSeal)
}
