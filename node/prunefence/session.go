package prunefence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

// Session keys never leave this object or reach disk. A cold copy can recover
// signed evidence but cannot reconstruct a session to replay a historical claim.
type Session struct {
	mu                        sync.Mutex
	candidate                 Candidate
	key                       ed25519.PrivateKey
	claimed, consumed, sealed bool
	claim                     Claim
	serviceKey                ed25519.PrivateKey
	guard                     guardwire.Chooser
	ctx                       context.Context
	consumption               *ServiceConsumption
}
type Permit struct{ session *Session }

func NewSession(p Policy, b Binding) (*Session, error) {
	if p.Service != nil {
		return nil, ErrFence
	}
	return newSession(p, b, nil, nil, nil)
}
func newSession(p Policy, b Binding, serviceKey ed25519.PrivateKey, guard guardwire.Chooser, ctx context.Context) (*Session, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	c := Candidate{Policy: p, Binding: b}
	copy(c.Session[:], pub)
	if p.Service != nil {
		body, err := c.body()
		if err != nil || len(serviceKey) != ed25519.PrivateKeySize || !bytes.Equal(serviceKey[32:], p.Service.Service[:]) {
			clear(key)
			return nil, ErrFence
		}
		h := types.DomainHash(domain+"service-session/sign/v0", body)
		copy(c.ServiceSignature[:], ed25519.Sign(serviceKey, h[:]))
	}
	raw, e := c.CanonicalBytes()
	if e != nil {
		clear(key)
		return nil, e
	}
	c, e = DecodeCandidate(raw)
	if e != nil {
		clear(key)
		return nil, e
	}
	return &Session{candidate: c, key: key, serviceKey: append(ed25519.PrivateKey(nil), serviceKey...), guard: guard, ctx: ctx}, nil
}
func (s *Session) Candidate() (Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 64 {
		return Candidate{}, ErrFence
	}
	raw, e := s.candidate.CanonicalBytes()
	if e != nil {
		return Candidate{}, e
	}
	return DecodeCandidate(raw)
}
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.key = nil
	clear(s.serviceKey)
	s.serviceKey = nil
}
func (s *Session) Authorize(q custodyfence.Certificate) (*Permit, Claim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 64 || s.claimed {
		return nil, Claim{}, ErrFence
	}
	c := Claim{Candidate: s.candidate, Certificate: q}
	raw, e := c.CanonicalBytes()
	if e != nil {
		return nil, Claim{}, e
	}
	c, e = DecodeClaim(raw)
	if e != nil {
		return nil, Claim{}, e
	}
	s.claimed = true
	s.claim = c
	copy, err := DecodeClaim(raw)
	if err != nil {
		return nil, Claim{}, err
	}
	return &Permit{session: s}, copy, nil
}

// Consume is called at the real storage target, under its lock and before any
// deletion. Even a later storage error cannot make this permit usable again.
func (p *Permit) Consume(operation, pair types.Hash) error {
	return p.ConsumeProtected(operation, pair, types.Hash{})
}

// ConsumeProtected also checks the enrollment committed in the actual storage
// operation. A protected attempt is spent before contacting the guard, including
// when its reply is lost or the key has been revoked.
func (p *Permit) ConsumeProtected(operation, pair, enrollment types.Hash) error {
	if p == nil || p.session == nil {
		return ErrFence
	}
	s := p.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 64 || !s.claimed || s.consumed || s.candidate.Binding.OperationID != operation || s.candidate.Binding.StoragePairID != pair {
		return ErrFence
	}
	var want types.Hash
	if s.candidate.Policy.Service != nil {
		want, _ = s.candidate.Policy.Service.ID()
	}
	if want != enrollment {
		return ErrFence
	}
	s.consumed = true
	if s.candidate.Policy.Service != nil {
		return s.consumeService()
	}
	return nil
}

type Result struct {
	ServiceConsumption *ServiceConsumption
	Claim              Claim
	EffectID           types.Hash
	Signature          [64]byte
}

func (r Result) message() (types.Hash, error) {
	if r.EffectID.IsZero() {
		return types.Hash{}, ErrFence
	}
	if e := r.Claim.Verify(); e != nil {
		return types.Hash{}, e
	}
	if (r.ServiceConsumption == nil) != (r.Claim.Candidate.Policy.Service == nil) {
		return types.Hash{}, ErrFence
	}
	if r.ServiceConsumption != nil {
		if err := r.ServiceConsumption.verify(r.Claim.Candidate); err != nil {
			return types.Hash{}, err
		}
	}
	b, _ := r.Claim.Candidate.CanonicalBytes()
	cid, _ := r.Claim.Certificate.Command.ID()
	if r.ServiceConsumption != nil {
		return types.DomainHash(domain+"result/sign/v1", b, cid[:], r.ServiceConsumption.Nonce[:], r.ServiceConsumption.Seal[:], r.EffectID[:]), nil
	}
	return types.DomainHash(domain+"result/sign/v0", b, cid[:], r.EffectID[:]), nil
}
func (p *Permit) Seal(effect types.Hash) (Result, error) {
	if p == nil || p.session == nil {
		return Result{}, ErrFence
	}
	s := p.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 64 || !s.claimed || !s.consumed || s.sealed {
		return Result{}, ErrFence
	}
	r := Result{Claim: s.claim, EffectID: effect}
	if s.consumption != nil {
		owned := *s.consumption
		r.ServiceConsumption = &owned
	}
	id, e := r.message()
	if e != nil {
		return Result{}, e
	}
	copy(r.Signature[:], ed25519.Sign(s.key, id[:]))
	s.sealed = true
	clear(s.key)
	s.key = nil
	return r, nil
}
func (r Result) CanonicalBytes() ([]byte, error) {
	id, e := r.message()
	if e != nil || !ed25519.Verify(r.Claim.Candidate.Session[:], id[:], r.Signature[:]) {
		return nil, ErrFence
	}
	c, _ := r.Claim.CanonicalBytes()
	out := codec.NewEncoder(MaximumResultBytes)
	out.Fixed([]byte("OMPRFR00"))
	version := uint16(0)
	if r.ServiceConsumption != nil {
		version = 1
	}
	out.U16(version)
	out.BytesField(c)
	if r.ServiceConsumption != nil {
		out.Fixed(r.ServiceConsumption.Nonce[:])
		out.Fixed(r.ServiceConsumption.Seal[:])
	}
	out.Fixed(r.EffectID[:])
	out.Fixed(r.Signature[:])
	return out.Bytes(), nil
}
func DecodeResult(raw []byte) (Result, error) {
	var r Result
	if len(raw) > MaximumResultBytes {
		return r, ErrFence
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMPRFR00" || v > 1 {
		return r, ErrFence
	}
	b, e := d.BytesField(MaximumClaimBytes)
	if e != nil {
		return r, e
	}
	r.Claim, e = DecodeClaim(b)
	if e != nil {
		return r, e
	}
	if (v == 1) != (r.Claim.Candidate.Policy.Service != nil) {
		return Result{}, ErrFence
	}
	if v == 1 {
		proof := new(ServiceConsumption)
		for _, dst := range [][]byte{proof.Nonce[:], proof.Seal[:]} {
			raw, err := d.Fixed(len(dst))
			if err != nil {
				return Result{}, ErrFence
			}
			copy(dst, raw)
		}
		r.ServiceConsumption = proof
	}
	for _, out := range [][]byte{r.EffectID[:], r.Signature[:]} {
		b, e := d.Fixed(len(out))
		if e != nil {
			return Result{}, e
		}
		copy(out, b)
	}
	b, e = r.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, b) {
		return Result{}, ErrFence
	}
	return r, nil
}
