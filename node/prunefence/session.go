package prunefence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

// Session keys never leave this object or reach disk. A cold copy can recover
// signed evidence but cannot reconstruct a session to replay a historical claim.
type Session struct {
	mu                        sync.Mutex
	candidate                 Candidate
	key                       ed25519.PrivateKey
	claimed, consumed, sealed bool
	claim                     Claim
}
type Permit struct{ session *Session }

func NewSession(p Policy, b Binding) (*Session, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	c := Candidate{Policy: p, Binding: b}
	copy(c.Session[:], pub)
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
	return &Session{candidate: c, key: key}, nil
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
	if p == nil || p.session == nil {
		return ErrFence
	}
	s := p.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 64 || !s.claimed || s.consumed || s.candidate.Binding.OperationID != operation || s.candidate.Binding.StoragePairID != pair {
		return ErrFence
	}
	s.consumed = true
	return nil
}

type Result struct {
	Claim     Claim
	EffectID  types.Hash
	Signature [64]byte
}

func (r Result) message() (types.Hash, error) {
	if r.EffectID.IsZero() {
		return types.Hash{}, ErrFence
	}
	if e := r.Claim.Verify(); e != nil {
		return types.Hash{}, e
	}
	b, _ := r.Claim.Candidate.CanonicalBytes()
	cid, _ := r.Claim.Certificate.Command.ID()
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
	out.U16(0)
	out.BytesField(c)
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
	if string(m) != "OMPRFR00" || v != 0 {
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
