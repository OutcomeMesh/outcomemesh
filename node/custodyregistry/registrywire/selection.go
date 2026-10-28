package registrywire

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

// Selection carries the complete opaque canonical candidate. Typed callers
// MUST derive and verify it from the actual admission Genesis, including caps,
// roles, source and profile. This package checks framing and cryptography only.
type Selection struct {
	Version                                               uint16
	RegistryID, DescriptorID                              types.Hash
	Candidate                                             []byte
	IssuerSignature, AuthoritySignature, ControlSignature [64]byte
}

func (s Selection) UnsignedBytes() ([]byte, error) {
	if !validVersion(s.Version) || s.RegistryID.IsZero() || s.DescriptorID.IsZero() || len(s.Candidate) == 0 || len(s.Candidate) > MaximumSelectionBytes-300 {
		return nil, ErrSelection
	}
	e := codec.NewEncoder(len(s.Candidate) + 96)
	e.Fixed([]byte(versionMagic("OMCRSEL", s.Version)))
	e.U16(s.Version)
	e.Fixed(s.RegistryID[:])
	e.Fixed(s.DescriptorID[:])
	e.BytesField(s.Candidate)
	return e.Bytes(), nil
}
func (s Selection) CanonicalBytes() ([]byte, error) {
	b, e := s.UnsignedBytes()
	if e != nil {
		return nil, e
	}
	b = append(b, s.IssuerSignature[:]...)
	b = append(b, s.AuthoritySignature[:]...)
	b = append(b, s.ControlSignature[:]...)
	if len(b) > MaximumSelectionBytes {
		return nil, ErrSelection
	}
	return b, nil
}
func DecodeSelection(raw []byte) (Selection, error) {
	var s Selection
	if len(raw) > MaximumSelectionBytes {
		return s, ErrSelection
	}
	d := codec.NewDecoder(raw)
	v, e := readVersion(d, "OMCRSEL")
	if e != nil {
		return s, e
	}
	s.Version = v
	readFixed(d, s.RegistryID[:])
	readFixed(d, s.DescriptorID[:])
	s.Candidate, e = d.BytesField(MaximumSelectionBytes - 300)
	if e != nil {
		return Selection{}, e
	}
	readFixed(d, s.IssuerSignature[:])
	readFixed(d, s.AuthoritySignature[:])
	readFixed(d, s.ControlSignature[:])
	again, e := s.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return Selection{}, ErrSelection
	}
	return s, nil
}
func (s Selection) ID() (types.Hash, error) {
	b, e := s.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(Domain(s.Version)+"selection/id", b), nil
}
func (s *Selection) signature(role string) *[64]byte {
	switch role {
	case "issuer":
		return &s.IssuerSignature
	case "authority":
		return &s.AuthoritySignature
	case "control":
		return &s.ControlSignature
	}
	return nil
}
func (s Selection) Sign(role string, key ed25519.PrivateKey) (Selection, error) {
	sig := s.signature(role)
	if sig == nil || !validPrivateKey(key) {
		return Selection{}, ErrSelection
	}
	b, e := s.UnsignedBytes()
	if e != nil {
		return Selection{}, e
	}
	h := types.DomainHash(Domain(s.Version)+"selection/signature/"+role, b)
	copy(sig[:], ed25519.Sign(key, h[:]))
	return s, nil
}
func (s Selection) Verify(g Genesis, authority, control [32]byte) error {
	id, e := g.ID()
	if e != nil {
		return e
	}
	did, _ := g.DescriptorID()
	if s.Version != g.Version || s.RegistryID != id || s.DescriptorID != did {
		return ErrSelection
	}
	b, e := s.UnsignedBytes()
	if e != nil {
		return e
	}
	for _, role := range []struct {
		name string
		key  [32]byte
	}{{"issuer", g.Issuer}, {"authority", authority}, {"control", control}} {
		h := types.DomainHash(Domain(s.Version)+"selection/signature/"+role.name, b)
		if !ed25519.Verify(role.key[:], h[:], s.signature(role.name)[:]) {
			return ErrSelection
		}
	}
	return nil
}

type Certificate struct {
	Version   uint16
	Selection Selection
	Votes     []Vote
}

func (c Certificate) CanonicalBytes() ([]byte, error) {
	if !validVersion(c.Version) || c.Selection.Version != c.Version || len(c.Votes) == 0 || len(c.Votes) > custodyfence.MaximumWitnesses {
		return nil, ErrQuorum
	}
	b, e := c.Selection.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	id, _ := c.Selection.ID()
	out := codec.NewEncoder(len(b) + len(c.Votes)*VoteBytes + 32)
	out.Fixed([]byte(versionMagic("OMCRGCT", c.Version)))
	out.U16(c.Version)
	out.BytesField(b)
	out.U8(uint8(len(c.Votes)))
	for i, v := range c.Votes {
		if v.Version != c.Version || v.RegistryID != c.Selection.RegistryID || v.DescriptorID != c.Selection.DescriptorID || v.SelectionID != id || i > 0 && bytes.Compare(c.Votes[i-1].Witness[:], v.Witness[:]) >= 0 {
			return nil, ErrQuorum
		}
		raw, e := v.CanonicalBytes()
		if e != nil {
			return nil, e
		}
		out.Fixed(raw)
	}
	return out.Bytes(), nil
}
func DecodeCertificate(raw []byte) (Certificate, error) {
	var c Certificate
	if len(raw) > MaximumCertificateBytes {
		return c, ErrQuorum
	}
	d := codec.NewDecoder(raw)
	v, e := readVersion(d, "OMCRGCT")
	if e != nil {
		return c, e
	}
	c.Version = v
	b, e := d.BytesField(MaximumSelectionBytes)
	if e != nil {
		return c, e
	}
	c.Selection, e = DecodeSelection(b)
	if e != nil {
		return c, e
	}
	n, e := d.U8()
	if e != nil || n == 0 || n > custodyfence.MaximumWitnesses || d.Remaining() != int(n)*VoteBytes {
		return Certificate{}, ErrQuorum
	}
	for i := 0; i < int(n); i++ {
		b, _ := d.Fixed(VoteBytes)
		v, e := DecodeVote(b)
		if e != nil {
			return Certificate{}, e
		}
		c.Votes = append(c.Votes, v)
	}
	again, e := c.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return Certificate{}, ErrQuorum
	}
	return c, nil
}
func (c Certificate) ID() (types.Hash, error) {
	b, e := c.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(Domain(c.Version)+"certificate/id", b), nil
}

// Verify checks all signatures after the caller has checked the typed candidate.
func (c Certificate) Verify(g Genesis, authority, control [32]byte) error {
	if _, e := c.CanonicalBytes(); e != nil {
		return e
	}
	if e := c.Selection.Verify(g, authority, control); e != nil {
		return e
	}
	if len(c.Votes) < int(g.Threshold) {
		return ErrQuorum
	}
	for _, v := range c.Votes {
		if e := v.Verify(g); e != nil {
			return e
		}
	}
	return nil
}
