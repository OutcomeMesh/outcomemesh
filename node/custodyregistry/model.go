// Package custodyregistry owns typed one-choice selection journals. Version 1
// remains profile-3 selection only. Version 2 selects fresh profile-4 assignments
// whose runtime requires the exact retained registry certificate.
package custodyregistry

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const Version1 = wire.Version1
const Version2 = wire.Version2
const SelectionVersionImported = wire.SelectionVersionImported
const MaximumGenesisBytes = wire.MaximumGenesisBytes
const MaximumSelectionBytes = wire.MaximumSelectionBytes
const VoteBytes = wire.VoteBytes
const MaximumCertificateBytes = wire.MaximumCertificateBytes

var ErrRegistry = wire.ErrRegistry
var ErrSelection = wire.ErrSelection
var ErrQuorum = wire.ErrQuorum
var ErrPosition = errors.New("custody registry position differs")
var ErrSelected = errors.New("custody registry has permanently selected its assignment")

const domain = "OMESH/custody-registry/v1/"

type Genesis = wire.Genesis
type Vote = wire.Vote

func DecodeGenesis(b []byte) (Genesis, error) { return wire.DecodeGenesis(b) }
func DecodeVote(b []byte) (Vote, error)       { return wire.DecodeVote(b) }

type Selection struct {
	Version                                               uint16
	RegistryID, DescriptorID                              types.Hash
	Initial                                               v2.AdmissionGenesis
	IssuerSignature, AuthoritySignature, ControlSignature [64]byte
}

func (s Selection) toWire() (wire.Selection, error) {
	b, e := s.Initial.CanonicalBytes()
	if e != nil {
		return wire.Selection{}, e
	}
	return wire.Selection{Version: s.Version, RegistryID: s.RegistryID, DescriptorID: s.DescriptorID, Candidate: b, IssuerSignature: s.IssuerSignature, AuthoritySignature: s.AuthoritySignature, ControlSignature: s.ControlSignature}, nil
}
func (s Selection) unsignedBytes() ([]byte, error) {
	x, e := s.toWire()
	if e != nil {
		return nil, e
	}
	return x.UnsignedBytes()
}
func (s Selection) CanonicalBytes() ([]byte, error) {
	x, e := s.toWire()
	if e != nil {
		return nil, e
	}
	if (s.Version == Version1 && s.Initial.Assignment.Policy.Version != v2.PolicyVersionAdmission) || (s.Version == Version2 && s.Initial.Assignment.Policy.Version != v2.PolicyVersionEnrolled) || (s.Version == SelectionVersionImported && s.Initial.Assignment.Policy.Version != v2.PolicyVersionImported) {
		return nil, ErrSelection
	}
	return x.CanonicalBytes()
}
func DecodeSelection(b []byte) (Selection, error) {
	x, e := wire.DecodeSelection(b)
	if e != nil {
		return Selection{}, e
	}
	g, e := v2.DecodeAdmissionGenesis(x.Candidate)
	if e != nil {
		return Selection{}, e
	}
	s := Selection{Version: x.Version, RegistryID: x.RegistryID, DescriptorID: x.DescriptorID, Initial: g, IssuerSignature: x.IssuerSignature, AuthoritySignature: x.AuthoritySignature, ControlSignature: x.ControlSignature}
	again, e := s.CanonicalBytes()
	if e != nil || !bytes.Equal(b, again) {
		return Selection{}, ErrSelection
	}
	return s, nil
}
func (s Selection) ID() (types.Hash, error) {
	b, e := s.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(wire.Domain(s.Version)+"selection/id", b), nil
}
func (s Selection) ValidateDraft(g Genesis) error {
	if _, e := s.CanonicalBytes(); e != nil {
		return e
	}
	if !wire.SupportsSelection(g.Version, s.Version) {
		return ErrSelection
	}
	id, e := g.ID()
	if e != nil {
		return e
	}
	did, _ := g.DescriptorID()
	if s.RegistryID != id || s.DescriptorID != did {
		return ErrSelection
	}
	if e := v2.ValidateRegistryCandidate(g, s.Initial); e != nil {
		return errors.Join(ErrSelection, e)
	}
	return nil
}
func (s *Selection) signer(g Genesis, role string) ([32]byte, *[64]byte) {
	switch role {
	case "issuer":
		return g.Issuer, &s.IssuerSignature
	case "authority":
		return s.Initial.Assignment.Base.AuthorityPublicKey, &s.AuthoritySignature
	case "control":
		return s.Initial.Assignment.Base.RemoteControlPublicKey, &s.ControlSignature
	}
	return [32]byte{}, nil
}
func (s Selection) Sign(g Genesis, role string, key ed25519.PrivateKey) (Selection, error) {
	if e := s.ValidateDraft(g); e != nil {
		return Selection{}, e
	}
	pub, sig := s.signer(g, role)
	if sig == nil || !keyMatches(key, pub) {
		return Selection{}, ErrSelection
	}
	x, e := s.toWire()
	if e != nil {
		return Selection{}, e
	}
	x, e = x.Sign(role, key)
	if e != nil {
		return Selection{}, e
	}
	s.IssuerSignature, s.AuthoritySignature, s.ControlSignature = x.IssuerSignature, x.AuthoritySignature, x.ControlSignature
	return s, nil
}
func (s Selection) Verify(g Genesis) error {
	if e := s.ValidateDraft(g); e != nil {
		return e
	}
	x, e := s.toWire()
	if e != nil {
		return e
	}
	return x.Verify(g, s.Initial.Assignment.Base.AuthorityPublicKey, s.Initial.Assignment.Base.RemoteControlPublicKey)
}
func SignVote(g Genesis, s Selection, key ed25519.PrivateKey) (Vote, error) {
	if e := s.Verify(g); e != nil {
		return Vote{}, e
	}
	id, _ := s.ID()
	return (Vote{Version: s.Version, RegistryID: s.RegistryID, DescriptorID: s.DescriptorID, SelectionID: id}).Sign(g, key)
}

type Certificate struct {
	Version   uint16
	Selection Selection
	Votes     []Vote
}

func (c Certificate) toWire() (wire.Certificate, error) {
	s, e := c.Selection.toWire()
	if e != nil {
		return wire.Certificate{}, e
	}
	return wire.Certificate{Version: c.Version, Selection: s, Votes: c.Votes}, nil
}
func (c Certificate) CanonicalBytes() ([]byte, error) {
	if _, e := c.Selection.CanonicalBytes(); e != nil {
		return nil, e
	}
	x, e := c.toWire()
	if e != nil {
		return nil, e
	}
	return x.CanonicalBytes()
}
func DecodeCertificate(b []byte) (Certificate, error) {
	x, e := wire.DecodeCertificate(b)
	if e != nil {
		return Certificate{}, e
	}
	raw, _ := x.Selection.CanonicalBytes()
	s, e := DecodeSelection(raw)
	if e != nil {
		return Certificate{}, e
	}
	return Certificate{Version: x.Version, Selection: s, Votes: x.Votes}, nil
}
func (c Certificate) ID() (types.Hash, error) {
	b, e := c.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(wire.Domain(c.Version)+"certificate/id", b), nil
}
func (c Certificate) Verify(g Genesis) error {
	if !wire.SupportsSelection(g.Version, c.Version) {
		return ErrQuorum
	}
	if e := c.Selection.Verify(g); e != nil {
		return e
	}
	x, e := c.toWire()
	if e != nil {
		return e
	}
	return x.Verify(g, c.Selection.Initial.Assignment.Base.AuthorityPublicKey, c.Selection.Initial.Assignment.Base.RemoteControlPublicKey)
}
func magic(d *codec.Decoder, value string) bool {
	b, e := d.Fixed(8)
	return e == nil && string(b) == value
}
func readFixed(d *codec.Decoder, dst []byte) {
	b, e := d.Fixed(len(dst))
	if e == nil {
		copy(dst, b)
	}
}
func keyMatches(key ed25519.PrivateKey, public [32]byte) bool {
	return validPrivateKey(key) && bytes.Equal(key.Public().(ed25519.PublicKey), public[:])
}
func validPrivateKey(key ed25519.PrivateKey) bool {
	if len(key) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	return bytes.Equal(derived, key)
}
