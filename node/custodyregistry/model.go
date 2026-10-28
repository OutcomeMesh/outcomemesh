// Package custodyregistry implements an experimental one-choice enrollment
// foundation. A selection retains one exact profile-3 admission genesis under
// an independently pinned resource anchor. It grants no execution, migration,
// profile upgrade or mainnet activation permission.
package custodyregistry

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const Version1 uint16 = 1
const MaximumGenesisBytes = 2048
const MaximumSelectionBytes = 8 << 20
const VoteBytes = 10 + 4*types.HashSize + ed25519.SignatureSize
const MaximumCertificateBytes = MaximumSelectionBytes + custodyfence.MaximumWitnesses*VoteBytes + 32

var ErrRegistry = errors.New("invalid pinned custody resource registry")
var ErrSelection = errors.New("invalid custody registry selection")
var ErrQuorum = errors.New("invalid custody registry quorum")
var ErrPosition = errors.New("custody registry position differs")
var ErrSelected = errors.New("custody registry has permanently selected its assignment")

const domain = "OMESH/custody-registry/v1/"

// Genesis describes one externally assigned resource anchor. ID excludes
// mutable assignment, receipt, role, budget and roster choices; DescriptorID
// independently pins all of those registry policy fields. Independent enrollment
// must prevent adopting another descriptor/history for the same anchor, or
// declaring another ResourceID for the same protected physical resource.
type Genesis struct {
	Version                    uint16
	NetworkID                  uint32
	ChainGenesisID, ResourceID types.Hash
	Issuer                     [32]byte
	Threshold                  uint16
	Witnesses                  [][32]byte
	MaximumOperations          uint32
	MaximumPending             uint16
}

func (g Genesis) Validate() error {
	if g.Version != Version1 || g.NetworkID == 0 || g.ChainGenesisID.IsZero() || g.ResourceID.IsZero() || types.Hash(g.Issuer).IsZero() ||
		len(g.Witnesses) < 4 || len(g.Witnesses) > custodyfence.MaximumWitnesses || int(g.Threshold) > len(g.Witnesses) || 3*int(g.Threshold) <= 2*len(g.Witnesses) ||
		g.MaximumOperations == 0 || g.MaximumOperations > custodyauthority.MaximumOperations || g.MaximumPending == 0 || g.MaximumPending > custodyauthority.MaximumPending || uint32(g.MaximumPending) > g.MaximumOperations {
		return ErrRegistry
	}
	for i, key := range g.Witnesses {
		if types.Hash(key).IsZero() || key == g.Issuer || i > 0 && bytes.Compare(g.Witnesses[i-1][:], key[:]) >= 0 {
			return ErrRegistry
		}
	}
	return nil
}

func (g Genesis) CanonicalBytes() ([]byte, error) {
	if e := g.Validate(); e != nil {
		return nil, e
	}
	out := codec.NewEncoder(MaximumGenesisBytes)
	out.Fixed([]byte("OMCRGNS1"))
	out.U16(g.Version)
	out.U32(g.NetworkID)
	out.Fixed(g.ChainGenesisID[:])
	out.Fixed(g.ResourceID[:])
	out.Fixed(g.Issuer[:])
	out.U16(g.Threshold)
	out.U8(uint8(len(g.Witnesses)))
	for _, key := range g.Witnesses {
		out.Fixed(key[:])
	}
	out.U32(g.MaximumOperations)
	out.U16(g.MaximumPending)
	return out.Bytes(), nil
}

func DecodeGenesis(raw []byte) (Genesis, error) {
	var g Genesis
	if len(raw) > MaximumGenesisBytes {
		return g, ErrRegistry
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCRGNS1") {
		return g, ErrRegistry
	}
	g.Version, _ = d.U16()
	g.NetworkID, _ = d.U32()
	readFixed(d, g.ChainGenesisID[:])
	readFixed(d, g.ResourceID[:])
	readFixed(d, g.Issuer[:])
	g.Threshold, _ = d.U16()
	n, e := d.U8()
	if e != nil || n > custodyfence.MaximumWitnesses || d.Remaining() != int(n)*32+6 {
		return Genesis{}, ErrRegistry
	}
	g.Witnesses = make([][32]byte, int(n))
	for i := range g.Witnesses {
		readFixed(d, g.Witnesses[i][:])
	}
	g.MaximumOperations, _ = d.U32()
	g.MaximumPending, _ = d.U16()
	again, e := g.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(again, raw) {
		return Genesis{}, ErrRegistry
	}
	return g, nil
}

func (g Genesis) ID() (types.Hash, error) {
	if e := g.Validate(); e != nil {
		return types.Hash{}, e
	}
	out := codec.NewEncoder(68)
	out.U32(g.NetworkID)
	out.Fixed(g.ChainGenesisID[:])
	out.Fixed(g.ResourceID[:])
	return types.DomainHash(domain+"id", out.Bytes()), nil
}

func (g Genesis) DescriptorID() (types.Hash, error) {
	b, e := g.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"descriptor/id", b), nil
}

// Selection pins the full genesis of one newly prepared profile-3 assignment.
// The full-replay receipt shape excludes an explicit renewed receipt. It cannot
// prove that no old physical owner or legacy grant exists; the external issuer
// must establish that eligibility. There is no legacy import/accounting bridge.
// Selection alone cannot change this candidate to a future mandatory profile.
type Selection struct {
	Version                  uint16
	RegistryID, DescriptorID types.Hash
	Initial                  v2.AdmissionGenesis
	IssuerSignature          [64]byte
	AuthoritySignature       [64]byte
	ControlSignature         [64]byte
}

func (s Selection) unsignedBytes() ([]byte, error) {
	if s.Version != Version1 || s.RegistryID.IsZero() || s.DescriptorID.IsZero() || s.Initial.Assignment.Policy.Version != v2.PolicyVersionAdmission || s.Initial.Initial.Version != workarchive.ReplicaReceiptVersion0 {
		return nil, ErrSelection
	}
	b, e := s.Initial.CanonicalBytes()
	if e != nil || len(b) > MaximumSelectionBytes-300 {
		return nil, errors.Join(ErrSelection, e)
	}
	out := codec.NewEncoder(len(b) + 96)
	out.Fixed([]byte("OMCRSEL1"))
	out.U16(s.Version)
	out.Fixed(s.RegistryID[:])
	out.Fixed(s.DescriptorID[:])
	out.BytesField(b)
	return out.Bytes(), nil
}

func (s Selection) CanonicalBytes() ([]byte, error) {
	b, e := s.unsignedBytes()
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
	if !magic(d, "OMCRSEL1") {
		return s, ErrSelection
	}
	s.Version, _ = d.U16()
	readFixed(d, s.RegistryID[:])
	readFixed(d, s.DescriptorID[:])
	b, e := d.BytesField(v2.MaximumAdmissionGenesisBytes)
	if e != nil {
		return Selection{}, e
	}
	s.Initial, e = v2.DecodeAdmissionGenesis(b)
	if e != nil {
		return Selection{}, e
	}
	readFixed(d, s.IssuerSignature[:])
	readFixed(d, s.AuthoritySignature[:])
	readFixed(d, s.ControlSignature[:])
	again, e := s.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(again, raw) {
		return Selection{}, ErrSelection
	}
	return s, nil
}

func (s Selection) ID() (types.Hash, error) {
	b, e := s.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"selection/id", b), nil
}

func (s Selection) ValidateDraft(g Genesis) error {
	if _, e := s.CanonicalBytes(); e != nil {
		return e
	}
	id, e := g.ID()
	if e != nil {
		return e
	}
	did, _ := g.DescriptorID()
	a := s.Initial.Assignment.Base
	if id != s.RegistryID || did != s.DescriptorID || a.NetworkID != g.NetworkID || a.GenesisID != g.ChainGenesisID || a.MaximumOperations > g.MaximumOperations || a.MaximumPending > g.MaximumPending {
		return ErrSelection
	}
	// Registry signers and journal keys must be independently selected, not
	// relabelled participant, consumer or per-assignment witness keys.
	roles := [][32]byte{a.AuthorityPublicKey, a.RemoteControlPublicKey, a.ReplicaPublicKey, a.RemoteTransportPublicKey}
	for _, c := range a.Consumers {
		roles = append(roles, c.PublicKey)
	}
	roles = append(roles, a.Auditors...)
	roles = append(roles, s.Initial.CustodyPolicy.TrustedAuditors...)
	roles = append(roles, s.Initial.Assignment.Policy.Witnesses...)
	for _, key := range roles {
		if key == g.Issuer {
			return ErrSelection
		}
		for _, w := range g.Witnesses {
			if key == w {
				return ErrSelection
			}
		}
	}
	return nil
}

func (s Selection) Sign(g Genesis, role string, key ed25519.PrivateKey) (Selection, error) {
	if e := s.ValidateDraft(g); e != nil {
		return Selection{}, e
	}
	public, signature := s.signer(g, role)
	if signature == nil || !keyMatches(key, public) {
		return Selection{}, ErrSelection
	}
	b, _ := s.unsignedBytes()
	h := types.DomainHash(domain+"selection/signature/"+role, b)
	copy(signature[:], ed25519.Sign(key, h[:]))
	// signer returned a pointer into this receiver's copy, so no caller-owned
	// signatures or slices are modified by signing.
	return s, nil
}

func (s *Selection) signer(g Genesis, role string) ([32]byte, *[64]byte) {
	switch role {
	case "issuer":
		return g.Issuer, &s.IssuerSignature
	case "authority":
		return s.Initial.Assignment.Base.AuthorityPublicKey, &s.AuthoritySignature
	case "control":
		return s.Initial.Assignment.Base.RemoteControlPublicKey, &s.ControlSignature
	default:
		return [32]byte{}, nil
	}
}

func (s Selection) Verify(g Genesis) error {
	if e := s.ValidateDraft(g); e != nil {
		return e
	}
	b, _ := s.unsignedBytes()
	for _, role := range []string{"issuer", "authority", "control"} {
		public, signature := s.signer(g, role)
		h := types.DomainHash(domain+"selection/signature/"+role, b)
		if !ed25519.Verify(public[:], h[:], signature[:]) {
			return ErrSelection
		}
	}
	return nil
}

type Vote struct {
	Version                               uint16
	RegistryID, DescriptorID, SelectionID types.Hash
	Witness                               [32]byte
	Signature                             [64]byte
}

func (v Vote) unsignedBytes() ([]byte, error) {
	if v.Version != Version1 || v.RegistryID.IsZero() || v.DescriptorID.IsZero() || v.SelectionID.IsZero() || types.Hash(v.Witness).IsZero() {
		return nil, ErrQuorum
	}
	out := codec.NewEncoder(VoteBytes)
	out.Fixed([]byte("OMCRVOT1"))
	out.U16(v.Version)
	out.Fixed(v.RegistryID[:])
	out.Fixed(v.DescriptorID[:])
	out.Fixed(v.SelectionID[:])
	out.Fixed(v.Witness[:])
	return out.Bytes(), nil
}

func (v Vote) CanonicalBytes() ([]byte, error) {
	b, e := v.unsignedBytes()
	if e != nil {
		return nil, e
	}
	return append(b, v.Signature[:]...), nil
}

func DecodeVote(raw []byte) (Vote, error) {
	var v Vote
	if len(raw) != VoteBytes {
		return v, ErrQuorum
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCRVOT1") {
		return v, ErrQuorum
	}
	v.Version, _ = d.U16()
	readFixed(d, v.RegistryID[:])
	readFixed(d, v.DescriptorID[:])
	readFixed(d, v.SelectionID[:])
	readFixed(d, v.Witness[:])
	readFixed(d, v.Signature[:])
	again, e := v.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(again, raw) {
		return Vote{}, ErrQuorum
	}
	return v, nil
}

func (v Vote) ID() (types.Hash, error) {
	b, e := v.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"vote/id", b), nil
}

func (v Vote) Sign(g Genesis, key ed25519.PrivateKey) (Vote, error) {
	if !validPrivateKey(key) {
		return Vote{}, ErrQuorum
	}
	copy(v.Witness[:], key.Public().(ed25519.PublicKey))
	if e := v.validate(g); e != nil {
		return Vote{}, e
	}
	b, _ := v.unsignedBytes()
	h := types.DomainHash(domain+"vote/signature", b)
	copy(v.Signature[:], ed25519.Sign(key, h[:]))
	return v, nil
}

func SignVote(g Genesis, s Selection, key ed25519.PrivateKey) (Vote, error) {
	if e := s.Verify(g); e != nil {
		return Vote{}, e
	}
	id, _ := s.ID()
	return (Vote{Version: Version1, RegistryID: s.RegistryID, DescriptorID: s.DescriptorID, SelectionID: id}).Sign(g, key)
}

func (v Vote) validate(g Genesis) error {
	if _, e := v.unsignedBytes(); e != nil {
		return e
	}
	id, e := g.ID()
	if e != nil {
		return e
	}
	did, _ := g.DescriptorID()
	if v.RegistryID != id || v.DescriptorID != did {
		return ErrQuorum
	}
	for _, w := range g.Witnesses {
		if w == v.Witness {
			return nil
		}
	}
	return ErrQuorum
}

func (v Vote) Verify(g Genesis) error {
	if e := v.validate(g); e != nil {
		return e
	}
	b, _ := v.unsignedBytes()
	h := types.DomainHash(domain+"vote/signature", b)
	if !ed25519.Verify(v.Witness[:], h[:], v.Signature[:]) {
		return ErrQuorum
	}
	return nil
}

type Certificate struct {
	Version   uint16
	Selection Selection
	Votes     []Vote
}

func (c Certificate) CanonicalBytes() ([]byte, error) {
	if c.Version != Version1 || len(c.Votes) == 0 || len(c.Votes) > custodyfence.MaximumWitnesses {
		return nil, ErrQuorum
	}
	b, e := c.Selection.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	id, _ := c.Selection.ID()
	out := codec.NewEncoder(len(b) + len(c.Votes)*VoteBytes + 32)
	out.Fixed([]byte("OMCRGCT1"))
	out.U16(c.Version)
	out.BytesField(b)
	out.U8(uint8(len(c.Votes)))
	for i, v := range c.Votes {
		if v.Version != Version1 || v.RegistryID != c.Selection.RegistryID || v.DescriptorID != c.Selection.DescriptorID || v.SelectionID != id || i > 0 && bytes.Compare(c.Votes[i-1].Witness[:], v.Witness[:]) >= 0 {
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
	if !magic(d, "OMCRGCT1") {
		return c, ErrQuorum
	}
	c.Version, _ = d.U16()
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
	c.Votes = make([]Vote, int(n))
	for i := range c.Votes {
		b, _ := d.Fixed(VoteBytes)
		c.Votes[i], e = DecodeVote(b)
		if e != nil {
			return Certificate{}, e
		}
	}
	again, e := c.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(again, raw) {
		return Certificate{}, ErrQuorum
	}
	return c, nil
}

func (c Certificate) ID() (types.Hash, error) {
	b, e := c.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"certificate/id", b), nil
}

func (c Certificate) Verify(g Genesis) error {
	if _, e := c.CanonicalBytes(); e != nil {
		return e
	}
	if e := c.Selection.Verify(g); e != nil {
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
