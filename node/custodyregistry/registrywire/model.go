// Package registrywire owns the shared canonical registry proof formats. It
// imports no custody runtime. Version 2 binds fresh policy-4 owners; version-1
// encodings and the semantic resource namespace remain unchanged.
package registrywire

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const Version1 uint16 = 1
const Version2 uint16 = 2

// SelectionVersionImported adds an accounting import choice to the SAME existing
// version-2 slot. There is no version-3 resource descriptor or new namespace.
const SelectionVersionImported uint16 = 3

func SupportsSelection(g, choice uint16) bool {
	return (g == Version1 && choice == Version1) || (g == Version2 && (choice == Version2 || choice == SelectionVersionImported))
}

const MaximumGenesisBytes = 2048
const MaximumSelectionBytes = 8 << 20
const VoteBytes = 10 + 4*types.HashSize + ed25519.SignatureSize
const MaximumCertificateBytes = MaximumSelectionBytes + custodyfence.MaximumWitnesses*VoteBytes + 32

var ErrRegistry = errors.New("invalid pinned custody resource registry")
var ErrSelection = errors.New("invalid custody registry selection")
var ErrQuorum = errors.New("invalid custody registry quorum")

const domain = "OMESH/custody-registry/v1/"

func Domain(v uint16) string {
	if v == Version1 {
		return domain
	}
	if v == Version2 {
		return "OMESH/custody-registry/v2/"
	}
	if v == SelectionVersionImported {
		return "OMESH/custody-registry/v3/"
	}
	return ""
}
func validVersion(v uint16) bool {
	return v == Version1 || v == Version2 || v == SelectionVersionImported
}
func versionMagic(prefix string, v uint16) string { return fmt.Sprintf("%s%d", prefix, v) }
func readVersion(d *codec.Decoder, prefix string) (uint16, error) {
	b, e := d.Fixed(8)
	if e != nil {
		return 0, e
	}
	v, e := d.U16()
	if e != nil || !validVersion(v) || string(b) != versionMagic(prefix, v) {
		return 0, ErrRegistry
	}
	return v, nil
}

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
	if (g.Version != Version1 && g.Version != Version2) || g.NetworkID == 0 || g.ChainGenesisID.IsZero() || g.ResourceID.IsZero() || types.Hash(g.Issuer).IsZero() ||
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
	out.Fixed([]byte(versionMagic("OMCRGNS", g.Version)))
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
	version, e := readVersion(d, "OMCRGNS")
	if e != nil {
		return g, ErrRegistry
	}
	g.Version = version
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
	return types.DomainHash(Domain(g.Version)+"descriptor/id", b), nil
}

type Vote struct {
	Version                               uint16
	RegistryID, DescriptorID, SelectionID types.Hash
	Witness                               [32]byte
	Signature                             [64]byte
}

func (v Vote) unsignedBytes() ([]byte, error) {
	if !validVersion(v.Version) || v.RegistryID.IsZero() || v.DescriptorID.IsZero() || v.SelectionID.IsZero() || types.Hash(v.Witness).IsZero() {
		return nil, ErrQuorum
	}
	out := codec.NewEncoder(VoteBytes)
	out.Fixed([]byte(versionMagic("OMCRVOT", v.Version)))
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
	version, e := readVersion(d, "OMCRVOT")
	if e != nil {
		return v, ErrQuorum
	}
	v.Version = version
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
	return types.DomainHash(Domain(v.Version)+"vote/id", b), nil
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
	h := types.DomainHash(Domain(v.Version)+"vote/signature", b)
	copy(v.Signature[:], ed25519.Sign(key, h[:]))
	return v, nil
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
	if !SupportsSelection(g.Version, v.Version) || v.RegistryID != id || v.DescriptorID != did {
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
	h := types.DomainHash(Domain(v.Version)+"vote/signature", b)
	if !ed25519.Verify(v.Witness[:], h[:], v.Signature[:]) {
		return ErrQuorum
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
