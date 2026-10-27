// Package custodyfence implements an experimental, separately pinned witness
// protocol for one remote execution slot. It is not wired into V0/V1 custody,
// consensus, a network service or an at-most-once physical effect executor.
// Witnesses must persist non-equivocation locks before signing. Fewer than one
// third of independently operated witnesses may lose/clone their keys or locks.
package custodyfence

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0                uint16 = 0
	MaximumWitnesses               = 16
	MaximumScopeBytes              = 8 + 2 + 4*32 + 2*32 + 2 + MaximumWitnesses*32
	CommandBytes                   = 8 + 2 + 32 + 8 + 32 + 1 + 2*32 + 64
	VoteBytes                      = 8 + 2 + 32 + 32 + 64
	MaximumCertificateBytes        = 8 + 2 + CommandBytes + 1 + MaximumWitnesses*VoteBytes
)

var (
	ErrScope      = errors.New("invalid independent custody fence scope")
	ErrCommand    = errors.New("invalid independent custody fence command")
	ErrQuorum     = errors.New("invalid independent custody fence quorum")
	ErrTransition = errors.New("custody fence transition or exact position is forbidden")
	ErrLocked     = errors.New("custody witness has already locked another proposal")
)

// Scope is immutable and independently selected before use. AssignmentID and
// IntentID alone are not a pin: adapters must bind this exact Scope ID in the
// new assignment/proof version, or callers could bypass it with a new scope.
// Witness keys must differ from both participant control keys.
type Scope struct {
	Version                                 uint16
	AssignmentID, IntentID, PlanID, BeginID types.Hash
	Owner, Controller                       [32]byte
	Threshold                               uint8
	Witnesses                               [][32]byte // strictly sorted, unique
}

func (s Scope) CanonicalBytes() ([]byte, error) {
	n := len(s.Witnesses)
	if s.Version != Version0 || s.AssignmentID.IsZero() || s.IntentID.IsZero() || s.PlanID.IsZero() || s.BeginID.IsZero() ||
		types.Hash(s.Owner).IsZero() || types.Hash(s.Controller).IsZero() || s.Owner == s.Controller ||
		n < 4 || n > MaximumWitnesses || int(s.Threshold) > n || 3*int(s.Threshold) <= 2*n {
		return nil, ErrScope
	}
	e := codec.NewEncoder(MaximumScopeBytes)
	e.Fixed([]byte("OMCFSC00"))
	e.U16(s.Version)
	for _, id := range []types.Hash{s.AssignmentID, s.IntentID, s.PlanID, s.BeginID} {
		e.Fixed(id[:])
	}
	e.Fixed(s.Owner[:])
	e.Fixed(s.Controller[:])
	e.U8(s.Threshold)
	e.U8(uint8(n))
	for i, key := range s.Witnesses {
		if types.Hash(key).IsZero() || key == s.Owner || key == s.Controller || (i > 0 && bytes.Compare(s.Witnesses[i-1][:], key[:]) >= 0) {
			return nil, ErrScope
		}
		e.Fixed(key[:])
	}
	return e.Bytes(), nil
}

func (s Scope) ID() (types.Hash, error) {
	b, err := s.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-fence/scope/id/v0", b), nil
}

func DecodeScope(b []byte) (Scope, error) {
	var s Scope
	if len(b) > MaximumScopeBytes {
		return s, ErrScope
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFSC00" {
		return s, ErrScope
	}
	s.Version, _ = d.U16()
	for _, out := range [][]byte{s.AssignmentID[:], s.IntentID[:], s.PlanID[:], s.BeginID[:], s.Owner[:], s.Controller[:]} {
		readFixed(d, out)
	}
	s.Threshold, _ = d.U8()
	n, err := d.U8()
	if err != nil || n > MaximumWitnesses || d.Remaining() != int(n)*32 {
		return Scope{}, ErrScope
	}
	s.Witnesses = make([][32]byte, int(n))
	for i := range s.Witnesses {
		readFixed(d, s.Witnesses[i][:])
	}
	if _, err := s.CanonicalBytes(); err != nil {
		return Scope{}, err
	}
	return s, nil
}

type Kind uint8

const (
	Claim Kind = 1 + iota
	MarkUnknown
	RecordResult
	CloseUnclaimed
)

// Command is owner-signed for Claim/RecordResult and controller-signed for
// MarkUnknown/CloseUnclaimed. EvidenceID is an opaque immutable commitment,
// never a validated custody proof. There is no expiry or owner replacement.
type Command struct {
	Version             uint16
	ScopeID             types.Hash
	ExpectedSequence    uint64
	ExpectedHead        types.Hash
	Kind                Kind
	ClaimID, EvidenceID types.Hash
	Signature           [64]byte
}

func (c Command) unsignedBytes() ([]byte, error) {
	if c.Version != Version0 || c.ScopeID.IsZero() || c.ExpectedHead.IsZero() || c.ExpectedSequence >= 3 {
		return nil, ErrCommand
	}
	switch c.Kind {
	case Claim:
		if !c.ClaimID.IsZero() || !c.EvidenceID.IsZero() {
			return nil, ErrCommand
		}
	case MarkUnknown, RecordResult:
		if c.ClaimID.IsZero() || c.EvidenceID.IsZero() {
			return nil, ErrCommand
		}
	case CloseUnclaimed:
		if !c.ClaimID.IsZero() || c.EvidenceID.IsZero() {
			return nil, ErrCommand
		}
	default:
		return nil, ErrCommand
	}
	e := codec.NewEncoder(CommandBytes)
	e.Fixed([]byte("OMCFCM00"))
	e.U16(c.Version)
	e.Fixed(c.ScopeID[:])
	e.U64(c.ExpectedSequence)
	e.Fixed(c.ExpectedHead[:])
	e.U8(uint8(c.Kind))
	e.Fixed(c.ClaimID[:])
	e.Fixed(c.EvidenceID[:])
	return e.Bytes(), nil
}

func (c Command) CanonicalBytes() ([]byte, error) {
	b, err := c.unsignedBytes()
	if err != nil {
		return nil, err
	}
	return append(b, c.Signature[:]...), nil
}
func (c Command) ID() (types.Hash, error) {
	b, err := c.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-fence/command/id/v0", b), nil
}
func (c Command) Sign(key ed25519.PrivateKey) (Command, error) {
	if !validKey(key) {
		return Command{}, ErrCommand
	}
	b, err := c.unsignedBytes()
	if err != nil {
		return Command{}, err
	}
	h := types.DomainHash("OMESH/custody-fence/command/signature/v0", b)
	copy(c.Signature[:], ed25519.Sign(key, h[:]))
	return c, nil
}
func (c Command) Verify(s Scope) error {
	id, err := s.ID()
	if err != nil || id != c.ScopeID {
		return ErrScope
	}
	b, err := c.unsignedBytes()
	if err != nil {
		return err
	}
	key := s.Owner
	if c.Kind == MarkUnknown || c.Kind == CloseUnclaimed {
		key = s.Controller
	}
	h := types.DomainHash("OMESH/custody-fence/command/signature/v0", b)
	if !ed25519.Verify(key[:], h[:], c.Signature[:]) {
		return ErrCommand
	}
	return nil
}
func DecodeCommand(b []byte) (Command, error) {
	var c Command
	if len(b) != CommandBytes {
		return c, ErrCommand
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFCM00" {
		return c, ErrCommand
	}
	c.Version, _ = d.U16()
	readFixed(d, c.ScopeID[:])
	c.ExpectedSequence, _ = d.U64()
	readFixed(d, c.ExpectedHead[:])
	k, _ := d.U8()
	c.Kind = Kind(k)
	readFixed(d, c.ClaimID[:])
	readFixed(d, c.EvidenceID[:])
	readFixed(d, c.Signature[:])
	if _, err := c.CanonicalBytes(); err != nil {
		return Command{}, err
	}
	return c, nil
}

// Vote is a durable witness's endorsement, not permission to execute an effect.
// Its signing API is deliberately private; Witness.Vote persists the lock first.
type Vote struct {
	Version   uint16
	CommandID types.Hash
	Witness   [32]byte
	Signature [64]byte
}

func (v Vote) CanonicalBytes() ([]byte, error) {
	if v.Version != Version0 || v.CommandID.IsZero() || types.Hash(v.Witness).IsZero() {
		return nil, ErrQuorum
	}
	e := codec.NewEncoder(VoteBytes)
	e.Fixed([]byte("OMCFVT00"))
	e.U16(v.Version)
	e.Fixed(v.CommandID[:])
	e.Fixed(v.Witness[:])
	b := e.Bytes()
	h := types.DomainHash("OMESH/custody-fence/vote/signature/v0", b)
	if !ed25519.Verify(v.Witness[:], h[:], v.Signature[:]) {
		return nil, ErrQuorum
	}
	return append(b, v.Signature[:]...), nil
}
func signVote(c Command, key ed25519.PrivateKey) (Vote, error) {
	id, err := c.ID()
	if err != nil || !validKey(key) {
		return Vote{}, ErrQuorum
	}
	v := Vote{CommandID: id}
	copy(v.Witness[:], key.Public().(ed25519.PublicKey))
	e := codec.NewEncoder(VoteBytes)
	e.Fixed([]byte("OMCFVT00"))
	e.U16(v.Version)
	e.Fixed(v.CommandID[:])
	e.Fixed(v.Witness[:])
	h := types.DomainHash("OMESH/custody-fence/vote/signature/v0", e.Bytes())
	copy(v.Signature[:], ed25519.Sign(key, h[:]))
	return v, nil
}
func DecodeVote(b []byte) (Vote, error) {
	var v Vote
	if len(b) != VoteBytes {
		return v, ErrQuorum
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFVT00" {
		return v, ErrQuorum
	}
	v.Version, _ = d.U16()
	readFixed(d, v.CommandID[:])
	readFixed(d, v.Witness[:])
	readFixed(d, v.Signature[:])
	if _, err := v.CanonicalBytes(); err != nil {
		return Vote{}, err
	}
	return v, nil
}

// Certificate's transition ID is Command.ID, independent of which valid quorum
// subset supplied the votes. Different subsets cannot fork the next position.
type Certificate struct {
	Version uint16
	Command Command
	Votes   []Vote // strictly sorted by witness key
}

func (c Certificate) CanonicalBytes() ([]byte, error) {
	if c.Version != Version0 || len(c.Votes) == 0 || len(c.Votes) > MaximumWitnesses {
		return nil, ErrQuorum
	}
	b, err := c.Command.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	id, _ := c.Command.ID()
	e := codec.NewEncoder(MaximumCertificateBytes)
	e.Fixed([]byte("OMCFQC00"))
	e.U16(c.Version)
	e.Fixed(b)
	e.U8(uint8(len(c.Votes)))
	for i, v := range c.Votes {
		if v.CommandID != id || (i > 0 && bytes.Compare(c.Votes[i-1].Witness[:], v.Witness[:]) >= 0) {
			return nil, ErrQuorum
		}
		b, err := v.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.Fixed(b)
	}
	return e.Bytes(), nil
}
func (c Certificate) Verify(s Scope) error {
	if _, err := c.CanonicalBytes(); err != nil {
		return err
	}
	if err := c.Command.Verify(s); err != nil {
		return err
	}
	if len(c.Votes) < int(s.Threshold) {
		return ErrQuorum
	}
	for _, v := range c.Votes {
		found := false
		for _, key := range s.Witnesses {
			if v.Witness == key {
				found = true
				break
			}
		}
		if !found {
			return ErrQuorum
		}
	}
	return nil
}
func DecodeCertificate(b []byte) (Certificate, error) {
	var c Certificate
	if len(b) > MaximumCertificateBytes {
		return c, ErrQuorum
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFQC00" {
		return c, ErrQuorum
	}
	c.Version, _ = d.U16()
	raw, err := d.Fixed(CommandBytes)
	if err != nil {
		return c, ErrQuorum
	}
	c.Command, err = DecodeCommand(raw)
	if err != nil {
		return c, err
	}
	n, err := d.U8()
	if err != nil || n > MaximumWitnesses || d.Remaining() != int(n)*VoteBytes {
		return Certificate{}, ErrQuorum
	}
	c.Votes = make([]Vote, int(n))
	for i := range c.Votes {
		raw, _ := d.Fixed(VoteBytes)
		c.Votes[i], err = DecodeVote(raw)
		if err != nil {
			return Certificate{}, err
		}
	}
	if _, err := c.CanonicalBytes(); err != nil {
		return Certificate{}, err
	}
	return c, nil
}
func readFixed(d *codec.Decoder, out []byte) { b, _ := d.Fixed(len(out)); copy(out, b) }
func validKey(key ed25519.PrivateKey) bool {
	return len(key) == ed25519.PrivateKeySize && bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]))
}
