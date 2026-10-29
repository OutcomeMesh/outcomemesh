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
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const (
	Version0                uint16 = 0
	Version1                uint16 = 1
	MaximumWitnesses               = 16
	MaximumScopeBytes              = 32 + 8 + 2 + 4*32 + 2*32 + 2 + MaximumWitnesses*32
	CommandBytes                   = 8 + 2 + 32 + 8 + 32 + 1 + 2*32 + 64
	VoteBytes                      = 8 + 2 + 32 + 32 + 64
	MaximumVoteBytes               = VoteBytes + guard.SealBytes
	MaximumCertificateBytes        = 8 + 2 + CommandBytes + 1 + MaximumWitnesses*MaximumVoteBytes
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
	Guard                                   [32]byte
	Version                                 uint16
	AssignmentID, IntentID, PlanID, BeginID types.Hash
	Owner, Controller                       [32]byte
	Threshold                               uint8
	Witnesses                               [][32]byte // strictly sorted, unique
}

func (s Scope) CanonicalBytes() ([]byte, error) {
	n := len(s.Witnesses)
	if (s.Version != Version0 && s.Version != Version1) || s.AssignmentID.IsZero() || s.IntentID.IsZero() || s.PlanID.IsZero() || s.BeginID.IsZero() ||
		types.Hash(s.Owner).IsZero() || types.Hash(s.Controller).IsZero() || s.Owner == s.Controller ||
		n < 4 || n > MaximumWitnesses || int(s.Threshold) > n || 3*int(s.Threshold) <= 2*n {
		return nil, ErrScope
	}
	e := codec.NewEncoder(MaximumScopeBytes)
	if s.Guard == ([32]byte{}) {
		e.Fixed([]byte("OMCFSC00"))
	} else {
		if s.Guard == s.Owner || s.Guard == s.Controller {
			return nil, ErrScope
		}
		e.Fixed([]byte("OMCFSG01"))
	}
	e.U16(s.Version)
	for _, id := range []types.Hash{s.AssignmentID, s.IntentID, s.PlanID, s.BeginID} {
		e.Fixed(id[:])
	}
	e.Fixed(s.Owner[:])
	e.Fixed(s.Controller[:])
	e.U8(s.Threshold)
	e.U8(uint8(n))
	for i, key := range s.Witnesses {
		if types.Hash(key).IsZero() || key == s.Guard || key == s.Owner || key == s.Controller || (i > 0 && bytes.Compare(s.Witnesses[i-1][:], key[:]) >= 0) {
			return nil, ErrScope
		}
		e.Fixed(key[:])
	}
	if s.Guard != ([32]byte{}) {
		e.Fixed(s.Guard[:])
	}
	return e.Bytes(), nil
}

func (s Scope) ID() (types.Hash, error) {
	b, err := s.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(fenceDomain(s.Version, "scope/id"), b), nil
}

func DecodeScope(b []byte) (Scope, error) {
	var s Scope
	if len(b) > MaximumScopeBytes {
		return s, ErrScope
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFSC00" && string(magic) != "OMCFSG01" {
		return s, ErrScope
	}
	s.Version, _ = d.U16()
	for _, out := range [][]byte{s.AssignmentID[:], s.IntentID[:], s.PlanID[:], s.BeginID[:], s.Owner[:], s.Controller[:]} {
		readFixed(d, out)
	}
	s.Threshold, _ = d.U8()
	n, err := d.U8()
	extra := 0
	if string(magic) == "OMCFSG01" {
		extra = 32
	}
	if err != nil || n > MaximumWitnesses || d.Remaining() != int(n)*32+extra {
		return Scope{}, ErrScope
	}
	s.Witnesses = make([][32]byte, int(n))
	for i := range s.Witnesses {
		readFixed(d, s.Witnesses[i][:])
	}
	if extra != 0 {
		readFixed(d, s.Guard[:])
		if s.Guard == ([32]byte{}) {
			return Scope{}, ErrScope
		}
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
	if (c.Version != Version0 && c.Version != Version1) || c.ScopeID.IsZero() || c.ExpectedHead.IsZero() || c.ExpectedSequence >= 3 {
		return nil, ErrCommand
	}
	switch c.Kind {
	case Claim:
		if !c.ClaimID.IsZero() || (c.Version == Version0 && !c.EvidenceID.IsZero()) || (c.Version == Version1 && c.EvidenceID.IsZero()) {
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
	return types.DomainHash(fenceDomain(c.Version, "command/id"), b), nil
}
func (c Command) Sign(key ed25519.PrivateKey) (Command, error) {
	if !validKey(key) {
		return Command{}, ErrCommand
	}
	b, err := c.unsignedBytes()
	if err != nil {
		return Command{}, err
	}
	h := types.DomainHash(fenceDomain(c.Version, "command/signature"), b)
	copy(c.Signature[:], ed25519.Sign(key, h[:]))
	return c, nil
}
func (c Command) Verify(s Scope) error {
	id, err := s.ID()
	if err != nil || id != c.ScopeID || c.Version != s.Version {
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
	h := types.DomainHash(fenceDomain(c.Version, "command/signature"), b)
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
	GuardSeal [64]byte
	Version   uint16
	CommandID types.Hash
	Witness   [32]byte
	Signature [64]byte
}

func (v Vote) CanonicalBytes() ([]byte, error) {
	if (v.Version != Version0 && v.Version != Version1) || v.CommandID.IsZero() || types.Hash(v.Witness).IsZero() {
		return nil, ErrQuorum
	}
	e := codec.NewEncoder(VoteBytes)
	e.Fixed([]byte("OMCFVT00"))
	e.U16(v.Version)
	e.Fixed(v.CommandID[:])
	e.Fixed(v.Witness[:])
	b := e.Bytes()
	h := types.DomainHash(fenceDomain(v.Version, "vote/signature"), b)
	if !ed25519.Verify(v.Witness[:], h[:], v.Signature[:]) {
		return nil, ErrQuorum
	}
	raw := append(b, v.Signature[:]...)
	if v.GuardSeal != ([64]byte{}) {
		copy(raw[:8], []byte("OMCFVG01"))
		raw = append(raw, v.GuardSeal[:]...)
	}
	return raw, nil
}
func signVote(c Command, key ed25519.PrivateKey) (Vote, error) {
	id, err := c.ID()
	if err != nil || !validKey(key) {
		return Vote{}, ErrQuorum
	}
	v := Vote{Version: c.Version, CommandID: id}
	copy(v.Witness[:], key.Public().(ed25519.PublicKey))
	e := codec.NewEncoder(VoteBytes)
	e.Fixed([]byte("OMCFVT00"))
	e.U16(v.Version)
	e.Fixed(v.CommandID[:])
	e.Fixed(v.Witness[:])
	h := types.DomainHash(fenceDomain(v.Version, "vote/signature"), e.Bytes())
	copy(v.Signature[:], ed25519.Sign(key, h[:]))
	return v, nil
}
func DecodeVote(b []byte) (Vote, error) {
	var v Vote
	if len(b) != VoteBytes && len(b) != MaximumVoteBytes {
		return v, ErrQuorum
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFVT00" && string(magic) != "OMCFVG01" {
		return v, ErrQuorum
	}
	v.Version, _ = d.U16()
	readFixed(d, v.CommandID[:])
	readFixed(d, v.Witness[:])
	readFixed(d, v.Signature[:])
	if string(magic) == "OMCFVG01" {
		readFixed(d, v.GuardSeal[:])
		if v.GuardSeal == ([64]byte{}) {
			return Vote{}, ErrQuorum
		}
	}
	raw, err := v.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, b) {
		return Vote{}, ErrQuorum
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
	if (c.Version != Version0 && c.Version != Version1) || c.Command.Version != c.Version || len(c.Votes) == 0 || len(c.Votes) > MaximumWitnesses {
		return nil, ErrQuorum
	}
	b, err := c.Command.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	id, _ := c.Command.ID()
	e := codec.NewEncoder(MaximumCertificateBytes)
	guarded := c.Votes[0].GuardSeal != ([64]byte{})
	if guarded {
		e.Fixed([]byte("OMCFQG01"))
	} else {
		e.Fixed([]byte("OMCFQC00"))
	}
	e.U16(c.Version)
	e.Fixed(b)
	e.U8(uint8(len(c.Votes)))
	for i, v := range c.Votes {
		if (v.GuardSeal != ([64]byte{})) != guarded || v.Version != c.Version || v.CommandID != id || (i > 0 && bytes.Compare(c.Votes[i-1].Witness[:], v.Witness[:]) >= 0) {
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
		if v.VerifyGuard(s, c.Command) != nil {
			return ErrQuorum
		}
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
	if string(magic) != "OMCFQC00" && string(magic) != "OMCFQG01" {
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
	size := VoteBytes
	if string(magic) == "OMCFQG01" {
		size = MaximumVoteBytes
	}
	if err != nil || n > MaximumWitnesses || d.Remaining() != int(n)*size {
		return Certificate{}, ErrQuorum
	}
	c.Votes = make([]Vote, int(n))
	for i := range c.Votes {
		raw, _ := d.Fixed(size)
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

func fenceDomain(version uint16, suffix string) string {
	if version == Version1 {
		return "OMESH/custody-fence/" + suffix + "/v1"
	}
	return "OMESH/custody-fence/" + suffix + "/v0"
}

func VoteGuardRequest(c Command, witness [32]byte) guard.Request {
	id, _ := c.ID()
	return guard.Request{Kind: guard.Fence, Subject: witness, Namespace: c.ScopeID, Slot: c.ExpectedSequence, Choice: id}
}

// VerifyGuard is also used when accepting a single network vote, before quorum assembly.
func (v Vote) VerifyGuard(s Scope, c Command) error {
	id, e := c.ID()
	if e != nil || v.CommandID != id || v.Version != c.Version {
		return ErrQuorum
	}
	if s.Guard == ([32]byte{}) {
		if v.GuardSeal != ([64]byte{}) {
			return ErrQuorum
		}
		return nil
	}
	return VoteGuardRequest(c, v.Witness).VerifySeal(s.Guard, v.GuardSeal)
}
