package review

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
)

const ObservationBytes = 10 + 8*32 + 8 + 8 + 1 + 64
const MaximumBlueprintBytes = 1024
const MaximumProposalBytes = MaximumEvidenceBytes + wire.MaximumGenesisBytes + MaximumBlueprintBytes + 2*ObservationBytes + 512

type Role uint8

const (
	Authority Role = 1
	Target    Role = 2
)

// Observation is historical, not an activation or live freshness certificate.
type Observation struct {
	Version                                                                                               uint16
	EvidenceID, AssignmentID, RetirementID, SourceHeadID, ReceiptID, PlacementCommitment, Nonce, AnchorID types.Hash
	SourceSequence, MinimumRetainUntil                                                                    uint64
	Role                                                                                                  Role
	Signature                                                                                             [64]byte
}

func (o Observation) unsigned() ([]byte, error) {
	if o.Version != Version1 || (o.Role != Authority && o.Role != Target) || o.EvidenceID.IsZero() || o.AssignmentID.IsZero() || o.RetirementID.IsZero() || o.ReceiptID.IsZero() || o.PlacementCommitment.IsZero() || o.Nonce.IsZero() || o.AnchorID.IsZero() || o.MinimumRetainUntil == 0 || (o.SourceSequence == 0) != o.SourceHeadID.IsZero() {
		return nil, ErrPreparation
	}
	e := codec.NewEncoder(ObservationBytes)
	e.Fixed([]byte("OMCXOBS1"))
	e.U16(o.Version)
	for _, h := range []types.Hash{o.EvidenceID, o.AssignmentID, o.RetirementID, o.SourceHeadID, o.ReceiptID, o.PlacementCommitment, o.Nonce, o.AnchorID} {
		e.Fixed(h[:])
	}
	e.U64(o.SourceSequence)
	e.U64(o.MinimumRetainUntil)
	e.U8(uint8(o.Role))
	return e.Bytes(), nil
}
func (o Observation) CanonicalBytes() ([]byte, error) {
	b, e := o.unsigned()
	if e != nil {
		return nil, e
	}
	return append(b, o.Signature[:]...), nil
}
func DecodeObservation(raw []byte) (Observation, error) {
	var o Observation
	if len(raw) != ObservationBytes {
		return o, ErrPreparation
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCXOBS1") {
		return o, ErrPreparation
	}
	o.Version, _ = d.U16()
	for _, h := range []*types.Hash{&o.EvidenceID, &o.AssignmentID, &o.RetirementID, &o.SourceHeadID, &o.ReceiptID, &o.PlacementCommitment, &o.Nonce, &o.AnchorID} {
		fixed(d, h[:])
	}
	o.SourceSequence, _ = d.U64()
	o.MinimumRetainUntil, _ = d.U64()
	r, _ := d.U8()
	o.Role = Role(r)
	fixed(d, o.Signature[:])
	again, e := o.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return Observation{}, ErrPreparation
	}
	return o, nil
}
func (o Observation) ID() (types.Hash, error) {
	b, e := o.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"observation/id", b), nil
}
func (o Observation) Verify(e Evidence, anchor types.Hash) error {
	id, _ := e.Assignment.ID()
	assess, err := e.Verify(id, e.End)
	if err != nil {
		return err
	}
	return o.verifyAssessment(e, anchor, assess)
}

// verifyAssessment is used only after this same complete Evidence was verified.
// It shares that immutable assessment across the two observations in a proposal.
func (o Observation) verifyAssessment(e Evidence, anchor types.Hash, assess Assessment) error {
	id, _ := e.Assignment.ID()
	eid, _ := e.ID()
	if o.AnchorID != anchor || o.EvidenceID != eid || o.AssignmentID != id || o.RetirementID != assess.RetirementID || o.SourceSequence != assess.SourceSequence || o.SourceHeadID != assess.SourceHeadID || o.ReceiptID != assess.ReceiptID || o.MinimumRetainUntil != assess.MinimumRetainUntil {
		return ErrPreparation
	}
	raw, err := o.unsigned()
	if err != nil {
		return err
	}
	key := e.Assignment.AuthorityPublicKey
	if o.Role == Target {
		key = e.Assignment.RemoteControlPublicKey
	}
	h := types.DomainHash(domain+"observation/signature", raw)
	if !ed25519.Verify(key[:], h[:], o.Signature[:]) {
		return ErrPreparation
	}
	return nil
}
func validKey(key ed25519.PrivateKey, pub [32]byte) bool {
	if len(key) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(key[:32])
	ok := bytes.Equal(derived, key) && bytes.Equal(pub[:], derived[32:])
	clear(derived)
	return ok
}

// Blueprint has its own non-runtime encoding. It contains no signed job,
// execution scope, Begin grant or zeroed admission genesis.
type Blueprint struct {
	Version                       uint16
	IncarnationID                 types.Hash
	Authority, Control, Transport [32]byte
	Threshold                     uint8
	Witnesses                     [][32]byte
	MaximumPending                uint16
}

func (b Blueprint) CanonicalBytes() ([]byte, error) {
	if b.Version != Version1 || b.IncarnationID.IsZero() || types.Hash(b.Authority).IsZero() || types.Hash(b.Control).IsZero() || types.Hash(b.Transport).IsZero() || b.Authority == b.Control || b.Authority == b.Transport || b.Control == b.Transport || len(b.Witnesses) < 4 || len(b.Witnesses) > custodyfence.MaximumWitnesses || int(b.Threshold) > len(b.Witnesses) || 3*int(b.Threshold) <= 2*len(b.Witnesses) || b.MaximumPending < 2 {
		return nil, ErrPreparation
	}
	e := codec.NewEncoder(MaximumBlueprintBytes)
	e.Fixed([]byte("OMCXBLP1"))
	e.U16(b.Version)
	e.Fixed(b.IncarnationID[:])
	for _, k := range [][32]byte{b.Authority, b.Control, b.Transport} {
		e.Fixed(k[:])
	}
	e.U8(b.Threshold)
	e.U8(uint8(len(b.Witnesses)))
	for i, k := range b.Witnesses {
		if types.Hash(k).IsZero() || k == b.Authority || k == b.Control || k == b.Transport || i > 0 && bytes.Compare(b.Witnesses[i-1][:], k[:]) >= 0 {
			return nil, ErrPreparation
		}
		e.Fixed(k[:])
	}
	e.U16(b.MaximumPending)
	return e.Bytes(), nil
}
func DecodeBlueprint(raw []byte) (Blueprint, error) {
	var b Blueprint
	if len(raw) > MaximumBlueprintBytes {
		return b, ErrPreparation
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCXBLP1") {
		return b, ErrPreparation
	}
	b.Version, _ = d.U16()
	fixed(d, b.IncarnationID[:])
	for _, k := range []*[32]byte{&b.Authority, &b.Control, &b.Transport} {
		fixed(d, k[:])
	}
	b.Threshold, _ = d.U8()
	n, e := d.U8()
	if e != nil || n > custodyfence.MaximumWitnesses || d.Remaining() != int(n)*32+2 {
		return b, ErrPreparation
	}
	for i := 0; i < int(n); i++ {
		var k [32]byte
		fixed(d, k[:])
		b.Witnesses = append(b.Witnesses, k)
	}
	b.MaximumPending, _ = d.U16()
	again, e := b.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return Blueprint{}, ErrPreparation
	}
	return b, nil
}
func (b Blueprint) ID() (types.Hash, error) {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"blueprint/id", raw), nil
}

type Proposal struct {
	Version                                               uint16
	Anchor                                                wire.Genesis
	Evidence                                              Evidence
	A, B                                                  Observation
	Successor                                             Blueprint
	Allowance                                             uint32
	IssuerSignature, AuthoritySignature, ControlSignature [64]byte
}
type Bridge struct {
	LegacyLimit, Spent, ResourceLimit, Authorized, Unallocated uint32
	WholeJobs                                                  uint32
	MaximumPending                                             uint16
	MinimumRetainUntil                                         uint64
	ActivationAllowed                                          bool
}

func (p Proposal) ValidateDraft(anchorID, descriptorID, legacyID types.Hash, end a.Position) (Bridge, error) {
	var result Bridge
	if p.Version != Version1 || p.Anchor.Version != wire.Version2 {
		return result, ErrPreparation
	}
	id, e := p.Anchor.ID()
	if e != nil {
		return result, e
	}
	did, _ := p.Anchor.DescriptorID()
	if anchorID.IsZero() || id != anchorID || descriptorID.IsZero() || did != descriptorID {
		return result, ErrPreparation
	}
	assess, e := p.Evidence.Verify(legacyID, end)
	if e != nil {
		return result, e
	}
	if p.Anchor.NetworkID != p.Evidence.Assignment.NetworkID || p.Anchor.ChainGenesisID != p.Evidence.Assignment.GenesisID || p.A.Role != Authority || p.B.Role != Target || p.A.PlacementCommitment == p.B.PlacementCommitment {
		return result, ErrPreparation
	}
	for _, o := range []Observation{p.A, p.B} {
		if e := o.verifyAssessment(p.Evidence, anchorID, assess); e != nil {
			return result, e
		}
	}
	if _, e := p.Successor.CanonicalBytes(); e != nil {
		return result, e
	}
	old := p.Evidence.Assignment
	if p.Successor.IncarnationID == old.IncarnationID || p.Successor.MaximumPending > old.MaximumPending || p.Successor.MaximumPending > p.Anchor.MaximumPending || uint32(p.Successor.MaximumPending) > p.Allowance {
		return result, ErrBudget
	}
	limit := assess.LegacyLimit
	if p.Anchor.MaximumOperations < limit {
		limit = p.Anchor.MaximumOperations
	}
	if assess.SpentOperations > limit || p.Allowance > limit-assess.SpentOperations {
		return result, ErrBudget
	}
	roles := [][32]byte{old.AuthorityPublicKey, old.RemoteControlPublicKey, old.RemoteTransportPublicKey, old.ReplicaPublicKey, p.Successor.Authority, p.Successor.Control, p.Successor.Transport}
	roles = append(roles, old.Auditors...)
	roles = append(roles, p.Evidence.Policy.TrustedAuditors...)

	for _, c := range old.Consumers {
		roles = append(roles, c.PublicKey)
	}
	for _, job := range p.Successor.Witnesses {
		for _, actor := range roles {
			if job == actor {
				return result, ErrPreparation
			}
		}
	}
	roles = append(roles, p.Successor.Witnesses...)
	for _, k := range roles {
		if k == p.Anchor.Issuer {
			return result, ErrPreparation
		}
		for _, w := range p.Anchor.Witnesses {
			if k == w {
				return result, ErrPreparation
			}
		}
	}
	return Bridge{LegacyLimit: assess.LegacyLimit, Spent: assess.SpentOperations, ResourceLimit: limit, Authorized: p.Allowance, Unallocated: limit - assess.SpentOperations - p.Allowance, WholeJobs: p.Allowance / 2, MaximumPending: p.Successor.MaximumPending, MinimumRetainUntil: assess.MinimumRetainUntil}, nil
}
func (p Proposal) unsigned() ([]byte, error) {
	if p.Version != Version1 {
		return nil, ErrPreparation
	}
	e := codec.NewEncoder(4096)
	e.Fixed([]byte("OMCXPRP1"))
	e.U16(p.Version)
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{p.Anchor, p.Evidence, p.A, p.B, p.Successor} {
		raw, err := v.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		if e.Len()+len(raw)+256 > MaximumProposalBytes {
			return nil, ErrPreparation
		}
		e.BytesField(raw)
	}
	e.U32(p.Allowance)
	return e.Bytes(), nil
}
func (p Proposal) CanonicalBytes() ([]byte, error) {
	b, e := p.unsigned()
	if e != nil {
		return nil, e
	}
	b = append(b, p.IssuerSignature[:]...)
	b = append(b, p.AuthoritySignature[:]...)
	return append(b, p.ControlSignature[:]...), nil
}
func DecodeProposal(raw []byte) (Proposal, error) {
	var p Proposal
	if len(raw) > MaximumProposalBytes {
		return p, ErrPreparation
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCXPRP1") {
		return p, ErrPreparation
	}
	p.Version, _ = d.U16()
	b, e := d.BytesField(wire.MaximumGenesisBytes)
	if e != nil {
		return p, e
	}
	p.Anchor, e = wire.DecodeGenesis(b)
	if e != nil {
		return p, e
	}
	b, e = d.BytesField(MaximumEvidenceBytes)
	if e != nil {
		return p, e
	}
	p.Evidence, e = DecodeEvidence(b)
	if e != nil {
		return p, e
	}
	b, e = d.BytesField(ObservationBytes)
	if e != nil {
		return p, e
	}
	p.A, e = DecodeObservation(b)
	if e != nil {
		return p, e
	}
	b, e = d.BytesField(ObservationBytes)
	if e != nil {
		return p, e
	}
	p.B, e = DecodeObservation(b)
	if e != nil {
		return p, e
	}
	b, e = d.BytesField(MaximumBlueprintBytes)
	if e != nil {
		return p, e
	}
	p.Successor, e = DecodeBlueprint(b)
	if e != nil {
		return p, e
	}
	p.Allowance, _ = d.U32()
	for _, sig := range []*[64]byte{&p.IssuerSignature, &p.AuthoritySignature, &p.ControlSignature} {
		fixed(d, sig[:])
	}
	again, e := p.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return Proposal{}, ErrPreparation
	}
	return p, nil
}
func (p Proposal) ID() (types.Hash, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"proposal/id", b), nil
}
func (p *Proposal) role(name string) ([32]byte, *[64]byte) {
	switch name {
	case "issuer":
		return p.Anchor.Issuer, &p.IssuerSignature
	case "authority":
		return p.Evidence.Assignment.AuthorityPublicKey, &p.AuthoritySignature
	case "control":
		return p.Evidence.Assignment.RemoteControlPublicKey, &p.ControlSignature
	}
	return [32]byte{}, nil
}
func (p Proposal) Sign(anchorID, descriptorID, legacyID types.Hash, end a.Position, role string, key ed25519.PrivateKey) (Proposal, error) {
	if _, e := p.ValidateDraft(anchorID, descriptorID, legacyID, end); e != nil {
		return Proposal{}, e
	}
	pub, sig := p.role(role)
	if sig == nil || !validKey(key, pub) {
		return Proposal{}, ErrPreparation
	}
	raw, e := p.unsigned()
	if e != nil {
		return Proposal{}, e
	}
	h := types.DomainHash(domain+"proposal/signature/"+role, raw)
	copy(sig[:], ed25519.Sign(key, h[:]))
	return p, nil
}
func (p Proposal) Verify(anchorID, descriptorID, legacyID types.Hash, end a.Position) (Bridge, error) {
	b, e := p.ValidateDraft(anchorID, descriptorID, legacyID, end)
	if e != nil {
		return b, e
	}
	raw, e := p.unsigned()
	if e != nil {
		return Bridge{}, e
	}
	for _, role := range []string{"issuer", "authority", "control"} {
		pub, sig := p.role(role)
		h := types.DomainHash(domain+"proposal/signature/"+role, raw)
		if !ed25519.Verify(pub[:], h[:], sig[:]) {
			return Bridge{}, ErrPreparation
		}
	}
	return b, nil
}

// Sign creates a historical observation. It cannot establish current ownership.
func (o Observation) Sign(e Evidence, anchor types.Hash, key ed25519.PrivateKey) (Observation, error) {
	pub := e.Assignment.AuthorityPublicKey
	if o.Role == Target {
		pub = e.Assignment.RemoteControlPublicKey
	}
	if !validKey(key, pub) {
		return Observation{}, ErrPreparation
	}
	raw, err := o.unsigned()
	if err != nil {
		return Observation{}, err
	}
	h := types.DomainHash(domain+"observation/signature", raw)
	copy(o.Signature[:], ed25519.Sign(key, h[:]))
	if err := o.Verify(e, anchor); err != nil {
		return Observation{}, err
	}
	return o, nil
}
