package prunefence

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const (
	MaximumSettlementProposalBytes = MaximumClaimBytes + 180
	MaximumSettlementBytes         = MaximumSettlementProposalBytes + custodyfence.MaximumCertificateBytes + 32
)

// SettlementScope selects one observed-effect proposal for the original request.
// It is separate from execution: CloseUnclaimed here closes this decision slot,
// not the already claimed execution slot. Enroll the original witnesses with
// separate original pins; never replace their execution history.
func (p Policy) SettlementScope(assignment, request types.Hash) (custodyfence.Scope, error) {
	s, err := p.Scope(assignment, request)
	if err != nil {
		return s, err
	}
	id, _ := s.ID()
	s.BeginID = types.DomainHash(domain+"settlement-slot/v0", id[:])
	return s, nil
}

// SettlementProposal is an explicit agreement about a retained effect. It never
// substitutes for the volatile session signature. Both original roles must sign;
// the application must independently re-read the actual protected storage effect.
// Drafts may contain zero or one valid signature, but cannot obtain a decision.
type SettlementProposal struct {
	Claim                               Claim
	EffectID                            types.Hash
	OwnerSignature, ControllerSignature [64]byte
}

func (p SettlementProposal) body() ([]byte, error) {
	claim, err := p.Claim.CanonicalBytes()
	if err != nil || p.EffectID.IsZero() {
		return nil, ErrFence
	}
	e := codec.NewEncoder(MaximumSettlementProposalBytes)
	e.Fixed([]byte("OMPRSP00"))
	e.U16(0)
	e.BytesField(claim)
	e.Fixed(p.EffectID[:])
	return e.Bytes(), nil
}
func (p SettlementProposal) signingHash(role string) (types.Hash, error) {
	if role != "owner" && role != "controller" {
		return types.Hash{}, ErrFence
	}
	b, err := p.body()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"settlement/"+role+"/sign/v0", b), nil
}
func (p SettlementProposal) CanonicalBytes() ([]byte, error) {
	b, err := p.body()
	if err != nil {
		return nil, err
	}
	for _, v := range []struct {
		role string
		key  [32]byte
		sig  [64]byte
	}{
		{"owner", p.Claim.Candidate.Policy.Owner, p.OwnerSignature},
		{"controller", p.Claim.Candidate.Policy.Controller, p.ControllerSignature},
	} {
		h, _ := p.signingHash(v.role)
		if v.sig != ([64]byte{}) && !ed25519.Verify(v.key[:], h[:], v.sig[:]) {
			return nil, ErrFence
		}
	}
	b = append(b, p.OwnerSignature[:]...)
	b = append(b, p.ControllerSignature[:]...)
	return b, nil
}
func (p SettlementProposal) ID() (types.Hash, error) {
	b, err := p.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"settlement-proposal/id/v0", b), nil
}
func (p SettlementProposal) Verify() error {
	if p.OwnerSignature == ([64]byte{}) || p.ControllerSignature == ([64]byte{}) {
		return ErrFence
	}
	_, err := p.CanonicalBytes()
	return err
}
func (p SettlementProposal) ReviewID(role string) (types.Hash, error) {
	if _, err := p.signingHash(role); err != nil {
		return types.Hash{}, err
	}
	b, err := p.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"settlement/"+role+"/review/v0", b), nil
}
func (p SettlementProposal) Sign(role string, expected types.Hash, key ed25519.PrivateKey) (SettlementProposal, error) {
	review, err := p.ReviewID(role)
	if err != nil || expected != review || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) {
		return SettlementProposal{}, ErrFence
	}
	want := p.Claim.Candidate.Policy.Owner
	if role == "controller" {
		want = p.Claim.Candidate.Policy.Controller
	}
	if !bytes.Equal(key[32:], want[:]) {
		return SettlementProposal{}, ErrFence
	}
	raw, _ := p.CanonicalBytes()
	p, _ = DecodeSettlementProposal(raw)
	h, _ := p.signingHash(role)
	signature := ed25519.Sign(key, h[:])
	if role == "owner" {
		copy(p.OwnerSignature[:], signature)
	} else {
		copy(p.ControllerSignature[:], signature)
	}
	return p, nil
}
func (p SettlementProposal) Draft() (custodyfence.Scope, custodyfence.Command, error) {
	if err := p.Verify(); err != nil {
		return custodyfence.Scope{}, custodyfence.Command{}, err
	}
	c := p.Claim.Candidate
	s, err := c.Policy.SettlementScope(c.Binding.AssignmentID, c.Binding.RequestID)
	if err != nil {
		return s, custodyfence.Command{}, err
	}
	sid, _ := s.ID()
	id, _ := p.ID()
	return s, custodyfence.Command{Version: custodyfence.Version1, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: id}, nil
}
func DecodeSettlementProposal(raw []byte) (SettlementProposal, error) {
	var p SettlementProposal
	if len(raw) > MaximumSettlementProposalBytes {
		return p, ErrFence
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMPRSP00" || v != 0 {
		return p, ErrFence
	}
	claim, err := d.BytesField(MaximumClaimBytes)
	if err != nil {
		return p, err
	}
	p.Claim, err = DecodeClaim(claim)
	if err != nil {
		return p, err
	}
	for _, out := range [][]byte{p.EffectID[:], p.OwnerSignature[:], p.ControllerSignature[:]} {
		b, err := d.Fixed(len(out))
		if err != nil {
			return SettlementProposal{}, err
		}
		copy(out, b)
	}
	b, err := p.CanonicalBytes()
	if err != nil || d.Finish() != nil || !bytes.Equal(raw, b) {
		return SettlementProposal{}, ErrFence
	}
	return p, nil
}

// Settlement selects the fully signed proposal, not physical storage truth or
// present execution permission. Application still requires the original owners.
type Settlement struct {
	Proposal    SettlementProposal
	Certificate custodyfence.Certificate
}

func (s Settlement) Verify() error {
	scope, draft, err := s.Proposal.Draft()
	if err != nil {
		return err
	}
	draft.Signature = s.Certificate.Command.Signature
	if draft != s.Certificate.Command {
		return ErrFence
	}
	return s.Certificate.Verify(scope)
}
func (s Settlement) CanonicalBytes() ([]byte, error) {
	if err := s.Verify(); err != nil {
		return nil, err
	}
	p, _ := s.Proposal.CanonicalBytes()
	q, err := s.Certificate.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumSettlementBytes)
	e.Fixed([]byte("OMPRSC00"))
	e.U16(0)
	e.BytesField(p)
	e.BytesField(q)
	return e.Bytes(), nil
}
func (s Settlement) ID() (types.Hash, error) {
	b, err := s.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"settlement-certificate/id/v0", b), nil
}
func DecodeSettlement(raw []byte) (Settlement, error) {
	var s Settlement
	if len(raw) > MaximumSettlementBytes {
		return s, ErrFence
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMPRSC00" || v != 0 {
		return s, ErrFence
	}
	p, err := d.BytesField(MaximumSettlementProposalBytes)
	if err != nil {
		return s, err
	}
	s.Proposal, err = DecodeSettlementProposal(p)
	if err != nil {
		return s, err
	}
	q, err := d.BytesField(custodyfence.MaximumCertificateBytes)
	if err != nil {
		return s, err
	}
	s.Certificate, err = custodyfence.DecodeCertificate(q)
	if err != nil {
		return s, err
	}
	b, err := s.CanonicalBytes()
	if err != nil || d.Finish() != nil || !bytes.Equal(raw, b) {
		return Settlement{}, ErrFence
	}
	return s, nil
}
