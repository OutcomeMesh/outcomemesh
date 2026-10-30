// Package prunefence binds one scheduled deletion to an independently selected
// witness quorum and a volatile executor session. It does not prove physical
// deletion or protect an executor whose process or witness quorum is compromised.
package prunefence

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const (
	MaximumPolicyBytes    = 640
	MaximumCandidateBytes = 1024
	MaximumClaimBytes     = MaximumCandidateBytes + custodyfence.MaximumCertificateBytes + 32
	MaximumResultBytes    = MaximumClaimBytes + 128
	domain                = "OMESH/prune-fence/"
)

var ErrFence = errors.New("prune requires its original independent claim and live execution session")

// Policy is committed in the request before any authority admission. Keys and
// locks belong to independent witnesses; participant backups must exclude them.
type Policy struct {
	Owner, Controller, Guard [32]byte
	Threshold                uint8
	Witnesses                [][32]byte
}

func (p Policy) Scope(assignment, request types.Hash) (custodyfence.Scope, error) {
	id, err := p.ID()
	if err != nil {
		return custodyfence.Scope{}, err
	}
	s := custodyfence.Scope{Version: custodyfence.Version1, Guard: p.Guard, AssignmentID: assignment, IntentID: request, PlanID: id,
		BeginID: types.DomainHash(domain+"slot/v0", request[:]), Owner: p.Owner, Controller: p.Controller, Threshold: p.Threshold, Witnesses: append([][32]byte(nil), p.Witnesses...)}
	_, err = s.CanonicalBytes()
	return s, err
}

func (p Policy) CanonicalBytes() ([]byte, error) {
	dummy := types.DomainHash(domain+"policy-shape/v0", nil)
	s := custodyfence.Scope{Version: 1, Guard: p.Guard, AssignmentID: dummy, IntentID: dummy, PlanID: dummy, BeginID: dummy, Owner: p.Owner, Controller: p.Controller, Threshold: p.Threshold, Witnesses: p.Witnesses}
	if _, err := s.CanonicalBytes(); err != nil {
		return nil, ErrFence
	}
	e := codec.NewEncoder(MaximumPolicyBytes)
	e.Fixed([]byte("OMPRFP00"))
	e.U16(0)
	for _, k := range [][32]byte{p.Owner, p.Controller, p.Guard} {
		e.Fixed(k[:])
	}
	e.U8(p.Threshold)
	e.U8(uint8(len(p.Witnesses)))
	for _, k := range p.Witnesses {
		e.Fixed(k[:])
	}
	return e.Bytes(), nil
}
func (p Policy) ID() (types.Hash, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"policy/id/v0", b), nil
}
func DecodePolicy(raw []byte) (Policy, error) {
	var p Policy
	if len(raw) > MaximumPolicyBytes {
		return p, ErrFence
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMPRFP00" || v != 0 {
		return p, ErrFence
	}
	for _, out := range [][]byte{p.Owner[:], p.Controller[:], p.Guard[:]} {
		b, e := d.Fixed(32)
		if e != nil {
			return Policy{}, ErrFence
		}
		copy(out, b)
	}
	p.Threshold, _ = d.U8()
	n, e := d.U8()
	if e != nil || n > custodyfence.MaximumWitnesses || d.Remaining() != int(n)*32 {
		return Policy{}, ErrFence
	}
	for i := 0; i < int(n); i++ {
		var k [32]byte
		b, _ := d.Fixed(32)
		copy(k[:], b)
		p.Witnesses = append(p.Witnesses, k)
	}
	b, e := p.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, b) {
		return Policy{}, ErrFence
	}
	return p, nil
}

// Binding fixes the actual operation and original storage/executor pair. Only
// request and assignment derive the witness slot, so copies cannot get new slots
// by changing their local inventory or executor identity.
type Binding struct {
	RequestID, AssignmentID, OperationID, InventoryID, ExecutorBindingID, StoragePairID types.Hash
}

func (b Binding) bytes() ([]byte, error) {
	e := codec.NewEncoder(192)
	for _, id := range []types.Hash{b.RequestID, b.AssignmentID, b.OperationID, b.InventoryID, b.ExecutorBindingID, b.StoragePairID} {
		if id.IsZero() {
			return nil, ErrFence
		}
		e.Fixed(id[:])
	}
	return e.Bytes(), nil
}
func (b Binding) ID() (types.Hash, error) {
	raw, e := b.bytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash(domain+"binding/id/v0", raw), nil
}

type Candidate struct {
	Policy  Policy
	Binding Binding
	Session [32]byte
}

func (c Candidate) CanonicalBytes() ([]byte, error) {
	p, e := c.Policy.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	b, e := c.Binding.bytes()
	if e != nil || c.Session == ([32]byte{}) {
		return nil, ErrFence
	}
	for _, k := range append(append([][32]byte{c.Policy.Owner, c.Policy.Controller, c.Policy.Guard}, c.Policy.Witnesses...), [32]byte{}) {
		if c.Session == k {
			return nil, ErrFence
		}
	}
	out := codec.NewEncoder(MaximumCandidateBytes)
	out.Fixed([]byte("OMPRFC00"))
	out.U16(0)
	out.BytesField(p)
	out.Fixed(b)
	out.Fixed(c.Session[:])
	return out.Bytes(), nil
}
func DecodeCandidate(raw []byte) (Candidate, error) {
	var c Candidate
	if len(raw) > MaximumCandidateBytes {
		return c, ErrFence
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMPRFC00" || v != 0 {
		return c, ErrFence
	}
	p, e := d.BytesField(MaximumPolicyBytes)
	if e != nil {
		return c, ErrFence
	}
	c.Policy, e = DecodePolicy(p)
	if e != nil {
		return c, e
	}
	for _, out := range [][]byte{c.Binding.RequestID[:], c.Binding.AssignmentID[:], c.Binding.OperationID[:], c.Binding.InventoryID[:], c.Binding.ExecutorBindingID[:], c.Binding.StoragePairID[:], c.Session[:]} {
		b, e := d.Fixed(32)
		if e != nil {
			return Candidate{}, ErrFence
		}
		copy(out, b)
	}
	b, e := c.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, b) {
		return Candidate{}, ErrFence
	}
	return c, nil
}
func (c Candidate) Draft() (custodyfence.Scope, custodyfence.Command, error) {
	raw, e := c.CanonicalBytes()
	if e != nil {
		return custodyfence.Scope{}, custodyfence.Command{}, e
	}
	s, e := c.Policy.Scope(c.Binding.AssignmentID, c.Binding.RequestID)
	if e != nil {
		return s, custodyfence.Command{}, e
	}
	id, _ := s.ID()
	return s, custodyfence.Command{Version: 1, ScopeID: id, ExpectedHead: id, Kind: custodyfence.Claim, EvidenceID: types.DomainHash(domain+"session/id/v0", raw)}, nil
}

type Claim struct {
	Candidate   Candidate
	Certificate custodyfence.Certificate
}

func (c Claim) Verify() error {
	s, want, e := c.Candidate.Draft()
	if e != nil {
		return e
	}
	want.Signature = c.Certificate.Command.Signature
	if want != c.Certificate.Command {
		return ErrFence
	}
	return c.Certificate.Verify(s)
}
func (c Claim) CanonicalBytes() ([]byte, error) {
	if e := c.Verify(); e != nil {
		return nil, e
	}
	a, _ := c.Candidate.CanonicalBytes()
	q, e := c.Certificate.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(MaximumClaimBytes)
	out.Fixed([]byte("OMPRFQ00"))
	out.U16(0)
	out.BytesField(a)
	out.BytesField(q)
	return out.Bytes(), nil
}
func DecodeClaim(raw []byte) (Claim, error) {
	var c Claim
	if len(raw) > MaximumClaimBytes {
		return c, ErrFence
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMPRFQ00" || v != 0 {
		return c, ErrFence
	}
	a, e := d.BytesField(MaximumCandidateBytes)
	if e != nil {
		return c, e
	}
	c.Candidate, e = DecodeCandidate(a)
	if e != nil {
		return c, e
	}
	q, e := d.BytesField(custodyfence.MaximumCertificateBytes)
	if e != nil {
		return c, e
	}
	c.Certificate, e = custodyfence.DecodeCertificate(q)
	if e != nil {
		return c, e
	}
	b, e := c.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, b) {
		return Claim{}, ErrFence
	}
	return c, nil
}
