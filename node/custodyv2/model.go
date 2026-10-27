// Package custodyv2 implements a separate witness-mandatory custody job
// protocol. Its assignments, jobs, execution results and roots cannot be opened
// as V0/V1 operational histories. It does not activate a consensus fork.
package custodyv2

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const Version2 uint16 = 2
const MaximumPolicyBytes = 1024
const MaximumAssignmentBytes = 16 * 1024
const MaximumPlanBytes = 4096

var ErrProtocol = errors.New("invalid witness-mandatory custody V2 context, authorization or result")
var ErrSession = errors.New("custody V2 permission does not belong to this live execution session")
var ErrConsumed = errors.New("custody V2 execution already consumed; recover retained result only")
var ErrUncertain = errors.New("custody V2 persistence uncertain; retain the exact attempt and reopen without execution")

// Policy exists before the assignment, plan and slot. Its ID is consequently
// not recursive. Version two always requires the session-bound witness format.
type Policy struct {
	Version   uint16
	Threshold uint8
	Witnesses [][32]byte
}

func (p Policy) CanonicalBytes() ([]byte, error) {
	if p.Version != Version2 || len(p.Witnesses) < 4 || len(p.Witnesses) > custodyfence.MaximumWitnesses || int(p.Threshold) > len(p.Witnesses) || 3*int(p.Threshold) <= 2*len(p.Witnesses) {
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(MaximumPolicyBytes)
	e.Fixed([]byte("OMCVPOL2"))
	e.U16(p.Version)
	e.U8(p.Threshold)
	e.U8(uint8(len(p.Witnesses)))
	for i, k := range p.Witnesses {
		if types.Hash(k).IsZero() || i > 0 && bytes.Compare(p.Witnesses[i-1][:], k[:]) >= 0 {
			return nil, ErrProtocol
		}
		e.Fixed(k[:])
	}
	return e.Bytes(), nil
}
func (p Policy) ID() (types.Hash, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/witness-policy/id", b), nil
}
func DecodePolicy(b []byte) (Policy, error) {
	var p Policy
	if len(b) > MaximumPolicyBytes {
		return p, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVPOL2") {
		return p, ErrProtocol
	}
	p.Version, _ = d.U16()
	p.Threshold, _ = d.U8()
	n, e := d.U8()
	if e != nil || n > custodyfence.MaximumWitnesses || d.Remaining() != int(n)*32 {
		return p, ErrProtocol
	}
	p.Witnesses = make([][32]byte, int(n))
	for i := range p.Witnesses {
		fixed(d, p.Witnesses[i][:])
	}
	if _, e := p.CanonicalBytes(); e != nil {
		return Policy{}, e
	}
	return p, nil
}

// Base is public archive/role preparation only. Its V1 ID never authorizes V2
// work; the independently pinned outer ID commits the complete witness policy.
type Assignment struct {
	Version uint16
	Base    custodyauthority.Assignment
	Policy  Policy
}

func (a Assignment) CanonicalBytes() ([]byte, error) {
	if a.Version != Version2 || a.Base.Version != custodyauthority.Version1 {
		return nil, ErrProtocol
	}
	base, e := a.Base.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	policy, e := a.Policy.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	roles := [][32]byte{a.Base.AuthorityPublicKey, a.Base.ReplicaPublicKey, a.Base.RemoteControlPublicKey, a.Base.RemoteTransportPublicKey}
	roles = append(roles, a.Base.Auditors...)
	for _, c := range a.Base.Consumers {
		roles = append(roles, c.PublicKey)
	}
	for _, w := range a.Policy.Witnesses {
		for _, k := range roles {
			if w == k {
				return nil, ErrProtocol
			}
		}
	}
	e2 := codec.NewEncoder(MaximumAssignmentBytes)
	e2.Fixed([]byte("OMCVASG2"))
	e2.U16(a.Version)
	e2.BytesField(base)
	e2.BytesField(policy)
	return e2.Bytes(), nil
}
func (a Assignment) ID() (types.Hash, error) {
	b, e := a.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/assignment/id", b), nil
}
func DecodeAssignment(b []byte) (Assignment, error) {
	var a Assignment
	if len(b) > MaximumAssignmentBytes {
		return a, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVASG2") {
		return a, ErrProtocol
	}
	a.Version, _ = d.U16()
	raw, e := d.BytesField(custodyauthority.MaximumAssignmentBytes)
	if e != nil {
		return a, e
	}
	a.Base, e = custodyauthority.DecodeAssignment(raw)
	if e != nil {
		return a, e
	}
	raw, e = d.BytesField(MaximumPolicyBytes)
	if e != nil || d.Finish() != nil {
		return Assignment{}, ErrProtocol
	}
	a.Policy, e = DecodePolicy(raw)
	if e != nil {
		return Assignment{}, e
	}
	if _, e := a.CanonicalBytes(); e != nil {
		return Assignment{}, e
	}
	return a, nil
}

// Plan fixes one exact source predecessor and challenge. Both admitted control
// consumers and the authority authorize the same immutable job, in distinct
// signature domains. No caller-selected witness scope is accepted by a runtime.
type Plan struct {
	Version                                            uint16
	AssignmentID                                       types.Hash
	Intent                                             workarchive.CustodyAuditIntent
	Challenge                                          workarchive.CustodyChallenge
	ServeConsumer                                      [32]byte
	ClientTransportPublicKey                           [32]byte
	AuditSignature, ServeSignature, AuthoritySignature [64]byte
}

func (p Plan) unsignedBytes() ([]byte, error) {
	if p.Version != Version2 || p.AssignmentID.IsZero() || p.Intent.AssignmentID != p.AssignmentID || types.Hash(p.ServeConsumer).IsZero() || types.Hash(p.ClientTransportPublicKey).IsZero() || p.Intent.Validate() != nil {
		return nil, ErrProtocol
	}
	i, e := p.Intent.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	c, e := p.Challenge.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	if p.Intent.AuditorPublicKey != p.Challenge.AuditorPublicKey || p.Intent.Nonce != p.Challenge.Nonce || p.Intent.IssuedAt != p.Challenge.IssuedAt || p.Intent.ExpiresAt != p.Challenge.ExpiresAt || p.Intent.RenewUntil != p.Challenge.RenewUntil || p.Intent.PriorReceiptID != p.Challenge.ReceiptID || p.Intent.RequestedSamples != p.Challenge.RequestedSamples {
		return nil, ErrProtocol
	}
	out := codec.NewEncoder(MaximumPlanBytes)
	out.Fixed([]byte("OMCVPLN2"))
	out.U16(p.Version)
	out.Fixed(p.AssignmentID[:])
	out.Fixed(p.ServeConsumer[:])
	out.Fixed(p.ClientTransportPublicKey[:])
	out.BytesField(i)
	out.BytesField(c)
	return out.Bytes(), nil
}
func (p Plan) CanonicalBytes() ([]byte, error) {
	b, e := p.unsignedBytes()
	if e != nil {
		return nil, e
	}
	b = append(b, p.AuditSignature[:]...)
	b = append(b, p.ServeSignature[:]...)
	return append(b, p.AuthoritySignature[:]...), nil
}
func (p Plan) ID() (types.Hash, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/plan/id", b), nil
}
func (p Plan) Sign(role string, key ed25519.PrivateKey) (Plan, error) {
	if !validKey(key) {
		return Plan{}, ErrProtocol
	}
	b, e := p.unsignedBytes()
	if e != nil {
		return Plan{}, e
	}
	var out *[64]byte
	switch role {
	case "audit":
		if !bytes.Equal(key.Public().(ed25519.PublicKey), p.Intent.ConsumerPublicKey[:]) {
			return Plan{}, ErrProtocol
		}
		out = &p.AuditSignature
	case "serve":
		if !bytes.Equal(key.Public().(ed25519.PublicKey), p.ServeConsumer[:]) {
			return Plan{}, ErrProtocol
		}
		out = &p.ServeSignature
	case "authority":
		out = &p.AuthoritySignature
	default:
		return Plan{}, ErrProtocol
	}
	h := types.DomainHash("OMESH/custody/v2/plan/"+role+"/signature", b)
	copy(out[:], ed25519.Sign(key, h[:]))
	return p, nil
}
func (p Plan) ValidateDraft(a Assignment) error {
	id, e := a.ID()
	if e != nil || id != p.AssignmentID {
		return ErrProtocol
	}
	if _, e := p.unsignedBytes(); e != nil {
		return e
	}
	audit, serve := false, false
	for _, c := range a.Base.Consumers {
		audit = audit || c.PublicKey == p.Intent.ConsumerPublicKey && c.Purposes&custodyauthority.Audit != 0
		serve = serve || c.PublicKey == p.ServeConsumer && c.Purposes&custodyauthority.Serve != 0
	}
	roles := [][32]byte{a.Base.AuthorityPublicKey, a.Base.ReplicaPublicKey, a.Base.RemoteControlPublicKey, a.Base.RemoteTransportPublicKey}
	roles = append(roles, a.Base.Auditors...)
	roles = append(roles, a.Policy.Witnesses...)
	for _, c := range a.Base.Consumers {
		roles = append(roles, c.PublicKey)
	}
	for _, role := range roles {
		if p.ClientTransportPublicKey == role {
			return ErrProtocol
		}
	}
	if !audit || !serve {
		return ErrProtocol
	}
	return nil
}
func (p Plan) Verify(a Assignment) error {
	if e := p.ValidateDraft(a); e != nil {
		return e
	}
	b, e := p.unsignedBytes()
	if e != nil {
		return e
	}
	for _, x := range []struct {
		role string
		key  [32]byte
		sig  [64]byte
	}{{"audit", p.Intent.ConsumerPublicKey, p.AuditSignature}, {"serve", p.ServeConsumer, p.ServeSignature}, {"authority", a.Base.AuthorityPublicKey, p.AuthoritySignature}} {
		h := types.DomainHash("OMESH/custody/v2/plan/"+x.role+"/signature", b)
		if !ed25519.Verify(x.key[:], h[:], x.sig[:]) {
			return ErrProtocol
		}
	}
	return nil
}
func DecodePlan(b []byte) (Plan, error) {
	var p Plan
	if len(b) > MaximumPlanBytes {
		return p, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVPLN2") {
		return p, ErrProtocol
	}
	p.Version, _ = d.U16()
	fixed(d, p.AssignmentID[:])
	fixed(d, p.ServeConsumer[:])
	fixed(d, p.ClientTransportPublicKey[:])
	raw, e := d.BytesField(workarchive.MaximumCustodyAuditIntentBytes)
	if e != nil {
		return p, e
	}
	p.Intent, e = workarchive.DecodeCustodyAuditIntent(raw)
	if e != nil {
		return p, e
	}
	raw, e = d.BytesField(workarchive.MaximumCustodyChallengeBytes)
	if e != nil {
		return p, e
	}
	p.Challenge, e = workarchive.DecodeCustodyChallenge(raw)
	if e != nil {
		return p, e
	}
	fixed(d, p.AuditSignature[:])
	fixed(d, p.ServeSignature[:])
	fixed(d, p.AuthoritySignature[:])
	if d.Finish() != nil {
		return Plan{}, ErrProtocol
	}
	out, e := p.CanonicalBytes()
	if e != nil || !bytes.Equal(out, b) {
		return Plan{}, ErrProtocol
	}
	return p, nil
}

type Context struct {
	Assignment        Assignment
	Plan              Plan
	Manifest          workarchive.Manifest
	Initial, Previous workarchive.ReplicaReceipt
	CustodyPolicy     workarchive.CustodyPolicy
}

func (c Context) Validate() error {
	if e := c.Plan.Verify(c.Assignment); e != nil {
		return e
	}
	return c.validateArchive()
}

// ValidateDraft checks public job and archive bindings before the three role signatures exist.
func (c Context) ValidateDraft() error {
	if e := c.Plan.ValidateDraft(c.Assignment); e != nil {
		return e
	}
	return c.validateArchive()
}
func (c Context) validateArchive() error {
	a := c.Assignment.Base
	derived, e := workarchive.CreateRemoteCustodyAuthorityAssignment(c.Manifest, c.Initial, c.CustodyPolicy, a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
	if e != nil {
		return e
	}
	want, _ := a.ID()
	got, _ := derived.ID()
	if want != got {
		return ErrProtocol
	}
	rid, e := c.Previous.ID()
	if e != nil || rid != c.Plan.Intent.PriorReceiptID {
		return ErrProtocol
	}
	if c.Plan.Intent.PriorSequence == 0 && c.Previous != c.Initial {
		return ErrProtocol
	}
	if c.Previous.Binding != c.Initial.Binding || c.Previous.ManifestID != c.Initial.ManifestID || c.Previous.StatementID != c.Initial.StatementID || c.Previous.AnchorID != c.Initial.AnchorID || c.Previous.LocationID != c.Initial.LocationID || c.Previous.ReplicaPublicKey != c.Initial.ReplicaPublicKey {
		return ErrProtocol
	}
	peer, e := transport.PeerIDFromPublicKey(a.RemoteTransportPublicKey[:])
	if e != nil || peer != c.Plan.Intent.ReplicaPeerID {
		return ErrProtocol
	}
	return c.Plan.Challenge.Verify(c.Manifest, c.Previous, c.CustodyPolicy, c.Plan.Challenge.ExpiresAt)
}
func (c Context) Scope() (custodyfence.Scope, error) {
	if e := c.Validate(); e != nil {
		return custodyfence.Scope{}, e
	}
	aid, _ := c.Assignment.ID()
	pid, _ := c.Plan.ID()
	iid, _ := c.Plan.Intent.ID()
	begin := types.DomainHash("OMESH/custody/v2/begin/id", pid[:])
	s := custodyfence.Scope{Version: custodyfence.Version1, AssignmentID: aid, IntentID: iid, PlanID: pid, BeginID: begin, Owner: c.Assignment.Base.RemoteControlPublicKey, Controller: c.Assignment.Base.AuthorityPublicKey, Threshold: c.Assignment.Policy.Threshold, Witnesses: append([][32]byte(nil), c.Assignment.Policy.Witnesses...)}
	_, e := s.ID()
	return s, e
}
func (c Context) freeze() (Context, error) {
	if e := c.Validate(); e != nil {
		return Context{}, e
	}
	ab, _ := c.Assignment.CanonicalBytes()
	c.Assignment, _ = DecodeAssignment(ab)
	pb, _ := c.Plan.CanonicalBytes()
	c.Plan, _ = DecodePlan(pb)
	mb, _ := c.Manifest.CanonicalBytes()
	c.Manifest, _ = workarchive.DecodeManifest(mb)
	c.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), c.CustodyPolicy.TrustedAuditors...)
	return c, c.Validate()
}
func SessionID(public [32]byte) types.Hash {
	return types.DomainHash("OMESH/custody/v2/execution-session/id", public[:])
}
func validKey(k ed25519.PrivateKey) bool {
	return len(k) == 64 && bytes.Equal(k, ed25519.NewKeyFromSeed(k[:32]))
}
func magic(d *codec.Decoder, s string) bool { b, e := d.Fixed(8); return e == nil && string(b) == s }
func fixed(d *codec.Decoder, b []byte)      { v, _ := d.Fixed(len(b)); copy(b, v) }
