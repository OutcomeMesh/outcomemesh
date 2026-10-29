package custodyv2

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const MaximumContextBytes = workarchive.MaximumManifestBytes + MaximumAssignmentBytes + MaximumPlanBytes + 2*workarchive.MaximumReplicaReceiptBytes + 4096
const MaximumResultBytes = workarchive.MaximumCustodyJournalEntryBytes + 1024 + gateway.MaximumEffectBytes + 32
const MaximumBundleBytes = MaximumResultBytes + 3*(custodyfence.MaximumCertificateBytes+10) + 64

func (c Context) CanonicalBytes() ([]byte, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	e := codec.NewEncoder(4096)
	e.Fixed([]byte("OMCVCTX2"))
	e.U16(Version2)
	for _, value := range []interface{ CanonicalBytes() ([]byte, error) }{c.Assignment, c.Plan, c.Manifest, c.Initial, c.Previous} {
		b, err := value.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(b)
	}
	e.U64(c.CustodyPolicy.MaximumChallengeLifetime)
	e.U64(c.CustodyPolicy.MaximumProofAge)
	e.U64(c.CustodyPolicy.MaximumRenewalTerm)
	e.U16(uint16(len(c.CustodyPolicy.TrustedAuditors)))
	for _, k := range c.CustodyPolicy.TrustedAuditors {
		e.Fixed(k[:])
	}
	b := e.Bytes()
	if len(b) > MaximumContextBytes {
		return nil, ErrProtocol
	}
	return b, nil
}
func (c Context) ID() (types.Hash, error) {
	b, e := c.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/context/id", b), nil
}
func DecodeContext(b []byte) (Context, error) {
	var c Context
	if len(b) > MaximumContextBytes {
		return c, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVCTX2") {
		return c, ErrProtocol
	}
	v, e := d.U16()
	if e != nil || v != Version2 {
		return c, ErrProtocol
	}
	limits := []uint64{MaximumAssignmentBytes, MaximumPlanBytes, workarchive.MaximumManifestBytes, workarchive.MaximumReplicaReceiptBytes, workarchive.MaximumReplicaReceiptBytes}
	raw := make([][]byte, 5)
	for i, limit := range limits {
		raw[i], e = d.BytesField(limit)
		if e != nil {
			return c, e
		}
	}
	c.Assignment, e = DecodeAssignment(raw[0])
	if e != nil {
		return c, e
	}
	c.Plan, e = DecodePlan(raw[1])
	if e != nil {
		return c, e
	}
	c.Manifest, e = workarchive.DecodeManifest(raw[2])
	if e != nil {
		return c, e
	}
	c.Initial, e = workarchive.DecodeReplicaReceipt(raw[3])
	if e != nil {
		return c, e
	}
	c.Previous, e = workarchive.DecodeReplicaReceipt(raw[4])
	if e != nil {
		return c, e
	}
	c.CustodyPolicy.MaximumChallengeLifetime, _ = d.U64()
	c.CustodyPolicy.MaximumProofAge, _ = d.U64()
	c.CustodyPolicy.MaximumRenewalTerm, _ = d.U64()
	n, e := d.U16()
	if e != nil || n > 64 || d.Remaining() != int(n)*32 {
		return c, ErrProtocol
	}
	c.CustodyPolicy.TrustedAuditors = make([][32]byte, int(n))
	for i := range c.CustodyPolicy.TrustedAuditors {
		fixed(d, c.CustodyPolicy.TrustedAuditors[i][:])
	}
	out, e := c.CanonicalBytes()
	if e != nil || !bytes.Equal(out, b) {
		return Context{}, ErrProtocol
	}
	return c, nil
}

type Candidate struct {
	Version          uint16
	SessionPublicKey [32]byte
	Claim            custodyfence.Command
}

func (c Candidate) CanonicalBytes() ([]byte, error) {
	if c.Version != Version2 || types.Hash(c.SessionPublicKey).IsZero() || c.Claim.Version != custodyfence.Version1 || c.Claim.Kind != custodyfence.Claim || c.Claim.EvidenceID != SessionID(c.SessionPublicKey) {
		return nil, ErrSession
	}
	b, e := c.Claim.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(256)
	out.Fixed([]byte("OMCVCAN2"))
	out.U16(c.Version)
	out.Fixed(c.SessionPublicKey[:])
	out.Fixed(b)
	return out.Bytes(), nil
}
func DecodeCandidate(b []byte) (Candidate, error) {
	var c Candidate
	if len(b) != 10+32+custodyfence.CommandBytes {
		return c, ErrSession
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVCAN2") {
		return c, ErrSession
	}
	c.Version, _ = d.U16()
	fixed(d, c.SessionPublicKey[:])
	raw, _ := d.Fixed(custodyfence.CommandBytes)
	var e error
	c.Claim, e = custodyfence.DecodeCommand(raw)
	if e != nil {
		return c, e
	}
	if _, e := c.CanonicalBytes(); e != nil {
		return Candidate{}, e
	}
	return c, nil
}
func (c Candidate) Verify(ctx Context) error {
	if _, e := c.CanonicalBytes(); e != nil {
		return e
	}
	roles := [][32]byte{ctx.Assignment.Base.AuthorityPublicKey, ctx.Assignment.Base.ReplicaPublicKey, ctx.Assignment.Base.RemoteControlPublicKey, ctx.Assignment.Base.RemoteTransportPublicKey, ctx.Plan.ClientTransportPublicKey}
	roles = append(roles, ctx.Assignment.Base.Auditors...)
	roles = append(roles, ctx.Assignment.Policy.Witnesses...)
	for _, member := range ctx.Assignment.Base.Consumers {
		roles = append(roles, member.PublicKey)
	}
	for _, role := range roles {
		if c.SessionPublicKey == role {
			return ErrSession
		}
	}
	scope, e := ctx.Scope()
	if e != nil {
		return e
	}
	if e := c.Claim.Verify(scope); e != nil {
		return e
	}
	id, _ := scope.ID()
	if c.Claim.ExpectedSequence != 0 || c.Claim.ExpectedHead != id {
		return ErrSession
	}
	return nil
}

// Result requires possession of the winning volatile session key in addition
// to the long-term replica signature inside Entry. That key is never persisted.
type Result struct {
	Protection       *gateway.Effect
	Version          uint16
	ScopeID, ClaimID types.Hash
	SessionPublicKey [32]byte
	Entry            workarchive.CustodyJournalEntry
	SessionSignature [64]byte
}

func (r Result) unsignedBytes() ([]byte, error) {
	if r.Version != Version2 || r.ScopeID.IsZero() || r.ClaimID.IsZero() || types.Hash(r.SessionPublicKey).IsZero() {
		return nil, ErrProtocol
	}
	entry, e := r.Entry.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(entry) + 256)
	out.Fixed([]byte("OMCVRES2"))
	out.U16(r.Version)
	out.Fixed(r.ScopeID[:])
	out.Fixed(r.ClaimID[:])
	out.Fixed(r.SessionPublicKey[:])
	out.BytesField(entry)
	return out.Bytes(), nil
}
func (r Result) CanonicalBytes() ([]byte, error) {
	if r.Version == ProtectedVersion {
		return r.protectedBytes()
	}
	if r.Protection != nil {
		return nil, ErrProtocol
	}
	b, e := r.unsignedBytes()
	if e != nil {
		return nil, e
	}
	h := types.DomainHash("OMESH/custody/v2/result/session-signature", b)
	if !ed25519.Verify(r.SessionPublicKey[:], h[:], r.SessionSignature[:]) {
		return nil, ErrSession
	}
	return append(b, r.SessionSignature[:]...), nil
}
func (r Result) ID() (types.Hash, error) {
	b, e := r.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	domain := "OMESH/custody/v2/result/id"
	if r.Version == ProtectedVersion {
		domain = "OMESH/custody/v5/result/id"
	}
	return types.DomainHash(domain, b), nil
}
func DecodeResult(b []byte) (Result, error) {
	var r Result
	if len(b) >= 8 && string(b[:8]) == "OMCVRES5" {
		return decodeProtectedResult(b)
	}
	if len(b) > MaximumResultBytes {
		return r, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVRES2") {
		return r, ErrProtocol
	}
	r.Version, _ = d.U16()
	fixed(d, r.ScopeID[:])
	fixed(d, r.ClaimID[:])
	fixed(d, r.SessionPublicKey[:])
	raw, e := d.BytesField(workarchive.MaximumCustodyJournalEntryBytes)
	if e != nil {
		return r, e
	}
	r.Entry, e = workarchive.DecodeCustodyJournalEntry(raw)
	if e != nil {
		return r, e
	}
	fixed(d, r.SessionSignature[:])
	if d.Finish() != nil {
		return Result{}, ErrProtocol
	}
	out, e := r.CanonicalBytes()
	if e != nil || !bytes.Equal(out, b) {
		return Result{}, ErrProtocol
	}
	return r, nil
}
func (r Result) Verify(c Context, claim custodyfence.Certificate) error {
	if ProtectedContext(c) {
		if r.Version != ProtectedVersion {
			return ErrProtocol
		}
		id, e := r.CoreID()
		head, _ := r.Entry.ID()
		if e != nil || VerifyProtectedEffect(c, r.Protection, gateway.EffectExecute, id, head, r.Entry.Sequence, r.Entry.Record.Proof.RespondedAt) != nil {
			return ErrProtocol
		}
	} else if r.Version != Version2 || r.Protection != nil {
		return ErrProtocol
	}

	if e := (Candidate{Version: Version2, SessionPublicKey: r.SessionPublicKey, Claim: claim.Command}).Verify(c); e != nil {
		return e
	}
	if _, e := r.CanonicalBytes(); e != nil {
		return e
	}
	s, e := c.Scope()
	if e != nil {
		return e
	}
	sid, _ := s.ID()
	cid, _ := claim.Command.ID()
	if r.ScopeID != sid || r.ClaimID != cid || claim.Command.Kind != custodyfence.Claim || claim.Command.EvidenceID != SessionID(r.SessionPublicKey) {
		return ErrSession
	}
	state, e := custodyfence.NewState(s, sid)
	if e != nil {
		return e
	}
	if e := state.Apply(claim); e != nil {
		return e
	}
	if e := r.Entry.Verify(c.Manifest, c.CustodyPolicy, c.Plan.Intent.PriorSequence+1, c.Plan.Intent.PriorHeadID, c.Previous); e != nil {
		return e
	}
	wanted, _ := c.Plan.Challenge.ID()
	got, _ := r.Entry.Record.Challenge.ID()
	if wanted != got {
		return ErrProtocol
	}
	return nil
}

type Bundle struct {
	Version uint16
	Result  Result
	Chain   []custodyfence.Certificate
}

func (b Bundle) CanonicalBytes() ([]byte, error) {
	if b.Version != Version2 || len(b.Chain) < 2 || len(b.Chain) > 3 {
		return nil, ErrProtocol
	}
	raw, e := b.Result.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(raw) + 4096)
	out.Fixed([]byte("OMCVBND2"))
	out.U16(b.Version)
	out.BytesField(raw)
	out.U8(uint8(len(b.Chain)))
	for _, c := range b.Chain {
		raw, e := c.CanonicalBytes()
		if e != nil {
			return nil, e
		}
		out.BytesField(raw)
	}
	return out.Bytes(), nil
}
func DecodeBundle(raw []byte) (Bundle, error) {
	var b Bundle
	if len(raw) > MaximumBundleBytes {
		return b, ErrProtocol
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVBND2") {
		return b, ErrProtocol
	}
	b.Version, _ = d.U16()
	r, e := d.BytesField(MaximumResultBytes)
	if e != nil {
		return b, e
	}
	b.Result, e = DecodeResult(r)
	if e != nil {
		return b, e
	}
	n, e := d.U8()
	if e != nil || n < 2 || n > 3 {
		return b, ErrProtocol
	}
	b.Chain = make([]custodyfence.Certificate, int(n))
	for i := range b.Chain {
		r, e := d.BytesField(custodyfence.MaximumCertificateBytes)
		if e != nil {
			return b, e
		}
		b.Chain[i], e = custodyfence.DecodeCertificate(r)
		if e != nil {
			return b, e
		}
	}
	if d.Finish() != nil {
		return Bundle{}, ErrProtocol
	}
	out, e := b.CanonicalBytes()
	if e != nil || !bytes.Equal(out, raw) {
		return Bundle{}, ErrProtocol
	}
	return b, nil
}
func (b Bundle) ID() (types.Hash, error) {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/bundle/id", raw), nil
}
func (b Bundle) Verify(c Context) error {
	if _, e := b.CanonicalBytes(); e != nil {
		return e
	}
	if e := b.Result.Verify(c, b.Chain[0]); e != nil {
		return e
	}
	s, e := c.Scope()
	if e != nil {
		return e
	}
	sid, _ := s.ID()
	state, e := custodyfence.NewState(s, sid)
	if e != nil {
		return e
	}
	for _, cert := range b.Chain {
		if e := state.Apply(cert); e != nil {
			return e
		}
	}
	x := state.Snapshot()
	rid, _ := b.Result.ID()
	if x.Phase != custodyfence.ResultRecorded || x.EvidenceID != rid || x.SessionID != SessionID(b.Result.SessionPublicKey) || !x.ObligationHeld {
		return ErrProtocol
	}
	return nil
}
