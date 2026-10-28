package custodyv2

import (
	"bytes"
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const MaximumServeProposalBytes = MaximumBundleBytes + ReceiptBytes + 256
const MaximumServeCertificateBytes = MaximumServeProposalBytes + custodyfence.MaximumCertificateBytes + 32

type ServeOutcome uint8

const (
	ServeFulfilled ServeOutcome = 1 + iota
	ServeUnclaimed
)

// ServeProposal closes only this V2 job's execution obligation. Archive
// retention and legacy authority-ledger tickets are separate obligations.
// There is deliberately no unknown/timeout/no-work assertion outcome.
type ServeProposal struct {
	Version                               uint16
	ContextID                             types.Hash
	Outcome                               ServeOutcome
	Evidence                              []byte
	AuthoritySignature, ConsumerSignature [64]byte
}

func NewServeFulfilled(c Context, b Bundle, r Receipt) (ServeProposal, error) {
	if e := r.Verify(c, b); e != nil {
		return ServeProposal{}, e
	}
	bb, _ := b.CanonicalBytes()
	rb, _ := r.CanonicalBytes()
	e := codec.NewEncoder(len(bb) + len(rb) + 16)
	e.BytesField(bb)
	e.Fixed(rb)
	id, err := c.ID()
	if err != nil {
		return ServeProposal{}, err
	}
	return ServeProposal{Version: Version2, ContextID: id, Outcome: ServeFulfilled, Evidence: e.Bytes()}, nil
}

func NewServeUnclaimed(c Context, q custodyfence.Certificate) (ServeProposal, error) {
	id, e := c.ID()
	if e != nil {
		return ServeProposal{}, e
	}
	b, e := q.CanonicalBytes()
	if e != nil {
		return ServeProposal{}, e
	}
	p := ServeProposal{Version: Version2, ContextID: id, Outcome: ServeUnclaimed, Evidence: b}
	_, e = p.Retention(c)
	return p, e
}

func (p ServeProposal) unsignedBytes() ([]byte, error) {
	if p.Version != Version2 || p.ContextID.IsZero() || (p.Outcome != ServeFulfilled && p.Outcome != ServeUnclaimed) || len(p.Evidence) == 0 || len(p.Evidence) > MaximumServeProposalBytes-175 {
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(len(p.Evidence) + 64)
	e.Fixed([]byte("OMCVSPR2"))
	e.U16(p.Version)
	e.Fixed(p.ContextID[:])
	e.U8(uint8(p.Outcome))
	e.BytesField(p.Evidence)
	return e.Bytes(), nil
}

// CanonicalBytes also supports a draft carrying zero or one role signature.
// A draft is never a witness vote or permission to settle.
func (p ServeProposal) CanonicalBytes() ([]byte, error) {
	b, e := p.unsignedBytes()
	if e != nil {
		return nil, e
	}
	b = append(b, p.AuthoritySignature[:]...)
	return append(b, p.ConsumerSignature[:]...), nil
}
func DecodeServeProposal(b []byte) (ServeProposal, error) {
	var p ServeProposal
	if len(b) > MaximumServeProposalBytes {
		return p, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVSPR2") {
		return p, ErrProtocol
	}
	p.Version, _ = d.U16()
	fixed(d, p.ContextID[:])
	k, _ := d.U8()
	p.Outcome = ServeOutcome(k)
	var e error
	p.Evidence, e = d.BytesField(MaximumServeProposalBytes)
	if e != nil {
		return p, e
	}
	fixed(d, p.AuthoritySignature[:])
	fixed(d, p.ConsumerSignature[:])
	again, e := p.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(b, again) {
		return ServeProposal{}, ErrProtocol
	}
	return p, nil
}
func (p ServeProposal) ID() (types.Hash, error) {
	b, e := p.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/serve/proposal/id", b), nil
}
func (p ServeProposal) fulfilled() (Bundle, Receipt, error) {
	if p.Outcome != ServeFulfilled {
		return Bundle{}, Receipt{}, ErrProtocol
	}
	d := codec.NewDecoder(p.Evidence)
	b, e := d.BytesField(MaximumBundleBytes)
	if e != nil {
		return Bundle{}, Receipt{}, e
	}
	r, e := d.Fixed(ReceiptBytes)
	if e != nil || d.Finish() != nil {
		return Bundle{}, Receipt{}, ErrProtocol
	}
	bundle, e := DecodeBundle(b)
	if e != nil {
		return Bundle{}, Receipt{}, e
	}
	receipt, e := DecodeReceipt(r)
	return bundle, receipt, e
}

// Retention verifies the complete typed evidence, including the original
// execution quorum and historical fresh A acceptance. It grants no deletion.
func (p ServeProposal) Retention(c Context) (uint64, error) {
	if _, e := p.unsignedBytes(); e != nil {
		return 0, e
	}
	id, e := c.ID()
	if e != nil || id != p.ContextID {
		return 0, ErrProtocol
	}
	s, e := c.Scope()
	if e != nil {
		return 0, e
	}
	sid, _ := s.ID()
	switch p.Outcome {
	case ServeFulfilled:
		b, r, e := p.fulfilled()
		if e != nil {
			return 0, e
		}
		if e := r.Verify(c, b); e != nil {
			return 0, e
		}
		return b.Result.Entry.Record.RenewedReceipt.RetainUntil, nil
	case ServeUnclaimed:
		q, e := custodyfence.DecodeCertificate(p.Evidence)
		if e != nil {
			return 0, e
		}
		state, e := custodyfence.NewState(s, sid)
		if e != nil {
			return 0, e
		}
		if e := state.Apply(q); e != nil {
			return 0, e
		}
		if state.Snapshot().Phase != custodyfence.UnclaimedClosed {
			return 0, ErrProtocol
		}
		return c.Previous.RetainUntil, nil
	}
	return 0, ErrProtocol
}
func (p ServeProposal) ValidateDraft(c Context) error {
	if _, e := p.Retention(c); e != nil {
		return e
	}
	b, _ := p.unsignedBytes()
	for _, r := range []struct {
		label string
		key   [32]byte
		sig   [64]byte
	}{{"authority", c.Assignment.Base.AuthorityPublicKey, p.AuthoritySignature}, {"consumer", c.Plan.ServeConsumer, p.ConsumerSignature}} {
		if r.sig == ([64]byte{}) {
			continue
		}
		h := types.DomainHash("OMESH/custody/v2/serve/proposal/"+r.label+"/signature", b)
		if !ed25519.Verify(r.key[:], h[:], r.sig[:]) {
			return ErrProtocol
		}
	}
	return nil
}
func (p ServeProposal) Verify(c Context) error {
	if p.AuthoritySignature == ([64]byte{}) || p.ConsumerSignature == ([64]byte{}) {
		return ErrProtocol
	}
	return p.ValidateDraft(c)
}
func (p ServeProposal) Sign(c Context, role string, key ed25519.PrivateKey) (ServeProposal, error) {
	if e := p.ValidateDraft(c); e != nil {
		return ServeProposal{}, e
	}
	public := c.Assignment.Base.AuthorityPublicKey
	sig := &p.AuthoritySignature
	if role == "consumer" {
		public = c.Plan.ServeConsumer
		sig = &p.ConsumerSignature
	} else if role != "authority" {
		return ServeProposal{}, ErrProtocol
	}
	if !matches(key, public) {
		return ServeProposal{}, ErrProtocol
	}
	b, _ := p.unsignedBytes()
	h := types.DomainHash("OMESH/custody/v2/serve/proposal/"+role+"/signature", b)
	copy(sig[:], ed25519.Sign(key, h[:]))
	return p, nil
}

// ServeScope is a separate, outcome-independent one-shot decision slot. Only
// CloseUnclaimed at its initial position is exposed by the typed adapter below.
// This closes the unused *decision* slot over Proposal.ID, not the execution
// slot. Its QC alone says nothing about execution: ServeCertificate verifies
// the full typed proposal. V0/V1 execution encodings and domains are unchanged.
func (c Context) ServeScope() (custodyfence.Scope, error) {
	s, e := c.Scope()
	if e != nil {
		return s, e
	}
	job, _ := s.ID()
	s.Version = custodyfence.Version0
	s.BeginID = types.DomainHash("OMESH/custody/v2/serve/decision-slot", job[:])
	return s, nil
}
func (p ServeProposal) Decision(c Context, key ed25519.PrivateKey) (custodyfence.Command, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return custodyfence.Command{}, err
	}
	p, err = DecodeServeProposal(raw)
	if err != nil {
		return custodyfence.Command{}, err
	}
	if e := p.Verify(c); e != nil {
		return custodyfence.Command{}, e
	}
	if !matches(key, c.Assignment.Base.AuthorityPublicKey) {
		return custodyfence.Command{}, ErrProtocol
	}
	s, e := c.ServeScope()
	if e != nil {
		return custodyfence.Command{}, e
	}
	sid, _ := s.ID()
	pid, _ := p.ID()
	q, e := (custodyfence.Command{Version: s.Version, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: pid}).Sign(key)
	if e != nil {
		return q, e
	}
	return q, validateServeDecision(c, p, q)
}
func validateServeDecision(c Context, p ServeProposal, q custodyfence.Command) error {
	if e := p.Verify(c); e != nil {
		return e
	}
	s, e := c.ServeScope()
	if e != nil {
		return e
	}
	sid, _ := s.ID()
	pid, _ := p.ID()
	if q.Kind != custodyfence.CloseUnclaimed || q.ExpectedSequence != 0 || q.ExpectedHead != sid || !q.ClaimID.IsZero() || q.EvidenceID != pid {
		return ErrProtocol
	}
	return q.Verify(s)
}

type ServeCertificate struct {
	Version  uint16
	Proposal ServeProposal
	Decision custodyfence.Certificate
}

func (s ServeCertificate) Verify(c Context) error {
	if s.Version != Version2 {
		return ErrProtocol
	}
	if e := validateServeDecision(c, s.Proposal, s.Decision.Command); e != nil {
		return e
	}
	scope, e := c.ServeScope()
	if e != nil {
		return e
	}
	return s.Decision.Verify(scope)
}
func (s ServeCertificate) CanonicalBytes() ([]byte, error) {
	if s.Version != Version2 {
		return nil, ErrProtocol
	}
	p, e := s.Proposal.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	q, e := s.Decision.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(p) + len(q) + 32)
	out.Fixed([]byte("OMCVSQC2"))
	out.U16(s.Version)
	out.BytesField(p)
	out.BytesField(q)
	return out.Bytes(), nil
}
func DecodeServeCertificate(b []byte) (ServeCertificate, error) {
	var s ServeCertificate
	if len(b) > MaximumServeCertificateBytes {
		return s, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVSQC2") {
		return s, ErrProtocol
	}
	s.Version, _ = d.U16()
	p, e := d.BytesField(MaximumServeProposalBytes)
	if e != nil {
		return s, e
	}
	q, e := d.BytesField(custodyfence.MaximumCertificateBytes)
	if e != nil || d.Finish() != nil {
		return s, ErrProtocol
	}
	s.Proposal, e = DecodeServeProposal(p)
	if e != nil {
		return s, e
	}
	s.Decision, e = custodyfence.DecodeCertificate(q)
	if e != nil {
		return s, e
	}
	again, e := s.CanonicalBytes()
	if e != nil || !bytes.Equal(b, again) {
		return ServeCertificate{}, ErrProtocol
	}
	return s, nil
}
func (s ServeCertificate) ID() (types.Hash, error) {
	b, e := s.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/serve/certificate/id", b), nil
}

// VoteServe and CommitServe are the only witness operations in the Serve CLI.
// They verify typed evidence and both participant signatures before acquiring
// any new permanent vote. Generic hash-only witness RPC is never used here.
func VoteServe(c Context, p ServeProposal, cmd custodyfence.Command, w *custodyfence.Witness, before custodyfence.WitnessPin) (custodyfence.Vote, error) {
	if w == nil {
		return custodyfence.Vote{}, ErrProtocol
	}
	raw, err := p.CanonicalBytes()
	if err != nil {
		return custodyfence.Vote{}, err
	}
	p, err = DecodeServeProposal(raw)
	if err != nil {
		return custodyfence.Vote{}, err
	}
	if e := validateServeDecision(c, p, cmd); e != nil {
		return custodyfence.Vote{}, e
	}
	return w.VoteAt(before, cmd)
}
func CommitServe(c Context, s ServeCertificate, w *custodyfence.Witness, before custodyfence.WitnessPin) error {
	if w == nil {
		return ErrProtocol
	}
	raw, err := s.CanonicalBytes()
	if err != nil {
		return err
	}
	s, err = DecodeServeCertificate(raw)
	if err != nil {
		return err
	}
	if e := s.Verify(c); e != nil {
		return e
	}
	return w.CommitAt(before, s.Decision)
}
