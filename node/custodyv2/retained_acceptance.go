package custodyv2

import (
	"bytes"
	"crypto/ed25519"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const RetainedAcceptanceBytes = 8 + 3*32 + 16 + 128
const MaximumRetainedAcceptanceWindow = 24 * 60 * 60

// RetainedAcceptance is explicit consent to accept one already completed,
// quorum-certified result after delivery delay. It cannot authorize execution,
// assert absence, extend archive retention, refund spend, or replace a source.
// EvidenceID names the operator's incident inventory; it is not a work proof.
type RetainedAcceptance struct {
	ContextID, BundleID, EvidenceID       types.Hash
	NotBefore, NotAfter                   uint64
	AuthoritySignature, ConsumerSignature [64]byte
}

func (a RetainedAcceptance) unsignedBytes() ([]byte, error) {
	if a.ContextID.IsZero() || a.BundleID.IsZero() || a.EvidenceID.IsZero() || a.NotBefore == 0 || a.NotAfter < a.NotBefore || a.NotAfter-a.NotBefore > MaximumRetainedAcceptanceWindow {
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(RetainedAcceptanceBytes)
	e.Fixed([]byte("OMCVRAC1"))
	for _, h := range []types.Hash{a.ContextID, a.BundleID, a.EvidenceID} {
		e.Fixed(h[:])
	}
	e.U64(a.NotBefore)
	e.U64(a.NotAfter)
	return e.Bytes(), nil
}
func (a RetainedAcceptance) CanonicalBytes() ([]byte, error) {
	b, e := a.unsignedBytes()
	if e != nil {
		return nil, e
	}
	b = append(b, a.AuthoritySignature[:]...)
	return append(b, a.ConsumerSignature[:]...), nil
}
func DecodeRetainedAcceptance(b []byte) (RetainedAcceptance, error) {
	var a RetainedAcceptance
	if len(b) != RetainedAcceptanceBytes {
		return a, ErrProtocol
	}
	d := codec.NewDecoder(b)
	if !magic(d, "OMCVRAC1") {
		return a, ErrProtocol
	}
	for _, h := range [][]byte{a.ContextID[:], a.BundleID[:], a.EvidenceID[:]} {
		fixed(d, h)
	}
	a.NotBefore, _ = d.U64()
	a.NotAfter, _ = d.U64()
	fixed(d, a.AuthoritySignature[:])
	fixed(d, a.ConsumerSignature[:])
	raw, e := a.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(b, raw) {
		return RetainedAcceptance{}, ErrProtocol
	}
	return a, nil
}
func (a RetainedAcceptance) validate(c Context, b Bundle) error {
	if !ProtectedContext(c) || c.Plan.Deployment.Guard == ([32]byte{}) || b.Verify(c) != nil {
		return ErrProtocol
	}
	cid, e := c.ID()
	bid, e2 := b.ID()
	if e != nil || e2 != nil || cid != a.ContextID || bid != a.BundleID {
		return ErrProtocol
	}
	_, e = a.unsignedBytes()
	return e
}
func (a RetainedAcceptance) Sign(c Context, b Bundle, role string, key ed25519.PrivateKey) (RetainedAcceptance, error) {
	if a.validate(c, b) != nil {
		return RetainedAcceptance{}, ErrProtocol
	}
	public := c.Assignment.Base.AuthorityPublicKey
	sig := &a.AuthoritySignature
	if role == "consumer" {
		public = c.Plan.ServeConsumer
		sig = &a.ConsumerSignature
	} else if role != "authority" {
		return RetainedAcceptance{}, ErrProtocol
	}
	if !matches(key, public) {
		return RetainedAcceptance{}, ErrProtocol
	}
	raw, _ := a.unsignedBytes()
	h := types.DomainHash("OMESH/custody/v5/retained-acceptance/"+role, raw)
	copy(sig[:], ed25519.Sign(key, h[:]))
	return a, nil
}
func (a RetainedAcceptance) Verify(c Context, b Bundle, at uint64) error {
	if a.validate(c, b) != nil || at < a.NotBefore || at > a.NotAfter || at < b.Result.Entry.Record.Proof.RespondedAt {
		return ErrProtocol
	}
	// Consent covers delivery age only. The result must have been valid when
	// executed, and its archive retention must still cover the acceptance time.
	if fresh(c, b.Result, b.Result.Entry.Record.Proof.RespondedAt) != nil || at > b.Result.Entry.Record.RenewedReceipt.RetainUntil {
		return ErrProtocol
	}
	raw, _ := a.unsignedBytes()
	for _, r := range []struct {
		role   string
		public [32]byte
		sig    [64]byte
	}{{"authority", c.Assignment.Base.AuthorityPublicKey, a.AuthoritySignature}, {"consumer", c.Plan.ServeConsumer, a.ConsumerSignature}} {
		h := types.DomainHash("OMESH/custody/v5/retained-acceptance/"+r.role, raw)
		if !ed25519.Verify(r.public[:], h[:], r.sig[:]) {
			return ErrProtocol
		}
	}
	return nil
}
func EncodeRetainedAcceptance(b Bundle, a RetainedAcceptance) ([]byte, error) {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	consent, e := a.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(raw) + len(consent) + 16)
	out.Fixed([]byte("OMCVRAD1"))
	out.BytesField(raw)
	out.Fixed(consent)
	return out.Bytes(), nil
}
func DecodeRetainedAcceptanceData(raw []byte) (Bundle, RetainedAcceptance, error) {
	var b Bundle
	var a RetainedAcceptance
	if len(raw) > MaximumBundleBytes+RetainedAcceptanceBytes+16 {
		return b, a, ErrProtocol
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVRAD1") {
		return b, a, ErrProtocol
	}
	bb, e := d.BytesField(MaximumBundleBytes)
	if e != nil {
		return b, a, e
	}
	ab, e := d.Fixed(RetainedAcceptanceBytes)
	if e != nil || d.Finish() != nil {
		return b, a, ErrProtocol
	}
	b, e = DecodeBundle(bb)
	if e != nil {
		return b, a, e
	}
	a, e = DecodeRetainedAcceptance(ab)
	return b, a, e
}
