//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"errors"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"os"
)

func acceptanceData(p v2.ProtectedCommand) (v2.Bundle, *v2.RetainedAcceptance, error) {
	if p.Kind == v2.ProtectedAcceptRetained || p.Kind == v2.ProtectedResumeRetained {
		b, a, e := v2.DecodeRetainedAcceptanceData(p.Data)
		return b, &a, e
	}
	b, e := v2.DecodeBundle(p.Data)
	return b, nil, e
}
func sameConsent(a, b *v2.RetainedAcceptance) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func resumeAcceptance(kind uint8) bool {
	return kind == v2.ProtectedResumeAccept || kind == v2.ProtectedResumeRetained
}
func encodeAcceptancePending(b v2.Bundle, a *v2.RetainedAcceptance, at uint64) ([]byte, error) {
	if a == nil {
		return encodeExecutionPending(b, at)
	}
	raw, e := v2.EncodeRetainedAcceptance(b, *a)
	if e != nil || at == 0 {
		return nil, ErrExecution
	}
	out := codec.NewEncoder(len(raw) + 24)
	out.Fixed([]byte("OMCVRPN1"))
	out.U64(at)
	out.BytesField(raw)
	return out.Bytes(), nil
}
func decodeAcceptancePending(raw []byte) (v2.Bundle, *v2.RetainedAcceptance, uint64, error) {
	if len(raw) < 8 || string(raw[:8]) != "OMCVRPN1" {
		b, at, e := decodeExecutionPending(raw)
		return b, nil, at, e
	}
	d := codec.NewDecoder(raw)
	d.Fixed(8)
	at, e := d.U64()
	if e != nil || at == 0 {
		return v2.Bundle{}, nil, 0, ErrExecution
	}
	data, e := d.BytesField(wire.MaximumRuntimePayloadBytes)
	if e != nil || d.Finish() != nil {
		return v2.Bundle{}, nil, 0, ErrExecution
	}
	b, a, e := v2.DecodeRetainedAcceptanceData(data)
	if e != nil {
		return b, nil, 0, e
	}
	again, e := encodeAcceptancePending(b, &a, at)
	if e != nil || !bytes.Equal(raw, again) {
		return b, nil, 0, ErrExecution
	}
	return b, &a, at, nil
}
func (o *Owner) preflightAcceptance(p v2.ProtectedCommand, c v2.Context, sid types.Hash) error {
	b, a, e := acceptanceData(p)
	if e != nil || b.Verify(c) != nil || o.checkResultAdmission(p.Admission, b.Result) != nil {
		return ErrExecution
	}
	if raw, e := o.jobRead(sid, "accepted", v2.MaximumProtectedReceiptBytes); e == nil {
		r, e := v2.DecodeReceipt(raw)
		if e != nil || !sameConsent(r.RetainedAcceptance, a) || r.Verify(c, b) != nil {
			return ErrExecution
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	checked := p.Now
	if raw, e := o.jobRead(sid, "pending", wire.MaximumRuntimePayloadBytes); e == nil {
		prior, consent, at, e := decodeAcceptancePending(raw)
		if e != nil {
			return e
		}
		want, _ := b.ID()
		actual, _ := prior.ID()
		if want != actual || !sameConsent(a, consent) {
			return ErrExecution
		}
		checked = at
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else if resumeAcceptance(p.Kind) {
		return v2.ErrPending
	}
	if a != nil {
		return a.Verify(c, b, checked)
	}
	return workarchive.VerifyCustodyResponse(c.Manifest, c.Previous, c.Plan.Challenge, b.Result.Entry.Record.Batch, b.Result.Entry.Record.Proof, c.CustodyPolicy, checked)
}
