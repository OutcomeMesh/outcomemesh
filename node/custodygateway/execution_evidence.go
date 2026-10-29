//go:build linux || darwin

package custodygateway

import (
	"bytes"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

// Reading is not resumption. A partial intent never creates a missing receipt.
// The enclosing runtime request still needs the current owner/guard cursor and
// produces its ordinary authenticated response. Original receipt bytes and times
// are returned unchanged; they do not assert current source state.
func (o *Owner) readProtectedEvidence(p v2.ProtectedCommand, c v2.Context, sid types.Hash) ([]byte, error) {
	if !v2.ProtectedEvidenceRead(p.Kind) || len(p.Data) != 0 {
		return nil, ErrExecution
	}
	admission, e := o.jobRead(sid, "admission", wire.MaximumRuntimePayloadBytes)
	if e != nil {
		return nil, e
	}
	want, e := p.Admission.CanonicalBytes()
	if e != nil || !bytes.Equal(admission, want) {
		return nil, ErrExecution
	}
	switch p.Kind {
	case v2.ProtectedReadResult:
		if o.config.Source.Role != cut.Target {
			return nil, ErrExecution
		}
		r, e := o.readExecutionResult(c, sid)
		if e != nil {
			return nil, e
		}
		if e = o.checkResultAdmission(p.Admission, r); e != nil {
			return nil, e
		}
		return r.CanonicalBytes()
	case v2.ProtectedReadAcceptance:
		if o.config.Source.Role == cut.Target {
			return nil, ErrExecution
		}
		raw, e := o.jobRead(sid, "accepted", v2.MaximumProtectedReceiptBytes)
		if e != nil {
			return nil, e
		}
		pending, e := o.jobRead(sid, "pending", wire.MaximumRuntimePayloadBytes)
		if e != nil {
			return nil, e
		}
		b, consent, at, e := decodeAcceptancePending(pending)
		if e != nil || o.checkResultAdmission(p.Admission, b.Result) != nil {
			return nil, ErrExecution
		}
		r, e := v2.DecodeReceipt(raw)
		if e != nil || r.AcceptedAt != at || !sameConsent(r.RetainedAcceptance, consent) || r.Verify(c, b) != nil || o.checkEffectAdmission(p.Admission, r.Protection) != nil {
			return nil, ErrExecution
		}
		return raw, nil
	case v2.ProtectedReadServe:
		raw, e := o.jobRead(sid, "serve.settled", v2.MaximumProtectedServeReceiptBytes)
		if e != nil {
			return nil, e
		}
		pending, e := o.jobRead(sid, "serve.pending", wire.MaximumRuntimePayloadBytes)
		if e != nil {
			return nil, e
		}
		d := codec.NewDecoder(pending)
		at, e := d.U64()
		data, e2 := d.BytesField(wire.MaximumRuntimePayloadBytes)
		if e != nil || e2 != nil || at == 0 || d.Finish() != nil {
			return nil, ErrExecution
		}
		cert, parent, e := decodeExecutionServe(data)
		if e != nil {
			return nil, e
		}
		role := uint8(v2.ServeAuthority)
		if o.config.Source.Role == cut.Target {
			role = v2.ServeTarget
		}
		r, e := v2.DecodeServeReceipt(raw)
		if e != nil || r.AppliedAt != at || r.Verify(c, cert, role, parent) != nil || o.checkEffectAdmission(p.Admission, r.Protection) != nil {
			return nil, ErrExecution
		}
		return raw, nil
	}
	return nil, ErrExecution
}
