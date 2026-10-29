//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"context"
	"errors"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"os"
)

func EncodeExecutionServe(cert v2.ServeCertificate, parent *v2.ServeReceipt) ([]byte, error) {
	b, e := cert.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	var p []byte
	if parent != nil {
		p, e = parent.CanonicalBytes()
		if e != nil {
			return nil, e
		}
	}
	out := codec.NewEncoder(len(b) + len(p) + 32)
	out.BytesField(b)
	out.BytesField(p)
	return out.Bytes(), nil
}
func decodeExecutionServe(raw []byte) (v2.ServeCertificate, *v2.ServeReceipt, error) {
	var c v2.ServeCertificate
	d := codec.NewDecoder(raw)
	b, e := d.BytesField(v2.MaximumServeCertificateBytes)
	if e != nil {
		return c, nil, e
	}
	c, e = v2.DecodeServeCertificate(b)
	if e != nil {
		return c, nil, e
	}
	b, e = d.BytesField(v2.MaximumProtectedServeReceiptBytes)
	if e != nil || d.Finish() != nil {
		return c, nil, ErrExecution
	}
	if len(b) == 0 {
		return c, nil, nil
	}
	r, e := v2.DecodeServeReceipt(b)
	return c, &r, e
}
func (o *Owner) preflightExecutionServe(p v2.ProtectedCommand, c v2.Context, sid types.Hash) error {
	cert, parent, e := decodeExecutionServe(p.Data)
	if e != nil || cert.Verify(c) != nil {
		return ErrExecution
	}
	role := uint8(v2.ServeAuthority)
	if o.config.Source.Role == cut.Target {
		role = v2.ServeTarget
		if parent == nil || parent.Verify(c, cert, v2.ServeAuthority, nil) != nil {
			return ErrExecution
		}
	} else if parent != nil {
		return ErrExecution
	}
	if raw, e := o.jobRead(sid, "serve.settled", v2.MaximumProtectedServeReceiptBytes); e == nil {
		r, e := v2.DecodeServeReceipt(raw)
		if e != nil {
			return e
		}
		return r.Verify(c, cert, role, parent)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if raw, e := o.jobRead(sid, "serve.pending", wire.MaximumRuntimePayloadBytes); e == nil {
		d := codec.NewDecoder(raw)
		at, e := d.U64()
		prior, e2 := d.BytesField(wire.MaximumRuntimePayloadBytes)
		if e != nil || e2 != nil || d.Finish() != nil || at == 0 || !bytes.Equal(prior, p.Data) {
			return ErrExecution
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if cert.Proposal.Outcome == v2.ServeUnclaimed {
		if _, e = o.jobRead(sid, "consumed", 4096); e == nil {
			return ErrExecution
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return o.requireExecutionSource(c, false)
	}
	b, accepted, e := v2.ServeFulfilledEvidence(cert.Proposal)
	if e != nil || o.checkResultAdmission(p.Admission, b.Result) != nil {
		return ErrExecution
	}
	if role == v2.ServeTarget {
		r, e := o.readExecutionResult(c, sid)
		if e != nil {
			return e
		}
		want, _ := r.CanonicalBytes()
		got, _ := b.Result.CanonicalBytes()
		if !bytes.Equal(want, got) {
			return ErrExecution
		}
	} else {
		raw, e := o.jobRead(sid, "accepted", v2.MaximumProtectedReceiptBytes)
		if e != nil {
			return e
		}
		want, _ := accepted.CanonicalBytes()
		if !bytes.Equal(want, raw) {
			return ErrExecution
		}
	}
	if p.Now < accepted.AcceptedAt || parent != nil && p.Now < parent.AppliedAt {
		return ErrExecution
	}
	return o.requireExecutionSource(c, true)
}
func (o *Owner) applyExecutionServe(ctx context.Context, p v2.ProtectedCommand, c v2.Context, sid types.Hash) ([]byte, error) {
	if raw, e := o.jobRead(sid, "serve.settled", v2.MaximumProtectedServeReceiptBytes); e == nil {
		return raw, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	checked := p.Now
	if raw, e := o.jobRead(sid, "serve.pending", wire.MaximumRuntimePayloadBytes); e == nil {
		d := codec.NewDecoder(raw)
		checked, e = d.U64()
		if e != nil {
			return nil, e
		}
		prior, e := d.BytesField(wire.MaximumRuntimePayloadBytes)
		if e != nil || d.Finish() != nil || !bytes.Equal(prior, p.Data) {
			return nil, ErrExecution
		}
	} else if errors.Is(e, os.ErrNotExist) {
		d := codec.NewEncoder(len(p.Data) + 16)
		d.U64(checked)
		d.BytesField(p.Data)
		if e = o.jobWrite(sid, "serve.pending", d.Bytes()); e != nil {
			return nil, e
		}
	} else {
		return nil, e
	}
	cert, parent, e := decodeExecutionServe(p.Data)
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if _, e = cut.InspectSourceHandoff(ctx, o.g, o.b, o.config.Pins, o.config.Source); e != nil {
		return nil, e
	}
	if e = o.check(); e != nil {
		return nil, e
	}
	cid, _ := cert.ID()
	retain, e := cert.Proposal.Retention(c)
	if e != nil {
		return nil, e
	}
	head, seq := c.Plan.Intent.PriorHeadID, c.Plan.Intent.PriorSequence
	if cert.Proposal.Outcome == v2.ServeFulfilled {
		b, _, e := v2.ServeFulfilledEvidence(cert.Proposal)
		if e != nil {
			return nil, e
		}
		head, _ = b.Result.Entry.ID()
		seq = b.Result.Entry.Sequence
	}
	role, kind := uint8(v2.ServeAuthority), wire.EffectServeA
	key := o.execution.keys.Authority
	var pid types.Hash
	signer := c.Assignment.Base.AuthorityPublicKey
	if o.config.Source.Role == cut.Target {
		role = v2.ServeTarget
		kind = wire.EffectServeB
		key = o.execution.keys.Control
		signer = c.Assignment.Base.RemoteControlPublicKey
		if parent == nil {
			return nil, ErrExecution
		}
		pid, _ = parent.ID()
	}
	r, e := v2.SignServeApplication(v2.ServeReceipt{Version: v2.Version2, Role: role, ScopeID: sid, CertificateID: cid, SourceHeadID: head, ParentID: pid, SourceSequence: seq, MinimumRetainUntil: retain, AppliedAt: checked, Signer: signer}, key)
	if e != nil {
		return nil, e
	}
	id, _ := r.CoreID()
	ef, e := o.executionEffect(ctx, c, p.Admission, kind, id, head, seq, checked)
	if e != nil {
		return nil, e
	}
	r.Version = v2.ProtectedVersion
	r.Protection = &ef
	if e = r.Verify(c, cert, role, parent); e != nil {
		return nil, e
	}
	raw, e := r.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	if e = o.jobWrite(sid, "serve.settled", raw); e != nil {
		return nil, e
	}
	return raw, nil
}
