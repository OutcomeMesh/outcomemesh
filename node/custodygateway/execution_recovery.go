//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"context"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// readRetainedExecutionCore requires the original owner lock. The caller must
// also enforce the exact retained runtime request and current deployment. This
// path reads signed historical evidence; it never opens an execution session.
func (o *Owner) readRetainedExecutionCore(p v2.ProtectedCommand, c v2.Context, sid types.Hash) (v2.Result, error) {
	var zero v2.Result
	if p.Kind != v2.ProtectedExecute || o.execution == nil || o.execution.deployment.Guard == ([32]byte{}) || o.guard == nil {
		return zero, ErrExecution
	}
	raw, err := o.jobRead(sid, "core-result", v2.MaximumResultBytes)
	if err != nil {
		return zero, err
	}
	core, err := v2.DecodeResult(raw)
	if err != nil {
		return zero, err
	}
	consumed, err := o.jobRead(sid, "consumed", custodyfence.MaximumCertificateBytes)
	if err != nil || !bytes.Equal(consumed, p.Data) {
		return zero, ErrExecution
	}
	claim, err := custodyfence.DecodeCertificate(consumed)
	if err != nil || core.VerifyRetainedResultCore(c, claim) != nil {
		return zero, ErrExecution
	}
	admission, err := o.jobRead(sid, "admission", wire.MaximumRuntimePayloadBytes)
	want, we := p.Admission.CanonicalBytes()
	if err != nil || we != nil || !bytes.Equal(admission, want) {
		return zero, ErrExecution
	}
	candidateRaw, err := o.jobRead(sid, "candidate", 1024)
	if err != nil {
		return zero, err
	}
	candidate, err := v2.DecodeCandidate(candidateRaw)
	if err != nil || candidate.Verify(c) != nil || candidate.Claim != claim.Command || candidate.SessionPublicKey != core.SessionPublicKey {
		return zero, ErrExecution
	}
	entry, err := o.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes)
	want, we = core.Entry.CanonicalBytes()
	if err != nil || we != nil || !bytes.Equal(entry, want) {
		return zero, ErrExecution
	}
	source, err := o.currentExecutionSource()
	head, he := core.Entry.ID()
	if err != nil || he != nil || source.Sequence != core.Entry.Sequence || source.Head != head || source.Receipt != core.Entry.Record.RenewedReceipt {
		return zero, ErrExecution
	}
	return core, nil
}

func (o *Owner) recoverExecutionCore(ctx context.Context, p v2.ProtectedCommand, c v2.Context, sid types.Hash) ([]byte, error) {
	core, err := o.readRetainedExecutionCore(p, c, sid)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = o.check(); err != nil {
		return nil, err
	}
	if o.executionHook != nil {
		if err = o.executionHook("retained-core-before-seal"); err != nil {
			return nil, err
		}
	}
	// Repeat the binding/source read after any intervening owner check. The
	// signature and original RespondedAt are preserved, including after expiry.
	checked, err := o.readRetainedExecutionCore(p, c, sid)
	if err != nil {
		return nil, err
	}
	want, _ := core.CoreID()
	got, _ := checked.CoreID()
	if want != got {
		return nil, ErrExecution
	}
	claim, err := custodyfence.DecodeCertificate(p.Data)
	if err != nil {
		return nil, err
	}
	return o.publishExecutionResult(ctx, p, c, sid, claim, checked)
}
