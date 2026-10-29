//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func (o *Owner) runProtected(ctx context.Context, q wire.Request, payload []byte) ([]byte, error) {
	cmd, e := v2.DecodeProtectedCommand(payload)
	if e != nil {
		return nil, e
	}
	cmd.Now = uint64(time.Now().Unix())
	if o.clock != nil {
		cmd.Now = o.clock()
	}
	if e = o.preflightProtected(ctx, cmd); e != nil {
		return nil, e
	}
	usage, e := o.executionUsage()
	if e != nil || usage+len(payload)+4*maximumExecutionProofBytes > MaximumExecutionStoreBytes {
		return nil, ErrExecution
	}
	if e = o.retainRuntimeIntent(q, payload); e != nil {
		return nil, e
	}
	if cmd.Kind == v2.ProtectedEndorse {
		return o.endorse(ctx, cmd.Data)
	}
	c, e := v2.ProtectedContextOf(cmd.Admission)
	if e != nil {
		return nil, e
	}
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	if e = o.retainJob(sid, cmd.Admission); e != nil {
		return nil, e
	}
	switch cmd.Kind {
	case v2.ProtectedPrepare:
		return o.prepareExecution(c, sid)
	case v2.ProtectedExecute:
		return o.executeJob(ctx, cmd, c, sid)
	case v2.ProtectedResultCommand:
		return o.resultCommand(cmd, c, sid)
	case v2.ProtectedAccept, v2.ProtectedResumeAccept:
		return o.acceptJob(ctx, cmd, c, sid)
	case v2.ProtectedServe:
		return o.applyExecutionServe(ctx, cmd, c, sid)
	case v2.ProtectedReadResult:
		r, e := o.readExecutionResult(c, sid)
		if e != nil {
			return nil, e
		}
		return r.CanonicalBytes()
	}
	return nil, ErrExecution
}
func (o *Owner) preflightProtected(ctx context.Context, p v2.ProtectedCommand) error {
	if p.Kind == v2.ProtectedEndorse {
		d, pair, e := decodeEndorsement(p.Data)
		if e != nil {
			return e
		}
		if e = o.verifyDeployment(d, pair); e != nil {
			return e
		}
		if d.IssuerSignature == ([64]byte{}) || d.AuthoritySignature == ([64]byte{}) || d.ControlSignature == ([64]byte{}) {
			return ErrExecution
		}
		id, _ := d.ID()
		if prior, e := privateRead(filepath.Join(o.root, "deployment-choice"), 32); e == nil {
			if !bytes.Equal(prior, id[:]) {
				return ErrExecution
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return nil
	}
	if o.execution == nil || (o.execution.deployment.Guard != ([32]byte{}) && o.guard == nil) {
		return ErrExecution
	}
	if e := v2.VerifyProtectedBinding(p.Admission, o.b, o.execution.deployment); e != nil {
		return e
	}
	c, e := v2.ProtectedContextOf(p.Admission)
	if e != nil {
		return e
	}
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	// A strict first release bounds proof work before consumption or any object
	// read. Full-size native profiles retain their existing independent limits.
	var bytes uint64
	for _, chunk := range c.Manifest.Chunks {
		bytes += uint64(chunk.EncodedBytes)
		if bytes > maximumExecutionProofBytes {
			return ErrExecution
		}
	}
	if p.Kind != v2.ProtectedServe {
		if _, e = o.jobRead(sid, "serve.pending", wire.MaximumRuntimePayloadBytes); e == nil {
			return v2.ErrServeClosed
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if _, e = o.jobRead(sid, "serve.settled", v2.MaximumProtectedServeReceiptBytes); e == nil {
			return v2.ErrServeClosed
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	target := p.Kind == v2.ProtectedPrepare || p.Kind == v2.ProtectedExecute || p.Kind == v2.ProtectedResultCommand || p.Kind == v2.ProtectedReadResult
	if p.Kind != v2.ProtectedServe && (target != (o.config.Source.Role == cut.Target)) {
		return ErrExecution
	}
	if e = o.requireExecutionSource(c, p.Kind != v2.ProtectedPrepare); e != nil {
		return e
	}
	switch p.Kind {
	case v2.ProtectedPrepare:
		if len(p.Data) != 0 {
			return ErrExecution
		}
		if _, e = o.jobRead(sid, "consumed", custodyfence.MaximumCertificateBytes); e == nil {
			return v2.ErrConsumed
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	case v2.ProtectedExecute:
		claim, e := custodyfence.DecodeCertificate(p.Data)
		if e != nil {
			return e
		}
		if e = claim.Verify(scope); e != nil {
			return e
		}
		if raw, e := o.jobRead(sid, "result", v2.MaximumResultBytes); e == nil {
			r, e := v2.DecodeResult(raw)
			if e != nil || r.Verify(c, claim) != nil {
				return ErrExecution
			}
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if _, e = o.jobRead(sid, "consumed", custodyfence.MaximumCertificateBytes); e == nil {
			return v2.ErrConsumed
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		live := o.execution.sessions[sid]
		if live == nil || len(live.key) != 64 || live.candidate.Claim != claim.Command || claim.Command.Kind != custodyfence.Claim {
			return v2.ErrSession
		}
		return c.Plan.Challenge.Verify(c.Manifest, c.Previous, c.CustodyPolicy, p.Now)
	case v2.ProtectedResultCommand:
		prefix, e := v2.DecodeProtectedPrefix(p.Data)
		if e != nil {
			return e
		}
		r, e := o.readExecutionResult(c, sid)
		if e != nil {
			return e
		}
		_, e = o.makeResultCommand(c, r, prefix)
		return e
	case v2.ProtectedReadResult:
		if len(p.Data) != 0 {
			return ErrExecution
		}
		_, e = o.readExecutionResult(c, sid)
		return e
	case v2.ProtectedAccept, v2.ProtectedResumeAccept:
		b, e := v2.DecodeBundle(p.Data)
		if e != nil || b.Verify(c) != nil {
			return ErrExecution
		}
		if e = o.checkResultAdmission(p.Admission, b.Result); e != nil {
			return e
		}
		if raw, e := o.jobRead(sid, "accepted", v2.MaximumProtectedReceiptBytes); e == nil {
			r, e := v2.DecodeReceipt(raw)
			if e != nil || r.Verify(c, b) != nil {
				return ErrExecution
			}
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if p.Kind == v2.ProtectedResumeAccept {
			raw, e := o.jobRead(sid, "pending", wire.MaximumRuntimePayloadBytes)
			if e != nil {
				return e
			}
			prior, _, e := decodeExecutionPending(raw)
			if e != nil {
				return e
			}
			want, _ := b.ID()
			actual, _ := prior.ID()
			if want != actual {
				return ErrExecution
			}
		}
		return workarchive.VerifyCustodyResponse(c.Manifest, c.Previous, c.Plan.Challenge, b.Result.Entry.Record.Batch, b.Result.Entry.Record.Proof, c.CustodyPolicy, p.Now)
	case v2.ProtectedServe:
		return o.preflightExecutionServe(p, c, sid)
	default:
		return ErrExecution
	}
	return ctx.Err()
}
func (o *Owner) prepareExecution(c v2.Context, sid types.Hash) ([]byte, error) {
	if raw, e := o.jobRead(sid, "candidate", 1024); e == nil {
		return raw, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	var session [32]byte
	copy(session[:], pub)
	claim, e := (custodyfence.Command{Version: custodyfence.Version1, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.Claim, EvidenceID: v2.SessionID(session)}).Sign(o.execution.keys.Control)
	if e != nil {
		clear(key)
		return nil, e
	}
	candidate := v2.Candidate{Version: v2.Version2, SessionPublicKey: session, Claim: claim}
	raw, e := candidate.CanonicalBytes()
	if e != nil {
		clear(key)
		return nil, e
	}
	if e = o.jobWrite(sid, "candidate", raw); e != nil {
		clear(key)
		return nil, e
	}
	o.execution.sessions[sid] = &liveExecution{key, candidate}
	return raw, nil
}
func (o *Owner) executionEffect(ctx context.Context, c v2.Context, b v2.AdmissionBinding, kind uint8, artifact, head types.Hash, seq, at uint64) (wire.Effect, error) {
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	did, _ := o.execution.deployment.ID()
	bid, e := b.ID()
	if e != nil {
		return wire.Effect{}, e
	}
	aid, e := v2.AdmissionEntryID(b)
	if e != nil {
		return wire.Effect{}, e
	}
	ef, e := (wire.Effect{Kind: kind, DeploymentID: did, ScopeID: sid, AdmissionID: aid, BindingID: bid, ArtifactID: artifact, SourceSequence: seq, SourceHead: head, CheckedAt: at}).Sign(o.key)
	if e != nil {
		return wire.Effect{}, e
	}
	if key := o.execution.deployment.Guard; key != ([32]byte{}) {
		q, e := ef.GuardRequest()
		if e != nil {
			return wire.Effect{}, e
		}
		ef.GuardSeal, e = guard.Obtain(ctx, o.guard, key, q, o.key)
		if e != nil {
			return wire.Effect{}, e
		}
	}
	return ef, nil
}
func (o *Owner) checkResultAdmission(b v2.AdmissionBinding, r v2.Result) error {
	bid, _ := b.ID()
	aid, _ := v2.AdmissionEntryID(b)
	if r.Protection == nil || r.Protection.BindingID != bid || r.Protection.AdmissionID != aid {
		return ErrExecution
	}
	return nil
}
func (o *Owner) executeJob(ctx context.Context, p v2.ProtectedCommand, c v2.Context, sid types.Hash) ([]byte, error) {
	if raw, e := o.jobRead(sid, "result", v2.MaximumResultBytes); e == nil {
		return raw, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	claim, e := custodyfence.DecodeCertificate(p.Data)
	if e != nil {
		return nil, e
	}
	live := o.execution.sessions[sid]
	if live == nil || len(live.key) != 64 {
		return nil, v2.ErrSession
	}
	if _, e = o.jobRead(sid, "consumed", custodyfence.MaximumCertificateBytes); e == nil {
		return nil, v2.ErrConsumed
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if e = o.jobWrite(sid, "consumed", p.Data); e != nil {
		return nil, e
	}
	defer clear(live.key)
	if o.executionHook != nil {
		if e = o.executionHook("consumed-before-read"); e != nil {
			return nil, e
		}
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = o.check(); e != nil {
		return nil, e
	}
	record, e := cut.AnswerSourceHandoffChallenge(ctx, o.g, o.b, o.config.Pins, o.config.Source, o.config.Objects, c.Previous, c.Plan.Challenge, o.execution.keys.Replica, p.Now)
	if e != nil {
		return nil, e
	}
	entry := workarchive.CustodyJournalEntry{Version: workarchive.CustodyJournalEntryVersion0, Sequence: c.Plan.Intent.PriorSequence + 1, PreviousEntryID: c.Plan.Intent.PriorHeadID, PreviousReceipt: c.Previous, Record: record}
	if e = entry.Verify(c.Manifest, c.CustodyPolicy, entry.Sequence, entry.PreviousEntryID, c.Previous); e != nil {
		return nil, e
	}
	raw, _ := entry.CanonicalBytes()
	if e = o.jobWrite(sid, "entry", raw); e != nil {
		return nil, e
	}
	if o.executionHook != nil {
		if e = o.executionHook("source-before-result"); e != nil {
			return nil, e
		}
	}
	cid, _ := claim.Command.ID()
	result, e := v2.SignResultSession(v2.Result{Version: v2.Version2, ScopeID: sid, ClaimID: cid, SessionPublicKey: live.candidate.SessionPublicKey, Entry: entry}, live.key)
	if e != nil {
		return nil, e
	}
	raw, e = result.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	if e = o.jobWrite(sid, "core-result", raw); e != nil {
		return nil, e
	}
	id, _ := result.CoreID()
	head, _ := entry.ID()
	effect, e := o.executionEffect(ctx, c, p.Admission, wire.EffectExecute, id, head, entry.Sequence, record.Proof.RespondedAt)
	if e != nil {
		return nil, e
	}
	result.Version = v2.ProtectedVersion
	result.Protection = &effect
	if e = result.Verify(c, claim); e != nil {
		return nil, e
	}
	raw, e = result.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	if e = o.jobWrite(sid, "result", raw); e != nil {
		return nil, e
	}
	return raw, nil
}
func (o *Owner) readExecutionResult(c v2.Context, sid types.Hash) (v2.Result, error) {
	raw, e := o.jobRead(sid, "result", v2.MaximumResultBytes)
	if e != nil {
		return v2.Result{}, e
	}
	r, e := v2.DecodeResult(raw)
	if e != nil {
		return r, e
	}
	raw, e = o.jobRead(sid, "consumed", custodyfence.MaximumCertificateBytes)
	if e != nil {
		return r, e
	}
	q, e := custodyfence.DecodeCertificate(raw)
	if e != nil {
		return r, e
	}
	return r, r.Verify(c, q)
}
func (o *Owner) makeResultCommand(c v2.Context, r v2.Result, prefix []custodyfence.Certificate) (custodyfence.Command, error) {
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	state, e := custodyfence.NewState(scope, sid)
	if e != nil {
		return custodyfence.Command{}, e
	}
	for _, q := range prefix {
		if e = state.Apply(q); e != nil {
			return custodyfence.Command{}, e
		}
	}
	s := state.Snapshot()
	if (s.Phase != custodyfence.Claimed && s.Phase != custodyfence.Unknown) || s.ClaimID != r.ClaimID || s.SessionID != v2.SessionID(r.SessionPublicKey) {
		return custodyfence.Command{}, ErrExecution
	}
	id, _ := r.ID()
	return (custodyfence.Command{Version: custodyfence.Version1, ScopeID: sid, ExpectedSequence: s.Position.Sequence, ExpectedHead: s.Position.HeadID, Kind: custodyfence.RecordResult, ClaimID: r.ClaimID, EvidenceID: id}).Sign(o.execution.keys.Control)
}
func (o *Owner) resultCommand(p v2.ProtectedCommand, c v2.Context, sid types.Hash) ([]byte, error) {
	r, e := o.readExecutionResult(c, sid)
	if e != nil {
		return nil, e
	}
	prefix, e := v2.DecodeProtectedPrefix(p.Data)
	if e != nil {
		return nil, e
	}
	cmd, e := o.makeResultCommand(c, r, prefix)
	if e != nil {
		return nil, e
	}
	return cmd.CanonicalBytes()
}
func encodeExecutionPending(b v2.Bundle, at uint64) ([]byte, error) {
	raw, e := b.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	out := codec.NewEncoder(len(raw) + 16)
	out.U64(at)
	out.BytesField(raw)
	return out.Bytes(), nil
}
func decodeExecutionPending(raw []byte) (v2.Bundle, uint64, error) {
	d := codec.NewDecoder(raw)
	at, e := d.U64()
	if e != nil || at == 0 {
		return v2.Bundle{}, 0, ErrExecution
	}
	b, e := d.BytesField(v2.MaximumBundleBytes)
	if e != nil || d.Finish() != nil {
		return v2.Bundle{}, 0, ErrExecution
	}
	bundle, e := v2.DecodeBundle(b)
	return bundle, at, e
}
func (o *Owner) acceptJob(ctx context.Context, p v2.ProtectedCommand, c v2.Context, sid types.Hash) ([]byte, error) {
	if raw, e := o.jobRead(sid, "accepted", v2.MaximumProtectedReceiptBytes); e == nil {
		return raw, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	b, e := v2.DecodeBundle(p.Data)
	if e != nil {
		return nil, e
	}
	checked := p.Now
	if raw, e := o.jobRead(sid, "pending", wire.MaximumRuntimePayloadBytes); e == nil {
		prior, at, e := decodeExecutionPending(raw)
		if e != nil {
			return nil, e
		}
		pid, _ := prior.ID()
		bid, _ := b.ID()
		if pid != bid {
			return nil, ErrExecution
		}
		checked = at
	} else if errors.Is(e, os.ErrNotExist) {
		if p.Kind == v2.ProtectedResumeAccept {
			return nil, ErrExecution
		}
		raw, e := encodeExecutionPending(b, checked)
		if e != nil {
			return nil, e
		}
		if e = o.jobWrite(sid, "pending", raw); e != nil {
			return nil, e
		}
	} else {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if _, e = cut.InspectSourceHandoff(ctx, o.g, o.b, o.config.Pins, o.config.Source); e != nil {
		return nil, e
	}
	raw, e := b.Result.Entry.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	if e = o.jobWrite(sid, "entry", raw); e != nil {
		return nil, e
	}
	if o.executionHook != nil {
		if e = o.executionHook("accepted-source-before-receipt"); e != nil {
			return nil, e
		}
	}
	if e = o.check(); e != nil {
		return nil, e
	}
	if _, e = cut.InspectSourceHandoff(ctx, o.g, o.b, o.config.Pins, o.config.Source); e != nil {
		return nil, e
	}
	aid, _ := c.Assignment.ID()
	pid, _ := c.Plan.ID()
	rid, _ := b.Result.ID()
	bid, _ := b.ID()
	head, _ := b.Result.Entry.ID()
	r, e := v2.SignAcceptance(v2.Receipt{Version: v2.Version2, AssignmentID: aid, PlanID: pid, ScopeID: sid, ResultID: rid, BundleID: bid, SourceHeadID: head, SourceSequence: b.Result.Entry.Sequence, AcceptedAt: checked, Authority: c.Assignment.Base.AuthorityPublicKey}, o.execution.keys.Authority)
	if e != nil {
		return nil, e
	}
	id, _ := r.CoreID()
	ef, e := o.executionEffect(ctx, c, p.Admission, wire.EffectAccept, id, head, r.SourceSequence, checked)
	if e != nil {
		return nil, e
	}
	r.Version = v2.ProtectedVersion
	r.Protection = &ef
	if e = r.Verify(c, b); e != nil {
		return nil, e
	}
	raw, e = r.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	if e = o.jobWrite(sid, "accepted", raw); e != nil {
		return nil, e
	}
	return raw, nil
}
