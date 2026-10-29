//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"fmt"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	fixture "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"sort"
	"testing"
)

func retainedFixture(t testing.TB) (*protectedFixture, v2.Bundle, v2.RetainedAcceptance, uint64) {
	t.Helper()
	x := newProtectedFixture(t, true, true, true)
	claim := x.claim(t)
	raw, _ := claim.CanonicalBytes()
	resultRaw := mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "execute")
	r, e := v2.DecodeResult(resultRaw)
	fixture.Require(t, e)
	b := x.recordBundle(t, claim, r)
	at := r.Entry.Record.Proof.RespondedAt + x.c.CustodyPolicy.MaximumProofAge + 1
	cid, _ := x.c.ID()
	bid, _ := b.ID()
	a := v2.RetainedAcceptance{ContextID: cid, BundleID: bid, EvidenceID: f.Hash("inventory"), NotBefore: at, NotAfter: at + 60}
	a, e = a.Sign(x.c, b, "authority", f.Key(101))
	fixture.Require(t, e)
	a, e = a.Sign(x.c, b, "consumer", f.Key(4))
	fixture.Require(t, e)
	fixture.Require(t, a.Verify(x.c, b, at))
	x.a.clock = func() uint64 { return at }
	x.b.clock = func() uint64 { return at }
	return x, b, a, at
}
func TestProtectedRetainedAcceptanceConsentAndClosure(t *testing.T) {
	x, b, a, at := retainedFixture(t)
	assertUnavailableEvidence(t, x)
	raw, _ := b.CanonicalBytes()
	before, _ := x.a.Position()
	if _, _, _, e := protectedCall(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAccept, Admission: x.binding, Data: raw, Now: 1}, "ordinary-expired"); e == nil {
		t.Fatal("ordinary age bypass")
	}
	for _, bad := range []v2.RetainedAcceptance{func() v2.RetainedAcceptance { v := a; v.ConsumerSignature = [64]byte{}; return v }(), func() v2.RetainedAcceptance { v := a; v.BundleID = f.Hash("foreign"); return v }(), func() v2.RetainedAcceptance { v := a; v.NotAfter = at - 1; return v }()} {
		data, e := v2.EncodeRetainedAcceptance(b, bad)
		if e != nil {
			continue
		}
		if _, _, _, e = protectedCall(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAcceptRetained, Admission: x.binding, Data: data, Now: 1}, "bad-consent"); e == nil {
			t.Fatal("bad consent")
		}
	}
	if after, _ := x.a.Position(); after != before {
		t.Fatal("invalid consent consumed position")
	}
	data, e := v2.EncodeRetainedAcceptance(b, a)
	fixture.Require(t, e)
	raw = mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAcceptRetained, Admission: x.binding, Data: data, Now: 1}, "retained")
	r, e := v2.DecodeReceipt(raw)
	fixture.Require(t, e)
	fixture.Require(t, r.Verify(x.c, b))
	if r.AcceptedAt != at || r.RetainedAcceptance == nil {
		t.Fatal("acceptance time/consent lost")
	}
	stripped := r
	stripped.RetainedAcceptance = nil
	if stripped.Verify(x.c, b) == nil {
		t.Fatal("consent stripping")
	}
	changed := a
	changed.EvidenceID = f.Hash("different inventory")
	r.RetainedAcceptance = &changed
	if r.Verify(x.c, b) == nil {
		t.Fatal("unsealed consent")
	}
	r.RetainedAcceptance = &a
	p, e := v2.NewServeFulfilled(x.c, b, r)
	fixture.Require(t, e)
	for _, role := range []string{"authority", "consumer"} {
		seed := byte(101)
		if role == "consumer" {
			seed = 4
		}
		p, e = p.Sign(x.c, role, f.Key(seed))
		fixture.Require(t, e)
	}
	cmd, e := p.Decision(x.c, f.Key(101))
	fixture.Require(t, e)
	scope, e := x.c.ServeScope()
	fixture.Require(t, e)
	q := custodyfence.Certificate{Version: scope.Version, Command: cmd}
	sid, _ := scope.ID()
	for _, seed := range []byte{70, 71, 72} {
		w, e := custodyfence.Create(fmt.Sprintf("%s/retained-serve-%d", x.source.Root, seed), scope, sid, f.Key(seed))
		fixture.Require(t, e)
		w.SetGuard(x.guard)
		v, e := w.Vote(cmd)
		fixture.Require(t, e)
		q.Votes = append(q.Votes, v)
		w.Close()
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	cert := v2.ServeCertificate{Version: 2, Proposal: p, Decision: q}
	fixture.Require(t, cert.Verify(x.c))
	data, e = EncodeExecutionServe(cert, nil)
	fixture.Require(t, e)
	araw := mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.binding, Data: data, Now: 1}, "serve-a")
	ar, e := v2.DecodeServeReceipt(araw)
	fixture.Require(t, e)
	data, e = EncodeExecutionServe(cert, &ar)
	fixture.Require(t, e)
	braw := mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.binding, Data: data, Now: 1}, "serve-b")
	br, e := v2.DecodeServeReceipt(braw)
	fixture.Require(t, e)
	closure := v2.AdmissionClosure{Serve: cert, A: ar, B: br}
	fixture.Require(t, closure.Verify(x.c))
	x.account(t, v2.AdmissionClose, &closure)
	s := x.state.Snapshot()
	if s.PendingOperations != 0 || s.SpentOperations != 2 || s.SourceSequence != 1 || s.RetainUntil < x.dep.MinimumRetainUntil {
		t.Fatal("accounting reset", s)
	}
	assertRecoveredEvidence(t, x, b, raw, araw, braw)
}
func TestProtectedRetainedAcceptanceCrashKeepsOriginalTime(t *testing.T) {
	x, b, a, at := retainedFixture(t)
	data, e := v2.EncodeRetainedAcceptance(b, a)
	fixture.Require(t, e)
	x.a.executionHook = func(stage string) error {
		if stage == "accepted-source-before-receipt" {
			return fmt.Errorf("cut")
		}
		return nil
	}
	_, q, payload, e := protectedCall(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAcceptRetained, Admission: x.binding, Data: data, Now: 1}, "cut")
	if e == nil {
		t.Fatal("fault ignored")
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	if _, err := x.a.readProtectedEvidence(v2.ProtectedCommand{Kind: v2.ProtectedReadAcceptance, Admission: x.binding}, x.c, sid); err == nil {
		t.Fatal("pending became acceptance")
	}
	before, _ := x.a.Position()
	x.a.Close()
	did, _ := x.ad.ID()
	x.a, e = Open(x.aroot, did, before, &q)
	fixture.Require(t, e)
	x.a.SetGuard(x.guard)
	x.a.clock = func() uint64 { return a.NotAfter + 10 }
	raw, e := x.a.ExecuteRuntime(t.Context(), q, payload)
	fixture.Require(t, e)
	reply, e := wire.DecodeResponse(raw)
	fixture.Require(t, e)
	r, e := v2.DecodeReceipt(reply.Data)
	fixture.Require(t, e)
	fixture.Require(t, r.Verify(x.c, b))
	if r.AcceptedAt != at {
		t.Fatal("refreshed time")
	}
}
func FuzzRetainedPending(fz *testing.F) {
	fz.Add([]byte("OMCVRPN1"))
	fz.Fuzz(func(t *testing.T, raw []byte) {
		if b, a, at, e := decodeAcceptancePending(raw); e == nil {
			again, e := encodeAcceptancePending(b, a, at)
			if e != nil || !bytes.Equal(raw, again) {
				t.Fatal("noncanonical")
			}
		}
	})
}

func TestRetainedConsentCannotCloseUnknownOrExpiredAuthorization(t *testing.T) {
	x, b, a, at := retainedFixture(t)
	incomplete := b
	incomplete.Chain = incomplete.Chain[:1]
	if a.Verify(x.c, incomplete, at) == nil {
		t.Fatal("missing result quorum accepted")
	}
	unguarded := x.c
	deployment := *x.c.Plan.Deployment
	deployment.Guard = [32]byte{}
	unguarded.Plan.Deployment = &deployment
	if a.Verify(unguarded, b, at) == nil {
		t.Fatal("unguarded consent accepted")
	}
	for _, when := range []uint64{a.NotBefore - 1, a.NotAfter + 1, b.Result.Entry.Record.RenewedReceipt.RetainUntil + 1} {
		if a.Verify(x.c, b, when) == nil {
			t.Fatal("time boundary", when)
		}
	}
	a.NotBefore = at - 60
	a.NotAfter = at - 1
	var e error
	a, e = a.Sign(x.c, b, "authority", f.Key(101))
	fixture.Require(t, e)
	a, e = a.Sign(x.c, b, "consumer", f.Key(4))
	fixture.Require(t, e)
	data, e := v2.EncodeRetainedAcceptance(b, a)
	fixture.Require(t, e)
	before, _ := x.a.Position()
	if _, _, _, e = protectedCall(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAcceptRetained, Admission: x.binding, Data: data, Now: at - 1}, "expired-server-clock"); e == nil {
		t.Fatal("client clock refreshed consent")
	}
	if after, _ := x.a.Position(); after != before {
		t.Fatal("expired consent consumed")
	}
	if snapshot := x.state.Snapshot(); snapshot.PendingOperations != 2 || snapshot.SpentOperations != 2 {
		t.Fatal("unknown/expired refunded", snapshot)
	}
}
