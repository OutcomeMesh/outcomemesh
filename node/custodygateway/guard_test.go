//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	fixture "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guardwire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestGuardedProfile5FullLifecycleAndCopiedAdmissionAndServiceKeys(t *testing.T) {
	x := newProtectedFixture(t, true)
	// The full signed deployment and scope survive canonical round trips.
	cb, e := x.c.CanonicalBytes()
	fixture.Require(t, e)
	decoded, e := v2.DecodeContext(cb)
	fixture.Require(t, e)
	fixture.Require(t, decoded.Validate())
	bb, e := x.binding.CanonicalBytes()
	fixture.Require(t, e)
	binding, e := v2.DecodeAdmissionBinding(bb)
	fixture.Require(t, e)
	fixture.Require(t, binding.Verify(x.c))
	bare := binding
	bare.Chain = append([]v2.AdmissionCertificate(nil), binding.Chain...)
	bare.Chain[0].Votes = append([]v2.AdmissionVote(nil), binding.Chain[0].Votes...)
	for i := range bare.Chain[0].Votes {
		bare.Chain[0].Votes[i].GuardSeal = [64]byte{}
	}
	if bare.Verify(x.c) == nil {
		t.Fatal("admission seal stripped")
	}
	// Same original genesis and enrollment, copied witness key, empty local root.
	gid, _ := x.source.Genesis.ID()
	clone, e := v2.CreateAdmissionWitness(filepath.Join(x.source.Root, "cloned-admission"), x.source.Genesis, gid, f.Key(70), x.source.Enrollment)
	fixture.Require(t, e)
	defer clone.Close()
	clone.SetGuard(x.guard)
	other := x.c
	other.Plan.ClientTransportPublicKey = f.Public(47)
	for _, role := range []struct {
		name string
		seed byte
	}{{"audit", 4}, {"serve", 4}, {"authority", 101}} {
		other.Plan, e = other.Plan.Sign(role.name, f.Key(role.seed))
		fixture.Require(t, e)
	}
	entry, e := (v2.AdmissionEntry{Version: 2, GenesisID: gid, ExpectedHead: gid, Kind: v2.AdmissionAdmit, Context: other}).Sign(x.source.Genesis, f.Key(101))
	fixture.Require(t, e)
	_, pin, e := clone.Snapshot()
	fixture.Require(t, e)
	if _, e = clone.VoteAt(pin, entry); e == nil {
		t.Fatal("copied admission witness selected competing job")
	}
	// A copied service key cannot downgrade a previously endorsed deployment.
	downgrade := x.dep
	downgrade.Guard = [32]byte{}
	if downgrade.Verify() == nil {
		t.Fatal("deployment downgrade")
	}
	before, _ := x.b.Position()
	x.b.SetGuard(nil)
	if _, _, _, e = protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedPrepare, Admission: x.binding, Now: 1}, "missing-guard"); e == nil {
		t.Fatal("guard absent")
	}
	if after, _ := x.b.Position(); after != before {
		t.Fatal("missing guard consumed intent")
	}
	x.b.SetGuard(x.guard)
	claim := x.claim(t)
	raw, e := claim.CanonicalBytes()
	fixture.Require(t, e)
	resultRaw := mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "execute")
	r, e := v2.DecodeResult(resultRaw)
	fixture.Require(t, e)
	fixture.Require(t, r.Verify(x.c, claim))
	original := *r.Protection
	unsealed := original
	unsealed.GuardSeal = [64]byte{}
	r.Protection = &unsealed
	if r.Verify(x.c, claim) == nil {
		t.Fatal("service seal stripped")
	}
	r.Protection = &original
	forged := original
	forged.CheckedAt++
	forged.GuardSeal = [64]byte{}
	forged, e = forged.Sign(x.b.key)
	fixture.Require(t, e)
	request, e := forged.GuardRequest()
	fixture.Require(t, e)
	if _, e = guardwire.Obtain(t.Context(), x.guard, x.dep.Guard, request, x.b.key); e == nil {
		t.Fatal("copied service key selected second effect")
	}
	forged.GuardSeal = original.GuardSeal
	if forged.VerifyGuard(x.dep.Guard) == nil {
		t.Fatal("service seal rebound")
	}
	bundle := x.recordBundle(t, claim, r)
	data, e := bundle.CanonicalBytes()
	fixture.Require(t, e)
	raw = mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAccept, Admission: x.binding, Data: data, Now: 1}, "accept")
	receipt, e := v2.DecodeReceipt(raw)
	fixture.Require(t, e)
	fixture.Require(t, receipt.Verify(x.c, bundle))
	proposal, e := v2.NewServeFulfilled(x.c, bundle, receipt)
	fixture.Require(t, e)
	for _, role := range []struct {
		name string
		seed byte
	}{{"authority", 101}, {"consumer", 4}} {
		proposal, e = proposal.Sign(x.c, role.name, f.Key(role.seed))
		fixture.Require(t, e)
	}
	decision, e := proposal.Decision(x.c, f.Key(101))
	fixture.Require(t, e)
	serveScope, e := x.c.ServeScope()
	fixture.Require(t, e)
	qc := protectedQuorum(t, x.source.Root, serveScope, decision, x.guard)
	cert := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: qc}
	fixture.Require(t, cert.Verify(x.c))
	data, e = EncodeExecutionServe(cert, nil)
	fixture.Require(t, e)
	raw = mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.binding, Data: data, Now: 1}, "serve-a")
	ar, e := v2.DecodeServeReceipt(raw)
	fixture.Require(t, e)
	data, e = EncodeExecutionServe(cert, &ar)
	fixture.Require(t, e)
	raw = mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.binding, Data: data, Now: 1}, "serve-b")
	br, e := v2.DecodeServeReceipt(raw)
	fixture.Require(t, e)
	cl := v2.AdmissionClosure{Serve: cert, A: ar, B: br}
	fixture.Require(t, cl.Verify(x.c))
	x.account(t, v2.AdmissionClose, &cl)
	s := x.state.Snapshot()
	if s.PendingOperations != 0 || s.SpentOperations != 2 || s.SourceSequence != 1 {
		t.Fatal(s)
	}
	// Every accepted effect has independent evidence, not merely the outer RPC.
	for _, ef := range []wire.Effect{original, *receipt.Protection, *ar.Protection, *br.Protection} {
		fixture.Require(t, ef.VerifyGuard(x.dep.Guard))
		raw, e := ef.CanonicalBytes()
		fixture.Require(t, e)
		got, e := wire.DecodeEffect(raw)
		fixture.Require(t, e)
		if got != ef {
			t.Fatal("effect codec")
		}
	}
	p, e := x.guardStore.Position()
	fixture.Require(t, e)
	if p.Sequence != 19 {
		t.Fatal("expected 6 admission + 9 job/Serve votes + 4 effects", p)
	}
}

func TestGuardedProfile5RevocationHoldsUnsealedEffectAndCopiedAdmission(t *testing.T) {
	x := newProtectedFixture(t, true, true)
	claim := x.claim(t)
	id := x.guardStore.Identity()
	for _, subject := range [][32]byte{x.bd.Gateway, f.Public(70)} {
		q, e := (guardwire.Revocation{GuardID: id.ID(), Subject: subject, Authority: f.Public(250), ReasonID: f.Hash("key incident")}).Sign(f.Key(250))
		fixture.Require(t, e)
		_, e = x.guardStore.Revoke(t.Context(), q)
		fixture.Require(t, e)
	}
	// A fresh local admission root cannot even repeat the original choice after revocation.
	gid, _ := x.source.Genesis.ID()
	clone, e := v2.CreateAdmissionWitness(filepath.Join(x.source.Root, "revoked-admission-copy"), x.source.Genesis, gid, f.Key(70), x.source.Enrollment)
	fixture.Require(t, e)
	defer clone.Close()
	clone.SetGuard(x.guard)
	_, pin, e := clone.Snapshot()
	fixture.Require(t, e)
	if _, e = clone.VoteAt(pin, x.binding.Chain[0].Entry); e == nil {
		t.Fatal("revoked copied admission signer")
	}
	fixture.Require(t, x.binding.Verify(x.c)) // Existing proofs remain historical.
	raw, _ := claim.CanonicalBytes()
	_, q, payload, e := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "revoked-execute")
	if e == nil {
		t.Fatal("revoked gateway published a protected result")
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	entry, e := x.b.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes)
	fixture.Require(t, e)
	if _, e = x.b.jobRead(sid, "result", v2.MaximumResultBytes); !os.IsNotExist(e) {
		t.Fatal("unsealed result exposed", e)
	}
	// The underlying source may have run before the seal was refused. It stays
	// consumed and pending; revocation is never a refund or permission to retry it.
	before, _ := x.b.Position()
	x.b.Close()
	did, _ := x.bd.ID()
	x.b, e = Open(x.broot, did, before, &q)
	fixture.Require(t, e)
	x.b.SetGuard(x.guard)
	if _, e = x.b.ExecuteRuntime(t.Context(), q, payload); e == nil {
		t.Fatal("revoked/consumed effect repeated after restart")
	}
	again, e := x.b.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes)
	fixture.Require(t, e)
	if !bytes.Equal(entry, again) {
		t.Fatal("source evidence changed")
	}
	for _, w := range x.admission {
		state, _, e := w.Snapshot()
		fixture.Require(t, e)
		if state.SpentOperations != 2 || state.PendingOperations != 2 {
			t.Fatal("revocation reset accounting", state)
		}
	}
}
