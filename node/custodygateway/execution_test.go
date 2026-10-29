//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	fixture "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard"
	guardwire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type protectedFixture struct {
	guard        guardwire.Chooser
	guardStore   *guard.Store
	source       fixture.Source
	a, b         *Owner
	aroot, broot string
	ad, bd       wire.Descriptor
	dep          wire.Deployment
	binding      v2.AdmissionBinding
	c            v2.Context
	admission    []*v2.AdmissionWitness
	state        *v2.AdmissionState
	jobWitnesses []*custodyfence.Witness
}

func protectedCall(t testing.TB, o *Owner, d wire.Descriptor, p v2.ProtectedCommand, label string) ([]byte, wire.Request, []byte, error) {
	t.Helper()
	payload, e := p.CanonicalBytes()
	if e != nil {
		return nil, wire.Request{}, nil, e
	}
	pos, _ := o.Position()
	id, _ := d.ID()
	q, e := (wire.Request{DescriptorID: id, Before: pos, Nonce: f.Hash(fmt.Sprint(label, pos.Sequence)), Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(payload)}).Sign(f.Key(14))
	if e != nil {
		return nil, q, payload, e
	}
	raw, e := o.ExecuteRuntime(t.Context(), q, payload)
	if e != nil {
		return nil, q, payload, e
	}
	r, e := wire.DecodeResponse(raw)
	if e != nil || r.Verify(d, q) != nil {
		return nil, q, payload, ErrExecution
	}
	return r.Data, q, payload, nil
}
func mustProtected(t testing.TB, o *Owner, d wire.Descriptor, p v2.ProtectedCommand, label string) []byte {
	t.Helper()
	b, _, _, e := protectedCall(t, o, d, p, label)
	fixture.Require(t, e)
	return b
}
func newProtectedFixture(t testing.TB, guarded ...bool) *protectedFixture {
	t.Helper()
	src := fixture.New(t)
	x := &protectedFixture{source: src}
	g, b := src.Genesis, src.Enrollment
	gb, _ := g.CanonicalBytes()
	eb, _ := b.CanonicalBytes()
	configure := func(label string, l cut.SourceLocation, p cut.SourceHandoffPins) (string, wire.Descriptor, *Owner) {
		root := filepath.Join(src.Root, "gateway-"+label)
		id, e := CreateIdentity(root)
		fixture.Require(t, e)
		h, e := cut.ReviewSourceHandoff(g, b, p, l.Role)
		fixture.Require(t, e)
		hid, _ := h.ID()
		d := wire.Descriptor{RootID: id.RootID, SourceID: hid, GenesisID: p.GenesisID, GenesisDescriptorID: p.GenesisDescriptorID, EnrollmentID: p.EnrollmentID, Gateway: id.PublicKey, Issuer: b.Registry.Issuer, OwnerUID: uint32(os.Geteuid()), ParticipantUID: 65534, Clients: [][32]byte{f.Public(14)}, EventLimit: 64}
		if d.OwnerUID == d.ParticipantUID {
			d.ParticipantUID = 65533
		}
		objects := ""
		if l.Role == cut.Target {
			objects = src.Objects
			d.ObjectsID, e = PlacementID(objects, true)
			fixture.Require(t, e)
		}
		d, e = d.Sign(f.Key(110))
		fixture.Require(t, e)
		raw, _ := d.CanonicalBytes()
		fixture.Require(t, Configure(t.Context(), root, Config{Descriptor: raw, Genesis: gb, Enrollment: eb, Pins: p, Source: l, Objects: objects}))
		did, _ := d.ID()
		owner, e := Open(root, did, wire.Position{}, nil)
		fixture.Require(t, e)
		return root, d, owner
	}
	x.aroot, x.ad, x.a = configure("a", src.A, src.AP)
	x.broot, x.bd, x.b = configure("b", src.B, src.BP)
	t.Cleanup(func() { x.a.Close(); x.b.Close() })
	pb, _ := src.Pair.CanonicalBytes()
	ab, _ := x.ad.CanonicalBytes()
	bb, _ := x.bd.CanonicalBytes()
	dep, e := PrepareDeployment(DeploymentPreparation{gb, eb, pb, ab, bb})
	fixture.Require(t, e)
	if len(guarded) > 0 && guarded[0] {
		subjects := append([][32]byte{x.ad.Gateway, x.bd.Gateway}, g.Assignment.Policy.Witnesses...)
		sort.Slice(subjects, func(i, j int) bool { return bytes.Compare(subjects[i][:], subjects[j][:]) < 0 })
		parent, e := filepath.EvalSymlinks(t.TempDir())
		fixture.Require(t, e)
		x.guardStore, e = guard.Create(filepath.Join(parent, "independent-guard"), guard.Config{Subjects: subjects, Limit: 128})
		fixture.Require(t, e)
		t.Cleanup(func() { x.guardStore.Close() })
		server := httptest.NewServer(guard.Handler(x.guardStore))
		t.Cleanup(server.Close)
		x.guard = guard.Client{URL: server.URL}
		dep.Guard = x.guardStore.Identity().PublicKey
	}
	for _, role := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		dep, e = dep.Sign(role.name, f.Key(role.seed))
		fixture.Require(t, e)
	}
	data, e := EncodeEndorsement(dep, src.Pair)
	fixture.Require(t, e)
	raw := mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedEndorse, Now: 1, Data: data}, "endorse-a")
	dep, e = wire.DecodeDeployment(raw)
	fixture.Require(t, e)
	data, e = EncodeEndorsement(dep, src.Pair)
	fixture.Require(t, e)
	raw = mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedEndorse, Now: 1, Data: data}, "endorse-b")
	dep, e = wire.DecodeDeployment(raw)
	fixture.Require(t, e)
	fixture.Require(t, dep.Verify())
	x.dep = dep
	ap, _ := x.a.Position()
	bp, _ := x.b.Position()
	x.a.Close()
	x.b.Close()
	db, _ := dep.CanonicalBytes()
	cfg := ExecutionConfig{db, pb}
	fixture.Require(t, ConfigureExecution(t.Context(), x.aroot, cfg, ExecutionKeys{Authority: f.Key(101)}))
	fixture.Require(t, ConfigureExecution(t.Context(), x.broot, cfg, ExecutionKeys{Replica: f.Key(61), Control: f.Key(102)}))
	aid, _ := x.ad.ID()
	bid, _ := x.bd.ID()
	x.a, e = Open(x.aroot, aid, ap, nil)
	fixture.Require(t, e)
	x.b, e = Open(x.broot, bid, bp, nil)
	fixture.Require(t, e)
	x.a.SetGuard(x.guard)
	x.b.SetGuard(x.guard)
	gid, _ := g.ID()
	x.state, e = v2.NewAdmissionState(g, gid)
	fixture.Require(t, e)
	base := src.Template
	challenge, e := workarchive.CreateCustodyChallenge(g.Manifest, g.Initial, f.Key(3), uint64(time.Now().Unix()), g.CustodyPolicy.MaximumChallengeLifetime, 1, g.Initial.RetainUntil+1)
	fixture.Require(t, e)
	intent := base.Plan.Intent
	assignment, _ := g.Assignment.ID()
	rid, _ := g.Initial.ID()
	intent.AssignmentID = assignment
	intent.PriorSequence = 0
	intent.PriorHeadID = types.Hash{}
	intent.PriorReceiptID = rid
	intent.Nonce = challenge.Nonce
	intent.IssuedAt = challenge.IssuedAt
	intent.ExpiresAt = challenge.ExpiresAt
	intent.RenewUntil = challenge.RenewUntil
	intent.RequestedSamples = challenge.RequestedSamples
	intent.ReplicaPeerID, e = transport.PeerIDFromPublicKey(g.Assignment.Base.RemoteTransportPublicKey[:])
	fixture.Require(t, e)
	plan := v2.Plan{Version: 5, Deployment: &dep, AssignmentID: assignment, Intent: intent, Challenge: challenge, ServeConsumer: f.Public(4), ClientTransportPublicKey: f.Public(46)}
	for _, role := range []struct {
		name string
		seed byte
	}{{"audit", 4}, {"serve", 4}, {"authority", 101}} {
		plan, e = plan.Sign(role.name, f.Key(role.seed))
		fixture.Require(t, e)
	}
	x.c = v2.Context{Assignment: g.Assignment, Plan: plan, Manifest: g.Manifest, Initial: g.Initial, Previous: g.Initial, CustodyPolicy: g.CustodyPolicy}
	fixture.Require(t, x.c.Validate())
	for _, seed := range []byte{70, 71, 72} {
		w, e := v2.CreateAdmissionWitness(filepath.Join(src.Root, fmt.Sprint("admission-", seed)), g, gid, f.Key(seed), b)
		fixture.Require(t, e)
		w.SetGuard(x.guard)
		x.admission = append(x.admission, w)
		t.Cleanup(func() { w.Close() })
	}
	q := x.account(t, v2.AdmissionAdmit, nil)
	x.binding = v2.AdmissionBinding{Version: 2, Genesis: g, Chain: []v2.AdmissionCertificate{q}}
	return x
}
func (x *protectedFixture) account(t testing.TB, kind v2.AdmissionKind, closure *v2.AdmissionClosure) v2.AdmissionCertificate {
	t.Helper()
	g := x.source.Genesis
	gid, _ := g.ID()
	s := x.state.Snapshot()
	entry, e := (v2.AdmissionEntry{Version: 2, GenesisID: gid, ExpectedSequence: s.Position.Sequence, ExpectedHead: s.Position.HeadID, Kind: kind, Context: x.c, Closure: closure}).Sign(g, f.Key(101))
	fixture.Require(t, e)
	q := v2.AdmissionCertificate{Version: 2, Entry: entry}
	for _, w := range x.admission {
		_, pin, e := w.Snapshot()
		fixture.Require(t, e)
		v, e := w.VoteAt(pin, entry)
		fixture.Require(t, e)
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	for _, w := range x.admission {
		_, pin, e := w.Snapshot()
		fixture.Require(t, e)
		fixture.Require(t, w.CommitAt(pin, q))
	}
	fixture.Require(t, x.state.Apply(q))
	return q
}
func (x *protectedFixture) claim(t testing.TB) custodyfence.Certificate {
	t.Helper()
	raw := mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedPrepare, Admission: x.binding, Now: 1}, "prepare")
	candidate, e := v2.DecodeCandidate(raw)
	fixture.Require(t, e)
	s, e := x.c.Scope()
	fixture.Require(t, e)
	sid, _ := s.ID()
	q := custodyfence.Certificate{Version: 1, Command: candidate.Claim}
	for _, seed := range []byte{70, 71, 72} {
		w, e := custodyfence.Create(filepath.Join(x.source.Root, fmt.Sprint("slot-", seed)), s, sid, f.Key(seed))
		fixture.Require(t, e)
		w.SetGuard(x.guard)
		x.jobWitnesses = append(x.jobWitnesses, w)
		t.Cleanup(func() { w.Close() })
		vote, e := w.Vote(candidate.Claim)
		fixture.Require(t, e)
		q.Votes = append(q.Votes, vote)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	for _, w := range x.jobWitnesses {
		fixture.Require(t, w.Commit(q))
	}
	return q
}
func TestProtected5RuntimeActualAndRevokedReplay(t *testing.T) {
	x := newProtectedFixture(t)
	claim := x.claim(t)
	qraw, _ := claim.CanonicalBytes()
	p := v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Now: 1, Data: qraw}
	data, request, payload, e := protectedCall(t, x.b, x.bd, p, "execute")
	fixture.Require(t, e)
	r, e := v2.DecodeResult(data)
	fixture.Require(t, e)
	fixture.Require(t, r.Verify(x.c, claim))
	if r.Entry.Sequence != 1 || r.Entry.Record.Proof.RespondedAt < x.c.Plan.Challenge.IssuedAt || r.Entry.Record.Proof.RespondedAt == 1 {
		t.Fatal("client timestamp influenced proof")
	}
	before, _ := x.b.Position()
	raw, e := x.b.ExecuteRuntime(t.Context(), request, payload)
	fixture.Require(t, e)
	reply, e := wire.DecodeResponse(raw)
	fixture.Require(t, e)
	if !bytes.Equal(reply.Data, data) {
		t.Fatal("cached result changed")
	}
	if after, _ := x.b.Position(); after != before {
		t.Fatal("retry advanced")
	}
	bare := r
	bare.Version = 2
	bare.Protection = nil
	if bare.Verify(x.c, claim) == nil {
		t.Fatal("old replica signature bypass")
	}
	d := x.dep
	d.B.Gateway = f.Public(200)
	if d.Verify() == nil {
		t.Fatal("changed service accepted")
	}
	revoke := testRevoke(t, x.b)
	revoke.Actor = [32]byte{}
	revoke, e = revoke.Sign(f.Key(110))
	fixture.Require(t, e)
	_, e = x.b.Execute(t.Context(), revoke)
	fixture.Require(t, e)
	if _, e = x.b.ExecuteRuntime(t.Context(), request, payload); e == nil {
		t.Fatal("revocation replay bypass")
	}
	for _, w := range x.admission {
		s, _, e := w.Snapshot()
		fixture.Require(t, e)
		if s.SpentOperations != 2 || s.PendingOperations != 2 {
			t.Fatal("revocation refunded admission", s)
		}
	}
}

func (x *protectedFixture) recordBundle(t testing.TB, claim custodyfence.Certificate, r v2.Result) v2.Bundle {
	t.Helper()
	prefix := []custodyfence.Certificate{claim}
	cmd, e := x.b.makeResultCommand(x.c, r, prefix)
	fixture.Require(t, e)
	q := custodyfence.Certificate{Version: 1, Command: cmd}
	for _, w := range x.jobWitnesses {
		vote, e := w.Vote(cmd)
		fixture.Require(t, e)
		q.Votes = append(q.Votes, vote)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	for _, w := range x.jobWitnesses {
		fixture.Require(t, w.Commit(q))
	}
	b := v2.Bundle{Version: 2, Result: r, Chain: []custodyfence.Certificate{claim, q}}
	fixture.Require(t, b.Verify(x.c))
	return b
}
func TestProtected5ConsumptionFaultCannotReexecuteAfterColdOpen(t *testing.T) {
	x := newProtectedFixture(t)
	claim := x.claim(t)
	raw, _ := claim.CanonicalBytes()
	failure := fmt.Errorf("controlled after-consumption failure")
	x.b.executionHook = func(stage string) error {
		if stage == "consumed-before-read" {
			return failure
		}
		return nil
	}
	_, q, payload, e := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "consume-fault")
	if e == nil {
		t.Fatal("fault ignored")
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	if _, e = x.b.jobRead(sid, "consumed", 4096); e != nil {
		t.Fatal(e)
	}
	if _, e = x.b.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes); !os.IsNotExist(e) {
		t.Fatal("read/advanced source after consumed fault", e)
	}
	before, _ := x.b.Position()
	x.b.Close()
	did, _ := x.bd.ID()
	if o, e := Open(x.broot, did, before, nil); e == nil {
		o.Close()
		t.Fatal("unknown intent adopted without exact attempt")
	}
	x.b, e = Open(x.broot, did, before, &q)
	fixture.Require(t, e)
	if _, e = x.b.ExecuteRuntime(t.Context(), q, payload); e == nil {
		t.Fatal("lost session reexecuted")
	}
	for _, w := range x.admission {
		s, _, e := w.Snapshot()
		fixture.Require(t, e)
		if s.PendingOperations != 2 || s.SpentOperations != 2 {
			t.Fatal("unknown effect refunded", s)
		}
	}
}
func TestProtected5AcceptedSourceExactRecoveryAndOldKeysRefused(t *testing.T) {
	x := newProtectedFixture(t)
	claim := x.claim(t)
	raw, _ := claim.CanonicalBytes()
	resultRaw := mustProtected(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "execute")
	r, e := v2.DecodeResult(resultRaw)
	fixture.Require(t, e)
	bundle := x.recordBundle(t, claim, r)
	data, _ := bundle.CanonicalBytes()
	x.a.executionHook = func(stage string) error {
		if stage == "accepted-source-before-receipt" {
			return fmt.Errorf("controlled after-source failure")
		}
		return nil
	}
	_, q, payload, e := protectedCall(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedAccept, Admission: x.binding, Data: data, Now: 1}, "accept-fault")
	if e == nil {
		t.Fatal("fault ignored")
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	if _, e = x.a.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes); e != nil {
		t.Fatal(e)
	}
	if _, e = x.a.jobRead(sid, "accepted", v2.MaximumProtectedReceiptBytes); !os.IsNotExist(e) {
		t.Fatal("signed receipt after fault", e)
	}
	before, _ := x.a.Position()
	x.a.Close()
	did, _ := x.ad.ID()
	wrong := q
	wrong.Nonce = f.Hash("other attempt")
	wrong, _ = wrong.Sign(f.Key(14))
	if o, e := Open(x.aroot, did, before, &wrong); e == nil {
		o.Close()
		t.Fatal("different recovery")
	}
	x.a, e = Open(x.aroot, did, before, &q)
	fixture.Require(t, e)
	responseRaw, e := x.a.ExecuteRuntime(t.Context(), q, payload)
	fixture.Require(t, e)
	reply, e := wire.DecodeResponse(responseRaw)
	fixture.Require(t, e)
	receipt, e := v2.DecodeReceipt(reply.Data)
	fixture.Require(t, e)
	fixture.Require(t, receipt.Verify(x.c, bundle))
	pendingRaw, e := x.a.jobRead(sid, "pending", wire.MaximumRuntimePayloadBytes)
	fixture.Require(t, e)
	_, checked, e := decodeExecutionPending(pendingRaw)
	fixture.Require(t, e)
	if receipt.AcceptedAt != checked || receipt.SourceSequence != 1 {
		t.Fatal("recovery changed time or appended twice")
	}
	bare := receipt
	bare.Version = 2
	bare.Protection = nil
	if bare.Verify(x.c, bundle) == nil {
		t.Fatal("raw authority key bypass")
	}
	fake := *receipt.Protection
	fake, e = fake.Sign(f.Key(101))
	fixture.Require(t, e)
	receipt.Protection = &fake
	if receipt.Verify(x.c, bundle) == nil {
		t.Fatal("old authority service impersonation")
	}
}
func TestProtected5ServerClockAndInvalidProofDoNotConsume(t *testing.T) {
	x := newProtectedFixture(t)
	claim := x.claim(t)
	raw, _ := claim.CanonicalBytes()
	x.b.clock = func() uint64 { return x.c.Plan.Challenge.ExpiresAt + 1 }
	before, _ := x.b.Position()
	_, _, _, e := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: x.c.Plan.Challenge.IssuedAt}, "past-client-time")
	if e == nil {
		t.Fatal("caller rewound server time")
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	if _, e = x.b.jobRead(sid, "consumed", 4096); !os.IsNotExist(e) {
		t.Fatal("expired request consumed", e)
	}
	if pos, _ := x.b.Position(); pos != before {
		t.Fatal("refusal advanced")
	}
	x.b.clock = nil
	bad := claim
	bad.Votes = bad.Votes[:1]
	badRaw, _ := bad.CanonicalBytes()
	_, _, _, e = protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: badRaw, Now: 1}, "minority")
	if e == nil {
		t.Fatal("minority claim")
	}
	if _, e = x.b.jobRead(sid, "consumed", 4096); !os.IsNotExist(e) {
		t.Fatal("minority consumed", e)
	}
}
func protectedQuorum(t testing.TB, root string, scope custodyfence.Scope, cmd custodyfence.Command, guardians ...guardwire.Chooser) custodyfence.Certificate {
	t.Helper()
	sid, _ := scope.ID()
	q := custodyfence.Certificate{Version: scope.Version, Command: cmd}
	var ws []*custodyfence.Witness
	for _, seed := range []byte{70, 71, 72} {
		w, e := custodyfence.Create(filepath.Join(root, fmt.Sprint(sid.String(), "-", seed)), scope, sid, f.Key(seed))
		fixture.Require(t, e)
		defer w.Close()
		ws = append(ws, w)
		if len(guardians) > 0 {
			w.SetGuard(guardians[0])
		}
		vote, e := w.Vote(cmd)
		fixture.Require(t, e)
		q.Votes = append(q.Votes, vote)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	for _, w := range ws {
		fixture.Require(t, w.Commit(q))
	}
	return q
}
func TestProtected5UnclaimedClosesWithServicesAndCannotExecute(t *testing.T) {
	x := newProtectedFixture(t)
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	cmd, e := (custodyfence.Command{Version: 1, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: f.Hash("no claim")}).Sign(f.Key(101))
	fixture.Require(t, e)
	unclaimed := protectedQuorum(t, x.source.Root, scope, cmd)
	proposal, e := v2.NewServeUnclaimed(x.c, unclaimed)
	fixture.Require(t, e)
	for _, role := range []string{"authority", "consumer"} {
		seed := byte(101)
		if role == "consumer" {
			seed = 4
		}
		proposal, e = proposal.Sign(x.c, role, f.Key(seed))
		fixture.Require(t, e)
	}
	decision, e := proposal.Decision(x.c, f.Key(101))
	fixture.Require(t, e)
	serveScope, _ := x.c.ServeScope()
	q := protectedQuorum(t, x.source.Root, serveScope, decision)
	cert := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: q}
	data, e := EncodeExecutionServe(cert, nil)
	fixture.Require(t, e)
	raw := mustProtected(t, x.a, x.ad, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.binding, Data: data, Now: 1}, "serve-a")
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
	if s.PendingOperations != 0 || s.SpentOperations != 2 || s.SourceSequence != 0 || s.RetainUntil < x.dep.MinimumRetainUntil {
		t.Fatal(s)
	}
	before, _ := x.b.Position()
	if _, _, _, e = protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedPrepare, Admission: x.binding, Now: 1}, "after-close"); e == nil {
		t.Fatal("closed job reentered")
	}
	if pos, _ := x.b.Position(); pos != before {
		t.Fatal("refused closed job advanced")
	}
}

func TestProtected5IntentPayloadMismatchAndRoleKeyCopyRefuse(t *testing.T) {
	x := newProtectedFixture(t)
	p := v2.ProtectedCommand{Kind: v2.ProtectedPrepare, Admission: x.binding, Now: 1}
	payload, e := p.CanonicalBytes()
	fixture.Require(t, e)
	pos, _ := x.b.Position()
	id, _ := x.bd.ID()
	q, e := (wire.Request{DescriptorID: id, Before: pos, Nonce: f.Hash("payload"), Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(payload)}).Sign(f.Key(14))
	fixture.Require(t, e)
	bad := append([]byte(nil), payload...)
	bad[len(bad)-1] ^= 1
	if _, e = x.b.ExecuteRuntime(t.Context(), q, bad); e == nil {
		t.Fatal("payload changed")
	}
	if after, _ := x.b.Position(); after != pos {
		t.Fatal("mismatch advanced")
	}
	key := x.b.executionPath("control.key")
	fixture.Require(t, os.Chmod(key, 0644))
	if _, e = x.b.ExecuteRuntime(t.Context(), q, payload); e == nil {
		t.Fatal("public role key accepted")
	}
}
func FuzzProtected5Commands(fz *testing.F) {
	x := newProtectedFixture(fz)
	admit, _ := (v2.ProtectedCommand{Kind: v2.ProtectedPrepare, Admission: x.binding, Now: 1}).CanonicalBytes()
	endorsement, e := EncodeEndorsement(x.dep, x.source.Pair)
	fixture.Require(fz, e)
	cmd, _ := (v2.ProtectedCommand{Kind: v2.ProtectedEndorse, Now: 1, Data: endorsement}).CanonicalBytes()
	for _, raw := range [][]byte{admit, cmd, endorsement} {
		fz.Add(raw)
	}
	fz.Fuzz(func(t *testing.T, b []byte) {
		if c, e := v2.DecodeProtectedCommand(b); e == nil {
			raw, e := c.CanonicalBytes()
			if e != nil || !bytes.Equal(b, raw) {
				t.Fatal("command")
			}
		}
		if d, p, e := decodeEndorsement(b); e == nil {
			raw, e := EncodeEndorsement(d, p)
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("endorsement")
			}
		}
		if c, p, e := decodeExecutionServe(b); e == nil {
			raw, e := EncodeExecutionServe(c, p)
			if e != nil || !bytes.Equal(b, raw) {
				t.Fatal("serve")
			}
		}
		if c, at, e := decodeExecutionPending(b); e == nil {
			raw, e := encodeExecutionPending(c, at)
			if e != nil || !bytes.Equal(b, raw) {
				t.Fatal("pending")
			}
		}
	})
}

func TestProtected5SourceAdvancedWithoutSessionResultStaysUnknown(t *testing.T) {
	x := newProtectedFixture(t)
	claim := x.claim(t)
	raw, _ := claim.CanonicalBytes()
	x.b.executionHook = func(stage string) error {
		if stage == "source-before-result" {
			return fmt.Errorf("controlled loss after source continuation")
		}
		return nil
	}
	_, q, payload, e := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "source-fault")
	if e == nil {
		t.Fatal("fault ignored")
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	entryRaw, e := x.b.jobRead(sid, "entry", workarchive.MaximumCustodyJournalEntryBytes)
	fixture.Require(t, e)
	entry, e := workarchive.DecodeCustodyJournalEntry(entryRaw)
	fixture.Require(t, e)
	if entry.Sequence != 1 {
		t.Fatal(entry.Sequence)
	}
	if _, e = x.b.jobRead(sid, "result", v2.MaximumResultBytes); !os.IsNotExist(e) {
		t.Fatal("invented result", e)
	}
	before, _ := x.b.Position()
	x.b.Close()
	id, _ := x.bd.ID()
	x.b, e = Open(x.broot, id, before, &q)
	fixture.Require(t, e)
	if _, e = x.b.ExecuteRuntime(t.Context(), q, payload); e == nil {
		t.Fatal("source effect repeated after session loss")
	}
	current, e := x.b.currentExecutionSource()
	fixture.Require(t, e)
	if current.Sequence != 1 || current.Retain < entry.Record.RenewedReceipt.RetainUntil {
		t.Fatal(current)
	}
	s := x.state.Snapshot()
	if s.PendingOperations != 2 || s.SpentOperations != 2 || s.SourceSequence != 0 {
		t.Fatal("B-only source treated as A acceptance", s)
	}
}
