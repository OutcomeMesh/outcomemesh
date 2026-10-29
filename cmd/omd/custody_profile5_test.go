//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	gw "github.com/outcomemesh/outcomemesh/node/custodygateway"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func profile5Call(t testing.TB, o *gw.Owner, d wire.Descriptor, p v2.ProtectedCommand, label string) []byte {
	t.Helper()
	tick := time.Now()
	defer func() { t.Logf("%s: %s", label, time.Since(tick)) }()
	payload, e := p.CanonicalBytes()
	if e != nil {
		t.Fatal(label, e)
	}
	pos, _ := o.Position()
	id, _ := d.ID()
	q, e := (wire.Request{DescriptorID: id, Before: pos, Nonce: f.Hash(fmt.Sprint(label, pos.Sequence)), Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(payload)}).Sign(f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := o.ExecuteRuntime(t.Context(), q, payload)
	if e != nil {
		t.Fatal(label, e)
	}
	r, e := wire.DecodeResponse(raw)
	if e != nil || r.Verify(d, q) != nil {
		t.Fatal(label, e)
	}
	return r.Data
}

type profile5Fixture struct {
	a, b       gatewayFixture
	oa, ob     *gw.Owner
	deployment wire.Deployment
	g          v2.AdmissionGenesis
	enrollment v2.EnrollmentBinding
	admission  v2.AdmissionBinding
	context    v2.Context
	witnesses  []*v2.AdmissionWitness
	state      *v2.AdmissionState
}

func profile5Prepare(t testing.TB, g v2.AdmissionGenesis, enrollment v2.EnrollmentBinding, l []cut.SourceLocation, pins []types.Hash, objects string) *profile5Fixture {
	t.Helper()
	a := gatewayPrepare(t, gatewayCLIInProcess, g, enrollment, l[0], pins[0], objects)
	b := gatewayPrepare(t, gatewayCLIInProcess, g, enrollment, l[1], pins[1], objects)
	oa, e := gw.Open(a.root, a.id, wire.Position{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	ob, e := gw.Open(b.root, b.id, wire.Position{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	ah, e := cut.InspectSourceHandoff(t.Context(), g, enrollment, a.config.Pins, l[0])
	if e != nil {
		t.Fatal(e)
	}
	bh, e := cut.InspectSourceHandoff(t.Context(), g, enrollment, b.config.Pins, l[1])
	if e != nil {
		t.Fatal(e)
	}
	pair := cut.SourceHandoffPair{A: ah, B: bh}
	pb, _ := pair.CanonicalBytes()
	gb, _ := g.CanonicalBytes()
	eb, _ := enrollment.CanonicalBytes()
	ab, _ := a.descriptor.CanonicalBytes()
	bb, _ := b.descriptor.CanonicalBytes()
	prep := filepath.Join(a.dir, "deployment-preparation.json")
	cutoverWrite(t, prep, gw.DeploymentPreparation{Genesis: gb, Enrollment: eb, Pair: pb, A: ab, B: bb})
	deploymentPath := filepath.Join(a.dir, "deployment-draft")
	profile5CLIAction(t, []string{custodyProfile5Command, "--action", "deployment", "--input", prep, "--out", deploymentPath})
	for _, r := range []struct {
		role string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		key := filepath.Join(a.dir, "role-"+r.role)
		writePruneCLIFile(t, key, []byte(hex.EncodeToString(f.Key(r.seed).Seed())))
		next := filepath.Join(a.dir, "deployment-"+r.role)
		profile5CLIAction(t, []string{custodyProfile5Command, "--action", "sign-deployment", "--input", deploymentPath, "--role", r.role, "--key", key, "--out", next})
		deploymentPath = next
	}
	deploymentRaw, e := os.ReadFile(deploymentPath)
	if e != nil {
		t.Fatal(e)
	}
	deployment, e := wire.DecodeDeployment(deploymentRaw)
	if e != nil {
		t.Fatal(e)
	}
	data, e := gw.EncodeEndorsement(deployment, pair)
	if e != nil {
		t.Fatal(e)
	}
	raw := profile5Call(t, oa, a.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedEndorse, Data: data, Now: g.Initial.StoredAt + 1}, "endorse-a")
	deployment, e = wire.DecodeDeployment(raw)
	if e != nil {
		t.Fatal(e)
	}
	data, e = gw.EncodeEndorsement(deployment, pair)
	if e != nil {
		t.Fatal(e)
	}
	raw = profile5Call(t, ob, b.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedEndorse, Data: data, Now: g.Initial.StoredAt + 1}, "endorse-b")
	deployment, e = wire.DecodeDeployment(raw)
	if e != nil || deployment.Verify() != nil {
		t.Fatal("complete deployment", e)
	}
	ap, _ := oa.Position()
	bp, _ := ob.Position()
	oa.Close()
	ob.Close()
	dr, _ := deployment.CanonicalBytes()
	config := gw.ExecutionConfig{Deployment: dr, Pair: pb}
	for _, role := range []struct {
		name    string
		fixture gatewayFixture
		keys    []struct {
			name string
			seed byte
		}
	}{
		{"a", a, []struct {
			name string
			seed byte
		}{{"authority", 101}}},
		{"b", b, []struct {
			name string
			seed byte
		}{{"replica", 61}, {"control", 102}}},
	} {
		setup := gw.ExecutionSetup{ExecutionConfig: config}
		for _, k := range role.keys {
			path := filepath.Join(role.fixture.dir, "execution-"+k.name+".seed")
			writePruneCLIFile(t, path, []byte(hex.EncodeToString(f.Key(k.seed).Seed())))
			switch k.name {
			case "replica":
				setup.ReplicaKeyPath = path
			case "control":
				setup.ControlKeyPath = path
			case "authority":
				setup.AuthorityKeyPath = path
			}
		}
		in := filepath.Join(role.fixture.dir, "execution-setup.json")
		cutoverWrite(t, in, setup)
		profile5CLIAction(t, []string{custodyProfile5Command, "--action", "configure", "--root", role.fixture.root, "--input", in, "--out", filepath.Join(role.fixture.dir, "execution-configured")})
	}
	oa, e = gw.Open(a.root, a.id, ap, nil)
	if e != nil {
		t.Fatal(e)
	}
	ob, e = gw.Open(b.root, b.id, bp, nil)
	if e != nil {
		t.Fatal(e)
	}
	x := &profile5Fixture{a: a, b: b, oa: oa, ob: ob, deployment: deployment, g: g, enrollment: enrollment}
	t.Cleanup(func() { x.oa.Close(); x.ob.Close() })
	gid, _ := g.ID()
	x.state, e = v2.NewAdmissionState(g, gid)
	if e != nil {
		t.Fatal(e)
	}
	var c v2.Context
	if len(g.Import.Evidence.Cycles) > 0 {
		c = importCLIContext(t, g, x.state.Snapshot())
	} else {
		aid, _ := g.Assignment.ID()
		rid, _ := g.Initial.ID()
		peer, e := transport.PeerIDFromPublicKey(g.Assignment.Base.RemoteTransportPublicKey[:])
		if e != nil {
			t.Fatal(e)
		}
		c = v2.Context{Assignment: g.Assignment, Manifest: g.Manifest, Initial: g.Initial, Previous: g.Initial, CustodyPolicy: g.CustodyPolicy}
		c.Plan = v2.Plan{Version: 2, AssignmentID: aid, ServeConsumer: f.Public(4), ClientTransportPublicKey: f.Public(46), Intent: workarchive.CustodyAuditIntent{Version: 0, AssignmentID: aid, ConsumerPublicKey: f.Public(4), AuditorPublicKey: f.Public(3), ReplicaPeerID: peer, PriorReceiptID: rid}}
	}
	ch, e := workarchive.CreateCustodyChallenge(g.Manifest, c.Previous, f.Key(3), uint64(time.Now().Unix()), g.CustodyPolicy.MaximumChallengeLifetime, 1, c.Previous.RetainUntil+1)
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.Challenge = ch
	c.Plan.Intent.Nonce = ch.Nonce
	c.Plan.Intent.IssuedAt = ch.IssuedAt
	c.Plan.Intent.ExpiresAt = ch.ExpiresAt
	c.Plan.Intent.RenewUntil = ch.RenewUntil
	c.Plan.Intent.RequestedSamples = ch.RequestedSamples

	c.Plan.Version = v2.ProtectedVersion
	c.Plan.Deployment = &deployment
	c.Plan.AuditSignature = [64]byte{}
	c.Plan.ServeSignature = [64]byte{}
	c.Plan.AuthoritySignature = [64]byte{}
	for _, r := range []struct {
		role string
		seed byte
	}{{"audit", 4}, {"serve", 4}, {"authority", 101}} {
		c.Plan, e = c.Plan.Sign(r.role, f.Key(r.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = c.Validate(); e != nil {
		t.Fatal(e)
	}
	x.context = c
	for _, seed := range []byte{70, 71, 72} {
		w, e := v2.CreateAdmissionWitness(filepath.Join(t.TempDir(), fmt.Sprint("w-", seed)), g, gid, f.Key(seed), enrollment)
		if e != nil {
			t.Fatal(e)
		}
		x.witnesses = append(x.witnesses, w)
		t.Cleanup(func() { w.Close() })
	}
	q := x.admitCertificate(t, v2.AdmissionAdmit, nil)
	x.admission = v2.AdmissionBinding{Version: v2.Version2, Genesis: g, Chain: []v2.AdmissionCertificate{q}}
	if e = v2.VerifyProtectedBinding(x.admission, enrollment, deployment); e != nil {
		t.Fatal(e)
	}
	return x
}
func (x *profile5Fixture) admitCertificate(t testing.TB, kind v2.AdmissionKind, closure *v2.AdmissionClosure) v2.AdmissionCertificate {
	t.Helper()
	gid, _ := x.g.ID()
	s := x.state.Snapshot()
	entry, e := (v2.AdmissionEntry{Version: v2.Version2, GenesisID: gid, ExpectedSequence: s.Position.Sequence, ExpectedHead: s.Position.HeadID, Kind: kind, Context: x.context, Closure: closure}).Sign(x.g, f.Key(101))
	if e != nil {
		t.Fatal(e)
	}
	q := v2.AdmissionCertificate{Version: v2.Version2, Entry: entry}
	for _, w := range x.witnesses {
		_, pin, e := w.Snapshot()
		if e != nil {
			t.Fatal(e)
		}
		vote, e := w.VoteAt(pin, entry)
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, vote)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	for _, w := range x.witnesses {
		_, pin, e := w.Snapshot()
		if e != nil {
			t.Fatal(e)
		}
		if e = w.CommitAt(pin, q); e != nil {
			t.Fatal(e)
		}
	}
	if e = x.state.Apply(q); e != nil {
		t.Fatal(e)
	}
	return q
}
func profile5WitnessQuorum(t testing.TB, scope custodyfence.Scope, commands ...custodyfence.Command) []custodyfence.Certificate {
	t.Helper()
	sid, _ := scope.ID()
	var ws []*custodyfence.Witness
	for _, seed := range []byte{70, 71, 72} {
		w, e := custodyfence.Create(filepath.Join(t.TempDir(), fmt.Sprint("job-", seed)), scope, sid, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		ws = append(ws, w)
		defer w.Close()
	}
	var chain []custodyfence.Certificate
	for _, cmd := range commands {
		q := custodyfence.Certificate{Version: scope.Version, Command: cmd}
		for _, w := range ws {
			v, e := w.Vote(cmd)
			if e != nil {
				t.Fatal(e)
			}
			q.Votes = append(q.Votes, v)
		}
		sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
		for _, w := range ws {
			if e := w.Commit(q); e != nil {
				t.Fatal(e)
			}
		}
		chain = append(chain, q)
	}
	return chain
}
func TestProtected5ActualExecutionAcceptanceAndAccounting(t *testing.T) {
	runSourceHandoffFixture(t, sourceHandoffCLIInProcess, func(g v2.AdmissionGenesis, b v2.EnrollmentBinding, l []cut.SourceLocation, p []types.Hash, objects string) {
		x := profile5Prepare(t, g, b, l, p, objects)
		now := x.context.Plan.Challenge.IssuedAt
		raw := profile5Call(t, x.ob, x.b.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedPrepare, Admission: x.admission, Now: now}, "prepare")
		candidate, e := v2.DecodeCandidate(raw)
		if e != nil {
			t.Fatal(e)
		}
		scope, _ := x.context.Scope()
		jobWitnesses := profile5OriginalWitnessGroup(t, scope)
		claim := jobWitnesses.certify(t, candidate.Claim)
		claimRaw, _ := claim.CanonicalBytes()
		raw = profile5Call(t, x.ob, x.b.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.admission, Data: claimRaw, Now: now}, "execute")
		result, e := v2.DecodeResult(raw)
		if e != nil || result.Verify(x.context, claim) != nil || result.Version != 5 || result.Entry.Sequence != 2 {
			t.Fatal("real result", e)
		}
		bare := result
		bare.Version = 2
		bare.Protection = nil
		if bare.Verify(x.context, claim) == nil {
			t.Fatal("raw replica key bypass")
		}
		prefix, _ := v2.EncodeProtectedPrefix([]custodyfence.Certificate{claim})
		raw = profile5Call(t, x.ob, x.b.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedResultCommand, Admission: x.admission, Data: prefix, Now: now}, "result-command")
		record, e := custodyfence.DecodeCommand(raw)
		if e != nil {
			t.Fatal(e)
		}
		chain := []custodyfence.Certificate{claim, jobWitnesses.certify(t, record)}
		bundle := v2.Bundle{Version: 2, Result: result, Chain: chain}
		if e = bundle.Verify(x.context); e != nil {
			t.Fatal(e)
		}
		bundleRaw, _ := bundle.CanonicalBytes()
		raw = profile5Call(t, x.oa, x.a.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedAccept, Admission: x.admission, Data: bundleRaw, Now: now}, "accept")
		receipt, e := v2.DecodeReceipt(raw)
		if e != nil || receipt.Verify(x.context, bundle) != nil || receipt.Version != 5 {
			t.Fatal("A receipt", e)
		}
		proposal, e := v2.NewServeFulfilled(x.context, bundle, receipt)
		if e != nil {
			t.Fatal(e)
		}
		for _, role := range []string{"authority", "consumer"} {
			seed := byte(101)
			if role == "consumer" {
				seed = 4
			}
			proposal, e = proposal.Sign(x.context, role, f.Key(seed))
			if e != nil {
				t.Fatal(e)
			}
		}
		decision, e := proposal.Decision(x.context, f.Key(101))
		if e != nil {
			t.Fatal(e)
		}
		serveScope, _ := x.context.ServeScope()
		qc := profile5WitnessQuorum(t, serveScope, decision)[0]
		cert := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: qc}
		if e = cert.Verify(x.context); e != nil {
			t.Fatal(e)
		}
		data, _ := gw.EncodeExecutionServe(cert, nil)
		raw = profile5Call(t, x.oa, x.a.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.admission, Data: data, Now: now}, "serve-a")
		ar, e := v2.DecodeServeReceipt(raw)
		if e != nil {
			t.Fatal(e)
		}
		data, _ = gw.EncodeExecutionServe(cert, &ar)
		raw = profile5Call(t, x.ob, x.b.descriptor, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.admission, Data: data, Now: now}, "serve-b")
		br, e := v2.DecodeServeReceipt(raw)
		if e != nil {
			t.Fatal(e)
		}
		closure := v2.AdmissionClosure{Serve: cert, A: ar, B: br}
		if e = closure.Verify(x.context); e != nil {
			t.Fatal(e)
		}
		encoded, e := closure.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = v2.DecodeAdmissionClosure(encoded); e != nil {
			t.Fatal(e)
		}
		x.admitCertificate(t, v2.AdmissionClose, &closure)
		s := x.state.Snapshot()
		if s.SpentOperations != 4 || s.PendingOperations != 0 || s.SourceSequence != 2 || s.RetainUntil < g.Import.Evidence.Cycles[0].Terminal.Entry.Record.RenewedReceipt.RetainUntil {
			t.Fatal(s)
		}
		for _, location := range l {
			if _, e = cut.InspectSourceHandoff(t.Context(), g, b, func() cut.SourceHandoffPins {
				if location.Role == cut.Authority {
					return x.a.config.Pins
				}
				return x.b.config.Pins
			}(), location); e != nil {
				t.Fatal("original source changed", e)
			}
		}
		t.Log("protected Plan5: real archive read and renewal, source 1->2, fresh service result/A receipt/Serve signatures, original imported witnesses close spent=4 pending=0; originals remain sealed")
	})
}

type profile5WitnessGroup struct {
	scope  custodyfence.Scope
	owners []*custodyfence.Witness
}

func profile5OriginalWitnessGroup(t testing.TB, scope custodyfence.Scope) *profile5WitnessGroup {
	t.Helper()
	x := &profile5WitnessGroup{scope: scope}
	sid, _ := scope.ID()
	for _, seed := range []byte{70, 71, 72} {
		w, e := custodyfence.Create(filepath.Join(t.TempDir(), fmt.Sprint("original-", seed)), scope, sid, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		x.owners = append(x.owners, w)
		t.Cleanup(func() { w.Close() })
	}
	return x
}
func (x *profile5WitnessGroup) certify(t testing.TB, cmd custodyfence.Command) custodyfence.Certificate {
	t.Helper()
	q := custodyfence.Certificate{Version: x.scope.Version, Command: cmd}
	for _, w := range x.owners {
		vote, e := w.Vote(cmd)
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, vote)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	for _, w := range x.owners {
		if e := w.Commit(q); e != nil {
			t.Fatal(e)
		}
	}
	return q
}

func profile5CLIInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if e := runCustodyProfile5(t.Context(), args, &out); e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}
func profile5CLIAction(t testing.TB, args []string) {
	t.Helper()
	profile5CLIInProcess(t, gatewayReviewed(t, profile5CLIInProcess, args))
}
