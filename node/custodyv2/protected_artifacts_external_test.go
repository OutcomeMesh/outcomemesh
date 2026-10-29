package custodyv2_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func artifactFixture(t testing.TB) (v2.Context, v2.Result, v2.Bundle, v2.Receipt, v2.AdmissionClosure) {
	t.Helper()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile("testdata/public-fixture/context")
	check(e)
	c, e := v2.DecodeContext(raw)
	check(e)
	mk := func(label string, key byte, objects bool) wire.Descriptor {
		d := wire.Descriptor{RootID: f.Hash(label + "root"), SourceID: f.Hash(label + "source"), GenesisID: f.Hash("g"), GenesisDescriptorID: f.Hash("gd"), EnrollmentID: f.Hash("enrol"), Gateway: f.Public(key), Issuer: f.Public(110), Clients: [][32]byte{f.Public(46)}, OwnerUID: 1000, ParticipantUID: 1001, EventLimit: 32}
		if objects {
			d.ObjectsID = f.Hash("objects")
		}
		d, e = d.Sign(f.Key(110))
		check(e)
		return d
	}
	dep := wire.Deployment{A: mk("a", 201, false), B: mk("b", 202, true), GenesisID: f.Hash("g"), GenesisDescriptorID: f.Hash("gd"), EnrollmentID: f.Hash("enrol"), ImportID: f.Hash("import"), PairID: f.Hash("pair"), MinimumRetainUntil: c.Initial.RetainUntil, Authority: c.Assignment.Base.AuthorityPublicKey, Control: c.Assignment.Base.RemoteControlPublicKey}
	for _, r := range []struct {
		role string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}, {"a", 201}, {"b", 202}} {
		dep, e = dep.Sign(r.role, f.Key(r.seed))
		check(e)
	}
	c.Assignment.Policy.Version = 5
	c.Assignment.Policy.RegistryID = f.Hash("registry")
	c.Assignment.Policy.RegistryDescriptorID = f.Hash("registry-descriptor")
	c.Assignment.Policy.ImportID = dep.ImportID
	aid, _ := c.Assignment.ID()
	c.Plan.Version = 5
	c.Plan.Deployment = &dep
	c.Plan.AssignmentID = aid
	c.Plan.Intent.AssignmentID = aid
	for _, r := range []struct {
		role string
		seed byte
	}{{"audit", 4}, {"serve", 4}, {"authority", 1}} {
		c.Plan, e = c.Plan.Sign(r.role, f.Key(r.seed))
		check(e)
	}
	check(c.Validate())
	scope, e := c.Scope()
	check(e)
	sid, _ := scope.ID()
	cmd, e := (custodyfence.Command{Version: 1, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.Claim, EvidenceID: v2.SessionID(f.Public(250))}).Sign(f.Key(14))
	check(e)
	claim := f.Certificate(cmd, 70, 71, 72)
	objects, e := workarchive.OpenObjectStore(filepath.Join(t.TempDir(), "objects"), workarchive.DefaultObjectStorePolicy())
	check(e)
	for _, d := range c.Manifest.Chunks {
		raw, e := os.ReadFile(filepath.Join("testdata/public-fixture", d.ID.String()))
		check(e)
		_, e = objects.Put(c.Manifest, d.ID, raw)
		check(e)
	}
	at := c.Plan.Challenge.IssuedAt
	batch, proof, e := workarchive.AnswerCustodyChallenge(objects, c.Manifest, c.Previous, c.Plan.Challenge, c.CustodyPolicy, f.Key(61), at)
	check(e)
	renewed, e := workarchive.RenewReplicaReceipt(c.Manifest, c.Previous, c.Plan.Challenge, batch, proof, c.CustodyPolicy, f.Key(61), at)
	check(e)
	entry := workarchive.CustodyJournalEntry{Version: 0, Sequence: c.Plan.Intent.PriorSequence + 1, PreviousEntryID: c.Plan.Intent.PriorHeadID, PreviousReceipt: c.Previous, Record: workarchive.CustodyRecord{Challenge: c.Plan.Challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}}
	cid, _ := cmd.ID()
	r, e := v2.SignResultSession(v2.Result{Version: 2, ScopeID: sid, ClaimID: cid, SessionPublicKey: f.Public(250), Entry: entry}, f.Key(250))
	check(e)
	head, _ := entry.ID()
	did, _ := dep.ID()
	effect := func(kind uint8, id types.Hash, key byte) wire.Effect {
		ef, e := (wire.Effect{Kind: kind, DeploymentID: did, ScopeID: sid, AdmissionID: f.Hash("admit"), BindingID: f.Hash("binding"), ArtifactID: id, SourceSequence: entry.Sequence, SourceHead: head, CheckedAt: at}).Sign(f.Key(key))
		check(e)
		return ef
	}
	rid, _ := r.CoreID()
	ef := effect(wire.EffectExecute, rid, 202)
	r.Version = 5
	r.Protection = &ef
	check(r.Verify(c, claim))
	sm, e := custodyfence.NewState(scope, sid)
	check(e)
	check(sm.Apply(claim))
	state := sm.Snapshot()
	id, _ := r.ID()
	record, e := (custodyfence.Command{Version: 1, ScopeID: sid, ExpectedSequence: state.Position.Sequence, ExpectedHead: state.Position.HeadID, Kind: custodyfence.RecordResult, ClaimID: cid, EvidenceID: id}).Sign(f.Key(14))
	check(e)
	bundle := v2.Bundle{Version: 2, Result: r, Chain: []custodyfence.Certificate{claim, f.Certificate(record, 70, 71, 72)}}
	check(bundle.Verify(c))
	plan, _ := c.Plan.ID()
	bid, _ := bundle.ID()
	receipt, e := v2.SignAcceptance(v2.Receipt{Version: 2, AssignmentID: aid, PlanID: plan, ScopeID: sid, ResultID: id, BundleID: bid, SourceHeadID: head, SourceSequence: entry.Sequence, AcceptedAt: at, Authority: c.Assignment.Base.AuthorityPublicKey}, f.Key(1))
	check(e)
	core, _ := receipt.CoreID()
	ae := effect(wire.EffectAccept, core, 201)
	receipt.Version = 5
	receipt.Protection = &ae
	check(receipt.Verify(c, bundle))
	proposal, e := v2.NewServeFulfilled(c, bundle, receipt)
	check(e)
	for _, role := range []struct {
		name string
		seed byte
	}{{"authority", 1}, {"consumer", 4}} {
		proposal, e = proposal.Sign(c, role.name, f.Key(role.seed))
		check(e)
	}
	decision, e := proposal.Decision(c, f.Key(1))
	check(e)
	cert := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: f.Certificate(decision, 70, 71, 72)}
	check(cert.Verify(c))
	retain, e := proposal.Retention(c)
	check(e)
	certID, _ := cert.ID()
	serve := func(role uint8, parent types.Hash, signer, key byte) v2.ServeReceipt {
		ack, e := v2.SignServeApplication(v2.ServeReceipt{Version: 2, Role: role, ScopeID: sid, CertificateID: certID, SourceHeadID: head, ParentID: parent, SourceSequence: entry.Sequence, MinimumRetainUntil: retain, AppliedAt: at, Signer: f.Public(signer)}, f.Key(signer))
		check(e)
		id, _ := ack.CoreID()
		kind := wire.EffectServeA
		if role == v2.ServeTarget {
			kind = wire.EffectServeB
		}
		ef := effect(kind, id, key)
		ack.Version = 5
		ack.Protection = &ef
		return ack
	}
	a := serve(v2.ServeAuthority, types.Hash{}, 1, 201)
	parent, _ := a.ID()
	b := serve(v2.ServeTarget, parent, 14, 202)
	closure := v2.AdmissionClosure{Serve: cert, A: a, B: b}
	check(closure.Verify(c))
	return c, r, bundle, receipt, closure
}
func TestProtected5ArtifactsCanonicalVectorAndBareKeyRefusal(t *testing.T) {
	c, r, b, receipt, closure := artifactFixture(t)
	var all []byte
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{c, r, b, receipt, closure, closure.Serve.Proposal, closure.A, closure.B} {
		raw, e := v.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		all = append(all, raw...)
	}
	got := types.DomainHash("OMESH/test/profile5/artifact-vector", all).String()
	const want = "3afabe12f01ece7a0a8d81eda9ea916fc0635a68a70d9be0f56a6c18e1232f67"
	if got != want {
		t.Fatal(got)
	}
	bare := r
	bare.Version = 2
	bare.Protection = nil
	if bare.Verify(c, b.Chain[0]) == nil {
		t.Fatal("bare result")
	}
	ar := receipt
	ar.Version = 2
	ar.Protection = nil
	if ar.Verify(c, b) == nil {
		t.Fatal("bare acceptance")
	}
	ack := closure.A
	ack.Version = 2
	ack.Protection = nil
	if ack.Verify(c, closure.Serve, v2.ServeAuthority, nil) == nil {
		t.Fatal("bare closure")
	}
}
func TestProtected5RejectsNestedAndMismatchedEffect(t *testing.T) {
	c, r, b, receipt, closure := artifactFixture(t)
	raw, _ := r.CanonicalBytes()
	ef, _ := r.Protection.CanonicalBytes()
	for i := 0; i < 8; i++ {
		out := codec.NewEncoder(len(raw) + 512)
		out.Fixed([]byte("OMCVRES5"))
		out.BytesField(raw)
		out.Fixed(ef)
		raw = out.Bytes()
	}
	if _, e := v2.DecodeResult(raw); e == nil {
		t.Fatal("nested protected result")
	}
	wrong := *r.Protection
	wrong.ScopeID = f.Hash("other")
	wrong, _ = wrong.Sign(f.Key(202))
	r.Protection = &wrong
	if r.Verify(c, b.Chain[0]) == nil {
		t.Fatal("foreign scope")
	}
	a := *receipt.Protection
	a, _ = a.Sign(f.Key(1))
	receipt.Protection = &a
	if receipt.Verify(c, b) == nil {
		t.Fatal("old authority service impersonation")
	}
	parent := closure.A
	parent.Protection = nil
	parent.Version = 2
	if closure.B.Verify(c, closure.Serve, v2.ServeTarget, &parent) == nil {
		t.Fatal("old A parent")
	}
}
func FuzzProtected5Artifacts(fz *testing.F) {
	c, r, b, a, cl := artifactFixture(fz)
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{c.Plan, c, r, b, a, cl, cl.A, cl.Serve.Proposal} {
		raw, e := v.CanonicalBytes()
		if e != nil {
			fz.Fatal(e)
		}
		fz.Add(raw)
	}
	fz.Fuzz(func(t *testing.T, raw []byte) {
		checks := []func([]byte) ([]byte, error){func(b []byte) ([]byte, error) {
			v, e := v2.DecodePlan(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, func(b []byte) ([]byte, error) {
			v, e := v2.DecodeContext(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, func(b []byte) ([]byte, error) {
			v, e := v2.DecodeResult(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, func(b []byte) ([]byte, error) {
			v, e := v2.DecodeReceipt(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, func(b []byte) ([]byte, error) {
			v, e := v2.DecodeServeReceipt(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, func(b []byte) ([]byte, error) {
			v, e := v2.DecodeServeProposal(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, func(b []byte) ([]byte, error) {
			v, e := v2.DecodeAdmissionClosure(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}}
		for _, decode := range checks {
			if b, e := decode(raw); e == nil && !bytes.Equal(b, raw) {
				t.Fatal("noncanonical protected artifact")
			}
		}
	})
}
