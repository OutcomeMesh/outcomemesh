package custodyv2

import (
	"bytes"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func modelAdmissionContext(t testing.TB, operations uint32, pending uint16) Context {
	t.Helper()
	c := fixtureContext(t)
	c.Assignment.Base.MaximumOperations = operations
	c.Assignment.Base.MaximumPending = pending
	aid, e := c.Assignment.ID()
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.AssignmentID = aid
	c.Plan.Intent.AssignmentID = aid
	return modelAdmissionResign(t, c)
}
func modelAdmissionResign(t testing.TB, c Context) Context {
	t.Helper()
	c.Plan.AuditSignature = [64]byte{}
	c.Plan.ServeSignature = [64]byte{}
	c.Plan.AuthoritySignature = [64]byte{}
	var e error
	for _, role := range []string{"audit", "serve", "authority"} {
		key := f.Key(4)
		if role == "authority" {
			key = f.Key(1)
		}
		c.Plan, e = c.Plan.Sign(role, key)
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func modelAdmissionCertificate(t testing.TB, e AdmissionEntry) AdmissionCertificate {
	t.Helper()
	q := AdmissionCertificate{Version: Version2, Entry: e}
	for _, seed := range []byte{70, 71, 72} {
		v, err := signAdmissionVote(e, f.Key(seed))
		if err != nil {
			t.Fatal(err)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	return q
}
func modelAdmissionEntry(t testing.TB, g AdmissionGenesis, s *AdmissionState, c Context, kind AdmissionKind, closure *AdmissionClosure) AdmissionEntry {
	t.Helper()
	pin := s.Snapshot().Position
	id, _ := g.ID()
	e, err := (AdmissionEntry{Version: Version2, GenesisID: id, ExpectedSequence: pin.Sequence, ExpectedHead: pin.HeadID, Kind: kind, Context: c, Closure: closure}).Sign(g, f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func modelAdmissionUnclaimed(t testing.TB, c Context) AdmissionClosure {
	t.Helper()
	x := fixtureWithContext(t, c)
	a := x.acceptor(t)
	target := x.target(t, "target")
	cert := unclaimedServe(t, c)
	ar, e := a.ApplyServe(t.Context(), cert, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), cert, ar, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	return AdmissionClosure{Serve: cert, A: ar, B: br}
}
func TestAdmissionReferenceBudgetNeverRefundsCancellation(t *testing.T) {
	c := modelAdmissionContext(t, 2, 2)
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := g.ID()
	s, e := NewAdmissionState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	admit := modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil)
	q := modelAdmissionCertificate(t, admit)
	if e := s.Apply(q); e != nil {
		t.Fatal(e)
	}
	first := s.Snapshot()
	if first.SpentOperations != 2 || first.PendingOperations != 2 || first.ActiveContextID.IsZero() {
		t.Fatal(first)
	}
	if e := s.ValidateNext(modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil)); e != ErrAdmissionActive {
		t.Fatal("active assignment admitted more work", e)
	}
	closure := modelAdmissionUnclaimed(t, c)
	close := modelAdmissionEntry(t, g, s, c, AdmissionClose, &closure)
	if e := s.Apply(modelAdmissionCertificate(t, close)); e != nil {
		t.Fatal(e)
	}
	last := s.Snapshot()
	if last.SpentOperations != 2 || last.PendingOperations != 0 || !last.ActiveContextID.IsZero() || last.SourceSequence != 0 || last.SourceReceiptID != first.SourceReceiptID || last.RetainUntil != first.RetainUntil {
		t.Fatal("cancellation refunded or advanced", last)
	}
	next := c
	next.Plan.ClientTransportPublicKey = f.Public(47)
	next = modelAdmissionResign(t, next)
	if e := s.ValidateNext(modelAdmissionEntry(t, g, s, next, AdmissionAdmit, nil)); e != ErrAdmissionBudget {
		t.Fatal("budget was refunded", e)
	}
}
func TestAdmissionReferenceRejectsReuseAndWeakQuorum(t *testing.T) {
	c := modelAdmissionContext(t, 4, 2)
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := g.ID()
	s, e := NewAdmissionState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	entry := modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil)
	q := modelAdmissionCertificate(t, entry)
	before := s.Snapshot()
	weak := q
	weak.Votes = weak.Votes[:2]
	if e := s.Apply(weak); e == nil {
		t.Fatal("weak quorum applied")
	}
	if s.Snapshot() != before {
		t.Fatal("invalid quorum mutated state")
	}
	if e := s.Apply(q); e != nil {
		t.Fatal(e)
	}
	closure := modelAdmissionUnclaimed(t, c)
	if e := s.Apply(modelAdmissionCertificate(t, modelAdmissionEntry(t, g, s, c, AdmissionClose, &closure))); e != nil {
		t.Fatal(e)
	}
	if e := s.ValidateNext(modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil)); e == nil {
		t.Fatal("closed context reused")
	}
	next := c
	next.Plan.ClientTransportPublicKey = f.Public(47)
	next = modelAdmissionResign(t, next)
	if e := s.Apply(modelAdmissionCertificate(t, modelAdmissionEntry(t, g, s, next, AdmissionAdmit, nil))); e != nil {
		t.Fatal("fresh job rejected", e)
	}
	if s.Snapshot().SpentOperations != 4 {
		t.Fatal("wrong budget")
	}
}
func TestAdmissionGenesisAndCodecsBindOnlyOneAssignmentNamespace(t *testing.T) {
	c := modelAdmissionContext(t, 4, 2)
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := g.ID()
	raw, e := g.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	back, e := DecodeAdmissionGenesis(raw)
	if e != nil {
		t.Fatal(e)
	}
	otherID, _ := back.ID()
	if id != otherID {
		t.Fatal("genesis round trip")
	}
	bad := g
	bad.Initial.RetainUntil++
	if _, e := bad.ID(); e == nil {
		t.Fatal("alternate initial receipt accepted")
	}
	bad = g
	bad.CustodyPolicy.MaximumProofAge++
	if _, e := bad.ID(); e == nil {
		t.Fatal("alternate policy accepted")
	}
	s, e := NewAdmissionState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	entry := modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil)
	q := modelAdmissionCertificate(t, entry)
	qr, e := q.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeAdmissionCertificate(qr)
	if e != nil || decoded.Verify(g) != nil {
		t.Fatal("QC round trip", e)
	}
	for _, b := range [][]byte{qr[:len(qr)-1], append(append([]byte{}, qr...), 0)} {
		if _, e := DecodeAdmissionCertificate(b); e == nil {
			t.Fatal("noncanonical QC")
		}
	}
	q.Votes[1] = q.Votes[0]
	if _, e := q.CanonicalBytes(); e == nil {
		t.Fatal("duplicate witness")
	}
}
func FuzzAdmissionDecoders(fz *testing.F) {
	c := modelAdmissionContext(fz, 4, 2)
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		fz.Fatal(e)
	}
	id, _ := g.ID()
	s, e := NewAdmissionState(g, id)
	if e != nil {
		fz.Fatal(e)
	}
	entry := modelAdmissionEntry(fz, g, s, c, AdmissionAdmit, nil)
	q := modelAdmissionCertificate(fz, entry)
	closure := modelAdmissionUnclaimed(fz, c)
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{g, entry, q, q.Votes[0], closure} {
		b, e := v.CanonicalBytes()
		if e != nil {
			fz.Fatal(e)
		}
		fz.Add(b)
	}
	fz.Fuzz(func(t *testing.T, b []byte) {
		if x, e := DecodeAdmissionGenesis(b); e == nil {
			again, _ := x.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("genesis")
			}
		}
		if x, e := DecodeAdmissionEntry(b); e == nil {
			again, _ := x.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("entry")
			}
		}
		if x, e := DecodeAdmissionCertificate(b); e == nil {
			again, _ := x.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("certificate")
			}
		}
		if x, e := DecodeAdmissionVote(b); e == nil {
			again, _ := x.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("vote")
			}
		}
		if x, e := DecodeAdmissionClosure(b); e == nil {
			again, _ := x.CanonicalBytes()
			if !bytes.Equal(b, again) {
				t.Fatal("closure")
			}
		}
	})
}

func TestAdmissionCanonicalVectors(t *testing.T) {
	c := modelAdmissionContext(t, 4, 2)
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := g.ID()
	s, e := NewAdmissionState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	entry := modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil)
	cert := modelAdmissionCertificate(t, entry)
	gid, _ := g.ID()
	descriptor, _ := g.DescriptorID()
	eid, _ := entry.ID()
	cid, _ := cert.ID()
	raw, _ := cert.Votes[0].CanonicalBytes()
	for name, vector := range map[string]struct {
		actual   types.Hash
		expected string
	}{
		"genesis":     {gid, "9933c7dfcbc1f0eec894011c9131c4403b1fcb3fbef791802c31f07c010a783f"},
		"descriptor":  {descriptor, "931d107b2a0d33755274df6a72035609e1735c97ba020b27f69ff1c1515dd011"},
		"entry":       {eid, "cbb1995ba9ccdfb4ee73450f657d8143cada923369b75bc57bfe3a4984e2a162"},
		"certificate": {cid, "0c4e0e70f17a7b71d4eac6ac7618f6cfa49ed99eef3dc76d1512d0210c77743b"},
		"vote":        {types.DomainHash("OMESH/test/admission/vote/vector", raw), "0f6f7bbbba85f60c80d4994cdd44ba70743d87de8e7b6ac093d389a5578e6cf2"},
	} {
		if vector.actual.String() != vector.expected {
			t.Fatalf("%s vector changed: %s", name, vector.actual)
		}
	}
}

func TestAdmissionReferenceFulfilledAdvancesExactSource(t *testing.T) {
	c := modelAdmissionContext(t, 4, 2)
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := g.ID()
	s, e := NewAdmissionState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Apply(modelAdmissionCertificate(t, modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil))); e != nil {
		t.Fatal(e)
	}
	x := fixtureWithContext(t, c)
	target := x.target(t, "target")
	a := x.acceptor(t)
	serve := fulfilledServe(t, x, target, a)
	ar, e := a.ApplyServe(t.Context(), serve, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	br, e := target.ApplyServe(t.Context(), serve, ar, c.Plan.Challenge.IssuedAt, false)
	if e != nil {
		t.Fatal(e)
	}
	closure := AdmissionClosure{Serve: serve, A: ar, B: br}
	held := s.Snapshot()
	missing := closure
	missing.B = ServeReceipt{}
	invalid := modelAdmissionCertificate(t, modelAdmissionEntry(t, g, s, c, AdmissionClose, &closure))
	invalid.Entry.Closure = &missing
	if e := s.Apply(invalid); e == nil {
		t.Fatal("missing B application closed active budget")
	}
	if s.Snapshot() != held {
		t.Fatal("missing B application changed active/spent state")
	}
	wrong := c
	wrong.Plan.ClientTransportPublicKey = f.Public(48)
	wrong = modelAdmissionResign(t, wrong)
	wrongClosure := modelAdmissionUnclaimed(t, wrong)
	wrongClose := modelAdmissionEntry(t, g, s, wrong, AdmissionClose, &wrongClosure)
	if e := s.Apply(modelAdmissionCertificate(t, wrongClose)); e == nil {
		t.Fatal("another valid context closed active budget")
	}
	if s.Snapshot() != held {
		t.Fatal("wrong-context closure changed active/spent state")
	}
	if e := s.Apply(modelAdmissionCertificate(t, modelAdmissionEntry(t, g, s, c, AdmissionClose, &closure))); e != nil {
		t.Fatal(e)
	}
	snap := s.Snapshot()
	bundle, _, e := serve.Proposal.fulfilled()
	if e != nil {
		t.Fatal(e)
	}
	head, _ := bundle.Result.Entry.ID()
	renewed := bundle.Result.Entry.Record.RenewedReceipt
	rid, _ := renewed.ID()
	if snap.SourceSequence != 1 || snap.SourceHeadID != head || snap.SourceReceiptID != rid || snap.CurrentReceipt != renewed || snap.RetainUntil != renewed.RetainUntil || snap.PendingOperations != 0 || snap.SpentOperations != 2 {
		t.Fatal("wrong fulfilled cursor", snap)
	}
	if e := s.ValidateNext(modelAdmissionEntry(t, g, s, c, AdmissionAdmit, nil)); e == nil {
		t.Fatal("fulfilled context was readmitted")
	}
	if s.Snapshot() != snap {
		t.Fatal("readmission attempt changed settled history")
	}
	stale := c
	stale.Plan.ClientTransportPublicKey = f.Public(47)
	stale = modelAdmissionResign(t, stale)
	if e := s.ValidateNext(modelAdmissionEntry(t, g, s, stale, AdmissionAdmit, nil)); e == nil {
		t.Fatal("old source admitted after fulfillment")
	}
	next := c
	next.Previous = renewed
	challenge, e := workarchive.CreateCustodyChallenge(c.Manifest, renewed, f.Key(3), renewed.StoredAt+1, 60, 1, renewed.RetainUntil+3600)
	if e != nil {
		t.Fatal(e)
	}
	next.Plan.Challenge = challenge
	intent := &next.Plan.Intent
	intent.PriorSequence = 1
	intent.PriorHeadID = head
	intent.PriorReceiptID = rid
	intent.IssuedAt = challenge.IssuedAt
	intent.ExpiresAt = challenge.ExpiresAt
	intent.RenewUntil = challenge.RenewUntil
	intent.RequestedSamples = challenge.RequestedSamples
	intent.Nonce = challenge.Nonce
	next = modelAdmissionResign(t, next)
	if e := s.Apply(modelAdmissionCertificate(t, modelAdmissionEntry(t, g, s, next, AdmissionAdmit, nil))); e != nil {
		t.Fatal("current exact successor rejected", e)
	}
}
