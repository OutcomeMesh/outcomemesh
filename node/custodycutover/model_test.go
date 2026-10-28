package custodycutover

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	w "github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	s "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func signEntry(t testing.TB, c a.Command, seed byte) a.Entry {
	t.Helper()
	cmd, err := c.Sign(f.Key(seed))
	if err != nil {
		t.Fatal(err)
	}
	e, err := a.SignEntry(cmd, f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func publicContext(t testing.TB) v2.Context {
	t.Helper()
	raw, err := os.ReadFile("../custodyv2/testdata/public-fixture/context")
	if err != nil {
		t.Fatal(err)
	}
	c, err := v2.DecodeContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func appendFixture(t testing.TB, e *Evidence, c a.Command, seed byte) a.Entry {
	t.Helper()
	id, _ := e.Assignment.ID()
	c.Version = a.Version1
	c.AssignmentID = id
	c.ExpectedSequence = uint64(len(e.History))
	c.ExpectedHead = id
	if len(e.History) > 0 {
		c.ExpectedHead, _ = e.History[len(e.History)-1].ID()
	}
	entry := signEntry(t, c, seed)
	e.History = append(e.History, entry)
	e.End = a.Position{Sequence: uint64(len(e.History))}
	e.End.HeadID, _ = entry.ID()
	return entry
}
func retireFixture(t testing.TB, e *Evidence) {
	t.Helper()
	stop := appendFixture(t, e, a.Command{Kind: a.Stop, EvidenceID: f.Hash("stop-review")}, 1)
	id, _ := stop.ID()
	appendFixture(t, e, a.Command{Kind: a.Retire, EvidenceID: id}, 1)
}
func evidenceFixture(t testing.TB, active bool) Evidence {
	t.Helper()
	c := publicContext(t)
	e := Evidence{Version: Version1, Assignment: c.Assignment.Base, Manifest: c.Manifest, Initial: c.Initial, Policy: c.CustodyPolicy}
	if active {
		// A real signed archive record, produced at the fixture's historical instant.
		root := t.TempDir()
		objects, err := workarchive.OpenObjectStore(filepath.Join(root, "objects"), workarchive.DefaultObjectStorePolicy())
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range c.Manifest.Chunks {
			raw, err := os.ReadFile(filepath.Join("../custodyv2/testdata/public-fixture", chunk.ID.String()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = objects.Put(c.Manifest, chunk.ID, raw); err != nil {
				t.Fatal(err)
			}
		}
		_, _, err = workarchive.OpenOrCreateCustodyJournal(filepath.Join(root, "journal"), c.Manifest, c.Initial, c.CustodyPolicy)
		if err != nil {
			t.Fatal(err)
		}
		scope, err := c.Scope()
		if err != nil {
			t.Fatal(err)
		}
		pin, _ := scope.ID()
		sources := v2.Sources{Journal: filepath.Join(root, "journal"), Objects: filepath.Join(root, "objects")}
		targetPath := filepath.Join(root, "target")
		if err = v2.CreateTarget(targetPath, c, pin, sources); err != nil {
			t.Fatal(err)
		}
		target, err := v2.OpenTarget(targetPath, c, pin, sources, f.Key(61), f.Key(14))
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := target.Prepare()
		if err != nil {
			t.Fatal(err)
		}
		result, err := target.Execute(t.Context(), f.Certificate(candidate.Claim, 70, 71, 72), c.Plan.Challenge.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		if err = target.Close(); err != nil {
			t.Fatal(err)
		}
		id, _ := e.Assignment.ID()
		intent := c.Plan.Intent
		intent.AssignmentID = id
		iid, _ := intent.ID()
		audit := appendFixture(t, &e, a.Command{Kind: a.Admit, Purpose: a.Audit, OperationID: iid}, 4)
		cid, _ := c.Plan.Challenge.ID()
		serve := appendFixture(t, &e, a.Command{Kind: a.Admit, Purpose: a.Serve, OperationID: cid}, 4)
		rid, _ := e.Initial.ID()
		plan := w.Plan{AssignmentID: id, Admission: serve, AuthorityTransportPublicKey: f.Public(16), AuditorTransportPublicKey: f.Public(46), PriorReceiptID: rid, Nonce: f.Hash("plan-review")}
		pid, _ := plan.ID()
		draft, err := a.BuildRemoteBeginCommand(e.Assignment, serve, pid, e.End)
		if err != nil {
			t.Fatal(err)
		}
		begin := appendFixture(t, &e, draft, 14)
		bid, _ := begin.ID()
		entryID, _ := result.Entry.ID()
		seal := w.Seal{PlanID: pid, BeginID: bid, SealingID: f.Hash("sealing-review"), Disposition: w.RetainedResult, ResultID: entryID}
		sid, _ := seal.ID()
		draft, err = a.BuildRemoteDrainedCommand(e.Assignment, begin, sid, e.End)
		if err != nil {
			t.Fatal(err)
		}
		drained := appendFixture(t, &e, draft, 14)
		terminal := s.RemoteCustodyTerminal{PlanID: pid, BeginID: bid, AuditAdmission: audit, Intent: intent, Seal: seal, Drained: drained, Entry: result.Entry}
		cycle := Cycle{Plan: plan, Begin: begin, Terminal: terminal}
		e.Cycles = []Cycle{cycle}
		for _, ticket := range []a.Entry{audit, serve} {
			tid, _ := ticket.ID()
			draft, err = s.BuildRemoteCustodyCompleteCommand(e.Scope(cycle), terminal, tid, e.End)
			if err != nil {
				t.Fatal(err)
			}
			appendFixture(t, &e, draft, 4)
		}
	}
	retireFixture(t, &e)
	id, _ := e.Assignment.ID()
	if _, err := e.Verify(id, e.End); err != nil {
		t.Fatal("fixture", err)
	}
	return e
}
func cloneEvidence(t testing.TB, e Evidence) Evidence {
	t.Helper()
	raw, err := e.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecodeEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func testWitnesses(first byte) [][32]byte {
	var keys [][32]byte
	for i := first; i < first+4; i++ {
		keys = append(keys, f.Public(i))
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	return keys
}
func proposalFixture(t testing.TB, e Evidence) (Proposal, Pins) {
	t.Helper()
	anchor := wire.Genesis{Version: 2, NetworkID: e.Assignment.NetworkID, ChainGenesisID: e.Assignment.GenesisID, ResourceID: f.Hash("legacy-resource"), Issuer: f.Public(110), Threshold: 3, Witnesses: testWitnesses(111), MaximumOperations: e.Assignment.MaximumOperations, MaximumPending: e.Assignment.MaximumPending}
	aid, _ := anchor.ID()
	did, _ := anchor.DescriptorID()
	lid, _ := e.Assignment.ID()
	assessment, err := e.Verify(lid, e.End)
	if err != nil {
		t.Fatal(err)
	}
	eid, _ := e.ID()
	observation := func(role Role, seed byte) Observation {
		o := Observation{Version: Version1, EvidenceID: eid, AssignmentID: lid, RetirementID: e.End.HeadID, SourceHeadID: assessment.SourceHeadID, SourceSequence: assessment.SourceSequence, ReceiptID: assessment.ReceiptID, MinimumRetainUntil: assessment.MinimumRetainUntil, Role: role, PlacementCommitment: f.Hash(string(rune('a' + role))), Nonce: f.Hash("source-observation-nonce"), AnchorID: aid}
		o, err = o.Sign(e, aid, f.Key(seed))
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	p := Proposal{Version: Version1, Anchor: anchor, Evidence: e, A: observation(Authority, 1), B: observation(Target, 14), Successor: Blueprint{Version: Version1, IncarnationID: f.Hash("successor-incarnation"), Authority: f.Public(101), Control: f.Public(102), Transport: f.Public(103), Threshold: 3, Witnesses: testWitnesses(70), MaximumPending: 2}, Allowance: assessment.RemainingOperations}
	for _, r := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		p, err = p.Sign(aid, did, lid, e.End, r.name, f.Key(r.seed))
		if err != nil {
			t.Fatal("sign", r.name, err)
		}
	}
	pid, _ := p.ID()
	return p, Pins{AnchorID: aid, DescriptorID: did, LegacyID: lid, Retired: e.End, ProposalID: pid}
}
func TestRemoteCutoverCompleteHistoryRetainsSpentBudget(t *testing.T) {
	e := evidenceFixture(t, true)
	id, _ := e.Assignment.ID()
	v, err := e.Verify(id, e.End)
	if err != nil || v.SpentOperations != 2 || v.RemainingOperations != e.Assignment.MaximumOperations-2 || v.SourceSequence != 1 {
		t.Fatal(v, err)
	}
	p, pins := proposalFixture(t, e)
	b, err := p.Verify(pins.AnchorID, pins.DescriptorID, id, e.End)
	if err != nil || b.Spent != 2 || b.ActivationAllowed || b.WholeJobs != p.Allowance/2 {
		t.Fatal(b, err)
	}
	if b.MinimumRetainUntil != v.CurrentReceipt.RetainUntil {
		t.Fatal("retention shortened")
	}
	p.Allowance++
	if _, err = p.ValidateDraft(pins.AnchorID, pins.DescriptorID, id, e.End); err == nil {
		t.Fatal("spent operations refunded")
	}
}
func TestRemoteCutoverRejectsIncompleteOpaqueAndSubstitutedEvidence(t *testing.T) {
	original := evidenceFixture(t, true)
	id, _ := original.Assignment.ID()
	cases := map[string]func(*Evidence){
		"omitted_cycle":    func(e *Evidence) { e.Cycles = nil },
		"duplicated_cycle": func(e *Evidence) { e.Cycles = append(e.Cycles, e.Cycles[0]) },
		"short_prefix": func(e *Evidence) {
			e.History = e.History[:len(e.History)-1]
			e.End.Sequence--
			e.End.HeadID, _ = e.History[len(e.History)-1].ID()
		},
		"source_sequence":  func(e *Evidence) { e.Cycles[0].Plan.PriorSequence++ },
		"terminal_receipt": func(e *Evidence) { e.Cycles[0].Terminal.Entry.Record.RenewedReceipt.RetainUntil++ },
		"opaque_completion": func(e *Evidence) {
			e.History = e.History[:4]
			for _, ticket := range []a.Entry{e.Cycles[0].Terminal.AuditAdmission, e.Cycles[0].Plan.Admission} {
				tid, _ := ticket.ID()
				appendFixture(t, e, a.Command{Kind: a.Complete, TicketID: tid, EvidenceID: f.Hash("opaque")}, 4)
			}
			retireFixture(t, e)
		},
		"unmatched_completed_operation": func(e *Evidence) {
			e.History = e.History[:6]
			admit := appendFixture(t, e, a.Command{Kind: a.Admit, Purpose: a.Audit, OperationID: f.Hash("extra")}, 4)
			tid, _ := admit.ID()
			appendFixture(t, e, a.Command{Kind: a.Complete, TicketID: tid, EvidenceID: f.Hash("opaque")}, 4)
			retireFixture(t, e)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := cloneEvidence(t, original)
			mutate(&e)
			if _, err := e.Verify(id, e.End); err == nil {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
	if _, err := original.Verify(f.Hash("substitute assignment"), original.End); err == nil {
		t.Fatal("wrong independent assignment accepted")
	}
	if _, err := original.Verify(id, a.Position{Sequence: original.End.Sequence, HeadID: f.Hash("wrong pin")}); err == nil {
		t.Fatal("wrong retirement accepted")
	}
}
func TestRemoteCutoverProposalBindsRolesLimitsAndHistory(t *testing.T) {
	p, pins := proposalFixture(t, evidenceFixture(t, false))
	raw, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Proposal){"allowance": func(p *Proposal) { p.Allowance++ }, "retention": func(p *Proposal) { p.B.MinimumRetainUntil-- }, "observation_role": func(p *Proposal) { p.B.Role = Authority }, "same_placement": func(p *Proposal) { p.B.PlacementCommitment = p.A.PlacementCommitment }, "descriptor": func(p *Proposal) { p.Anchor.MaximumOperations++ }, "issuer_job_key": func(p *Proposal) { p.Successor.Authority = p.Anchor.Issuer }, "old_job_witness": func(p *Proposal) { p.Successor.Witnesses = testWitnesses(1) }, "nonce_reuse": func(p *Proposal) { p.Successor.IncarnationID = p.Evidence.Assignment.IncarnationID }, "pending_expansion": func(p *Proposal) { p.Successor.MaximumPending++ }, "issuer_signature": func(p *Proposal) { p.IssuerSignature[0] ^= 1 }, "authority_signature": func(p *Proposal) { p.AuthoritySignature[0] ^= 1 }, "control_signature": func(p *Proposal) { p.ControlSignature[0] ^= 1 }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := DecodeProposal(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&v)
			if _, err = v.Verify(pins.AnchorID, pins.DescriptorID, pins.LegacyID, pins.Retired); err == nil {
				t.Fatal("substituted proposal accepted")
			}
		})
	}
	if _, err = p.Sign(pins.AnchorID, pins.DescriptorID, pins.LegacyID, pins.Retired, "authority", f.Key(14)); err == nil {
		t.Fatal("wrong key signed")
	}
	badKey := f.Key(1)
	badKey[63] ^= 1
	if _, err = p.Sign(pins.AnchorID, pins.DescriptorID, pins.LegacyID, pins.Retired, "authority", badKey); err == nil {
		t.Fatal("inconsistent private key accepted")
	}
	if _, err = v2.DecodeContext(raw); err == nil {
		t.Fatal("disabled proposal decoded as runtime context")
	}
	if _, err = wire.DecodeSelection(raw); err == nil {
		t.Fatal("disabled proposal decoded as registry selection")
	}
}

func TestRemoteCutoverMultipleCompletedCyclesRequireEntireSourceLineage(t *testing.T) {
	e := evidenceFixture(t, true)
	e.History = e.History[:6]
	e.End.Sequence = 6
	e.End.HeadID, _ = e.History[5].ID()
	prior := e.Cycles[0].Terminal.Entry
	previous := prior.Record.RenewedReceipt
	head, _ := prior.ID()
	rid, _ := previous.ID()
	lid, _ := e.Assignment.ID()
	objects, err := workarchive.OpenObjectStore(filepath.Join(t.TempDir(), "objects"), workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range e.Manifest.Chunks {
		raw, err := os.ReadFile(filepath.Join("../custodyv2/testdata/public-fixture", chunk.ID.String()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = objects.Put(e.Manifest, chunk.ID, raw); err != nil {
			t.Fatal(err)
		}
	}
	now := previous.StoredAt + 1
	challenge, err := workarchive.CreateCustodyChallenge(e.Manifest, previous, f.Key(3), now, 1, prior.Record.Challenge.RequestedSamples, previous.RetainUntil+1)
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := workarchive.AnswerCustodyChallenge(objects, e.Manifest, previous, challenge, e.Policy, f.Key(61), now)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := workarchive.RenewReplicaReceipt(e.Manifest, previous, challenge, batch, proof, e.Policy, f.Key(61), now)
	if err != nil {
		t.Fatal(err)
	}
	entry := workarchive.CustodyJournalEntry{Sequence: 2, PreviousEntryID: head, PreviousReceipt: previous, Record: workarchive.CustodyRecord{Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}}
	intent := e.Cycles[0].Terminal.Intent
	intent.PriorSequence = 1
	intent.PriorHeadID = head
	intent.PriorReceiptID = rid
	intent.Nonce = challenge.Nonce
	intent.IssuedAt = challenge.IssuedAt
	intent.ExpiresAt = challenge.ExpiresAt
	intent.RenewUntil = challenge.RenewUntil
	iid, _ := intent.ID()
	audit := appendFixture(t, &e, a.Command{Kind: a.Admit, Purpose: a.Audit, OperationID: iid}, 4)
	cid, _ := challenge.ID()
	serve := appendFixture(t, &e, a.Command{Kind: a.Admit, Purpose: a.Serve, OperationID: cid}, 4)
	plan := w.Plan{AssignmentID: lid, Admission: serve, AuthorityTransportPublicKey: f.Public(16), AuditorTransportPublicKey: f.Public(46), PriorSequence: 1, PriorHeadID: head, PriorReceiptID: rid, Nonce: f.Hash("second legacy cycle")}
	pid, _ := plan.ID()
	draft, err := a.BuildRemoteBeginCommand(e.Assignment, serve, pid, e.End)
	if err != nil {
		t.Fatal(err)
	}
	begin := appendFixture(t, &e, draft, 14)
	bid, _ := begin.ID()
	eid, err := entry.ID()
	if err != nil {
		t.Fatal(err)
	}
	seal := w.Seal{PlanID: pid, BeginID: bid, SealingID: f.Hash("second seal"), Disposition: w.RetainedResult, ResultID: eid}
	sid, _ := seal.ID()
	draft, err = a.BuildRemoteDrainedCommand(e.Assignment, begin, sid, e.End)
	if err != nil {
		t.Fatal(err)
	}
	drained := appendFixture(t, &e, draft, 14)
	terminal := s.RemoteCustodyTerminal{PlanID: pid, BeginID: bid, AuditAdmission: audit, Intent: intent, Seal: seal, Drained: drained, Entry: entry}
	cycle := Cycle{Plan: plan, Begin: begin, Terminal: terminal}
	e.Cycles = append(e.Cycles, cycle)
	for _, ticket := range []a.Entry{audit, serve} {
		tid, _ := ticket.ID()
		draft, err = s.BuildRemoteCustodyCompleteCommand(e.Scope(cycle), terminal, tid, e.End)
		if err != nil {
			t.Fatal(err)
		}
		appendFixture(t, &e, draft, 4)
	}
	retireFixture(t, &e)
	assessment, err := e.Verify(lid, e.End)
	if err != nil || assessment.SpentOperations != 4 || assessment.RemainingOperations != 0 || assessment.SourceSequence != 2 || assessment.ReceiptID == rid || assessment.MinimumRetainUntil != renewed.RetainUntil {
		t.Fatal(assessment, err)
	}
	for _, mutate := range []func(*Evidence){func(e *Evidence) { e.Cycles[0], e.Cycles[1] = e.Cycles[1], e.Cycles[0] }, func(e *Evidence) { e.Cycles = e.Cycles[1:] }, func(e *Evidence) { e.Cycles[1] = e.Cycles[0] }, func(e *Evidence) { e.Cycles[1].Terminal.Entry.PreviousReceipt = e.Initial }} {
		bad := cloneEvidence(t, e)
		mutate(&bad)
		if _, err := bad.Verify(lid, bad.End); err == nil {
			t.Fatal("missing, swapped or substituted source lineage accepted")
		}
	}
}
