package protectedtest

// These helpers create only the selected local source. A WAN campaign exchanges
// public observations, selection and descriptors; it never relocates a live
// owner, copies its private tree, or manufactures a second admission history.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	reg "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type DistributedDraft struct {
	Proposal cut.Proposal
	A, B     cut.SourceLocation
}

func DistributedSeed(t testing.TB, private, fixture string) DistributedDraft {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(fixture, "context"))
	Require(t, e)
	c, e := v2.DecodeContext(raw)
	Require(t, e)
	raw, e = c.Initial.CanonicalBytes()
	Require(t, e)
	now := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(raw[len(raw)-112:len(raw)-104], now-10)
	binary.BigEndian.PutUint64(raw[len(raw)-104:len(raw)-96], now+10000)
	h := types.DomainHash("OMESH/workgraph/archive/replica-receipt/signature/v0", raw[:len(raw)-64])
	copy(raw[len(raw)-64:], ed25519.Sign(f.Key(61), h[:]))
	initial, e := workarchive.DecodeReplicaReceipt(raw)
	Require(t, e)
	// Explicit test policy, established before any source, provides enough time
	// for cold CLI steps over SSH. No runtime clock or proof is rewritten.
	c.CustodyPolicy.MaximumChallengeLifetime = 600
	c.CustodyPolicy.MaximumProofAge = 600
	old, e := workarchive.CreateRemoteCustodyAuthorityAssignment(c.Manifest, initial, c.CustodyPolicy, f.Hash(private+"old"), f.Public(1), c.Assignment.Base.Consumers, 8, 2, f.Public(14), f.Public(15))
	Require(t, e)
	aid, _ := old.ID()
	evidence := cut.Evidence{Version: 1, Assignment: old, Manifest: c.Manifest, Initial: initial, Policy: c.CustodyPolicy}
	previous := aid
	for i, kind := range []a.Kind{a.Stop, a.Retire} {
		cmd := a.Command{Version: 1, AssignmentID: aid, ExpectedSequence: uint64(i), ExpectedHead: previous, Kind: kind, EvidenceID: f.Hash("stop")}
		if kind == a.Retire {
			cmd.EvidenceID = previous
		}
		cmd, e = cmd.Sign(f.Key(1))
		Require(t, e)
		entry, e := a.SignEntry(cmd, f.Key(1))
		Require(t, e)
		evidence.History = append(evidence.History, entry)
		previous, _ = entry.ID()
	}
	evidence.End = a.Position{Sequence: 2, HeadID: previous}
	registry := reg.Genesis{Version: 2, NetworkID: old.NetworkID, ChainGenesisID: old.GenesisID, ResourceID: f.Hash(private + "resource"), Issuer: f.Public(110), Threshold: 3, MaximumOperations: 8, MaximumPending: 2}
	for _, seed := range []byte{111, 112, 113, 114} {
		registry.Witnesses = append(registry.Witnesses, f.Public(seed))
	}
	sort.Slice(registry.Witnesses, func(i, j int) bool { return bytes.Compare(registry.Witnesses[i][:], registry.Witnesses[j][:]) < 0 })
	p := cut.Proposal{Version: 1, Anchor: registry, Evidence: evidence, Allowance: 4, Successor: cut.Blueprint{Version: 1, IncarnationID: f.Hash(private + "successor"), Authority: f.Public(101), Control: f.Public(102), Transport: f.Public(103), Threshold: 3, MaximumPending: 2}}
	for _, seed := range []byte{70, 71, 72, 73} {
		p.Successor.Witnesses = append(p.Successor.Witnesses, f.Public(seed))
	}
	sort.Slice(p.Successor.Witnesses, func(i, j int) bool {
		return bytes.Compare(p.Successor.Witnesses[i][:], p.Successor.Witnesses[j][:]) < 0
	})
	return DistributedDraft{p, cut.SourceLocation{Role: cut.Authority, Journal: filepath.Join(private, "a-source"), Authority: filepath.Join(private, "a-authority"), AuthorityPins: filepath.Join(private, "a-pins")}, cut.SourceLocation{Role: cut.Target, Journal: filepath.Join(private, "b-source")}}
}
func DistributedSource(t testing.TB, d DistributedDraft, role, objectsPath, fixture string) cut.Observation {
	t.Helper()
	p := d.Proposal
	l := d.A
	seed := byte(1)
	if role == "b" {
		l = d.B
		seed = 14
	} else if role != "a" {
		t.Fatal("role")
	}
	// Explicit first creation only. Existing sources cannot be reset/reused.
	if _, e := os.Lstat(l.Journal); !os.IsNotExist(e) {
		t.Fatal("source already exists", e)
	}
	aid, _ := p.Evidence.Assignment.ID()
	rid, _ := p.Anchor.ID()
	if role == "a" {
		owner, e := store.CreateCoordinatedAuthority(l.Authority, l.AuthorityPins, p.Evidence.Assignment, aid)
		Require(t, e)
		for _, entry := range p.Evidence.History {
			_, e = owner.Append(t.Context(), entry)
			Require(t, e)
		}
		Require(t, owner.Close())
	}
	_, _, e := workarchive.OpenOrCreateCustodyJournal(l.Journal, p.Evidence.Manifest, p.Evidence.Initial, p.Evidence.Policy)
	Require(t, e)
	if role == "b" {
		objects, e := workarchive.OpenObjectStore(objectsPath, workarchive.DefaultObjectStorePolicy())
		Require(t, e)
		for _, ch := range p.Evidence.Manifest.Chunks {
			b, e := os.ReadFile(filepath.Join(fixture, ch.ID.String()))
			Require(t, e)
			_, e = objects.Put(p.Evidence.Manifest, ch.ID, b)
			Require(t, e)
		}
	}
	placement, _ := l.LocationID()
	o, e := cut.CaptureSource(t.Context(), p.Evidence, aid, rid, p.Evidence.End, l, placement, f.Hash(l.Journal+"observation"), f.Key(seed), func(cut.Observation) error { return nil })
	Require(t, e)
	return o
}
func DistributedSelection(t testing.TB, d DistributedDraft, aa, bb cut.Observation) (v2.AdmissionGenesis, v2.EnrollmentBinding) {
	t.Helper()
	p := d.Proposal
	p.A = aa
	p.B = bb
	rid, _ := p.Anchor.ID()
	rdid, _ := p.Anchor.DescriptorID()
	aid, _ := p.Evidence.Assignment.ID()
	var e error
	for _, v := range []struct {
		role string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		p, e = p.Sign(rid, rdid, aid, p.Evidence.End, v.role, f.Key(v.seed))
		Require(t, e)
	}
	pid, _ := p.ID()
	g, e := v2.NewImportedAdmissionGenesis(p, v2.ImportPins{RegistryID: rid, RegistryDescriptorID: rdid, LegacyID: aid, Retirement: p.Evidence.End, ProposalID: pid})
	Require(t, e)
	raw, _ := g.CanonicalBytes()
	selection := reg.Selection{Version: 3, RegistryID: rid, DescriptorID: rdid, Candidate: raw}
	for _, v := range []struct {
		role string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		selection, e = selection.Sign(v.role, f.Key(v.seed))
		Require(t, e)
	}
	sid, _ := selection.ID()
	cert := reg.Certificate{Version: 3, Selection: selection}
	for _, seed := range []byte{111, 112, 113} {
		vote, e := (reg.Vote{Version: 3, RegistryID: rid, DescriptorID: rdid, SelectionID: sid}).Sign(p.Anchor, f.Key(seed))
		Require(t, e)
		cert.Votes = append(cert.Votes, vote)
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	raw, e = cert.CanonicalBytes()
	Require(t, e)
	return g, v2.EnrollmentBinding{Version: 5, Registry: p.Anchor, Certificate: raw}
}
