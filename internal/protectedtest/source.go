// Package protectedtest builds fresh, small retired-source fixtures using the
// committed public archive. No deployment keys or existing owners are loaded.
package protectedtest

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

type Source struct {
	Root, Objects string
	Genesis       v2.AdmissionGenesis
	Enrollment    v2.EnrollmentBinding
	A, B          cut.SourceLocation
	AP, BP        cut.SourceHandoffPins
	Pair          cut.SourceHandoffPair
	Template      v2.Context
}

func Require(t testing.TB, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func New(t testing.TB) Source {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	Require(t, e)
	repo, e := os.Getwd()
	Require(t, e)
	for {
		if _, e = os.Stat(filepath.Join(repo, "go.mod")); e == nil {
			break
		}
		parent := filepath.Dir(repo)
		if parent == repo {
			t.Fatal("repository fixture not found")
		}
		repo = parent
	}
	fixture := filepath.Join(repo, "node/custodyv2/testdata/public-fixture")
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
	old, e := workarchive.CreateRemoteCustodyAuthorityAssignment(c.Manifest, initial, c.CustodyPolicy, f.Hash(root+"old"), f.Public(1), c.Assignment.Base.Consumers, 8, 2, f.Public(14), f.Public(15))
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
	aa := cut.SourceLocation{Role: cut.Authority, Journal: filepath.Join(root, "a-source"), Authority: filepath.Join(root, "a-authority"), AuthorityPins: filepath.Join(root, "a-pins")}
	bb := cut.SourceLocation{Role: cut.Target, Journal: filepath.Join(root, "b-source")}
	owner, e := store.CreateCoordinatedAuthority(aa.Authority, aa.AuthorityPins, old, aid)
	Require(t, e)
	for _, entry := range evidence.History {
		_, e = owner.Append(t.Context(), entry)
		Require(t, e)
	}
	Require(t, owner.Close())
	for _, l := range []cut.SourceLocation{aa, bb} {
		_, _, e = workarchive.OpenOrCreateCustodyJournal(l.Journal, c.Manifest, initial, c.CustodyPolicy)
		Require(t, e)
	}
	objectsPath := filepath.Join(root, "objects")
	objects, e := workarchive.OpenObjectStore(objectsPath, workarchive.DefaultObjectStorePolicy())
	Require(t, e)
	for _, ch := range c.Manifest.Chunks {
		b, e := os.ReadFile(filepath.Join(fixture, ch.ID.String()))
		Require(t, e)
		_, e = objects.Put(c.Manifest, ch.ID, b)
		Require(t, e)
	}
	registry := reg.Genesis{Version: 2, NetworkID: old.NetworkID, ChainGenesisID: old.GenesisID, ResourceID: f.Hash(root + "resource"), Issuer: f.Public(110), Threshold: 3, MaximumOperations: 8, MaximumPending: 2}
	for _, seed := range []byte{111, 112, 113, 114} {
		registry.Witnesses = append(registry.Witnesses, f.Public(seed))
	}
	sort.Slice(registry.Witnesses, func(i, j int) bool { return bytes.Compare(registry.Witnesses[i][:], registry.Witnesses[j][:]) < 0 })
	rid, _ := registry.ID()
	rdid, _ := registry.DescriptorID()
	p := cut.Proposal{Version: 1, Anchor: registry, Evidence: evidence, Allowance: 4, Successor: cut.Blueprint{Version: 1, IncarnationID: f.Hash(root + "successor"), Authority: f.Public(101), Control: f.Public(102), Transport: f.Public(103), Threshold: 3, MaximumPending: 2}}
	for _, seed := range []byte{70, 71, 72, 73} {
		p.Successor.Witnesses = append(p.Successor.Witnesses, f.Public(seed))
	}
	sort.Slice(p.Successor.Witnesses, func(i, j int) bool {
		return bytes.Compare(p.Successor.Witnesses[i][:], p.Successor.Witnesses[j][:]) < 0
	})
	ap, e := aa.LocationID()
	Require(t, e)
	bp, e := bb.LocationID()
	Require(t, e)
	for _, v := range []struct {
		l         cut.SourceLocation
		placement types.Hash
		seed      byte
		dst       *cut.Observation
	}{{aa, ap, 1, &p.A}, {bb, bp, 14, &p.B}} {
		o, e := cut.CaptureSource(t.Context(), evidence, aid, rid, evidence.End, v.l, v.placement, f.Hash(root+"observation"), f.Key(v.seed), func(cut.Observation) error { return nil })
		Require(t, e)
		*v.dst = o
	}
	for _, v := range []struct {
		role string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		p, e = p.Sign(rid, rdid, aid, evidence.End, v.role, f.Key(v.seed))
		Require(t, e)
	}
	pid, _ := p.ID()
	g, e := v2.NewImportedAdmissionGenesis(p, v2.ImportPins{RegistryID: rid, RegistryDescriptorID: rdid, LegacyID: aid, Retirement: evidence.End, ProposalID: pid})
	Require(t, e)
	raw, _ = g.CanonicalBytes()
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
		vote, e := (reg.Vote{Version: 3, RegistryID: rid, DescriptorID: rdid, SelectionID: sid}).Sign(registry, f.Key(seed))
		Require(t, e)
		cert.Votes = append(cert.Votes, vote)
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	raw, e = cert.CanonicalBytes()
	Require(t, e)
	enrollment := v2.EnrollmentBinding{Version: 5, Registry: registry, Certificate: raw}
	gid, _ := g.ID()
	gdid, _ := g.DescriptorID()
	bid, _ := enrollment.ID()
	aPins := cut.SourceHandoffPins{GenesisID: gid, GenesisDescriptorID: gdid, EnrollmentID: bid, PlacementID: ap}
	bPins := aPins
	bPins.PlacementID = bp
	ah, _, e := cut.TransferSourceHandoff(t.Context(), g, enrollment, aPins, aa)
	Require(t, e)
	bh, _, e := cut.TransferSourceHandoff(t.Context(), g, enrollment, bPins, bb)
	Require(t, e)
	return Source{Root: root, Objects: objectsPath, Genesis: g, Enrollment: enrollment, A: aa, B: bb, AP: aPins, BP: bPins, Pair: cut.SourceHandoffPair{A: ah, B: bh}, Template: c}
}
