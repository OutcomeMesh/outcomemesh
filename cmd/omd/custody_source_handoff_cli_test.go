package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func sourceHandoffCLIInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if e := runCustodySourceHandoff(t.Context(), args, &out); e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}
func sourceHandoffCLIReviewed(t testing.TB, driver v2CLIDriver, args []string) []string {
	t.Helper()
	fields := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
	if fields["owners_opened"] != "false" || fields["keys_loaded"] != "false" || fields["execution_granted"] != "false" || fields["review_id"] == "" {
		t.Fatal(fields)
	}
	return append(append([]string{}, args...), "--mode", "run", "--expected-review-id", fields["review_id"])
}
func runSourceHandoffCLI(t *testing.T, driver v2CLIDriver) {
	legacy, evidence := cutoverAcceptedLegacy(t)
	lid, _ := evidence.Assignment.ID()
	owner, e := store.OpenCoordinator(legacy.authority, legacy.pins, evidence.Assignment, lid)
	if e != nil {
		t.Fatal(e)
	}
	state, e := owner.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	e = owner.WithConfirmedRetirement(t.Context(), state.Confirmed, cut.MaximumHistoryEntries, func(_ a.Assignment, history []a.Entry) error {
		evidence.History = history
		evidence.End = state.Confirmed
		return nil
	})
	owner.Close()
	if e != nil {
		t.Fatal(e)
	}
	registry := wire.Genesis{Version: 2, NetworkID: evidence.Assignment.NetworkID, ChainGenesisID: evidence.Assignment.GenesisID, ResourceID: f.Hash("handoff-real-source"), Issuer: f.Public(110), Threshold: 3, MaximumOperations: 4, MaximumPending: 2}
	for _, seed := range []byte{111, 112, 113, 114} {
		registry.Witnesses = append(registry.Witnesses, f.Public(seed))
	}
	sort.Slice(registry.Witnesses, func(i, j int) bool { return bytes.Compare(registry.Witnesses[i][:], registry.Witnesses[j][:]) < 0 })
	rid, _ := registry.ID()
	rdid, _ := registry.DescriptorID()
	p := cut.Proposal{Version: 1, Anchor: registry, Evidence: evidence, Allowance: 2, Successor: cut.Blueprint{Version: 1, IncarnationID: f.Hash("handoff-incarnation"), Authority: f.Public(101), Control: f.Public(102), Transport: f.Public(103), Threshold: 3, MaximumPending: 2}}
	for _, seed := range []byte{70, 71, 72, 73} {
		p.Successor.Witnesses = append(p.Successor.Witnesses, f.Public(seed))
	}
	sort.Slice(p.Successor.Witnesses, func(i, j int) bool {
		return bytes.Compare(p.Successor.Witnesses[i][:], p.Successor.Witnesses[j][:]) < 0
	})
	locations := []cut.SourceLocation{{Role: cut.Authority, Journal: legacy.base.config.Audit.JournalPath, Authority: legacy.authority, AuthorityPins: legacy.pins}, {Role: cut.Target, Journal: legacy.base.serve.config.Session.JournalPath, Workers: []string{legacy.worker}}}
	var placements []types.Hash
	for i := range locations {
		l := &locations[i]
		for _, path := range []*string{&l.Journal, &l.Authority, &l.AuthorityPins} {
			if *path != "" {
				*path, e = canonicalPruneLineageDirectory(*path)
				if e != nil {
					t.Fatal(e)
				}
			}
		}
		for j := range l.Workers {
			l.Workers[j], e = canonicalPruneLineageDirectory(l.Workers[j])
			if e != nil {
				t.Fatal(e)
			}
		}
		placement, e := l.LocationID()
		if e != nil {
			t.Fatal(e)
		}
		placements = append(placements, placement)
		seed := byte(1)
		if i == 1 {
			seed = 14
		}
		o, e := cut.CaptureSource(t.Context(), evidence, lid, rid, evidence.End, *l, placement, f.Hash("original-handoff-observation"), f.Key(seed), func(cut.Observation) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			p.A = o
		} else {
			p.B = o
		}
	}
	for _, r := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		p, e = p.Sign(rid, rdid, lid, evidence.End, r.name, f.Key(r.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	pid, _ := p.ID()
	g, e := v2.NewImportedAdmissionGenesis(p, v2.ImportPins{RegistryID: rid, RegistryDescriptorID: rdid, LegacyID: lid, Retirement: evidence.End, ProposalID: pid})
	if e != nil {
		t.Fatal(e)
	}
	gb, _ := g.CanonicalBytes()
	s := wire.Selection{Version: 3, RegistryID: rid, DescriptorID: rdid, Candidate: gb}
	for _, r := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		s, e = s.Sign(r.name, f.Key(r.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	sid, _ := s.ID()
	q := wire.Certificate{Version: 3, Selection: s}
	for _, seed := range []byte{111, 112, 113} {
		v, e := (wire.Vote{Version: 3, RegistryID: rid, DescriptorID: rdid, SelectionID: sid}).Sign(registry, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	qb, _ := q.CanonicalBytes()
	binding := v2.EnrollmentBinding{Version: 5, Registry: registry, Certificate: qb}
	bb, _ := binding.CanonicalBytes()
	gid, _ := g.ID()
	gdid, _ := g.DescriptorID()
	bid, _ := binding.ID()
	dir := t.TempDir()
	gp := filepath.Join(dir, "genesis")
	bp := filepath.Join(dir, "enrollment")
	writePruneCLIFile(t, gp, gb)
	writePruneCLIFile(t, bp, bb)
	for i, l := range locations {
		label := string(rune('a' + i))
		source := filepath.Join(dir, "source-"+label+".json")
		cutoverWrite(t, source, l)
		args := []string{custodySourceHandoffCommand, "--action", "transfer", "--genesis", gp, "--genesis-id", gid.String(), "--genesis-descriptor-id", gdid.String(), "--enrollment", bp, "--enrollment-id", bid.String(), "--source", source, "--placement-id", placements[i].String(), "--out", filepath.Join(dir, label+"-handoff")}
		reviewed := sourceHandoffCLIReviewed(t, driver, args)
		if e := runCustodySourceHandoff(t.Context(), replaceRemoteCLIFlag(reviewed, "--placement-id", f.Hash("wrong source").String()), &bytes.Buffer{}); e == nil {
			t.Fatal("stale review accepted")
		}
		driver(t, reviewed)
		raw, e := os.ReadFile(filepath.Join(dir, label+"-handoff"))
		if e != nil {
			t.Fatal(e)
		}
		h, e := workarchive.DecodeCustodySourceHandoff(raw)
		if e != nil || h.SourceSequence != 1 || h.SpentOperations != 2 {
			t.Fatal("lost source/spending", h, e)
		}
		retry := replaceRemoteCLIFlag(args, "--out", filepath.Join(dir, label+"-retry"))
		driver(t, sourceHandoffCLIReviewed(t, driver, retry))
		inspect := replaceRemoteCLIFlag(retry, "--action", "inspect")
		inspect = replaceRemoteCLIFlag(inspect, "--out", filepath.Join(dir, label+"-inspect"))
		driver(t, sourceHandoffCLIReviewed(t, driver, inspect))
		got, _ := os.ReadFile(filepath.Join(dir, label+"-inspect"))
		if !bytes.Equal(raw, got) {
			t.Fatal("cold inspect changed handoff")
		}
		if _, _, e := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), l.Journal, g.Manifest, g.Initial, g.CustodyPolicy, workarchive.DefaultCustodyJournalLimits()); e == nil {
			t.Fatal("legacy source remained live")
		}
	}
}
func TestRequiredSourceHandoffCLI(t *testing.T) { runSourceHandoffCLI(t, sourceHandoffCLIInProcess) }
