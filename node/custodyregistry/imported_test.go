package custodyregistry

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	ct "github.com/outcomemesh/outcomemesh/internal/carryovertest"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func importSelection(t testing.TB) (Genesis, Selection) {
	t.Helper()
	p := ct.Proposal(t)
	id, _ := p.Anchor.ID()
	did, _ := p.Anchor.DescriptorID()
	lid, _ := p.Evidence.Assignment.ID()
	pid, _ := p.ID()
	initial, e := v2.NewImportedAdmissionGenesis(p, v2.ImportPins{RegistryID: id, RegistryDescriptorID: did, LegacyID: lid, ProposalID: pid, Retirement: p.Evidence.End})
	if e != nil {
		t.Fatal(e)
	}
	s := Selection{Version: SelectionVersionImported, RegistryID: id, DescriptorID: did, Initial: initial}
	return p.Anchor, signImportedSelection(t, p.Anchor, s)
}
func signImportedSelection(t testing.TB, g Genesis, s Selection) Selection {
	t.Helper()
	for _, r := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		var e error
		s, e = s.Sign(g, r.name, f.Key(r.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	return s
}
func nativeAlternative(t testing.TB, g Genesis, s Selection) Selection {
	t.Helper()
	n := s.Initial
	n.Version = v2.Version2
	n.Import = nil
	n.Assignment.Policy.Version = v2.PolicyVersionEnrolled
	n.Assignment.Policy.ImportID = [32]byte{}
	return signImportedSelection(t, g, Selection{Version: Version2, RegistryID: s.RegistryID, DescriptorID: s.DescriptorID, Initial: n})
}
func TestRemoteImportedRegistrySharesSlotAcrossFormatsAndKeepsMinority(t *testing.T) {
	g, s := importSelection(t)
	other := nativeAlternative(t, g, s)
	id, _ := g.ID()
	before := registryWitnessBefore(t, g)
	var owners []*Witness
	var paths []string
	var votes []Vote
	for i := byte(0); i < 4; i++ {
		p, w := registryWitnessCreate(t, g, 111+i)
		paths = append(paths, p)
		owners = append(owners, w)
		choice := s
		if i == 3 {
			choice = other
		}
		v, e := w.VoteAt(before, choice)
		if e != nil {
			t.Fatal(e)
		}
		if i < 3 {
			votes = append(votes, v)
		}
	}
	sort.Slice(votes, func(i, j int) bool { return bytes.Compare(votes[i].Witness[:], votes[j].Witness[:]) < 0 })
	cert := Certificate{Version: SelectionVersionImported, Selection: s, Votes: votes}
	if e := cert.Verify(g); e != nil {
		t.Fatal(e)
	}
	for i, w := range owners {
		_, pending, e := w.Snapshot()
		if e != nil {
			t.Fatal(e)
		}
		conflict := other
		if i == 3 {
			conflict = s
		}
		if _, e := w.VoteAt(pending, conflict); e == nil {
			t.Fatal("format change bypassed choice")
		}
		if e := w.CommitAt(pending, cert); e != nil {
			t.Fatal(e)
		}
		x, final, e := w.Snapshot()
		if e != nil || !x.SelectionFinal {
			t.Fatal(x, e)
		}
		w.Close()
		if stale, e := OpenWitness(paths[i], g, id, f.Key(111+byte(i)), before); e == nil {
			stale.Close()
			t.Fatal("stale external pin")
		}
		w = registryWitnessOpen(t, paths[i], g, 111+byte(i), final)
		if _, e := w.VoteAt(final, other); e == nil {
			t.Fatal("selected resource allowed reset budget")
		}
		if e := w.CommitAt(pending, cert); e != nil {
			t.Fatal("exact lost commit recovery", e)
		}
		w.Close()
	}
	raw, e := os.ReadFile(filepath.Join(paths[3], "selection.vote"))
	if e != nil {
		t.Fatal(e)
	}
	minority, e := DecodeSelection(raw)
	if e != nil || minority.Version != Version2 {
		t.Fatal("minority vote overwritten", e)
	}
}
func TestRemoteImportedRegistryNativeChoiceBlocksImport(t *testing.T) {
	g, s := importSelection(t)
	other := nativeAlternative(t, g, s)
	_, w := registryWitnessCreate(t, g, 111)
	before := registryWitnessBefore(t, g)
	if _, e := w.VoteAt(before, other); e != nil {
		t.Fatal(e)
	}
	_, pin, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := w.VoteAt(pin, s); e == nil {
		t.Fatal("import bypassed pending native choice")
	}
	q := registryWitnessCert(t, g, other, 111, 112, 113)
	if e := w.CommitAt(pin, q); e != nil {
		t.Fatal(e)
	}
	_, pin, e = w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := w.VoteAt(pin, s); e == nil {
		t.Fatal("import bypassed selected native choice")
	}
}
func TestRemoteImportedRegistryFaultRecoveryKeepsExactChoice(t *testing.T) {
	g, s := importSelection(t)
	other := nativeAlternative(t, g, s)
	id, _ := g.ID()
	before := registryWitnessBefore(t, g)
	for _, stage := range []string{"selection.vote-before-sync", "selection.vote-durable"} {
		t.Run(stage, func(t *testing.T) {
			path, w := registryWitnessCreate(t, g, 111)
			injected := errors.New("selection persistence interrupted")
			w.hook = func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}
			if _, e := w.VoteAt(before, s); !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			w.Close()
			if stale, e := OpenWitness(path, g, id, f.Key(111), before); e == nil {
				stale.Close()
				t.Fatal("uncertain choice forgotten")
			}
			if _, e := RecoverVote(path, g, id, f.Key(111), before, other); e == nil {
				t.Fatal("replacement recovery")
			}
			w, e := RecoverVote(path, g, id, f.Key(111), before, s)
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			vote, e := w.VoteAt(before, s)
			if e != nil || vote.Version != SelectionVersionImported {
				t.Fatal(e)
			}
		})
	}
}
func TestRemoteImportedRegistryRejectsVersionAndSignatureSubstitution(t *testing.T) {
	g, s := importSelection(t)
	n := nativeAlternative(t, g, s)
	for _, bad := range []Selection{{Version: Version2, RegistryID: s.RegistryID, DescriptorID: s.DescriptorID, Initial: s.Initial}, {Version: SelectionVersionImported, RegistryID: n.RegistryID, DescriptorID: n.DescriptorID, Initial: n.Initial}} {
		if e := bad.ValidateDraft(g); e == nil {
			t.Fatal("mismatched selection profile")
		}
	}
	bad := s
	bad.AuthoritySignature = n.AuthoritySignature
	if e := bad.Verify(g); e == nil {
		t.Fatal("native signature reused")
	}
	old := g
	old.Version = Version1
	if e := s.Verify(old); e == nil {
		t.Fatal("old registry upgraded")
	}
	illegal := g
	illegal.Version = SelectionVersionImported
	if _, e := illegal.CanonicalBytes(); e == nil {
		t.Fatal("invented second resource namespace")
	}
	raw, e := s.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	back, e := DecodeSelection(raw)
	if e != nil || back.Verify(g) != nil {
		t.Fatal(e)
	}
	generic, e := wire.DecodeSelection(raw)
	if e != nil || generic.Version != SelectionVersionImported {
		t.Fatal(e)
	}
}
