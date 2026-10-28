package custodycutover

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func handoffFixture(t testing.TB) (v2.AdmissionGenesis, v2.EnrollmentBinding, SourceLocation, SourceLocation, SourceHandoffPins, SourceHandoffPins) {
	t.Helper()
	e, aa, bb := originalSources(t)
	p, pin := proposalFixture(t, e)
	var ap, bp types.Hash
	for _, item := range []struct {
		l         SourceLocation
		seed      byte
		dst       *Observation
		placement *types.Hash
	}{{aa, 1, &p.A, &ap}, {bb, 14, &p.B, &bp}} {
		*item.placement, _ = item.l.LocationID()
		o, err := CaptureSource(t.Context(), e, pin.LegacyID, pin.AnchorID, e.End, item.l, *item.placement, f.Hash("handoff-observation"), f.Key(item.seed), func(Observation) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		*item.dst = o
	}
	for _, r := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		var err error
		p, err = p.Sign(pin.AnchorID, pin.DescriptorID, pin.LegacyID, pin.Retired, r.name, f.Key(r.seed))
		if err != nil {
			t.Fatal(err)
		}
	}
	pid, _ := p.ID()
	g, err := v2.NewImportedAdmissionGenesis(p, v2.ImportPins{RegistryID: pin.AnchorID, RegistryDescriptorID: pin.DescriptorID, LegacyID: pin.LegacyID, Retirement: pin.Retired, ProposalID: pid})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := g.CanonicalBytes()
	s := wire.Selection{Version: 3, RegistryID: pin.AnchorID, DescriptorID: pin.DescriptorID, Candidate: raw}
	for _, r := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		s, err = s.Sign(r.name, f.Key(r.seed))
		if err != nil {
			t.Fatal(err)
		}
	}
	sid, _ := s.ID()
	q := wire.Certificate{Version: 3, Selection: s}
	for _, seed := range []byte{111, 112, 113} {
		v, err := (wire.Vote{Version: 3, RegistryID: pin.AnchorID, DescriptorID: pin.DescriptorID, SelectionID: sid}).Sign(p.Anchor, f.Key(seed))
		if err != nil {
			t.Fatal(err)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	raw, _ = q.CanonicalBytes()
	b := v2.EnrollmentBinding{Version: 5, Registry: p.Anchor, Certificate: raw}
	gid, _ := g.ID()
	gdid, _ := g.DescriptorID()
	bid, _ := b.ID()
	aPins := SourceHandoffPins{gid, gdid, bid, ap}
	bPins := aPins
	bPins.PlacementID = bp
	return g, b, aa, bb, aPins, bPins
}
func TestRemoteSourceHandoffOriginalBothRolesColdRetry(t *testing.T) {
	g, b, aa, bb, ap, bp := handoffFixture(t)
	for _, item := range []struct {
		l SourceLocation
		p SourceHandoffPins
	}{{aa, ap}, {bb, bp}} {
		want, e := ReviewSourceHandoff(g, b, item.p, item.l.Role)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := InspectSourceHandoff(t.Context(), g, b, item.p, item.l); e == nil {
			t.Fatal("missing transfer inspected")
		}
		got, changed, e := TransferSourceHandoff(t.Context(), g, b, item.p, item.l)
		if e != nil || !changed || got != want {
			t.Fatal(changed, e)
		}
		retry, changed, e := TransferSourceHandoff(t.Context(), g, b, item.p, item.l)
		if e != nil || changed || retry != want {
			t.Fatal("cold retry", changed, e)
		}
		if _, _, e := workarchive.OpenOrCreateCustodyJournal(item.l.Journal, g.Manifest, g.Initial, g.CustodyPolicy); e == nil {
			t.Fatal("legacy reopened")
		}
		observed, e := InspectSourceHandoff(t.Context(), g, b, item.p, item.l)
		if e != nil || observed != want {
			t.Fatal(e)
		}
	}
}
func TestRemoteSourceHandoffRejectsWrongPinsProofAndCopiedLocation(t *testing.T) {
	g, b, aa, _, ap, _ := handoffFixture(t)
	for _, mutate := range []func(*SourceHandoffPins){func(p *SourceHandoffPins) { p.GenesisID[0] ^= 1 }, func(p *SourceHandoffPins) { p.GenesisDescriptorID[0] ^= 1 }, func(p *SourceHandoffPins) { p.EnrollmentID[0] ^= 1 }, func(p *SourceHandoffPins) { p.PlacementID[0] ^= 1 }} {
		p := ap
		mutate(&p)
		if _, e := ReviewSourceHandoff(g, b, p, aa.Role); e == nil {
			t.Fatal("wrong pin")
		}
	}
	bad := b
	bad.Certificate = append([]byte(nil), b.Certificate...)
	bad.Certificate[len(bad.Certificate)-1] ^= 1
	if _, e := ReviewSourceHandoff(g, bad, ap, aa.Role); e == nil {
		t.Fatal("bad quorum")
	}
	if _, _, e := TransferSourceHandoff(t.Context(), g, b, ap, aa); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(originalTemp(t), "copy")
	if e := os.CopyFS(dest, os.DirFS(aa.Journal)); e != nil {
		t.Fatal(e)
	}
	os.Chmod(dest, 0700)
	aa.Journal = dest
	if _, _, e := TransferSourceHandoff(t.Context(), g, b, ap, aa); e == nil {
		t.Fatal("copy acquired original location")
	}
}
func TestRemoteSourceHandoffRequiresOriginalRetirementAndUnchangedSource(t *testing.T) {
	g, b, aa, bb, ap, bp := handoffFixture(t)
	wrong := aa
	wrong.AuthorityPins = bb.Journal
	if _, _, e := TransferSourceHandoff(t.Context(), g, b, ap, wrong); e == nil {
		t.Fatal("wrong original owner")
	}
	// A source growth after the signed observation blocks handoff rather than
	// silently selecting a different predecessor. Corrupt/unknown evidence blocks too.
	if e := os.WriteFile(filepath.Join(bb.Journal, "unexpected"), []byte("retained"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := TransferSourceHandoff(t.Context(), g, b, bp, bb); e == nil {
		t.Fatal("unclassified source accepted")
	}
}

func TestRemoteSourceHandoffPairRequiresBothExactOriginalRecords(t *testing.T) {
	g, b, aa, bb, ap, bp := handoffFixture(t)
	ah, _, e := TransferSourceHandoff(t.Context(), g, b, ap, aa)
	if e != nil {
		t.Fatal(e)
	}
	bh, _, e := TransferSourceHandoff(t.Context(), g, b, bp, bb)
	if e != nil {
		t.Fatal(e)
	}
	pair := SourceHandoffPair{ah, bh}
	if e := pair.Verify(g, b, ap, bp); e != nil {
		t.Fatal(e)
	}
	raw, e := pair.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	again, e := DecodeSourceHandoffPair(raw)
	if e != nil || again != pair {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*SourceHandoffPair){"missing-b": func(p *SourceHandoffPair) { p.B = workarchive.CustodySourceHandoff{} }, "swapped": func(p *SourceHandoffPair) { p.A, p.B = p.B, p.A }, "same-location": func(p *SourceHandoffPair) { p.B.PlacementID = p.A.PlacementID }, "source": func(p *SourceHandoffPair) { p.B.SourceSequence++ }, "spending": func(p *SourceHandoffPair) { p.B.SpentOperations++ }, "selection": func(p *SourceHandoffPair) { p.B.EnrollmentID[0] ^= 1 }} {
		t.Run(name, func(t *testing.T) {
			bad := pair
			mutate(&bad)
			if e := bad.Verify(g, b, ap, bp); e == nil {
				t.Fatal("incomplete/mixed pair")
			}
		})
	}
}
func FuzzSourceHandoffPair(f *testing.F) {
	id := types.Hash{1}
	h := workarchive.CustodySourceHandoff{Version: 1, TargetVersion: 5, Role: 1, RegistryID: id, RegistryDescriptorID: id, GenesisID: id, GenesisDescriptorID: id, EnrollmentID: id, ProposalID: id, PlacementID: id, ProofID: id, ReceiptID: id, RetainUntil: 1}
	p := SourceHandoffPair{h, h}
	p.B.Role = 2
	p.B.PlacementID = types.Hash{2}
	raw, _ := p.CanonicalBytes()
	f.Add(raw)
	f.Add([]byte("OMCSHPR1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := DecodeSourceHandoffPair(b)
		if e == nil {
			again, e := p.CanonicalBytes()
			if e != nil || !bytes.Equal(again, b) {
				t.Fatal("noncanonical pair")
			}
		}
	})
}
func TestRemoteSourceHandoffPairCanonicalVector(t *testing.T) {
	id := types.Hash{1}
	h := workarchive.CustodySourceHandoff{Version: 1, TargetVersion: 5, Role: 1, RegistryID: id, RegistryDescriptorID: id, GenesisID: id, GenesisDescriptorID: id, EnrollmentID: id, ProposalID: id, PlacementID: id, ProofID: id, ReceiptID: id, RetainUntil: 1}
	p := SourceHandoffPair{h, h}
	p.B.Role = 2
	p.B.PlacementID = types.Hash{2}
	raw, e := p.CanonicalBytes()
	if e != nil || len(raw) != 716 {
		t.Fatal(len(raw), e)
	}
	hash, _ := p.ID()
	if hash.String() != "9cacc3511d7e2416add69ef048f53c236feb2936662a0540c5afa0b4c941dbaf" {
		t.Fatal("pair vector changed", hash)
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), 0), raw[:len(raw)-1], append([]byte("OMCSHPR2"), raw[8:]...)} {
		if _, e := DecodeSourceHandoffPair(bad); e == nil {
			t.Fatal("noncanonical pair")
		}
	}
}
