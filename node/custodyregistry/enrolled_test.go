package custodyregistry

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func enrolledRegistryFixture(t testing.TB) (Genesis, Selection) {
	t.Helper()
	g, s := registryFixture(t)
	g.Version = Version2
	s.Version = Version2
	s.DescriptorID, _ = g.DescriptorID()
	s.Initial.Assignment.Policy.Version = v2.PolicyVersionEnrolled
	s.Initial.Assignment.Policy.RegistryID = s.RegistryID
	s.Initial.Assignment.Policy.RegistryDescriptorID = s.DescriptorID
	s.IssuerSignature, s.AuthoritySignature, s.ControlSignature = [64]byte{}, [64]byte{}, [64]byte{}
	return g, registrySign(t, g, s)
}
func TestEnrolledRegistryQuorumRetainsMinorityAndRejectsSecondSelection(t *testing.T) {
	g, s := enrolledRegistryFixture(t)
	runRegistryWitnessQuorum(t, g, s)
}
func TestEnrolledRegistryCannotResetExistingVersionOneHistory(t *testing.T) {
	old, selected := registryFixture(t)
	path, w := registryWitnessCreate(t, old, 111)
	before := registryWitnessBefore(t, old)
	if _, e := w.VoteAt(before, selected); e != nil {
		t.Fatal(e)
	}
	_, pending, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if e := w.CommitAt(pending, registryWitnessCert(t, old, selected, 111, 112, 113)); e != nil {
		t.Fatal(e)
	}
	_, final, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	_ = w.Close()
	g, s := enrolledRegistryFixture(t)
	id, _ := g.ID()
	oldID, _ := old.ID()
	if id != oldID {
		t.Fatal("format reset semantic resource identity")
	}
	a, _ := g.DescriptorID()
	b, _ := old.DescriptorID()
	if a == b {
		t.Fatal("format descriptors match")
	}
	for _, pin := range []struct {
		name   string
		before bool
	}{{"genesis", true}, {"selected", false}} {
		p := final
		if pin.before {
			p = registryWitnessBefore(t, g)
		}
		if x, e := OpenWitness(path, g, id, f.Key(111), p); e == nil {
			_ = x.Close()
			t.Fatal("version2 adopted old witness history", pin.name)
		}
	}
	if e := CreateWitness(path, g, id, f.Key(111)); e == nil {
		t.Fatal("recreated existing registry history")
	}
	if s.ValidateDraft(old) == nil || selected.ValidateDraft(g) == nil {
		t.Fatal("cross-profile selection accepted")
	}
	raw, e := os.ReadFile(filepath.Join(path, "origin"))
	if e != nil {
		t.Fatal(e)
	}
	want, _ := old.CanonicalBytes()
	if !bytes.Equal(raw, want) {
		t.Fatal("refusal mutated origin")
	}
}
func TestEnrolledRegistryArtifactsUseOwnFramingAndSignatures(t *testing.T) {
	g, s := enrolledRegistryFixture(t)
	q := registryWitnessCert(t, g, s, 111, 112, 113)
	tests := []struct {
		raw    []byte
		decode func([]byte) error
	}{}
	raw, _ := g.CanonicalBytes()
	tests = append(tests, struct {
		raw    []byte
		decode func([]byte) error
	}{raw, func(b []byte) error { _, e := DecodeGenesis(b); return e }})
	raw, _ = s.CanonicalBytes()
	tests = append(tests, struct {
		raw    []byte
		decode func([]byte) error
	}{raw, func(b []byte) error { _, e := DecodeSelection(b); return e }})
	raw, _ = q.CanonicalBytes()
	tests = append(tests, struct {
		raw    []byte
		decode func([]byte) error
	}{raw, func(b []byte) error { _, e := DecodeCertificate(b); return e }})
	raw, _ = q.Votes[0].CanonicalBytes()
	tests = append(tests, struct {
		raw    []byte
		decode func([]byte) error
	}{raw, func(b []byte) error { _, e := DecodeVote(b); return e }})
	for _, x := range tests {
		if x.raw[7] != '2' || x.decode(x.raw) != nil {
			t.Fatal("wrong version2 framing")
		}
		for _, b := range [][]byte{x.raw[:len(x.raw)-1], append(append([]byte{}, x.raw...), 0)} {
			if x.decode(b) == nil {
				t.Fatal("accepted truncation or trailing byte")
			}
		}
		b := append([]byte{}, x.raw...)
		b[7] = '1'
		if x.decode(b) == nil {
			t.Fatal("magic/version disagreement accepted")
		}
	}
	old := g
	old.Version = Version1
	if s.Verify(old) == nil || q.Verify(old) == nil {
		t.Fatal("profile4 signature accepted in version1")
	}
}
