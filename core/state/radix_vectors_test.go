package state

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestRadixFixedVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/radix-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Resources                                      []string
		Root, EmptyRoot, MembershipProof, AbsenceProof string
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	values := []resource.Resource{}
	for _, text := range f.Resources {
		b, e := hex.DecodeString(text)
		if e != nil {
			t.Fatal(e)
		}
		d := codec.NewDecoder(b)
		v, e := resource.Decode(d)
		if e != nil || d.Finish() != nil {
			t.Fatal("resource", e)
		}
		values = append(values, v)
	}
	s, e := NewVersion(values, CommitmentRadixV1)
	if e != nil || s.Root().String() != f.Root || s.Root() != rebuiltRadix(values) {
		t.Fatal("root", e)
	}
	empty, _ := EmptyVersion(CommitmentRadixV1)
	if empty.Root().String() != f.EmptyRoot {
		t.Fatal("empty")
	}
	for i, text := range []string{f.MembershipProof, f.AbsenceProof} {
		q := types.ResourceID{2}
		if i == 1 {
			q = types.ResourceID{9}
		}
		p, e := s.Prove(q)
		if e != nil {
			t.Fatal(e)
		}
		b, e := p.CanonicalBytes()
		if e != nil || hex.EncodeToString(b) != text {
			t.Fatal("proof vector", e)
		}
		if _, ok, e := VerifyRadixProof(s.Root(), q, p); e != nil || ok != (i == 0) {
			t.Fatal("verify", e)
		}
	}
}
