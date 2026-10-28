package custodycutover

import (
	"bytes"
	"github.com/outcomemesh/outcomemesh/core/types"
	"testing"
)

type publicArtifact interface {
	CanonicalBytes() ([]byte, error)
	ID() (types.Hash, error)
}

func publicParsers() []func([]byte) (publicArtifact, error) {
	return []func([]byte) (publicArtifact, error){func(raw []byte) (publicArtifact, error) { return DecodeEvidence(raw) }, func(raw []byte) (publicArtifact, error) { return DecodeObservation(raw) }, func(raw []byte) (publicArtifact, error) { return DecodeBlueprint(raw) }, func(raw []byte) (publicArtifact, error) { return DecodeProposal(raw) }}
}
func TestRemoteCutoverCanonicalVectorsAndVersionSeparation(t *testing.T) {
	p, _ := proposalFixture(t, evidenceFixture(t, true))
	values := []publicArtifact{p.Evidence, p.A, p.Successor, p}
	parsers := publicParsers()
	sizes := []int{9073, 347, 270, 10500}
	ids := []string{"71585d4d9e6ce31c53ee11f4c48d4b0380ff758e0e081824e16f491571eedcf1", "3e54fa0403f96d380267e0898f03812b6972160ad20c1c9ad7cb83f522542e76", "0953541d4c62e25c0f7026385a25e135ee25f93339a1f4db595ccbc6add6b802", "03f9b39861894321748c0e34213f66efeb48774153a085a8203c400172b934aa"}
	for i, v := range values {
		raw, err := v.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		id, err := v.ID()
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != sizes[i] || id.String() != ids[i] {
			t.Fatalf("changed vector %d bytes=%d id=%s", i, len(raw), id)
		}
		decoded, err := parsers[i](raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decoded.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, got) {
			t.Fatal("roundtrip", err)
		}
		for _, bad := range [][]byte{nil, raw[:8], raw[:len(raw)-1], append(append([]byte{}, raw...), 0), append([]byte{0}, raw...)} {
			if _, err := parsers[i](bad); err == nil {
				t.Fatal("noncanonical accepted", i)
			}
		}
		bad := append([]byte{}, raw...)
		bad[8]++
		if _, err := parsers[i](bad); err == nil {
			t.Fatal("future version accepted", i)
		}
		for j, parse := range parsers {
			if i != j {
				if _, err := parse(raw); err == nil {
					t.Fatal("cross-type decoded", i, j)
				}
			}
		}
	}
}
func FuzzCutoverPublicArtifacts(f *testing.F) {
	p, _ := proposalFixture(f, evidenceFixture(f, false))
	values := []publicArtifact{p.Evidence, p.A, p.Successor, p}
	for i, v := range values {
		raw, err := v.CanonicalBytes()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(i), raw)
	}
	f.Add(uint8(0), []byte("OMCXEVD1"))
	f.Add(uint8(3), []byte{})
	parsers := publicParsers()
	f.Fuzz(func(t *testing.T, kind uint8, input []byte) {
		parse := parsers[int(kind)%len(parsers)]
		v, err := parse(input)
		if err != nil {
			return
		}
		raw, err := v.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, input) {
			t.Fatal("noncanonical decoder success", err)
		}
		id, err := v.ID()
		if err != nil || id.IsZero() {
			t.Fatal("lost stable id", err)
		}
	})
}
