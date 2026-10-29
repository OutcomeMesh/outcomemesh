package gatewaywire

import (
	"bytes"
	"crypto/ed25519"
	"github.com/outcomemesh/outcomemesh/core/types"
	"testing"
)

func deploymentFixture(t testing.TB) (Deployment, Effect, []byte) {
	t.Helper()
	d, _, _ := fixture(t)
	d.ObjectsID = types.Hash{}
	d, e := d.Sign(key(1))
	if e != nil {
		t.Fatal(e)
	}
	b := d
	b.RootID = hash("b-root")
	b.SourceID = hash("b-source")
	b.ObjectsID = hash("b-objects")
	copy(b.Gateway[:], key(4).Public().(ed25519.PublicKey))
	b, e = b.Sign(key(1))
	if e != nil {
		t.Fatal(e)
	}
	p := Deployment{A: d, B: b, GenesisID: d.GenesisID, GenesisDescriptorID: d.GenesisDescriptorID, EnrollmentID: d.EnrollmentID, ImportID: hash("import"), PairID: hash("pair"), MinimumRetainUntil: 10000}
	copy(p.Authority[:], key(5).Public().(ed25519.PublicKey))
	copy(p.Control[:], key(6).Public().(ed25519.PublicKey))
	for _, r := range []struct {
		role string
		k    byte
	}{{"issuer", 1}, {"authority", 5}, {"control", 6}, {"a", 2}, {"b", 4}} {
		p, e = p.Sign(r.role, key(r.k))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = p.Verify(); e != nil {
		t.Fatal(e)
	}
	id, _ := p.ID()
	ef, e := (Effect{Kind: EffectExecute, DeploymentID: id, ScopeID: hash("scope"), AdmissionID: hash("admit"), BindingID: hash("binding"), ArtifactID: hash("artifact"), SourceSequence: 2, SourceHead: hash("head"), CheckedAt: 1234}).Sign(key(4))
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte("bounded runtime command")
	did, _ := d.ID()
	q, e := (Request{DescriptorID: did, Nonce: hash("runtime-nonce"), Kind: Runtime, ChunkID: RuntimePayloadID(payload)}).Sign(key(3))
	if e != nil {
		t.Fatal(e)
	}
	packet, e := EncodeRuntimeRequest(q, payload)
	if e != nil {
		t.Fatal(e)
	}
	return p, ef, packet
}

func TestProtected5WireDomainsGoldenAndCompleteEndorsements(t *testing.T) {
	p, ef, packet := deploymentFixture(t)
	raw, _ := p.CanonicalBytes()
	eb, _ := ef.CanonicalBytes()
	got := types.DomainHash("OMESH/test/profile5/wire-vector", raw, eb, packet).String()
	const want = "0a3f1f6ea4f104151e2699053f6c666fb6c1cee7f3f6ec84e068be3bb364256d"
	if got != want {
		t.Fatal(got)
	}
	copy := p
	copy.ASignature = [64]byte{}
	if copy.Verify() == nil {
		t.Fatal("partial deployment active")
	}
	if _, e := copy.CanonicalBytes(); e != nil {
		t.Fatal("partial draft unusable", e)
	}
	before, _ := p.ID()
	after, _ := copy.ID()
	if before != after {
		t.Fatal("endorsement changed choice ID")
	}
	copy = p
	copy.MinimumRetainUntil++
	if copy.Verify() == nil {
		t.Fatal("retention changed")
	}
	if _, e := p.Sign("a", key(5)); e == nil {
		t.Fatal("wrong gateway key")
	}
	q, payload, e := DecodeRuntimeRequest(packet)
	if e != nil || q.Authorize(p.A) != nil || q.ChunkID != RuntimePayloadID(payload) {
		t.Fatal(e)
	}
	q.Kind = ReadChunk
	if _, e = EncodeRuntimeRequest(q, payload); e == nil {
		t.Fatal("legacy operation smuggled")
	}
	q.Kind = Runtime
	payload[0] ^= 1
	if _, e = EncodeRuntimeRequest(q, payload); e == nil {
		t.Fatal("payload unbound")
	}
}
func TestProtected5WireRejectsAllTruncationsAndAlterations(t *testing.T) {
	p, ef, packet := deploymentFixture(t)
	raw, _ := p.CanonicalBytes()
	eb, _ := ef.CanonicalBytes()
	cases := []struct {
		raw    []byte
		decode func([]byte) error
	}{{raw, func(b []byte) error { _, e := DecodeDeployment(b); return e }}, {eb, func(b []byte) error { _, e := DecodeEffect(b); return e }}, {packet, func(b []byte) error { _, _, e := DecodeRuntimeRequest(b); return e }}}
	for _, c := range cases {
		for n := 0; n < len(c.raw); n++ {
			if c.decode(c.raw[:n]) == nil {
				t.Fatal("truncated", n)
			}
		}
		if c.decode(append(append([]byte(nil), c.raw...), 0)) == nil {
			t.Fatal("trailing")
		}
		bad := append([]byte(nil), c.raw...)
		bad[0] ^= 1
		if c.decode(bad) == nil {
			t.Fatal("magic")
		}
	}
	ef.ArtifactID = hash("changed")
	if _, e := ef.CanonicalBytes(); e == nil {
		t.Fatal("changed effect")
	}
}
func FuzzProtected5Wire(f *testing.F) {
	p, e, packet := deploymentFixture(f)
	pb, _ := p.CanonicalBytes()
	eb, _ := e.CanonicalBytes()
	for _, b := range [][]byte{pb, eb, packet} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, e := DecodeDeployment(b); e == nil {
			raw, e := p.CanonicalBytes()
			if e != nil || !bytes.Equal(b, raw) {
				t.Fatal("deployment")
			}
		}
		if p, e := DecodeEffect(b); e == nil {
			raw, e := p.CanonicalBytes()
			if e != nil || !bytes.Equal(b, raw) {
				t.Fatal("effect")
			}
		}
		if q, payload, e := DecodeRuntimeRequest(b); e == nil {
			raw, e := EncodeRuntimeRequest(q, payload)
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("envelope")
			}
		}
	})
}
