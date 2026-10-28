package gatewaywire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func key(v byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{v}, 32)) }
func hash(s string) types.Hash      { return types.DomainHash("gateway-test", []byte(s)) }
func fixture(t testing.TB) (Descriptor, Request, Response) {
	t.Helper()
	d := Descriptor{RootID: hash("root"), SourceID: hash("source"), GenesisID: hash("genesis"), GenesisDescriptorID: hash("descriptor"), EnrollmentID: hash("enrollment"), ObjectsID: hash("objects"), OwnerUID: 1000, ParticipantUID: 1001, EventLimit: 16}
	copy(d.Issuer[:], key(1).Public().(ed25519.PublicKey))
	copy(d.Gateway[:], key(2).Public().(ed25519.PublicKey))
	var client [32]byte
	copy(client[:], key(3).Public().(ed25519.PublicKey))
	d.Clients = [][32]byte{client}
	var e error
	d, e = d.Sign(key(1))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := d.ID()
	q, e := (Request{DescriptorID: id, Nonce: hash("nonce"), Kind: Inspect}).Sign(key(3))
	if e != nil {
		t.Fatal(e)
	}
	r, e := (Response{Request: q, SourceID: d.SourceID, Data: []byte("original sealed source")}).Sign(d, key(2))
	if e != nil {
		t.Fatal(e)
	}
	return d, q, r
}
func TestGatewayCanonicalVector(t *testing.T) {
	d, q, r := fixture(t)
	var ids []string
	for i, raw := range [][]byte{must(d.CanonicalBytes()), must(q.CanonicalBytes()), must(r.CanonicalBytes())} {
		h := types.DomainHash("gateway-vector", raw)
		ids = append(ids, hex.EncodeToString(h[:]))
		switch i {
		case 0:
			got, e := DecodeDescriptor(raw)
			if e != nil || !bytes.Equal(must(got.CanonicalBytes()), raw) {
				t.Fatal(e)
			}
		case 1:
			got, e := DecodeRequest(raw)
			if e != nil || got != q {
				t.Fatal(e)
			}
		case 2:
			got, e := DecodeResponse(raw)
			if e != nil || got.Verify(d, q) != nil {
				t.Fatal(e)
			}
		}
	}
	const want = "1a461a604157bf49402ec6c1891dac456c678a81900ce6c980aafa15ae1c77dd/f0cba95e45991201cf0537e02996fe53cea648cd5628a138219543a194836e1f/f20e5e4e709d65aea20bf6589071781c44cee64c150bf7b9ba3b4d1860dcd0f7"
	got := ids[0] + "/" + ids[1] + "/" + ids[2]
	if got != want {
		t.Fatal(got)
	}
}
func must(b []byte, e error) []byte {
	if e != nil {
		panic(e)
	}
	return b
}
func TestGatewayDescriptorsAndRoles(t *testing.T) {
	d, q, r := fixture(t)
	mutations := []func(*Descriptor){func(d *Descriptor) { d.ParticipantUID = 0 }, func(d *Descriptor) { d.ParticipantUID = d.OwnerUID }, func(d *Descriptor) { d.RootID = types.Hash{} }, func(d *Descriptor) { d.Gateway = d.Issuer }, func(d *Descriptor) { d.EventLimit = 1 }, func(d *Descriptor) { d.EventLimit = MaximumEvents + 1 }, func(d *Descriptor) { d.Clients = nil }, func(d *Descriptor) { d.Clients = append(d.Clients, d.Clients[0]) }, func(d *Descriptor) { d.Clients[0] = d.Gateway }}
	for i, m := range mutations {
		copy := d
		copy.Clients = append([][32]byte(nil), d.Clients...)
		m(&copy)
		if _, e := copy.Sign(key(1)); e == nil {
			t.Fatal("invalid descriptor", i)
		}
	}
	if _, e := d.Sign(key(3)); e == nil {
		t.Fatal("wrong issuer")
	}
	if _, e := r.Sign(d, key(1)); e == nil {
		t.Fatal("wrong service")
	}
	outsider, _ := q.Sign(key(4))
	if outsider.Authorize(d) == nil {
		t.Fatal("unlisted signer")
	}
	q.Kind = Revoke
	q, _ = q.Sign(key(3))
	if q.Authorize(d) == nil {
		t.Fatal("client revoked")
	}
	q, _ = q.Sign(key(1))
	if q.Authorize(d) != nil {
		t.Fatal("issuer revoke denied")
	}
	q.Kind = Inspect
	q, _ = q.Sign(key(1))
	if q.Authorize(d) == nil {
		t.Fatal("issuer read bypass")
	}
}
func TestGatewayReplyBindsExactAttemptAndBytes(t *testing.T) {
	d, q, r := fixture(t)
	if r.Verify(d, q) != nil {
		t.Fatal("valid response")
	}
	for _, m := range []func(*Request){func(q *Request) { q.Nonce = hash("newnonce") }, func(q *Request) { q.DescriptorID = hash("other") }, func(q *Request) { q.Before = Position{1, hash("head")} }, func(q *Request) { q.Kind = ReadChunk; q.ChunkID = hash("chunk") }} {
		other := q
		m(&other)
		other, _ = other.Sign(key(3))
		if r.Verify(d, other) == nil {
			t.Fatal("reply reused")
		}
	}
	for _, m := range []func(*Response){func(r *Response) { r.Data = []byte("changed") }, func(r *Response) { r.SourceID = hash("other") }, func(r *Response) { r.Signature[0] ^= 1 }} {
		other := r
		m(&other)
		if other.Verify(d, q) == nil {
			t.Fatal("reply changed")
		}
	}
	p, e := r.Position()
	if e != nil || p.Sequence != 1 || p.Head.IsZero() {
		t.Fatal(p, e)
	}
}
func TestGatewayCodecsRejectEveryTruncationAndTrailingByte(t *testing.T) {
	d, q, r := fixture(t)
	cases := []struct {
		raw    []byte
		decode func([]byte) error
	}{{must(d.CanonicalBytes()), func(b []byte) error { _, e := DecodeDescriptor(b); return e }}, {must(q.CanonicalBytes()), func(b []byte) error { _, e := DecodeRequest(b); return e }}, {must(r.CanonicalBytes()), func(b []byte) error { _, e := DecodeResponse(b); return e }}}
	for _, c := range cases {
		for n := 0; n < len(c.raw); n++ {
			if c.decode(c.raw[:n]) == nil {
				t.Fatal("truncation", n)
			}
		}
		if c.decode(append(c.raw, 0)) == nil {
			t.Fatal("trailing")
		}
		bad := append([]byte(nil), c.raw...)
		bad[0] ^= 1
		if c.decode(bad) == nil {
			t.Fatal("magic")
		}
	}
	for _, p := range []Position{{1, types.Hash{}}, {0, hash("bad")}, {MaximumEvents + 1, hash("bad")}} {
		if p.Valid() {
			t.Fatal(p)
		}
	}
}
func FuzzGatewayArtifacts(f *testing.F) {
	d, q, r := fixture(f)
	for _, b := range [][]byte{must(d.CanonicalBytes()), must(q.CanonicalBytes()), must(r.CanonicalBytes())} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, e := DecodeDescriptor(b); e == nil && !bytes.Equal(must(d.CanonicalBytes()), b) {
			t.Fatal("descriptor")
		}
		if q, e := DecodeRequest(b); e == nil && !bytes.Equal(must(q.CanonicalBytes()), b) {
			t.Fatal("request")
		}
		if r, e := DecodeResponse(b); e == nil && !bytes.Equal(must(r.CanonicalBytes()), b) {
			t.Fatal("response")
		}
	})
}
