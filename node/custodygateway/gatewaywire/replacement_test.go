package gatewaywire

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func replacementArtifacts(t testing.TB) (Descriptor, Request, Response, Effect) {
	t.Helper()
	public := func(seed byte) (p [32]byte) { copy(p[:], key(seed)[32:]); return }
	d, q, _ := fixture(t)
	d.Guard = public(240)
	var e error
	d, e = d.Sign(key(1))
	if e != nil {
		t.Fatal(e)
	}
	q.DescriptorID, _ = d.ID()
	q, e = q.Sign(key(3))
	if e != nil {
		t.Fatal(e)
	}
	command, e := (guard.Replacement{GuardID: hash("guard identity"), Subject: d.Gateway, Successor: public(92), Authority: public(91), RevocationID: hash("revoked"), EvidenceID: hash("inventory"), Before: guard.Position{Sequence: 1, Head: hash("guard head")}}).Accept(key(92))
	if e != nil {
		t.Fatal(e)
	}
	command, e = command.Authorize(key(91))
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := (guard.ReplacementReceipt{Request: command, Guard: d.Guard}).Sign(key(240))
	if e != nil {
		t.Fatal(e)
	}
	r, e := (Response{Request: q, SourceID: d.SourceID, Data: []byte("preserved obligations"), Replacement: &receipt}).Sign(d, key(92))
	if e != nil {
		t.Fatal(e)
	}
	req, e := r.GuardRequest(d)
	if e != nil {
		t.Fatal(e)
	}
	h, e := req.SealDigest()
	if e != nil {
		t.Fatal(e)
	}
	copy(r.GuardSeal[:], ed25519.Sign(key(240), h[:]))
	effect, e := (Effect{Kind: EffectExecute, DeploymentID: hash("dep"), ScopeID: hash("scope"), AdmissionID: hash("admit"), BindingID: hash("binding"), ArtifactID: hash("artifact"), SourceSequence: 1, SourceHead: hash("source head"), CheckedAt: 1, Replacement: &receipt}).Sign(key(92))
	if e != nil {
		t.Fatal(e)
	}
	req, e = effect.GuardRequest()
	if e != nil {
		t.Fatal(e)
	}
	h, e = req.SealDigest()
	if e != nil {
		t.Fatal(e)
	}
	copy(effect.GuardSeal[:], ed25519.Sign(key(240), h[:]))
	return d, q, r, effect
}
func TestReplacementGatewayWireBindingAndCanonicalVectors(t *testing.T) {
	d, q, r, ef := replacementArtifacts(t)
	if e := r.Verify(d, q); e != nil {
		t.Fatal(e)
	}
	if e := ef.VerifyGuard(d.Guard); e != nil {
		t.Fatal(e)
	}
	var vector []byte
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{d, r, ef} {
		b, e := v.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		vector = append(vector, b...)
	}
	if types.DomainHash("replacement gateway vector", vector).String() != "08992d1a06ec88e82d43a771c5c1eae4bc148c1310d4384c8cbfe734041001b5" {
		t.Fatal("replacement gateway wire vector changed")
	}
	b, _ := d.CanonicalBytes()
	decoded, e := DecodeDescriptor(b)
	if e != nil || decoded.Guard != d.Guard {
		t.Fatal(e)
	}
	b, _ = r.CanonicalBytes()
	got, e := DecodeResponse(b)
	if e != nil || got.Verify(d, q) != nil {
		t.Fatal(e)
	}
	b, _ = ef.CanonicalBytes()
	effect, e := DecodeEffect(b)
	if e != nil || effect.VerifyGuard(d.Guard) != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Response){func(v *Response) { v.GuardSeal = [64]byte{} }, func(v *Response) { v.Replacement = nil }, func(v *Response) { v.Data = []byte("different result") }} {
		bad := r
		mutate(&bad)
		if bad.Verify(d, q) == nil {
			t.Fatal("response proof rebound")
		}
	}
	wrong := d
	copy(wrong.Guard[:], key(239)[32:])
	wrong, e = wrong.Sign(key(1))
	if e != nil {
		t.Fatal(e)
	}
	if r.Verify(wrong, q) == nil {
		t.Fatal("foreign guard")
	}
	legacy := d
	legacy.Guard = [32]byte{}
	legacy, e = legacy.Sign(key(1))
	if e != nil {
		t.Fatal(e)
	}
	if r.Verify(legacy, q) == nil {
		t.Fatal("legacy descriptor upgraded")
	}
	ef.Replacement = nil
	if ef.VerifyGuard(d.Guard) == nil {
		t.Fatal("effect proof stripped")
	}
}
func FuzzReplacementGatewayCodecs(fz *testing.F) {
	d, _, r, ef := replacementArtifacts(fz)
	for i, v := range []interface{ CanonicalBytes() ([]byte, error) }{d, r, ef} {
		b, e := v.CanonicalBytes()
		if e != nil {
			fz.Fatal(e)
		}
		fz.Add(uint8(i), b)
	}
	fz.Fuzz(func(t *testing.T, kind uint8, raw []byte) {
		var v interface{ CanonicalBytes() ([]byte, error) }
		var e error
		switch kind % 3 {
		case 0:
			v, e = DecodeDescriptor(raw)
		case 1:
			v, e = DecodeResponse(raw)
		case 2:
			v, e = DecodeEffect(raw)
		}
		if e == nil {
			b, e := v.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("noncanonical replacement artifact")
			}
		}
	})
}
