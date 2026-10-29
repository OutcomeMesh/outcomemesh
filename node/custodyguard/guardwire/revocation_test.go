package guardwire

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func revocationVector(t testing.TB) (Revocation, RevocationReceipt) {
	t.Helper()
	authority := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	guard := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	subject := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	q := Revocation{GuardID: types.DomainHash("vector/guard"), ReasonID: types.DomainHash("vector/incident")}
	copy(q.Authority[:], authority[32:])
	copy(q.Subject[:], subject[32:])
	q, err := q.Sign(authority)
	if err != nil {
		t.Fatal(err)
	}
	r := RevocationReceipt{Request: q, Before: Position{Sequence: 4, Head: types.DomainHash("vector/head")}}
	copy(r.Guard[:], guard[32:])
	r, err = r.Sign(guard)
	if err != nil {
		t.Fatal(err)
	}
	return q, r
}
func TestRevocationVectorsAndEveryBit(t *testing.T) {
	q, r := revocationVector(t)
	qb, _ := q.CanonicalBytes()
	rb, _ := r.CanonicalBytes()
	// These hashes pin complete signed bytes, including domains, field order and endian.
	if types.DomainHash("vector", qb).String() != "3d4659d69c764b9418bc75e043e57325c6e95b9e117c916fad7e74c5d78d3b75" || types.DomainHash("vector", rb).String() != "d348cbfe979189c636060cf830b0d743b34af040b4d3501faef9b8093a46a89f" {
		t.Fatal("revocation vector changed")
	}
	for _, test := range []struct {
		name   string
		raw    []byte
		decode func([]byte) error
	}{
		{"request", qb, func(b []byte) error { _, e := DecodeRevocation(b); return e }},
		{"receipt", rb, func(b []byte) error { _, e := DecodeRevocationReceipt(b); return e }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.decode(test.raw) != nil {
				t.Fatal("valid vector")
			}
			for n := 0; n < len(test.raw); n++ {
				if test.decode(test.raw[:n]) == nil {
					t.Fatal("truncation", n)
				}
			}
			if test.decode(append(bytes.Clone(test.raw), 0)) == nil {
				t.Fatal("trailing byte")
			}
			for i := range test.raw {
				for bit := uint(0); bit < 8; bit++ {
					b := bytes.Clone(test.raw)
					b[i] ^= 1 << bit
					if test.decode(b) == nil {
						t.Fatal("accepted bit flip", i, bit)
					}
				}
			}
		})
	}
	if r.Verify(r.Guard, q.GuardID, q) != nil {
		t.Fatal("valid receipt")
	}
	bad := q
	bad.ReasonID = types.DomainHash("other")
	if r.Verify(r.Guard, q.GuardID, bad) == nil {
		t.Fatal("other request")
	}
	if r.Verify(q.Subject, q.GuardID, q) == nil || r.Verify(r.Guard, types.DomainHash("other"), q) == nil {
		t.Fatal("other trust root")
	}
	after, e := r.After()
	if e != nil || after.Sequence != 5 || after.Head != types.DomainHash(Domain+"event", r.Before.Head[:], qb) {
		t.Fatal("cursor", e)
	}
	for _, p := range []Position{{Head: after.Head}, {Sequence: 1}, {Sequence: MaximumEvents + 1, Head: after.Head}} {
		if p.Valid() {
			t.Fatal("invalid position")
		}
	}
}
func FuzzGuardRevocationCodecs(f *testing.F) {
	q, r := revocationVector(f)
	qb, _ := q.CanonicalBytes()
	rb, _ := r.CanonicalBytes()
	f.Add(qb)
	f.Add(rb)
	f.Fuzz(func(t *testing.T, b []byte) {
		if q, e := DecodeRevocation(b); e == nil {
			raw, e := q.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("request roundtrip")
			}
		}
		if r, e := DecodeRevocationReceipt(b); e == nil {
			raw, e := r.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("receipt roundtrip")
			}
		}
	})
}
