package guardwire

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func replacementVector(t testing.TB) (Replacement, ReplacementReceipt, []byte) {
	t.Helper()
	rev, receipt := revocationVector(t)
	authority := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))
	guard := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	p, _ := receipt.After()
	rid, _ := rev.ID()
	q := Replacement{GuardID: rev.GuardID, Subject: rev.Subject, Authority: rev.Authority, RevocationID: rid, EvidenceID: types.DomainHash("vector/inventory"), Before: p}
	copy(q.Successor[:], key[32:])
	q, err := q.Accept(key)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := q.ProposalBytes()
	if err != nil {
		t.Fatal(err)
	}
	q, err = q.Authorize(authority)
	if err != nil {
		t.Fatal(err)
	}
	r, err := (ReplacementReceipt{Request: q, Guard: receipt.Guard}).Sign(guard)
	if err != nil {
		t.Fatal(err)
	}
	return q, r, proposal
}
func TestReplacementCodecsAndIndependentConsents(t *testing.T) {
	q, r, proposal := replacementVector(t)
	qb, _ := q.CanonicalBytes()
	rb, _ := r.CanonicalBytes()
	if len(qb) != ReplacementBytes || len(rb) != ReplacementReceiptBytes {
		t.Fatal("fixed sizes")
	}
	for i, raw := range [][]byte{qb, rb, proposal} {
		want := []string{"cf669b859bdb2aebdc774201b25ba70793789e7bfca9b72d04704ff4cea537e1", "f8a46ee2ac7a382e92337843da1b0c3038ac61eb7b14083d657d96c35b7d0e01", "43bdc0ac5db6d91aeca13309b8c81c14bc2e76352a083019386bdd9d17a39713"}
		if types.DomainHash("vector", raw).String() != want[i] {
			t.Fatal("replacement wire vector changed", i)
		}
	}
	if _, err := DecodeReplacement(proposal); err == nil {
		t.Fatal("proposal authorized itself")
	}
	if _, err := DecodeReplacementProposal(qb); err == nil {
		t.Fatal("signed command interpreted as unsigned consent")
	}
	if _, err := q.ProposalBytes(); err == nil {
		t.Fatal("authorization silently discarded")
	}
	for _, test := range []struct {
		name   string
		raw    []byte
		decode func([]byte) error
	}{
		{"proposal", proposal, func(b []byte) error { _, e := DecodeReplacementProposal(b); return e }},
		{"request", qb, func(b []byte) error { _, e := DecodeReplacement(b); return e }},
		{"receipt", rb, func(b []byte) error { _, e := DecodeReplacementReceipt(b); return e }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(test.raw); err != nil {
				t.Fatal(err)
			}
			for n := 0; n < len(test.raw); n++ {
				if test.decode(test.raw[:n]) == nil {
					t.Fatal("truncated", n)
				}
			}
			if test.decode(append(bytes.Clone(test.raw), 0)) == nil {
				t.Fatal("trailing byte")
			}
			for n := range test.raw {
				for bit := byte(1); bit != 0; bit <<= 1 {
					b := bytes.Clone(test.raw)
					b[n] ^= bit
					if test.decode(b) == nil {
						t.Fatal("bit accepted", n, bit)
					}
				}
			}
		})
	}
	if principal, e := r.Principal(r.Guard, q.Successor); e != nil || principal != q.Subject {
		t.Fatal("principal", e)
	}
	if _, e := r.Principal(q.Authority, q.Successor); e == nil {
		t.Fatal("foreign guard")
	}
	if _, e := r.Principal(r.Guard, q.Subject); e == nil {
		t.Fatal("retired key is successor")
	}
	after, e := r.After()
	if e != nil || after.Sequence != q.Before.Sequence+1 || after.Head != types.DomainHash(Domain+"event", q.Before.Head[:], qb) {
		t.Fatal("cursor", e)
	}
}
func FuzzGuardReplacementCodecs(f *testing.F) {
	q, r, p := replacementVector(f)
	a, _ := q.CanonicalBytes()
	b, _ := r.CanonicalBytes()
	f.Add(a)
	f.Add(b)
	f.Add(p)
	f.Fuzz(func(t *testing.T, b []byte) {
		if q, e := DecodeReplacement(b); e == nil {
			raw, e := q.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("request")
			}
		}
		if q, e := DecodeReplacementProposal(b); e == nil {
			raw, e := q.ProposalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("proposal")
			}
		}
		if q, e := DecodeReplacementReceipt(b); e == nil {
			raw, e := q.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("receipt")
			}
		}
	})
}
