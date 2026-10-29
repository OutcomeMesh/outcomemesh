package custodyv2

import (
	"bytes"
	"encoding/hex"
	"github.com/outcomemesh/outcomemesh/core/types"
	"testing"
)

func TestRetainedAcceptanceCodecBounds(t *testing.T) {
	a := RetainedAcceptance{ContextID: types.Hash{1}, BundleID: types.Hash{2}, EvidenceID: types.Hash{3}, NotBefore: 10, NotAfter: 20}
	raw, e := a.CanonicalBytes()
	if e != nil || len(raw) != RetainedAcceptanceBytes {
		t.Fatal(e)
	}
	const vector = "4f4d435652414331010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	if hex.EncodeToString(raw) != vector {
		t.Fatal("v1 consent encoding changed")
	}
	b, e := DecodeRetainedAcceptance(raw)
	if e != nil || a != b {
		t.Fatal("roundtrip")
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(bytes.Clone(raw), 0), append([]byte("BADMAGIC"), raw[8:]...)} {
		if _, e = DecodeRetainedAcceptance(bad); e == nil {
			t.Fatal("noncanonical")
		}
	}
	a.NotAfter = a.NotBefore + MaximumRetainedAcceptanceWindow + 1
	if _, e = a.CanonicalBytes(); e == nil {
		t.Fatal("unbounded consent")
	}
}
func FuzzRetainedAcceptance(f *testing.F) {
	a := RetainedAcceptance{ContextID: types.Hash{1}, BundleID: types.Hash{2}, EvidenceID: types.Hash{3}, NotBefore: 10, NotAfter: 20}
	b, _ := a.CanonicalBytes()
	f.Add(b)
	f.Add([]byte("OMCVRAD1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if a, e := DecodeRetainedAcceptance(b); e == nil {
			raw, e := a.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("consent roundtrip")
			}
		}
		if bundle, a, e := DecodeRetainedAcceptanceData(b); e == nil {
			raw, e := EncodeRetainedAcceptance(bundle, a)
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("data roundtrip")
			}
		}
		if r, e := DecodeReceipt(b); e == nil {
			raw, e := r.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("receipt roundtrip")
			}
		}
	})
}
