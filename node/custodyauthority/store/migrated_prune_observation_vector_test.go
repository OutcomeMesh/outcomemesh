package store

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type pruneObservationVector struct {
	Kind  string `json:"kind"`
	Bytes []byte `json:"bytes"`
	ID    string `json:"id"`
}

func fixedPruneObservations(t testing.TB) []pruneObservationVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/migrated_prune_observation_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var v []pruneObservationVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPruneMigratedObservationGolden(t *testing.T) {
	for _, v := range fixedPruneObservations(t) {
		t.Run(v.Kind, func(t *testing.T) {
			o, err := DecodeMigratedPruneObservation(v.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			id, err := o.ID()
			if err != nil || id.String() != v.ID {
				t.Fatal("observation ID changed", err)
			}
			raw, err := o.CanonicalBytes()
			if err != nil || !bytes.Equal(raw, v.Bytes) {
				t.Fatal("canonical observation changed", err)
			}
			if (o.Effect != nil) != (v.Kind == "retained") {
				t.Fatal("observation branch changed")
			}
			for _, offset := range []int{0, 8, 9} {
				bad := bytes.Clone(raw)
				bad[offset] ^= 1
				if _, err := DecodeMigratedPruneObservation(bad); err == nil {
					t.Fatal("unknown magic/version accepted")
				}
			}
			// The first variable-length field starts after 13 hashes and Q/B/Q/Q.
			lengthAt := 10 + 13*32 + 8 + 1 + 8 + 8
			if v.Kind == "absent" {
				bad := append(bytes.Clone(raw[:lengthAt]), 0x80, 0)
				if _, err := DecodeMigratedPruneObservation(bad); err == nil {
					t.Fatal("overlong empty field accepted")
				}
			}
		})
	}
}

func FuzzPruneMigratedObservation(f *testing.F) {
	for _, v := range fixedPruneObservations(f) {
		f.Add(v.Bytes)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		o, err := DecodeMigratedPruneObservation(raw)
		if err != nil {
			return
		}
		encoded, err := o.CanonicalBytes()
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("noncanonical observation")
		}
		if _, err := o.ID(); err != nil {
			t.Fatal("accepted observation has no ID", err)
		}
		if _, err := DecodePruneCancellation(raw); err == nil {
			t.Fatal("observation decoded as terminal")
		}
	})
}
