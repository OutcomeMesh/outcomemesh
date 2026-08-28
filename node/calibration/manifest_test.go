package calibration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
)

func TestManifestCanonicalAndFileRoundTrip(t *testing.T) {
	records, binding := testChain(t)
	encoded, aggregate, err := EncodeManifest(records, binding)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodedAggregate, err := DecodeManifest(encoded, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(records) || !bytes.Equal(decoded[1].CanonicalBytes(), records[1].CanonicalBytes()) ||
		decodedAggregate.LastRecordID != aggregate.LastRecordID {
		t.Fatal("manifest changed during canonical round trip")
	}

	path := filepath.Join(t.TempDir(), "nested", "telemetry.omtm")
	saved, err := SaveFile(path, records, binding)
	if err != nil {
		t.Fatal(err)
	}
	loaded, loadedAggregate, err := LoadFile(path, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(records) || loadedAggregate.LastRecordID != saved.LastRecordID {
		t.Fatalf("loaded aggregate = %+v, saved = %+v", loadedAggregate, saved)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestManifestDecodeRejectsTruncationTrailingAndWrongBinding(t *testing.T) {
	records, binding := testChain(t)
	encoded, _, err := EncodeManifest(records, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeManifest(encoded[:len(encoded)-1], binding); err == nil {
		t.Fatal("truncated manifest was accepted")
	}
	if _, _, err := DecodeManifest(append(encoded, 0), binding); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing manifest error = %v", err)
	}
	foreign := binding
	foreign.ActivationHeight++
	if _, _, err := DecodeManifest(encoded, foreign); !errors.Is(err, ErrBinding) {
		t.Fatalf("foreign manifest error = %v", err)
	}
	if _, _, err := DecodeManifest(make([]byte, MaximumManifestBytes+1), binding); !errors.Is(err, ErrManifestLimit) {
		t.Fatalf("oversize manifest error = %v", err)
	}
}

func FuzzDecodeManifestNeverPanics(f *testing.F) {
	records, binding := testChain(f)
	encoded, _, err := EncodeManifest(records, binding)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = DecodeManifest(input, binding)
	})
}
