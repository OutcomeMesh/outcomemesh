package discovery

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
)

func TestPeerBookFileRoundTripPrunesExpiryAndPreservesAntiReplay(t *testing.T) {
	t.Parallel()

	policy := Policy{MaxRecords: 8, MaxPerNetwork: 4}
	book, err := NewBookWithPolicy(91, policy)
	if err != nil {
		t.Fatal(err)
	}
	expiring := mustSign(t, "stored-expiring", 91, 1, testNow+1, "10.0.0.1:1001")
	alive := mustSign(t, "stored-alive", 91, 7, testNow+100, "10.1.0.1:1002")
	if err := book.AddBatch([]Record{expiring, alive}, testNow); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "peers.bin")
	if err := SaveFile(path, book, testNow); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("peerbook mode = %o", info.Mode().Perm())
	}
	loaded, err := LoadFile(path, 91, policy, testNow+2)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Len(testNow + 2); got != 1 {
		t.Fatalf("loaded live records = %d, want 1", got)
	}
	if err := loaded.Add(alive, testNow+2); !errors.Is(err, ErrStale) {
		t.Fatalf("restored anti-replay error = %v", err)
	}
	id, err := alive.PeerID()
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := loaded.NextSequence(id, 3)
	if err != nil || sequence != alive.Sequence+1 {
		t.Fatalf("restart sequence = %d, %v", sequence, err)
	}
}

func TestDecodeBookRejectsWrongNetworkTrailingBytesAndOversizePolicy(t *testing.T) {
	t.Parallel()

	policy := Policy{MaxRecords: 2, MaxPerNetwork: 2}
	book, err := NewBookWithPolicy(91, policy)
	if err != nil {
		t.Fatal(err)
	}
	record := mustSign(t, "stored-decode", 91, 1, testNow+100, "127.0.0.1:9844")
	if err := book.Add(record, testNow); err != nil {
		t.Fatal(err)
	}
	encoded, err := book.CanonicalBytes(testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBook(encoded, 92, policy, testNow); !errors.Is(err, ErrNetwork) {
		t.Fatalf("network error = %v", err)
	}
	if _, err := DecodeBook(append(encoded, 0), 91, policy, testNow); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing error = %v", err)
	}
	if _, err := NewBookWithPolicy(91, Policy{MaxRecords: MaxBookRecords + 1, MaxPerNetwork: 1}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("oversize policy error = %v", err)
	}
}

func FuzzDecodeBookNeverPanics(f *testing.F) {
	policy := Policy{MaxRecords: 8, MaxPerNetwork: 8}
	book, err := NewBookWithPolicy(91, policy)
	if err != nil {
		f.Fatal(err)
	}
	record := mustSign(f, "stored-fuzz", 91, 1, testNow+100, "127.0.0.1:9844")
	if err := book.Add(record, testNow); err != nil {
		f.Fatal(err)
	}
	encoded, err := book.CanonicalBytes(testNow)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeBook(input, 91, policy, testNow)
	})
}
