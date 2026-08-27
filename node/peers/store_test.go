package peers

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestReputationFileRoundTripRestoresBackoffAndDecaysScore(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_400_000, 0)
	policy := testPolicy()
	policy.ScoreDecayInterval = time.Minute
	policy.DialBaseBackoff = 10 * time.Minute
	policy.DialMaxBackoff = 20 * time.Minute
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("test/peers/store")
	if err := manager.Record(id, EventUsefulSync); err != nil {
		t.Fatal(err)
	}
	if err := manager.Record(id, EventInvalidObject); err != nil {
		t.Fatal(err)
	}
	if err := manager.ObserveLatency(id, 25*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := manager.BeginDial(id); err != nil {
		t.Fatal(err)
	}
	if err := manager.EndDial(id, false); err != nil {
		t.Fatal(err)
	}
	if err := manager.Acquire(id); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reputation.bin")
	if err := SaveFile(path, manager); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("reputation mode = %o", info.Mode().Perm())
	}
	now = now.Add(2 * time.Minute)
	loaded, err := LoadFile(path, policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	snapshot, exists := loaded.Get(id)
	if !exists {
		t.Fatal("persisted peer was not restored")
	}
	// +5 useful, -10 invalid, -5 failed dial, then two points decay.
	if snapshot.Score != -8 || snapshot.DialFailures != 1 || snapshot.Sessions != 0 ||
		snapshot.UsefulSyncs != 1 || snapshot.InvalidEvents != 1 || snapshot.Timeouts != 1 ||
		snapshot.LatencyMillis != 25 || snapshot.LatencySamples != 1 {
		t.Fatalf("restored snapshot = %+v", snapshot)
	}
	if !now.Before(snapshot.NextDial) {
		t.Fatalf("dial backoff was not restored: %+v", snapshot)
	}
	if err := loaded.BeginDial(id); !errors.Is(err, ErrDialBackoff) {
		t.Fatalf("restored backoff error = %v", err)
	}
}

func TestDecodeReputationMigratesVersionZeroWithoutLatency(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_450_000, 0)
	policy := testPolicy()
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("test/peers/store/v0")
	if err := manager.Record(id, EventUsefulSync); err != nil {
		t.Fatal(err)
	}
	encoded, err := manager.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Version 1 appended two uint64 latency fields to each record. This fixture
	// has exactly one record, so removing its final fields recreates canonical
	// version-0 bytes and proves the local-policy upgrade path.
	if len(encoded) < 16 {
		t.Fatal("reputation fixture unexpectedly short")
	}
	legacy := append([]byte(nil), encoded[:len(encoded)-16]...)
	binary.BigEndian.PutUint16(legacy[len(reputationMagic):], reputationVersionV0)
	loaded, err := DecodeManager(legacy, policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	snapshot, exists := loaded.Get(id)
	if !exists || snapshot.UsefulSyncs != 1 || snapshot.LatencySamples != 0 || snapshot.LatencyMillis != 0 {
		t.Fatalf("migrated snapshot = %+v exists=%t", snapshot, exists)
	}
}

func TestDecodeReputationRejectsTrailingBytesAndPrunesRetention(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_500_000, 0)
	policy := testPolicy()
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("test/peers/store/prune")
	if err := manager.Record(id, EventValidMessage); err != nil {
		t.Fatal(err)
	}
	encoded, err := manager.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManager(append(encoded, 0), policy, func() time.Time { return now }); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing reputation error = %v", err)
	}
	now = now.Add(policy.Retention)
	loaded, err := DecodeManager(encoded, policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Len() != 0 {
		t.Fatalf("retained expired reputation records = %d", loaded.Len())
	}
}

func FuzzDecodeManagerNeverPanics(f *testing.F) {
	now := time.Unix(1_700_600_000, 0)
	policy := testPolicy()
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		f.Fatal(err)
	}
	if err := manager.Record(types.DomainHash("test/peers/store/fuzz"), EventUsefulSync); err != nil {
		f.Fatal(err)
	}
	encoded, err := manager.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeManager(input, policy, func() time.Time { return now })
	})
}
