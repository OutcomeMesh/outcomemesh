package peers

import (
	"errors"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestSessionAndInboundRateLimitsResetSafely(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	policy := testPolicy()
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("test/peers/limited")
	if err := manager.Acquire(id); err != nil {
		t.Fatal(err)
	}
	if err := manager.Acquire(id); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("session limit error = %v", err)
	}
	manager.Release(id)
	if err := manager.Acquire(id); err != nil {
		t.Fatalf("released session was not reusable: %v", err)
	}
	if err := manager.AllowInbound(id, 60); err != nil {
		t.Fatal(err)
	}
	if err := manager.AllowInbound(id, 41); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("rate limit error = %v", err)
	}
	now = now.Add(policy.Window)
	if err := manager.AllowInbound(id, 100); err != nil {
		t.Fatalf("new byte window remained limited: %v", err)
	}
	if err := manager.AllowOutbound(id, 70); err != nil {
		t.Fatal(err)
	}
	if err := manager.AllowOutbound(id, 31); !errors.Is(err, ErrOutboundRate) {
		t.Fatalf("outbound rate limit error = %v", err)
	}
	now = now.Add(policy.Window)
	if err := manager.AllowOutbound(id, 100); err != nil {
		t.Fatalf("new outbound window remained limited: %v", err)
	}
}

func TestInvalidMessagesBanAndBanExpires(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	policy := testPolicy()
	manager, _ := New(policy, func() time.Time { return now })
	id := types.DomainHash("test/peers/banned")
	for range 2 {
		if err := manager.Record(id, EventInvalidMessage); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.Acquire(id); !errors.Is(err, ErrBanned) {
		t.Fatalf("ban error = %v", err)
	}
	snapshot, _ := manager.Get(id)
	if snapshot.Score > policy.BanThreshold || !snapshot.BannedUntil.Equal(now.Add(policy.BanDuration)) {
		t.Fatalf("unexpected ban snapshot: %+v", snapshot)
	}
	now = now.Add(policy.BanDuration)
	if err := manager.Acquire(id); err != nil {
		t.Fatalf("expired ban still active: %v", err)
	}
	snapshot, _ = manager.Get(id)
	if snapshot.Score != 0 {
		t.Fatalf("expired ban score = %d, want reset", snapshot.Score)
	}
}

func TestPeerTableIsBoundedAndPrunesInactiveRecords(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	policy := testPolicy()
	policy.MaxTrackedPeers = 2
	manager, _ := New(policy, func() time.Time { return now })
	first := types.DomainHash("test/peers/first")
	second := types.DomainHash("test/peers/second")
	third := types.DomainHash("test/peers/third")
	if err := manager.Record(first, EventValidMessage); err != nil {
		t.Fatal(err)
	}
	if err := manager.Record(second, EventValidMessage); err != nil {
		t.Fatal(err)
	}
	if err := manager.Record(third, EventValidMessage); !errors.Is(err, ErrPeerCapacity) {
		t.Fatalf("peer table error = %v", err)
	}
	now = now.Add(policy.Retention)
	if err := manager.Record(third, EventValidMessage); err != nil {
		t.Fatalf("inactive peer table was not pruned: %v", err)
	}
	if manager.Len() != 1 {
		t.Fatalf("peer table length = %d, want 1 after pruning", manager.Len())
	}
}

func TestValidScoreCapsAndZeroIdentityFails(t *testing.T) {
	t.Parallel()

	manager, _ := New(testPolicy(), nil)
	id := types.DomainHash("test/peers/good")
	for range 100 {
		_ = manager.Record(id, EventValidMessage)
	}
	snapshot, _ := manager.Get(id)
	if snapshot.Score != testPolicy().MaxScore {
		t.Fatalf("score = %d, want cap %d", snapshot.Score, testPolicy().MaxScore)
	}
	if err := manager.Acquire(types.Hash{}); !errors.Is(err, ErrPeerID) {
		t.Fatalf("zero identity error = %v", err)
	}
}

func TestDialReservationBacksOffExponentiallyAndResetsOnSuccess(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	policy := testPolicy()
	policy.DialBaseBackoff = time.Second
	policy.DialMaxBackoff = 4 * time.Second
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("test/peers/dial")
	if err := manager.BeginDial(id); err != nil {
		t.Fatal(err)
	}
	if err := manager.BeginDial(id); !errors.Is(err, ErrDialBackoff) {
		t.Fatalf("parallel dial error = %v", err)
	}
	if err := manager.EndDial(id, false); err != nil {
		t.Fatal(err)
	}
	if err := manager.BeginDial(id); !errors.Is(err, ErrDialBackoff) {
		t.Fatalf("first backoff error = %v", err)
	}
	now = now.Add(time.Second)
	if err := manager.BeginDial(id); err != nil {
		t.Fatal(err)
	}
	if err := manager.EndDial(id, false); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := manager.Get(id)
	if snapshot.DialFailures != 2 || !snapshot.NextDial.Equal(now.Add(2*time.Second)) {
		t.Fatalf("dial snapshot = %+v", snapshot)
	}
	now = now.Add(2 * time.Second)
	if err := manager.BeginDial(id); err != nil {
		t.Fatal(err)
	}
	if err := manager.EndDial(id, true); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = manager.Get(id)
	if snapshot.DialFailures != 0 || !snapshot.NextDial.IsZero() {
		t.Fatalf("successful dial did not reset: %+v", snapshot)
	}
	if err := manager.EndDial(id, true); !errors.Is(err, ErrDialState) {
		t.Fatalf("unreserved dial completion error = %v", err)
	}
}

func TestPruningCannotDeleteActiveDialAndClockCannotRollBack(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	policy := testPolicy()
	policy.MaxTrackedPeers = 1
	policy.Retention = time.Minute
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	active := types.DomainHash("test/peers/active-dial")
	other := types.DomainHash("test/peers/prune-contender")
	if err := manager.BeginDial(active); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * policy.Retention)
	if err := manager.Record(other, EventValidMessage); !errors.Is(err, ErrPeerCapacity) {
		t.Fatalf("active dial was not protected from pruning: %v", err)
	}
	if err := manager.EndDial(active, false); err != nil {
		t.Fatalf("active dial reservation was lost: %v", err)
	}
	snapshot, _ := manager.Get(active)
	beforeRollback := snapshot.LastSeen
	now = now.Add(-24 * time.Hour)
	manager.Release(active)
	snapshot, _ = manager.Get(active)
	if snapshot.LastSeen.Before(beforeRollback) || !snapshot.NextDial.After(snapshot.LastSeen) {
		t.Fatalf("clock rollback escaped monotonic clamp: %+v", snapshot)
	}
}

func TestResourceExhaustionKeepsPeerStateBounded(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_100_000, 0)
	policy := testPolicy()
	policy.MaxTrackedPeers = 64
	policy.MaxSessionsPerPeer = 3
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]types.Hash, 256)
	for index := range ids {
		ids[index] = types.DomainHash("test/peers/exhaustion", []byte{byte(index)})
	}
	state := uint64(0x6a09e667f3bcc909)
	for step := 0; step < 50_000; step++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		id := ids[int(state%uint64(len(ids)))]
		switch (state >> 8) % 7 {
		case 0:
			_ = manager.Acquire(id)
		case 1:
			manager.Release(id)
		case 2:
			_ = manager.AllowInbound(id, state%150)
		case 3:
			_ = manager.Record(id, Event((state%6)+1))
		case 4:
			_ = manager.BeginDial(id)
		case 5:
			_ = manager.EndDial(id, state&1 == 0)
		case 6:
			if state&1 == 0 {
				now = now.Add(time.Second)
			} else {
				now = now.Add(-time.Second)
			}
		}
		assertManagerBounds(t, manager, policy)
	}
}

func TestBehaviorScoreTracksClassesAndDecaysTowardNeutral(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_300_000, 0)
	policy := testPolicy()
	policy.ScoreDecayInterval = time.Minute
	manager, err := New(policy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("test/peers/behavior")
	if err := manager.Record(id, EventUsefulSync); err != nil {
		t.Fatal(err)
	}
	if err := manager.Record(id, EventValidMessage); err != nil {
		t.Fatal(err)
	}
	if err := manager.Record(id, EventStaleData); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := manager.Get(id)
	if snapshot.Score != 5 || snapshot.UsefulSyncs != 1 || snapshot.ValidEvents != 1 || snapshot.StaleEvents != 1 {
		t.Fatalf("behavior snapshot = %+v", snapshot)
	}
	now = now.Add(3 * policy.ScoreDecayInterval)
	snapshot, _ = manager.Get(id)
	if snapshot.Score != 2 {
		t.Fatalf("decayed score = %d, want 2", snapshot.Score)
	}
	if err := manager.Record(id, EventInvalidObject); err != nil {
		t.Fatal(err)
	}
	if err := manager.Record(id, EventTimeout); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = manager.Get(id)
	if snapshot.Score != -13 || snapshot.InvalidEvents != 1 || snapshot.Timeouts != 1 {
		t.Fatalf("negative behavior snapshot = %+v", snapshot)
	}
	now = now.Add(20 * policy.ScoreDecayInterval)
	snapshot, _ = manager.Get(id)
	if snapshot.Score != 0 {
		t.Fatalf("negative score did not decay to neutral: %d", snapshot.Score)
	}
}

func TestLatencyObservationUsesBoundedIntegerEWMA(t *testing.T) {
	t.Parallel()

	manager, err := New(testPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("test/peers/latency")
	if err := manager.ObserveLatency(id, 80*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := manager.ObserveLatency(id, 160*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := manager.Get(id)
	if snapshot.LatencyMillis != 90 || snapshot.LatencySamples != 2 {
		t.Fatalf("latency snapshot = %+v", snapshot)
	}
	if err := manager.ObserveLatency(id, 0); !errors.Is(err, ErrLatency) {
		t.Fatalf("zero latency error = %v", err)
	}
	if err := manager.ObserveLatency(id, 2*MaxObservedLatency); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = manager.Get(id)
	if snapshot.LatencyMillis == 0 || snapshot.LatencyMillis > uint64(MaxObservedLatency/time.Millisecond) ||
		snapshot.LatencySamples != 3 {
		t.Fatalf("bounded latency snapshot = %+v", snapshot)
	}
}

func FuzzManagerStateMachine(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 255})
	f.Add([]byte("peer-manager-adversarial-sequence"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4_096 {
			input = input[:4_096]
		}
		now := time.Unix(1_700_200_000, 0)
		policy := testPolicy()
		policy.MaxTrackedPeers = 16
		manager, err := New(policy, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]types.Hash, 32)
		for index := range ids {
			ids[index] = types.DomainHash("test/peers/fuzz", []byte{byte(index)})
		}
		for index, value := range input {
			id := ids[(int(value)+index)%len(ids)]
			switch value % 10 {
			case 0:
				_ = manager.Acquire(id)
			case 1:
				manager.Release(id)
			case 2:
				_ = manager.AllowInbound(id, uint64(value)*2)
			case 3:
				_ = manager.Record(id, Event(value>>5))
			case 4:
				_ = manager.BeginDial(id)
			case 5:
				_ = manager.EndDial(id, value&0x10 != 0)
			case 6:
				now = now.Add(time.Duration(value) * time.Second)
			case 7:
				now = now.Add(-time.Duration(value) * time.Second)
			case 8:
				_ = manager.AllowOutbound(id, uint64(value)*2)
			case 9:
				_ = manager.ObserveLatency(id, time.Duration(value+1)*time.Millisecond)
			}
			assertManagerBounds(t, manager, policy)
		}
	})
}

func assertManagerBounds(t testing.TB, manager *Manager, policy Policy) {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.records) > policy.MaxTrackedPeers {
		t.Fatalf("peer records = %d, cap = %d", len(manager.records), policy.MaxTrackedPeers)
	}
	for id, entry := range manager.records {
		if id.IsZero() || entry.Sessions < 0 || entry.Sessions > policy.MaxSessionsPerPeer ||
			entry.WindowBytes > policy.MaxInboundWindowBytes || entry.OutboundWindowBytes > policy.MaxOutboundWindowBytes ||
			entry.Score < policy.BanThreshold ||
			entry.Score > policy.MaxScore ||
			entry.LatencyMillis > uint64(MaxObservedLatency/time.Millisecond) ||
			(entry.LatencySamples == 0) != (entry.LatencyMillis == 0) {
			t.Fatalf("peer invariant failed id=%s entry=%+v", id, entry)
		}
	}
}

func testPolicy() Policy {
	return Policy{
		MaxTrackedPeers:        10,
		MaxSessionsPerPeer:     1,
		MaxInboundWindowBytes:  100,
		MaxOutboundWindowBytes: 100,
		Window:                 time.Minute,
		Retention:              time.Hour,
		BanDuration:            10 * time.Minute,
		BanThreshold:           -50,
		MaxScore:               20,
	}
}
