package routing

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/peers"
)

func TestRouterRanksScoreSkipsSelfAndHonorsBackoff(t *testing.T) {
	t.Parallel()

	const nowUnix uint64 = 1_800_000_000
	clock := time.Unix(int64(nowUnix), 0)
	book, err := discovery.NewBook(91, 8)
	if err != nil {
		t.Fatal(err)
	}
	selfRecord := routingRecord(t, "self", "10.0.0.1:1", nowUnix)
	good := routingRecord(t, "good", "10.1.0.1:2", nowUnix)
	bad := routingRecord(t, "bad", "10.2.0.1:3", nowUnix)
	if err := book.AddBatch([]discovery.Record{selfRecord, good, bad}, nowUnix); err != nil {
		t.Fatal(err)
	}
	policy := peers.DefaultPolicy()
	policy.DialBaseBackoff = time.Minute
	policy.DialMaxBackoff = time.Minute
	manager, err := peers.New(policy, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	goodID, _ := good.PeerID()
	for range 3 {
		if err := manager.Record(goodID, peers.EventValidMessage); err != nil {
			t.Fatal(err)
		}
	}
	selfID, _ := selfRecord.PeerID()
	router, err := New(book, manager, selfID, func() uint64 { return uint64(clock.Unix()) })
	if err != nil {
		t.Fatal(err)
	}
	wantFailure := errors.New("unreachable")
	var order []types.Hash
	results := router.RunOnce(context.Background(), 2, func(_ context.Context, record discovery.Record) error {
		id, _ := record.PeerID()
		order = append(order, id)
		if id != goodID {
			return wantFailure
		}
		return nil
	})
	if len(results) != 2 || len(order) != 2 || order[0] != goodID {
		t.Fatalf("routing order=%v results=%v", order, results)
	}
	if order[0] == selfID || order[1] == selfID {
		t.Fatal("router dialed its own record")
	}

	// The failed candidate is backed off; the successful candidate is eligible
	// immediately and is the only second-run attempt.
	second := router.RunOnce(context.Background(), 2, func(_ context.Context, record discovery.Record) error {
		id, _ := record.PeerID()
		if id != goodID {
			t.Fatalf("backed-off peer was retried: %s", id)
		}
		return nil
	})
	if len(second) != 1 || second[0].PeerID != goodID {
		t.Fatalf("second routing results = %+v", second)
	}
}

func TestRouterCapsAttemptsPerResolvedASN(t *testing.T) {
	t.Parallel()

	const nowUnix uint64 = 1_800_000_000
	book, err := discovery.NewBook(91, 8)
	if err != nil {
		t.Fatal(err)
	}
	records := []discovery.Record{
		routingRecord(t, "asn-a-1", "10.1.0.1:1", nowUnix),
		routingRecord(t, "asn-a-2", "10.2.0.1:2", nowUnix),
		routingRecord(t, "asn-b", "11.1.0.1:3", nowUnix),
	}
	if err := book.AddBatch(records, nowUnix); err != nil {
		t.Fatal(err)
	}
	table, err := ParseASNTable(strings.NewReader("10.0.0.0/8,64500\n11.0.0.0/8,64501\n"))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(int64(nowUnix), 0)
	manager, err := peers.New(peers.DefaultPolicy(), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultPolicy()
	policy.ASNResolver = table
	policy.MaxPerASN = 1
	router, err := NewWithPolicy(book, manager, types.DomainHash("test/routing/asn-self"), func() uint64 { return nowUnix }, policy)
	if err != nil {
		t.Fatal(err)
	}
	attempted := make(map[uint32]int)
	results := router.RunOnce(context.Background(), 3, func(_ context.Context, record discovery.Record) error {
		ip, ok := recordAddressIP(record.Addresses[0])
		if !ok {
			t.Fatal("record address did not contain an IP")
		}
		asn, found := table.Lookup(ip)
		if !found {
			t.Fatal("record address was not ASN-resolved")
		}
		attempted[asn]++
		return nil
	})
	if len(results) != 2 || attempted[64500] != 1 || attempted[64501] != 1 {
		t.Fatalf("results=%d ASN attempts=%v", len(results), attempted)
	}
	if _, found := table.Lookup(netip.MustParseAddr("203.0.113.1")); found {
		t.Fatal("unexpected ASN match")
	}
}

func TestRouterRunUntilFiltersAndStopsAtSuccessfulCapabilityCount(t *testing.T) {
	t.Parallel()

	const nowUnix uint64 = 1_800_000_050
	book, err := discovery.NewBook(91, 8)
	if err != nil {
		t.Fatal(err)
	}
	records := []discovery.Record{
		routingRecord(t, "excluded", "10.1.0.1:1", nowUnix),
		routingRecord(t, "unsupported", "10.2.0.1:2", nowUnix),
		routingRecord(t, "supported-a", "10.3.0.1:3", nowUnix),
		routingRecord(t, "supported-b", "10.4.0.1:4", nowUnix),
		routingRecord(t, "unused", "10.5.0.1:5", nowUnix),
	}
	if err := book.AddBatch(records, nowUnix); err != nil {
		t.Fatal(err)
	}
	manager, err := peers.New(peers.DefaultPolicy(), func() time.Time { return time.Unix(int64(nowUnix), 0) })
	if err != nil {
		t.Fatal(err)
	}
	for index, record := range records {
		id, _ := record.PeerID()
		for range len(records) - index {
			if err := manager.Record(id, peers.EventValidMessage); err != nil {
				t.Fatal(err)
			}
		}
	}
	router, err := New(book, manager, types.DomainHash("test/routing/run-until-self"), func() uint64 { return nowUnix })
	if err != nil {
		t.Fatal(err)
	}
	excludedID, _ := records[0].PeerID()
	unsupportedID, _ := records[1].PeerID()
	unusedID, _ := records[4].PeerID()
	attempted := make([]types.Hash, 0, 3)
	results := router.RunUntil(
		context.Background(), 4, 2,
		func(record discovery.Record) bool {
			id, _ := record.PeerID()
			return id != excludedID
		},
		func(_ context.Context, record discovery.Record) error {
			id, _ := record.PeerID()
			attempted = append(attempted, id)
			if id == unsupportedID {
				return errors.New("capability unavailable")
			}
			return nil
		},
	)
	if len(results) != 3 || len(attempted) != 3 || attempted[0] != unsupportedID {
		t.Fatalf("run-until attempts=%v results=%+v", attempted, results)
	}
	for _, id := range attempted {
		if id == excludedID || id == unusedID {
			t.Fatalf("unexpected candidate attempted: %s", id)
		}
	}
}

func TestRouterUsesMeasuredLatencyAsDeterministicScoreTieBreak(t *testing.T) {
	t.Parallel()

	const nowUnix uint64 = 1_800_000_100
	book, err := discovery.NewBook(91, 8)
	if err != nil {
		t.Fatal(err)
	}
	fast := routingRecord(t, "latency-fast", "10.1.0.1:1", nowUnix)
	slow := routingRecord(t, "latency-slow", "10.2.0.1:2", nowUnix)
	unknown := routingRecord(t, "latency-unknown", "10.3.0.1:3", nowUnix)
	if err := book.AddBatch([]discovery.Record{unknown, slow, fast}, nowUnix); err != nil {
		t.Fatal(err)
	}
	manager, err := peers.New(peers.DefaultPolicy(), func() time.Time { return time.Unix(int64(nowUnix), 0) })
	if err != nil {
		t.Fatal(err)
	}
	fastID, _ := fast.PeerID()
	slowID, _ := slow.PeerID()
	unknownID, _ := unknown.PeerID()
	if err := manager.ObserveLatency(slowID, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := manager.ObserveLatency(fastID, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	router, err := New(book, manager, types.DomainHash("test/routing/latency-self"), func() uint64 { return nowUnix })
	if err != nil {
		t.Fatal(err)
	}
	var order []types.Hash
	results := router.RunOnce(context.Background(), 3, func(_ context.Context, record discovery.Record) error {
		id, _ := record.PeerID()
		order = append(order, id)
		return nil
	})
	if len(results) != 3 || len(order) != 3 || order[0] != fastID || order[1] != slowID || order[2] != unknownID {
		t.Fatalf("latency routing order=%v results=%v", order, results)
	}
}

func TestSchedulerRunsImmediateBoundedNonOverlappingPasses(t *testing.T) {
	const nowUnix uint64 = 1_800_000_000
	book, err := discovery.NewBook(91, 2)
	if err != nil {
		t.Fatal(err)
	}
	record := routingRecord(t, "scheduled", "10.10.0.1:10", nowUnix)
	if err := book.Add(record, nowUnix); err != nil {
		t.Fatal(err)
	}
	manager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	router, err := New(book, manager, types.DomainHash("test/routing/scheduler-self"), func() uint64 { return nowUnix })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls atomic.Int32
	var preflights atomic.Int32
	var active atomic.Int32
	var maximum atomic.Int32
	scheduler, err := NewScheduler(router, SchedulerConfig{
		Interval: time.Millisecond, AttemptLimit: 1,
		Preflight: func() error {
			preflights.Add(1)
			return nil
		},
	}, func(context.Context, discovery.Record) error {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond)
		active.Add(-1)
		if calls.Add(1) == 3 {
			cancel()
		}
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || preflights.Load() != 3 || maximum.Load() != 1 {
		t.Fatalf("scheduler calls=%d preflights=%d maximum_concurrency=%d", calls.Load(), preflights.Load(), maximum.Load())
	}
}

func TestSchedulerStopsBeforeDialWhenPreflightFails(t *testing.T) {
	const nowUnix uint64 = 1_800_000_200
	book, err := discovery.NewBook(91, 2)
	if err != nil {
		t.Fatal(err)
	}
	record := routingRecord(t, "preflight", "10.10.0.2:10", nowUnix)
	if err := book.Add(record, nowUnix); err != nil {
		t.Fatal(err)
	}
	manager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	router, err := New(book, manager, types.DomainHash("test/routing/preflight-self"), func() uint64 { return nowUnix })
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("stale routing policy")
	called := false
	scheduler, err := NewScheduler(router, SchedulerConfig{
		Interval: time.Second, AttemptLimit: 1, Preflight: func() error { return want },
	}, func(context.Context, discovery.Record) error {
		called = true
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Run(context.Background()); !errors.Is(err, want) || called {
		t.Fatalf("scheduler error=%v connector_called=%t", err, called)
	}
}

func routingRecord(t testing.TB, label, address string, now uint64) discovery.Record {
	t.Helper()
	seed := types.DomainHash("test/routing/key", []byte(label))
	record, err := discovery.Sign(ed25519.NewKeyFromSeed(seed[:]), 91, 1, now+600, []string{address})
	if err != nil {
		t.Fatal(err)
	}
	return record
}
