package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

func TestWorkPeerTargetsRequireUniqueAuthenticatedIdentities(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := testWorkPeerTarget(t, ctx, "first")
	second := testWorkPeerTarget(t, ctx, "second")
	addresses := repeatedStringFlag{first.address, second.address}
	pins := repeatedStringFlag{first.id.String(), second.id.String()}
	targets, err := parseWorkPeerTargets(addresses, pins)
	if err != nil || len(targets) != 2 || targets[0].id != first.id || targets[1].id != second.id {
		t.Fatalf("targets=%+v error=%v", targets, err)
	}
	if _, err := parseWorkPeerTargets(
		repeatedStringFlag{first.address, first.address},
		repeatedStringFlag{first.id.String(), first.id.String()},
	); err == nil {
		t.Fatal("duplicate authenticated identity was accepted")
	}
	if _, err := parseWorkPeerTargets(addresses, repeatedStringFlag{second.id.String(), first.id.String()}); err == nil {
		t.Fatal("mismatched peer pins were accepted")
	}
	if _, err := parseWorkPeerTargets(addresses, repeatedStringFlag{first.id.String()}); err == nil {
		t.Fatal("partial peer pin list was accepted")
	}
	overLimit := make(repeatedStringFlag, maxWorkMiningPeers+1)
	for index := range overLimit {
		overLimit[index] = first.address
	}
	if _, err := parseWorkPeerTargets(overLimit, nil); err == nil {
		t.Fatal("over-limit peer list was accepted")
	}
}

func TestWorkShareFanoutIsolatesSlowPeer(t *testing.T) {
	fast := workPeerTarget{id: types.DomainHash("test/omd/fanout/fast")}
	slow := workPeerTarget{id: types.DomainHash("test/omd/fanout/slow")}
	fastDone := make(chan struct{}, 1)
	slowStarted := make(chan struct{}, 1)
	relay := func(ctx context.Context, target workPeerTarget, ids []types.Hash) (worksession.Stats, error) {
		if target.id == slow.id {
			select {
			case slowStarted <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return worksession.Stats{}, ctx.Err()
		}
		fastDone <- struct{}{}
		return worksession.Stats{Announced: len(ids), Accepted: len(ids)}, nil
	}
	publisher, err := newWorkSharePublisher(context.Background(), []workPeerTarget{slow, fast}, 1, relay)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := publisher.Publish(testFanoutShare(1)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("Publish performed blocking relay work: %s", elapsed)
	}
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow peer worker did not start")
	}
	select {
	case <-fastDone:
	case <-time.After(time.Second):
		t.Fatal("healthy peer was blocked behind slow peer")
	}
	stats := publisher.Close()
	if stats.Peers != 2 || stats.ReachedPeers != 1 || stats.FailedPeers != 0 ||
		stats.Queued != 2 || stats.Relayed != 1 || stats.Failures != 0 || stats.Pending != 1 || stats.Dropped != 0 {
		t.Fatalf("fanout stats=%+v", stats)
	}
}

func TestWorkShareFanoutSortsAndHonorsNegotiatedPrefixes(t *testing.T) {
	target := workPeerTarget{id: types.DomainHash("test/omd/fanout/prefix")}
	var mu sync.Mutex
	var batches [][]types.Hash
	done := make(chan struct{}, 1)
	relay := func(_ context.Context, _ workPeerTarget, ids []types.Hash) (worksession.Stats, error) {
		mu.Lock()
		batches = append(batches, append([]types.Hash(nil), ids...))
		call := len(batches)
		mu.Unlock()
		if call == 2 {
			done <- struct{}{}
		}
		return worksession.Stats{Announced: 1}, nil
	}
	publisher, err := newWorkSharePublisher(context.Background(), []workPeerTarget{target}, 2, relay)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(testFanoutShare(2)); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(testFanoutShare(1)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("negotiated prefix was not retried")
	}
	stats := publisher.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 2 || len(batches[0]) != 2 || len(batches[1]) != 1 ||
		types.CompareHash(batches[0][0], batches[0][1]) >= 0 || batches[1][0] != batches[0][1] {
		t.Fatalf("relay batches=%v", batches)
	}
	if stats.Relayed != 2 || stats.Pending != 0 || stats.Failures != 0 {
		t.Fatalf("prefix stats=%+v", stats)
	}
}

func TestWorkAnchorNotifierCoalescesBusyPeerWithoutBlockingOthers(t *testing.T) {
	fast := workPeerTarget{id: types.DomainHash("test/omd/notify/fast")}
	slow := workPeerTarget{id: types.DomainHash("test/omd/notify/slow")}
	slowStarted := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})
	fastCalls := make(chan struct{}, 4)
	notify := func(ctx context.Context, target workPeerTarget) error {
		if target.id == fast.id {
			fastCalls <- struct{}{}
			return nil
		}
		select {
		case slowStarted <- struct{}{}:
		default:
		}
		select {
		case <-releaseSlow:
			return errors.New("isolated slow peer failure")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	notifier, err := newWorkAnchorNotifier(context.Background(), []workPeerTarget{slow, fast}, notify)
	if err != nil {
		t.Fatal(err)
	}
	if queued := notifier.Notify(); queued != 2 {
		t.Fatalf("first notification queued=%d", queued)
	}
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow notification did not start")
	}
	notifier.Notify()
	notifier.Notify()
	select {
	case <-fastCalls:
	case <-time.After(time.Second):
		t.Fatal("healthy notification was blocked")
	}
	close(releaseSlow)
	stats := notifier.Close()
	if stats.Peers != 2 || stats.Succeeded == 0 || stats.Failed == 0 || stats.Coalesced == 0 ||
		stats.Attempts > stats.Queued {
		t.Fatalf("notification stats=%+v", stats)
	}
}

func testWorkPeerTarget(t testing.TB, ctx context.Context, label string) workPeerTarget {
	t.Helper()
	seed := types.DomainHash("test/omd/fanout/key", []byte(label))
	key := ed25519.NewKeyFromSeed(seed[:])
	host, err := libp2ptransport.New(ctx, key, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	addresses := host.Addresses()
	if len(addresses) == 0 {
		t.Fatal("test host has no address")
	}
	return workPeerTarget{address: addresses[0], id: host.ID()}
}

func testFanoutShare(nonce uint64) workgraph.Share {
	return workgraph.Share{
		Version: workgraph.Version0, NetworkID: 1, Height: 1,
		AnchorParent: types.DomainHash("test/omd/fanout/parent"), Timestamp: 1,
		Target:        types.DomainHash("test/omd/fanout/target"),
		PayloadRoot:   types.DomainHash("test/omd/fanout/payload"),
		Miner:         types.Address(types.DomainHash("test/omd/fanout/miner")),
		InclusionRoot: types.DomainHash("test/omd/fanout/inclusion"), Nonce: nonce,
	}
}
