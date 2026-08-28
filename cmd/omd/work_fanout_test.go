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
	empty, err := parseWorkPeerTargets(nil, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty explicit target set=%v error=%v", empty, err)
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
	publisher, err := newWorkSharePublisher(context.Background(), []workPeerTarget{slow, fast}, 1, time.Minute, relay)
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
	publisher, err := newWorkSharePublisher(context.Background(), []workPeerTarget{target}, 2, time.Minute, relay)
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

func TestWorkShareFanoutFlushesPartialBatchOnTimer(t *testing.T) {
	target := workPeerTarget{id: types.DomainHash("test/omd/fanout/timed-partial")}
	relayed := make(chan []types.Hash, 1)
	relay := func(_ context.Context, _ workPeerTarget, ids []types.Hash) (worksession.Stats, error) {
		relayed <- append([]types.Hash(nil), ids...)
		return worksession.Stats{Announced: len(ids), Accepted: len(ids)}, nil
	}
	publisher, err := newWorkSharePublisher(
		context.Background(), []workPeerTarget{target}, 128, 10*time.Millisecond, relay,
	)
	if err != nil {
		t.Fatal(err)
	}
	share := testFanoutShare(1)
	id, err := share.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(share); err != nil {
		t.Fatal(err)
	}
	select {
	case ids := <-relayed:
		if len(ids) != 1 || ids[0] != id {
			t.Fatalf("timed relay ids=%v, want [%s]", ids, id)
		}
	case <-time.After(time.Second):
		t.Fatal("partial batch was not relayed on timer")
	}
	stats := publisher.Close()
	if stats.Queued != 1 || stats.Relayed != 1 || stats.Pending != 0 || stats.Failures != 0 {
		t.Fatalf("timed relay stats=%+v", stats)
	}
}

func TestWorkShareFanoutForwardsOnceWithoutEchoingSource(t *testing.T) {
	source := workPeerTarget{id: types.DomainHash("test/omd/fanout/source")}
	second := workPeerTarget{id: types.DomainHash("test/omd/fanout/second")}
	third := workPeerTarget{id: types.DomainHash("test/omd/fanout/third")}
	relayed := make(chan types.Hash, 2)
	relay := func(_ context.Context, target workPeerTarget, ids []types.Hash) (worksession.Stats, error) {
		if len(ids) != 1 {
			t.Errorf("forwarded ids=%v", ids)
		}
		relayed <- target.id
		return worksession.Stats{Announced: len(ids), Accepted: len(ids)}, nil
	}
	publisher, err := newWorkSharePublisher(
		context.Background(), []workPeerTarget{source, second, third}, 1, time.Minute, relay,
	)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := publisher.Forward(source.id, testFanoutShare(1))
	if err != nil || queued != 2 {
		t.Fatalf("forward queued=%d error=%v", queued, err)
	}
	seen := make(map[types.Hash]struct{}, 2)
	for range 2 {
		select {
		case peerID := <-relayed:
			seen[peerID] = struct{}{}
		case <-time.After(time.Second):
			t.Fatal("forwarded relay did not reach both non-source peers")
		}
	}
	stats := publisher.Close()
	if _, echoed := seen[source.id]; echoed {
		t.Fatal("remote share was echoed directly to its source")
	}
	if _, ok := seen[second.id]; !ok {
		t.Fatal("second peer did not receive forwarded share")
	}
	if _, ok := seen[third.id]; !ok {
		t.Fatal("third peer did not receive forwarded share")
	}
	if stats.Queued != 2 || stats.Relayed != 2 || stats.Pending != 0 {
		t.Fatalf("forward stats=%+v", stats)
	}
}

func TestWorkMiningRoundControlForwardsOnlyExactActiveContext(t *testing.T) {
	source := workPeerTarget{id: types.DomainHash("test/omd/control/source")}
	target := workPeerTarget{id: types.DomainHash("test/omd/control/target")}
	relayed := make(chan struct{}, 1)
	relay := func(_ context.Context, destination workPeerTarget, ids []types.Hash) (worksession.Stats, error) {
		if destination.id != target.id || len(ids) != 1 {
			t.Errorf("destination=%s ids=%v", destination.id, ids)
		}
		relayed <- struct{}{}
		return worksession.Stats{Announced: len(ids), Accepted: len(ids)}, nil
	}
	publisher, err := newWorkSharePublisher(
		context.Background(), []workPeerTarget{source, target}, 1, time.Minute, relay,
	)
	if err != nil {
		t.Fatal(err)
	}
	control := new(workMiningRoundControl)
	miningContext := workgraph.Context{
		AnchorParent: types.DomainHash("test/omd/control/parent"),
		PayloadRoot:  types.DomainHash("test/omd/control/payload"),
	}
	_, generation, finish := control.Begin(context.Background(), miningContext)
	stale := miningContext
	stale.PayloadRoot = types.DomainHash("test/omd/control/stale-payload")
	if control.Forward(stale, source.id, testFanoutShare(1)) {
		t.Fatal("share from a different mining context was forwarded")
	}
	if !control.Forward(miningContext, source.id, testFanoutShare(2)) {
		t.Fatal("share from active mining context was not buffered before attach")
	}
	if !control.Attach(generation, publisher) {
		t.Fatal("publisher was not attached to active generation")
	}
	select {
	case <-relayed:
	case <-time.After(time.Second):
		t.Fatal("active-context forward did not reach target")
	}
	stats := finish()
	publisher.Close()
	if stats.Shares != 1 || stats.Copies != 1 {
		t.Fatalf("gossip stats=%+v", stats)
	}
	if control.Forward(miningContext, source.id, testFanoutShare(3)) {
		t.Fatal("finished generation accepted a forward")
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
