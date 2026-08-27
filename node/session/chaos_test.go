package session

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestFiveNodePartitionHealConvergesWithFragmentedDelayedStreams(t *testing.T) {
	nodes := make([]nodeFixture, 5)
	for index := range nodes {
		nodes[index] = newNodeFixture(t, 610)
		defer nodes[index].store.Close()
	}
	minerA := types.Address(types.DomainHash("test/session/chaos/miner-a"))
	minerB := types.Address(types.DomainHash("test/session/chaos/miner-b"))

	// Partition A sees five blocks; partition B independently sees three.
	mine(t, nodes[0], minerA, 5)
	synchronizeFixtures(t, nodes[1], nodes[0], true)
	synchronizeFixtures(t, nodes[2], nodes[0], true)
	mine(t, nodes[3], minerB, 3)
	synchronizeFixtures(t, nodes[4], nodes[3], true)

	// Heal the partition through a chain of pairwise sessions. Duplicate sync is
	// intentional and must be harmless when the peer is no longer better.
	synchronizeFixtures(t, nodes[3], nodes[0], true)
	synchronizeFixtures(t, nodes[4], nodes[3], true)
	synchronizeFixtures(t, nodes[1], nodes[4], true)
	synchronizeFixtures(t, nodes[1], nodes[0], true)

	want, err := nodes[0].store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	for index, node := range nodes {
		got, err := node.store.Tip()
		if err != nil {
			t.Fatal(err)
		}
		if !storage.EqualTips(got, want) {
			t.Fatalf("node %d did not converge: height=%d id=%s", index, got.Height, got.ID)
		}
	}
}

func TestSevenNodeStochasticLossChurnAndAsymmetricPartitionsConverge(t *testing.T) {
	nodes := make([]nodeFixture, 7)
	for index := range nodes {
		nodes[index] = newNodeFixture(t, 613)
		defer nodes[index].store.Close()
	}
	miners := make([]types.Address, len(nodes))
	for index := range miners {
		miners[index] = types.Address(types.DomainHash("test/session/stochastic/miner", []byte{byte(index)}))
		mine(t, nodes[index], miners[index], 1)
	}

	random := rand.New(rand.NewSource(0x0_0c_0a_05))
	delivered := 0
	dropped := 0
	mined := len(nodes)
	for epoch := 0; epoch < 10; epoch++ {
		// Directional reachability models asymmetric partitions. Recreating a
		// fresh stream for every delivery also exercises connection churn.
		var reachable [7][7]bool
		for destination := range nodes {
			for source := range nodes {
				reachable[destination][source] = destination != source && random.Intn(100) < 45
			}
		}
		for range 14 {
			if random.Intn(100) < 48 {
				index := random.Intn(len(nodes))
				mine(t, nodes[index], miners[index], 1)
				mined++
				continue
			}
			destination := random.Intn(len(nodes))
			source := random.Intn(len(nodes) - 1)
			if source >= destination {
				source++
			}
			if !reachable[destination][source] || random.Intn(100) < 22 {
				dropped++
				continue
			}
			synchronizeFixtures(t, nodes[destination], nodes[source], true)
			delivered++
			if random.Intn(100) < 15 {
				// Whole-session duplication must be idempotent.
				synchronizeFixtures(t, nodes[destination], nodes[source], true)
				delivered++
			}
		}
	}
	if delivered == 0 || dropped == 0 || mined <= len(nodes) {
		t.Fatalf("insufficient chaos coverage: mined=%d delivered=%d dropped=%d", mined, delivered, dropped)
	}

	// Heal all links from the objectively best tip. Fork choice includes the
	// deterministic smaller-ID tie break, so every node must reach one result.
	winner := 0
	best, err := nodes[winner].store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index < len(nodes); index++ {
		candidate, err := nodes[index].store.Tip()
		if err != nil {
			t.Fatal(err)
		}
		if storage.BetterTip(candidate, best) {
			winner = index
			best = candidate
		}
	}
	for index := range nodes {
		if index != winner {
			synchronizeFixtures(t, nodes[index], nodes[winner], true)
		}
	}
	for index, node := range nodes {
		got, err := node.store.Tip()
		if err != nil {
			t.Fatal(err)
		}
		if !storage.EqualTips(got, best) {
			t.Fatalf("node %d did not converge after heal: height=%d id=%s", index, got.Height, got.ID)
		}
	}
	t.Logf("fixed-seed events: mined=%d delivered=%d dropped=%d winner=%d height=%d", mined, delivered, dropped, winner, best.Height)
}

func synchronizeFixtures(t testing.TB, destination, source nodeFixture, fragmented bool) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	var client Stream = clientRaw
	var server Stream = serverRaw
	if fragmented {
		client = &fragmentedStream{Conn: clientRaw, maxWrite: 7, delay: 20 * time.Microsecond}
		server = &fragmentedStream{Conn: serverRaw, maxWrite: 11, delay: 20 * time.Microsecond}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- source.session.Serve(ctx, server) }()
	if _, err := destination.session.Synchronize(ctx, client); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

type fragmentedStream struct {
	net.Conn
	maxWrite int
	delay    time.Duration
}

func (stream *fragmentedStream) Write(input []byte) (int, error) {
	if len(input) > stream.maxWrite {
		input = input[:stream.maxWrite]
	}
	if stream.delay > 0 {
		time.Sleep(stream.delay)
	}
	return stream.Conn.Write(input)
}
