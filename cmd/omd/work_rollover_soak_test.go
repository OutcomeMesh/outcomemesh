package main

import (
	"context"
	"net"
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestMultiNodeWorkRolloverConvergesAcrossClockSkewChurnAndRelayLoss(t *testing.T) {
	cycles := 32
	if text := os.Getenv("OUTCOMEMESH_WORK_ROLLOVER_SOAK_CYCLES"); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 8 || parsed > 1_000 {
			t.Fatalf("OUTCOMEMESH_WORK_ROLLOVER_SOAK_CYCLES must be 8..1000, got %q", text)
		}
		cycles = parsed
	}
	nodes := []*workRolloverSoakNode{
		newWorkRolloverSoakNode(t, "slow", 30),
		newWorkRolloverSoakNode(t, "behind", 50),
		newWorkRolloverSoakNode(t, "ahead", 70),
		newWorkRolloverSoakNode(t, "fast", 90),
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	totalShares := 0
	successfulRelays := 0
	inventoryRelays := 0
	droppedRelays := 0
	for cycle := 0; cycle < cycles; cycle++ {
		if cycle > 0 {
			for _, node := range nodes {
				node.clock.Add(workround.RolloverSeconds)
				next, err := node.manager.RollForward(node.round)
				if err != nil {
					t.Fatalf("cycle %d rollover %s: %v", cycle, node.label, err)
				}
				node.round = next
			}
		}
		origin := nodes[cycle%len(nodes)]
		if _, err := addWorkRolloverSoakShare(origin, inclusion, uint64(cycle)); err != nil {
			t.Fatalf("cycle %d add share on %s: %v", cycle, origin.label, err)
		}
		totalShares++

		for index := range nodes {
			next := (index + 1) % len(nodes)
			if workRolloverNodeOffline(cycle, index) || workRolloverNodeOffline(cycle, next) {
				droppedRelays++
				continue
			}
			drop := (cycle+index)%5 == 0
			stats, err := relayWorkRolloverSoak(nodes[index].round, nodes[next].round, drop)
			if drop {
				if err == nil {
					t.Fatalf("cycle %d dropped relay %s->%s succeeded", cycle, nodes[index].label, nodes[next].label)
				}
				droppedRelays++
				continue
			}
			if err != nil {
				t.Fatalf("cycle %d relay %s->%s: %v", cycle, nodes[index].label, nodes[next].label, err)
			}
			if stats.Announced > 0 {
				inventoryRelays++
			}
			successfulRelays++
		}
	}

	convergeWorkRolloverSoak(t, nodes)
	for {
		status, err := nodes[0].round.Status()
		if err != nil {
			t.Fatal(err)
		}
		if status.Tips <= workgraph.MaxParents {
			break
		}
		if _, err := addWorkRolloverSoakShare(nodes[0], inclusion, uint64(totalShares)); err != nil {
			t.Fatal(err)
		}
		totalShares++
		convergeWorkRolloverSoak(t, nodes)
	}
	wantIDs, err := nodes[0].round.IDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(wantIDs) != totalShares || successfulRelays == 0 || inventoryRelays == 0 || droppedRelays == 0 {
		t.Fatalf("shares=%d/%d successful_relays=%d inventory_relays=%d dropped_relays=%d",
			len(wantIDs), totalShares, successfulRelays, inventoryRelays, droppedRelays)
	}
	for _, node := range nodes {
		ids, err := node.round.IDs()
		if err != nil || !slices.Equal(ids, wantIDs) {
			t.Fatalf("node %s inventory=%d/%d error=%v", node.label, len(ids), len(wantIDs), err)
		}
		status, err := node.round.Status()
		if err != nil || status.Shares != totalShares || status.Pending != 0 {
			t.Fatalf("node %s status=%+v error=%v", node.label, status, err)
		}
	}

	template, err := nodes[0].round.Template(nodes[0].miner, inclusion)
	if err != nil {
		t.Fatal(err)
	}
	anchorContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	anchor, _, err := workgraph.MineAnchor(anchorContext, template, 0)
	if err != nil {
		t.Fatal(err)
	}
	block, _, err := nodes[0].round.Finalize(anchor)
	if err != nil || len(block.Shares) != totalShares {
		t.Fatalf("finalized retained shares=%d/%d error=%v", len(block.Shares), totalShares, err)
	}
}

type workRolloverSoakNode struct {
	label   string
	miner   types.Address
	clock   *atomic.Uint64
	manager *workround.Manager
	round   *workround.Round
}

type workRolloverSoakSource struct {
	tip        storage.Tip
	position   workblock.Position
	parameters workblock.Parameters
}

func newWorkRolloverSoakNode(t testing.TB, label string, initialOffset uint64) *workRolloverSoakNode {
	t.Helper()
	const parentTimestamp uint64 = 1_700_000_000
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	parent := types.DomainHash("test/omd/work-rollover-soak/parent")
	parameters := workblock.Parameters{
		NetworkID: 20260829, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: parentTimestamp, DifficultyAnchorTarget: target,
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
	source := &workRolloverSoakSource{
		tip: storage.Tip{ID: parent, Height: 0, Timestamp: parentTimestamp},
		position: workblock.Position{
			Height: 1, ParentID: parent, ParentTimestamp: parentTimestamp,
			MedianTimePast: parentTimestamp, Timestamp: parentTimestamp + initialOffset, Target: target,
		},
		parameters: parameters,
	}
	clock := new(atomic.Uint64)
	clock.Store(parentTimestamp + initialOffset)
	manager, err := workround.NewManager(source, clock.Load, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	round, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	return &workRolloverSoakNode{
		label: label, miner: types.Address(types.DomainHash("test/omd/work-rollover-soak/miner", []byte(label))),
		clock: clock, manager: manager, round: round,
	}
}

func (source *workRolloverSoakSource) Tip() (storage.Tip, error) {
	return source.tip, nil
}

func (source *workRolloverSoakSource) PrepareWork(
	parent types.Hash,
	timestamp uint64,
	_ []outcome.Transaction,
) (*workblock.Payload, workblock.Position, error) {
	if parent != source.tip.ID {
		return nil, workblock.Position{}, storage.ErrBlockNotFound
	}
	position := source.position
	position.Timestamp = timestamp
	payload, err := workblock.PreparePayload(state.Empty(), position, nil, nil, source.parameters)
	return payload, position, err
}

func addWorkRolloverSoakShare(
	node *workRolloverSoakNode,
	inclusion types.Hash,
	startNonce uint64,
) (types.Hash, error) {
	template, err := node.round.Template(node.miner, inclusion)
	if err != nil {
		return types.Hash{}, err
	}
	for {
		share, _, err := workgraph.Mine(context.Background(), template, startNonce)
		if err != nil {
			return types.Hash{}, err
		}
		hard, err := workgraph.MeetsAnchor(share)
		if err != nil {
			return types.Hash{}, err
		}
		if !hard {
			return node.round.Add(share)
		}
		startNonce = share.Nonce + 1
	}
}

func relayWorkRolloverSoak(
	source *workround.Round,
	destination *workround.Round,
	drop bool,
) (worksession.Stats, error) {
	client, server := net.Pipe()
	if drop {
		_ = server.Close()
		return source.Relay(context.Background(), client)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- destination.Serve(ctx, server) }()
	stats, relayErr := source.Relay(ctx, client)
	serveErr := <-serverDone
	if relayErr != nil {
		return worksession.Stats{}, relayErr
	}
	if serveErr != nil {
		return worksession.Stats{}, serveErr
	}
	return stats, nil
}

func convergeWorkRolloverSoak(t testing.TB, nodes []*workRolloverSoakNode) {
	t.Helper()
	for pass := 0; pass < 2; pass++ {
		for source := range nodes {
			for destination := range nodes {
				if source == destination {
					continue
				}
				if _, err := relayWorkRolloverSoak(nodes[source].round, nodes[destination].round, false); err != nil {
					t.Fatalf("convergence relay %s->%s: %v", nodes[source].label, nodes[destination].label, err)
				}
			}
		}
	}
}

func workRolloverNodeOffline(cycle, node int) bool {
	return (node == 3 && cycle >= 5 && cycle < 12) ||
		(node == 1 && cycle >= 14 && cycle < 18)
}

func TestWorkRolloverSoakDroppedStreamIsFailSoft(t *testing.T) {
	left := newWorkRolloverSoakNode(t, "drop-left", 50)
	right := newWorkRolloverSoakNode(t, "drop-right", 70)
	if _, err := relayWorkRolloverSoak(left.round, right.round, true); err == nil {
		t.Fatal("closed relay stream returned success")
	}
	if status, err := left.round.Status(); err != nil || status.Shares != 0 {
		t.Fatalf("dropped stream mutated source status=%+v error=%v", status, err)
	}
	if status, err := right.round.Status(); err != nil || status.Shares != 0 {
		t.Fatalf("dropped stream mutated destination status=%+v error=%v", status, err)
	}
}

var _ workround.Source = (*workRolloverSoakSource)(nil)
