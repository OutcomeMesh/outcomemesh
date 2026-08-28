package workround

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

func TestRemoteSharesBecomePartOfUnifiedAnchor(t *testing.T) {
	payload, position, parameters := testPayload(t)
	source, err := New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	destination, err := New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	miningContext, _ := source.Context()
	inclusion, _ := workgraph.InclusionRoot(nil)
	template, err := payload.SealTemplate(testAddress("remote"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	parent := mineWeak(t, miningContext, template, 0)
	parentID, err := source.Add(parent)
	if err != nil {
		t.Fatal(err)
	}
	template.Parents = []types.Hash{parentID}
	child := mineWeak(t, miningContext, template, parent.Nonce+1)
	childID, err := source.Add(child)
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	serveResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { serveResult <- destination.Serve(ctx, server) }()
	stats, err := source.Relay(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
	status, err := destination.Status()
	if err != nil || stats.Accepted != 2 || status.Accepted != 2 || status.Pending != 0 {
		t.Fatalf("relay stats=%+v pool=%+v err=%v", stats, status, err)
	}

	mined, err := destination.Mine(ctx, testAddress("anchor"), inclusion, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	included := make(map[types.Hash]struct{}, len(mined.Block.Shares))
	for _, share := range mined.Block.Shares {
		id, err := share.ID()
		if err != nil {
			t.Fatal(err)
		}
		included[id] = struct{}{}
	}
	if _, ok := included[parentID]; !ok {
		t.Fatal("relayed parent was not committed by the hard anchor")
	}
	if _, ok := included[childID]; !ok {
		t.Fatal("relayed child was not committed by the hard anchor")
	}
	if _, err := workblock.ValidateAndExecuteAt(
		state.Empty(), position, nil, mined.Block, parameters, position.Timestamp,
	); err != nil {
		t.Fatalf("replay relayed-share anchor: %v", err)
	}
}

func TestAcceptedRemoteSharesCanRelayAcrossSecondHop(t *testing.T) {
	payload, _, _ := testPayload(t)
	source, err := New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	middle, err := New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	destination, err := New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	miningContext, _ := source.Context()
	inclusion, _ := workgraph.InclusionRoot(nil)
	template, err := payload.SealTemplate(testAddress("two-hop"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	share := mineWeak(t, miningContext, template, 0)
	shareID, err := source.Add(share)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	firstClient, firstServer := net.Pipe()
	firstServed := make(chan error, 1)
	observed := make(chan types.Hash, 1)
	go func() {
		firstServed <- middle.ServeAccepted(ctx, firstServer, func(_ workgraph.Share, id types.Hash) {
			observed <- id
		})
	}()
	if _, err := source.RelayInventory(ctx, firstClient, []types.Hash{shareID}); err != nil {
		t.Fatal(err)
	}
	if err := <-firstServed; err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-observed:
		if id != shareID {
			t.Fatalf("middle observed=%s, want %s", id, shareID)
		}
	case <-time.After(time.Second):
		t.Fatal("middle did not observe first admission")
	}

	secondClient, secondServer := net.Pipe()
	secondServed := make(chan error, 1)
	go func() { secondServed <- destination.Serve(ctx, secondServer) }()
	stats, err := middle.RelayInventory(ctx, secondClient, []types.Hash{shareID})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-secondServed; err != nil {
		t.Fatal(err)
	}
	status, err := destination.Status()
	if err != nil || stats.Accepted != 1 || status.Shares != 1 || status.Accepted != 1 {
		t.Fatalf("second-hop stats=%+v status=%+v error=%v", stats, status, err)
	}
}

func TestFinalizeAcceptsExactExternalHardSolution(t *testing.T) {
	payload, _, _ := testPayload(t)
	round, err := New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	inclusion, _ := workgraph.InclusionRoot(nil)
	template, err := payload.SealTemplate(testAddress("external"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	block, result, err := round.Finalize(anchor)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := block.Header.ID()
	if result.BlockID != id || len(block.Shares) != 0 {
		t.Fatalf("external result=%+v shares=%d id=%s", result, len(block.Shares), id)
	}
}

func TestTimestampRolloverCancelsAndDrainsOldObjectiveWork(t *testing.T) {
	payload, position, parameters := testPayload(t)
	round, err := New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	activity, finish, err := round.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	position.Timestamp += workgraph.MaxShareTimestampLead / 2
	nextPayload, err := workblock.PreparePayload(state.Empty(), position, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	rolled := make(chan *Round, 1)
	rollErrors := make(chan error, 1)
	go func() {
		next, rollErr := round.RollForward(nextPayload)
		rolled <- next
		rollErrors <- rollErr
	}()
	select {
	case <-activity.Done():
	case <-time.After(time.Second):
		t.Fatal("retired generation did not cancel active objective work")
	}
	select {
	case <-rolled:
		t.Fatal("rollover completed before active objective work drained")
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	next := <-rolled
	if err := <-rollErrors; err != nil {
		t.Fatal(err)
	}
	oldContext, _ := round.Context()
	nextContext, _ := next.Context()
	if nextContext.AnchorTimestamp <= oldContext.AnchorTimestamp {
		t.Fatalf("timestamp did not advance %d -> %d", oldContext.AnchorTimestamp, nextContext.AnchorTimestamp)
	}
	inclusion, _ := workgraph.InclusionRoot(nil)
	if _, err := round.Template(testAddress("retired-objective"), inclusion); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired template error=%v", err)
	}
}

func TestRejectsInvalidRound(t *testing.T) {
	if _, err := New(nil, worksession.DefaultConfig()); err == nil {
		t.Fatal("nil payload was accepted")
	}
	if _, err := (*Round)(nil).Context(); err == nil {
		t.Fatal("nil round context was accepted")
	}
}

func testPayload(t testing.TB) (*workblock.Payload, workblock.Position, workblock.Parameters) {
	t.Helper()
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	parameters := workblock.Parameters{
		NetworkID: 71, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: 1_699_999_940, DifficultyAnchorTarget: target,
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
	position := workblock.Position{
		Height: 1, ParentID: types.DomainHash("test/workround/parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp,
		MedianTimePast:  parameters.DifficultyAnchorTimestamp,
		Timestamp:       parameters.DifficultyAnchorTimestamp + parameters.TargetSpacing,
		Target:          target,
	}
	payload, err := workblock.PreparePayload(state.Empty(), position, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	return payload, position, parameters
}

func mineWeak(
	t testing.TB,
	miningContext workgraph.Context,
	template workgraph.Share,
	start uint64,
) workgraph.Share {
	t.Helper()
	for {
		share, _, err := workgraph.Mine(context.Background(), template, start)
		if err != nil {
			t.Fatal(err)
		}
		hard, err := workgraph.MeetsAnchor(share)
		if err != nil {
			t.Fatal(err)
		}
		if !hard {
			if err := workgraph.ValidateShare(miningContext, share); err != nil {
				t.Fatal(err)
			}
			return share
		}
		start = share.Nonce + 1
	}
}

func testAddress(label string) types.Address {
	return types.Address(types.DomainHash("test/workround/address", []byte(label)))
}
