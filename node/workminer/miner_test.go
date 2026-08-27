package workminer

import (
	"context"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workpool"
)

func TestUnifiedMiningPublishesWeakSharesThenFinalizesSameSealSpace(t *testing.T) {
	t.Parallel()

	payload, position, parameters := testPayload(t, testAnchorTarget())
	inclusion, _ := workgraph.InclusionRoot(nil)
	template, err := payload.SealTemplate(testAddress("miner"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := workpool.New(workgraph.Context{
		NetworkID: template.NetworkID, Height: template.Height, AnchorParent: template.AnchorParent,
		AnchorTarget: template.Target, PayloadRoot: template.PayloadRoot,
		AnchorTimestamp: template.Timestamp, MedianTimePast: position.MedianTimePast,
	})
	if err != nil {
		t.Fatal(err)
	}
	var published uint64
	miner, err := New(payload, pool, template.Miner, inclusion, func(share workgraph.Share) error {
		published++
		meets, err := workgraph.MeetsAnchor(share)
		if err != nil || meets {
			t.Fatalf("published hard share meets=%t err=%v", meets, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := miner.Mine(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if published != result.WeakShares || uint64(len(result.Block.Shares)) != result.WeakShares ||
		pool.Status().Shares != int(result.WeakShares) {
		t.Fatalf("mining result=%+v published=%d pool=%+v", result, published, pool.Status())
	}
	meets, err := workgraph.MeetsAnchor(result.Block.Header.Seal)
	if err != nil || !meets {
		t.Fatalf("winning seal meets=%t err=%v", meets, err)
	}
	winningID, _ := result.Block.Header.Seal.ID()
	for _, share := range result.Block.Shares {
		id, _ := share.ID()
		if id == winningID {
			t.Fatal("winning seal was also included as a weak share")
		}
	}
	replayed, err := workblock.ValidateAndExecuteAt(
		state.Empty(), position, nil, result.Block, parameters, position.Timestamp,
	)
	if err != nil || replayed.BlockID != result.Execution.BlockID {
		t.Fatalf("mined block replay err=%v replay=%+v", err, replayed)
	}
	t.Logf("unified_mining weak_shares=%d winning_nonce=%d block_shares=%d",
		result.WeakShares, result.WinningNonce, len(result.Block.Shares))
}

func TestMiningHonorsCancellation(t *testing.T) {
	t.Parallel()

	var hardTarget types.Hash
	hardTarget[31] = 1
	payload, position, _ := testPayload(t, hardTarget)
	inclusion, _ := workgraph.InclusionRoot(nil)
	template, _ := payload.SealTemplate(testAddress("cancel-miner"), inclusion, nil)
	pool, err := workpool.New(workgraph.Context{
		NetworkID: template.NetworkID, Height: template.Height, AnchorParent: template.AnchorParent,
		AnchorTarget: template.Target, PayloadRoot: template.PayloadRoot,
		AnchorTimestamp: template.Timestamp, MedianTimePast: position.MedianTimePast,
	})
	if err != nil {
		t.Fatal(err)
	}
	miner, err := New(payload, pool, template.Miner, inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := miner.Mine(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled mining error=%v", err)
	}
}

func testPayload(
	t testing.TB,
	target types.Hash,
) (*workblock.Payload, workblock.Position, workblock.Parameters) {
	t.Helper()
	parameters := workblock.Parameters{
		NetworkID: 61, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: 1_699_999_940, DifficultyAnchorTarget: target,
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
	position := workblock.Position{
		Height: 1, ParentID: types.DomainHash("test/workminer/parent"),
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

func testAnchorTarget() types.Hash {
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return target
}

func testAddress(label string) types.Address {
	return types.Address(types.DomainHash("test/workminer/address", []byte(label)))
}
