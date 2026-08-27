package workround

import (
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/worksession"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestManagerReusesOnlyCurrentParentRound(t *testing.T) {
	payloadA, _, _ := testPayload(t)
	contextA, _ := payloadA.MiningContext()
	payloadB, tipB := managerPayload(t, contextA, 2)
	source := &managerSource{
		tip:      storage.Tip{ID: contextA.AnchorParent, Height: 0, Timestamp: contextA.MedianTimePast},
		payloads: map[types.Hash]*workblock.Payload{contextA.AnchorParent: payloadA, tipB.ID: payloadB},
	}
	manager, err := NewManager(source, func() uint64 { return contextA.AnchorTimestamp }, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	again, err := manager.Current()
	if err != nil || again != first || source.prepares != 1 {
		t.Fatalf("unchanged round=%p first=%p prepares=%d err=%v", again, first, source.prepares, err)
	}
	source.tip = tipB
	second, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	if second == first || source.prepares != 2 {
		t.Fatalf("new parent reused old round prepares=%d", source.prepares)
	}
	firstStatus, _ := first.Status()
	secondStatus, _ := second.Status()
	if firstStatus.Shares != 0 || secondStatus.Shares != 0 {
		t.Fatalf("unexpected manager pool state old=%+v new=%+v", firstStatus, secondStatus)
	}
	if err := manager.Invalidate(); err != nil {
		t.Fatal(err)
	}
	third, err := manager.Current()
	if err != nil || third == second || source.prepares != 3 {
		t.Fatalf("invalidated round=%p second=%p prepares=%d err=%v", third, second, source.prepares, err)
	}
}

func TestManagerBoundsMovingTipRetries(t *testing.T) {
	payload, _, _ := testPayload(t)
	miningContext, _ := payload.MiningContext()
	source := &managerSource{
		tip:      storage.Tip{ID: miningContext.AnchorParent, Height: 0, Timestamp: miningContext.MedianTimePast},
		payloads: map[types.Hash]*workblock.Payload{miningContext.AnchorParent: payload},
		moveTip:  true,
	}
	manager, _ := NewManager(source, func() uint64 { return miningContext.AnchorTimestamp }, worksession.DefaultConfig())
	if _, err := manager.Current(); !errors.Is(err, ErrUnstableChain) {
		t.Fatalf("moving-tip error=%v", err)
	}
	if source.prepares != maxBuildAttempts {
		t.Fatalf("moving-tip prepares=%d", source.prepares)
	}
}

type managerSource struct {
	tip      storage.Tip
	payloads map[types.Hash]*workblock.Payload
	prepares int
	moveTip  bool
}

func (source *managerSource) Tip() (storage.Tip, error) {
	result := source.tip
	if source.moveTip && source.prepares > 0 {
		result.ID[31] = byte(source.prepares)
	}
	return result, nil
}

func (source *managerSource) PrepareWork(
	parent types.Hash,
	_ uint64,
	_ []outcome.Transaction,
) (*workblock.Payload, workblock.Position, error) {
	source.prepares++
	payload := source.payloads[source.tip.ID]
	if payload == nil {
		payload = source.payloads[parent]
	}
	if payload == nil {
		return nil, workblock.Position{}, storage.ErrBlockNotFound
	}
	return payload, workblock.Position{}, nil
}

func managerPayload(t testing.TB, previous workgraph.Context, height uint64) (*workblock.Payload, storage.Tip) {
	t.Helper()
	parentID := types.DomainHash("test/workround/manager-parent", previous.AnchorParent[:])
	position := workblock.Position{
		Height: height, ParentID: parentID, ParentTimestamp: previous.AnchorTimestamp,
		MedianTimePast: previous.AnchorTimestamp, Timestamp: previous.AnchorTimestamp + 60,
		Target: previous.AnchorTarget,
	}
	parameters := workblock.Parameters{
		NetworkID: previous.NetworkID, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: height,
		DifficultyAnchorTimestamp: previous.MedianTimePast, DifficultyAnchorTarget: previous.AnchorTarget,
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
	payload, err := workblock.PreparePayload(state.Empty(), position, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	return payload, storage.Tip{ID: parentID, Height: height - 1, Timestamp: previous.AnchorTimestamp}
}
