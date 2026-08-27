package workchain

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestActivationForkReorgUsesOnlyHardWorkAndBranchLocalPayouts(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	store, err := New(base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	blockA, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "branch-a")
	blockB, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "branch-b")
	idA, _ := blockA.Header.ID()
	idB, _ := blockB.Header.ID()
	if idA == idB {
		t.Fatal("competing activation anchors have one ID")
	}
	if _, _, err := store.Commit(blockA, blockA.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Commit(blockB, blockB.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	current, _ := store.Tip()
	winnerID := idA
	loserID := idB
	loserBlock := blockB
	if current.ID == idB {
		winnerID, loserID = idB, idA
		loserBlock = blockA
	}
	if current.ID != winnerID || current.Height != parameters.ActivationHeight {
		t.Fatalf("equal-work fork choice tip=%+v", current)
	}
	winningChild, winningChildResult := mineChild(
		t, store, winnerID, loserBlock.Header.Seal.Timestamp+60, "winner-child",
	)
	losingChild, losingChildResult := mineChild(
		t, store, loserID, loserBlock.Header.Seal.Timestamp+60, "loser-child",
	)
	if len(winningChildResult.PayoutResources) != 1 || len(losingChildResult.PayoutResources) != 1 {
		t.Fatal("branch children did not materialize parent earnings")
	}
	if _, _, err := store.Commit(losingChild, losingChild.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	losingChildID, _ := losingChild.Header.ID()
	current, _ = store.Tip()
	if current.ID != losingChildID || current.Height != parameters.ActivationHeight+1 {
		t.Fatalf("higher-work side branch did not reorg: %+v", current)
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	losingPayout := losingChildResult.PayoutResources[0]
	winningPayout := winningChildResult.PayoutResources[0]
	if _, exists := snapshot.Get(losingPayout.ID); !exists {
		t.Fatal("selected branch payout is absent")
	}
	if _, exists := snapshot.Get(winningPayout.ID); exists {
		t.Fatal("abandoned branch payout leaked through reorg")
	}
	if _, _, err := store.Commit(winningChild, winningChild.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	current, _ = store.Tip()
	winningChildID, _ := winningChild.Header.ID()
	want := losingChildID
	if types.CompareHash(winningChildID, losingChildID) < 0 {
		want = winningChildID
	}
	if current.ID != want {
		t.Fatalf("equal cumulative work tie tip=%s want=%s", current.ID, want)
	}
}

func TestActivationBoundaryRejectsSkippedHeightAndUnknownParent(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	store, err := New(base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Prepare(types.DomainHash("unknown"), base.Tip.Timestamp+60, nil); !errors.Is(err, ErrParent) {
		t.Fatalf("unknown parent error=%v", err)
	}
	badBase := base
	badBase.Tip.Height++
	if _, err := New(badBase, parameters); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("skipped activation error=%v", err)
	}
}

func TestPebbleRestartPreservesForkTipStateAndFeeQueue(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	activation, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "persistent-activation")
	if _, _, err := store.Commit(activation, activation.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	activationID, _ := activation.Header.ID()
	sideActivation, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "persistent-side")
	if _, _, err := store.Commit(sideActivation, sideActivation.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	sideActivationID, _ := sideActivation.Header.ID()
	child, childResult := mineChild(t, store, activationID, activation.Header.Seal.Timestamp+60, "persistent-child")
	if _, _, err := store.Commit(child, child.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	beforeTip, _ := store.Tip()
	beforeState, _ := store.Snapshot()
	beforeQueueRoot, err := childResult.FeeQueue.Root()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	afterTip, _ := reopened.Tip()
	afterState, _ := reopened.Snapshot()
	if !storage.EqualTips(beforeTip, afterTip) || beforeState.Root() != afterState.Root() {
		t.Fatalf("restart tip/state before=%+v/%s after=%+v/%s",
			beforeTip, beforeState.Root(), afterTip, afterState.Root())
	}
	loadedBlock, err := reopened.BlockByID(beforeTip.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loadedBlock.Header.FeeQueueRoot != beforeQueueRoot {
		t.Fatalf("restart fee queue root=%s want=%s", loadedBlock.Header.FeeQueueRoot, beforeQueueRoot)
	}
	if _, err := reopened.BlockByID(sideActivationID); err != nil {
		t.Fatalf("restart lost side branch: %v", err)
	}
	grandchild, _ := mineChild(
		t, reopened, beforeTip.ID, beforeTip.Timestamp+parameters.TargetSpacing, "after-restart",
	)
	if _, _, err := reopened.Commit(grandchild, grandchild.Header.Seal.Timestamp); err != nil {
		t.Fatalf("post-restart commit: %v", err)
	}
}

func TestPebbleFailedBatchDoesNotMutateMemoryOrDisk(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "failed-batch")
	blockID, _ := block.Header.ID()
	injected := errors.New("injected pre-commit failure")
	store.persistence.commitHook = func() error { return injected }
	if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); !errors.Is(err, injected) {
		t.Fatalf("commit error=%v", err)
	}
	tip, err := store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if tip.ID != base.Tip.ID {
		t.Fatalf("memory tip changed after failed batch: %s", tip.ID)
	}
	if _, err := store.BlockByID(blockID); !errors.Is(err, ErrParent) {
		t.Fatalf("failed block entered memory: %v", err)
	}
	store.persistence.commitHook = nil
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	tip, err = reopened.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if tip.ID != base.Tip.ID {
		t.Fatalf("disk tip changed after failed batch: %s", tip.ID)
	}
	if _, err := reopened.BlockByID(blockID); !errors.Is(err, ErrParent) {
		t.Fatalf("failed block entered disk: %v", err)
	}
}

func FuzzDecodeNodeMetadataNeverPanics(f *testing.F) {
	base := testBase(f, testParameters())
	seed, err := encodeNodeMetadata(&chainNode{
		tip: base.Tip, history: append([]uint64(nil), base.RecentTimestamps...),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		node, err := decodeNodeMetadata(input)
		if err != nil {
			return
		}
		encoded, err := encodeNodeMetadata(node)
		if err != nil {
			t.Fatalf("accepted metadata cannot be encoded: %v", err)
		}
		if !bytes.Equal(input, encoded) {
			t.Fatal("accepted metadata was not canonical")
		}
	})
}

func FuzzDecodePersistedStateNeverPanics(f *testing.F) {
	seed, err := encodePersistedState(state.Empty())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := decodePersistedState(input)
		if err != nil {
			return
		}
		encoded, err := encodePersistedState(decoded)
		if err != nil {
			t.Fatalf("accepted state cannot be encoded: %v", err)
		}
		if !bytes.Equal(input, encoded) {
			t.Fatal("accepted state was not canonical")
		}
	})
}

func TestPebbleRejectsConsensusConfigurationMismatch(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	parameters.FeeDelay++
	if _, err := Open(path, base, parameters); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("configuration mismatch error=%v", err)
	}
}

func mineChild(
	t testing.TB,
	store *Store,
	parentID types.Hash,
	timestamp uint64,
	label string,
) (workblock.Block, workblock.Result) {
	t.Helper()
	payload, _, err := store.Prepare(parentID, timestamp, nil)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, _ := workgraph.InclusionRoot(nil)
	template, err := payload.SealTemplate(testAddress(label), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	block, result, err := payload.Finalize(anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	return block, result
}

func testBase(t testing.TB, parameters workblock.Parameters) Base {
	t.Helper()
	initial := state.Empty()
	return Base{
		Tip: storage.Tip{
			ID: types.DomainHash("test/workchain/base"), Height: parameters.ActivationHeight - 1,
			Timestamp: parameters.DifficultyAnchorTimestamp, Target: parameters.DifficultyAnchorTarget,
			StateRoot: initial.Root(),
		},
		State: initial, RecentTimestamps: []uint64{parameters.DifficultyAnchorTimestamp},
	}
}

func testParameters() workblock.Parameters {
	return workblock.Parameters{
		NetworkID: 71, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: 1_699_999_940, DifficultyAnchorTarget: testTarget(),
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
}

func testTarget() types.Hash {
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return target
}

func testAddress(label string) types.Address {
	return types.Address(types.DomainHash("test/workchain/address", []byte(label)))
}
