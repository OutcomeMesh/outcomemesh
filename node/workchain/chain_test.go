package workchain

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/resource"
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

func FuzzDecodeStateDeltaNeverPanics(f *testing.F) {
	seed, err := encodeStateDelta(stateDelta{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := decodeStateDelta(input)
		if err != nil {
			return
		}
		encoded, err := encodeStateDelta(decoded)
		if err != nil {
			t.Fatalf("accepted delta cannot be encoded: %v", err)
		}
		if !bytes.Equal(input, encoded) {
			t.Fatal("accepted delta was not canonical")
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

func TestPebbleStoresBaseCheckpointAndPerBlockDelta(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBaseWithResources(t, parameters, 256)
	store, err := Open(t.TempDir(), base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	block, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "delta-activation")
	if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	blockID, _ := block.Header.ID()
	if _, err := store.persistence.get(workStateKey(blockID)); !errors.Is(err, pebble.ErrNotFound) {
		t.Fatalf("non-base full snapshot exists: %v", err)
	}
	deltaBytes, err := store.persistence.get(workDeltaKey(blockID))
	if err != nil {
		t.Fatal(err)
	}
	delta, err := decodeStateDelta(deltaBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.deleted) != 0 || len(delta.created) != 0 || !bytes.Equal(deltaBytes, []byte{0, 0}) {
		t.Fatalf("unchanged activation delta deleted=%d created=%d bytes=%d",
			len(delta.deleted), len(delta.created), len(deltaBytes))
	}
	fullState, err := encodePersistedState(base.State)
	if err != nil {
		t.Fatal(err)
	}
	if len(deltaBytes)*1_000 >= len(fullState) {
		t.Fatalf("delta=%d full-state=%d does not demonstrate proportional storage", len(deltaBytes), len(fullState))
	}
}

func TestPebbleRejectsCorruptStateDeltaOnReopen(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "corrupt-delta")
	if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	blockID, _ := block.Header.ID()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Set(workDeltaKey(blockID), []byte{0, 0, 0}, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, base, parameters); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("corrupt delta error=%v", err)
	}
}

func TestPebbleHistoryBudgetRejectsCommitAtomically(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	usage, _, err := store.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenWithPolicy(path, base, parameters, Policy{MaxHistoryBytes: usage})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "history-limit")
	blockID, _ := block.Header.ID()
	if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); !errors.Is(err, storage.ErrHistoryLimit) {
		t.Fatalf("history limit error=%v", err)
	}
	tip, err := store.Tip()
	if err != nil || tip.ID != base.Tip.ID {
		t.Fatalf("tip after history rejection=%s err=%v", tip.ID, err)
	}
	afterUsage, limit, err := store.HistoryUsage()
	if err != nil || afterUsage != usage || limit != usage {
		t.Fatalf("history after rejection=%d/%d want=%d err=%v", afterUsage, limit, usage, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.BlockByID(blockID); !errors.Is(err, ErrParent) {
		t.Fatalf("budget-rejected block reached disk: %v", err)
	}
}

func TestPebblePrunesOnlyStaleForkSubtreesAtomically(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := OpenWithPolicy(path, base, parameters, Policy{
		MaxHistoryBytes: DefaultMaxHistoryBytes,
		ForkRetention:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	activationA, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "prune-canonical")
	activationB, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "prune-live")
	activationC, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "prune-stale")
	for _, block := range []workblock.Block{activationA, activationB, activationC} {
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	idA, _ := activationA.Header.ID()
	idB, _ := activationB.Header.ID()
	idC, _ := activationC.Header.ID()
	childA, _ := mineChild(t, store, idA, activationA.Header.Seal.Timestamp+60, "prune-canonical-2")
	if _, _, err := store.Commit(childA, childA.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	childAID, _ := childA.Header.ID()
	grandchildA, _ := mineChild(t, store, childAID, childA.Header.Seal.Timestamp+60, "prune-canonical-3")
	if _, _, err := store.Commit(grandchildA, grandchildA.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	grandchildAID, _ := grandchildA.Header.ID()
	greatGrandchildA, _ := mineChild(t, store, grandchildAID, grandchildA.Header.Seal.Timestamp+60, "prune-canonical-4")
	if _, _, err := store.Commit(greatGrandchildA, greatGrandchildA.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}

	childB, _ := mineChild(t, store, idB, activationB.Header.Seal.Timestamp+60, "prune-live-2")
	if _, _, err := store.Commit(childB, childB.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	childBID, _ := childB.Header.ID()
	grandchildB, _ := mineChild(t, store, childBID, childB.Header.Seal.Timestamp+60, "prune-live-3")
	if _, _, err := store.Commit(grandchildB, grandchildB.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	grandchildBID, _ := grandchildB.Header.ID()
	childC, _ := mineChild(t, store, idC, activationC.Header.Seal.Timestamp+60, "prune-stale-2")
	if _, _, err := store.Commit(childC, childC.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	childCID, _ := childC.Header.ID()

	usageBefore, _, err := store.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected prune failure")
	store.persistence.commitHook = func() error { return injected }
	if _, err := store.PruneStaleForks(); !errors.Is(err, injected) {
		t.Fatalf("failed prune error=%v", err)
	}
	if _, err := store.BlockByID(childCID); err != nil {
		t.Fatalf("failed prune changed memory: %v", err)
	}
	usageAfterFailure, _, err := store.HistoryUsage()
	if err != nil || usageAfterFailure != usageBefore {
		t.Fatalf("failed prune history=%d want=%d err=%v", usageAfterFailure, usageBefore, err)
	}

	store.persistence.commitHook = nil
	report, err := store.PruneStaleForks()
	if err != nil {
		t.Fatal(err)
	}
	if report.CutoffHeight != parameters.ActivationHeight+2 || report.RemovedNodes != 2 ||
		report.RetainedNodes != 8 || report.ReleasedHistoryBytes == 0 {
		t.Fatalf("prune report=%+v", report)
	}
	if _, err := store.BlockByID(idC); !errors.Is(err, ErrParent) {
		t.Fatalf("stale root survived prune: %v", err)
	}
	if _, err := store.BlockByID(childCID); !errors.Is(err, ErrParent) {
		t.Fatalf("stale child survived prune: %v", err)
	}
	for _, id := range []types.Hash{idA, idB, childBID, grandchildBID} {
		if _, err := store.BlockByID(id); err != nil {
			t.Fatalf("retained block %s missing: %v", id, err)
		}
	}
	usageAfter, _, err := store.HistoryUsage()
	if err != nil || usageAfter+report.ReleasedHistoryBytes != usageBefore {
		t.Fatalf("pruned history=%d released=%d before=%d err=%v",
			usageAfter, report.ReleasedHistoryBytes, usageBefore, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithPolicy(path, base, parameters, Policy{
		MaxHistoryBytes: DefaultMaxHistoryBytes,
		ForkRetention:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.BlockByID(childCID); !errors.Is(err, ErrParent) {
		t.Fatalf("restart restored pruned child: %v", err)
	}
	if _, err := reopened.BlockByID(grandchildBID); err != nil {
		t.Fatalf("restart lost live side branch: %v", err)
	}
	competing, _ := mineChild(
		t, reopened, grandchildBID, grandchildB.Header.Seal.Timestamp+60, "prune-live-4",
	)
	if _, _, err := reopened.Commit(competing, competing.Header.Seal.Timestamp); err != nil {
		t.Fatalf("retained side branch cannot extend after restart: %v", err)
	}
}

func TestPebbleRejectsOldWorkSchema(t *testing.T) {
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
	database, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Set(workKeySchema, []byte{0, 1}, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, base, parameters); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("old schema error=%v", err)
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

func testBaseWithResources(t testing.TB, parameters workblock.Parameters, count int) Base {
	t.Helper()
	resources := make([]resource.Resource, count)
	for index := range resources {
		resources[index] = resource.Resource{
			Version: resource.Version0,
			ID: types.ResourceID(types.DomainHash(
				"test/workchain/base-resource", []byte{byte(index >> 8), byte(index)},
			)),
			Owner:  testAddress("base-owner"),
			Asset:  types.NativeAssetID(),
			Amount: uint64(index + 1),
		}
	}
	initial, err := state.New(resources)
	if err != nil {
		t.Fatal(err)
	}
	return Base{
		Tip: storage.Tip{
			ID: types.DomainHash("test/workchain/resource-base"), Height: parameters.ActivationHeight - 1,
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
