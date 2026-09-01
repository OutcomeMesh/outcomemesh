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
	if current.ID != winnerID || current.Height != parameters.ActivationHeight {
		t.Fatalf("equal-work arrival incumbent tip=%+v want=%s", current, winnerID)
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
	if current.ID != losingChildID {
		t.Fatalf("equal cumulative work displaced incumbent tip=%s incumbent=%s competitor=%s",
			current.ID, losingChildID, winningChildID)
	}
}

func TestEqualWorkSelectionDependsOnArrivalUntilStrictlyExtended(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	left, err := New(base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	right, err := New(base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	blockA, _ := mineChild(t, left, base.Tip.ID, base.Tip.Timestamp+60, "arrival-a")
	blockB, _ := mineChild(t, left, base.Tip.ID, base.Tip.Timestamp+60, "arrival-b")
	idA, _ := blockA.Header.ID()
	idB, _ := blockB.Header.ID()
	if _, _, err := left.Commit(blockA, blockA.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if _, _, err := left.Commit(blockB, blockB.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if _, _, err := right.Commit(blockB, blockB.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if _, _, err := right.Commit(blockA, blockA.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	leftTip, _ := left.Tip()
	rightTip, _ := right.Tip()
	if leftTip.ID != idA || rightTip.ID != idB || leftTip.ID == rightTip.ID {
		t.Fatalf("arrival incumbents left=%s right=%s want=%s/%s", leftTip.ID, rightTip.ID, idA, idB)
	}
	child, _ := mineChild(t, left, idA, blockA.Header.Seal.Timestamp+60, "arrival-a-child")
	childID, _ := child.Header.ID()
	if _, _, err := right.Commit(child, child.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	rightTip, _ = right.Tip()
	if rightTip.ID != childID {
		t.Fatalf("strictly extended branch did not converge tip=%s want=%s", rightTip.ID, childID)
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

func TestSelectedAncestryArchiveAnchorSurvivesRestartButNotReorg(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	activation, _ := mineChild(
		t, store, base.Tip.ID, base.Tip.Timestamp+60, "archive-selected-activation",
	)
	if _, _, err := store.Commit(activation, activation.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	activationID, _ := activation.Header.ID()
	sideActivation, _ := mineChild(
		t, store, base.Tip.ID, base.Tip.Timestamp+60, "archive-side-activation",
	)
	if _, _, err := store.Commit(sideActivation, sideActivation.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	sideActivationID, _ := sideActivation.Header.ID()
	child, _ := mineChild(
		t, store, activationID, activation.Header.Seal.Timestamp+60, "archive-selected-child",
	)
	if _, _, err := store.Commit(child, child.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	anchor, err := store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	root, count, err := store.SelectedAncestryCommitment(anchor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("selected ancestry nodes=%d want=3", count)
	}
	const expectedAncestryRoot = "7d838893c1b8bf48c936f6a3bd4b021b8f46adcc53220fdc10efb9df0a9f9127"
	if root.String() != expectedAncestryRoot {
		t.Fatalf("selected ancestry root=%s want=%s", root, expectedAncestryRoot)
	}
	history, err := store.SelectedHistorySnapshot(anchor.ID, 2)
	if err != nil || history.BaseID != base.Tip.ID ||
		!storage.EqualTips(history.Anchor, anchor) || len(history.BlockIDs) != 2 ||
		history.BlockIDs[0] != activationID || history.BlockIDs[1] != anchor.ID ||
		history.AncestryRoot != root || history.AncestryNodes != count {
		t.Fatalf("selected history=%+v err=%v", history, err)
	}
	if _, err := store.SelectedHistorySnapshot(anchor.ID, 1); !errors.Is(err, storage.ErrHistoryLimit) {
		t.Fatalf("selected history limit error=%v", err)
	}
	if _, err := store.SelectedHistorySnapshot(sideActivationID, 2); !errors.Is(err, ErrPosition) {
		t.Fatalf("side history snapshot error=%v", err)
	}
	if selected, err := store.IsAncestor(base.Tip.ID, anchor.ID); err != nil || !selected {
		t.Fatalf("base ancestry selected=%t err=%v", selected, err)
	}
	if selected, err := store.IsAncestor(sideActivationID, anchor.ID); err != nil || selected {
		t.Fatalf("side ancestry selected=%t err=%v", selected, err)
	}
	if _, _, err := store.SelectedAncestryCommitment(sideActivationID); !errors.Is(err, ErrPosition) {
		t.Fatalf("side anchor commitment error=%v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	afterRoot, afterCount, err := reopened.SelectedAncestryCommitment(anchor.ID)
	if err != nil || afterRoot != root || afterCount != count {
		t.Fatalf("restart ancestry root/count=%s/%d want=%s/%d err=%v",
			afterRoot, afterCount, root, count, err)
	}
	nextSelected, _ := mineChild(
		t, reopened, anchor.ID, anchor.Timestamp+60, "archive-selected-after-restart",
	)
	if _, _, err := reopened.Commit(nextSelected, nextSelected.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if afterExtensionRoot, afterExtensionCount, err := reopened.SelectedAncestryCommitment(anchor.ID); err != nil || afterExtensionRoot != root || afterExtensionCount != count {
		t.Fatalf("selected descendant changed earlier ancestry=%s/%d want=%s/%d err=%v",
			afterExtensionRoot, afterExtensionCount, root, count, err)
	}

	sideChild, _ := mineChild(
		t, reopened, sideActivationID, sideActivation.Header.Seal.Timestamp+60, "archive-side-child",
	)
	if _, _, err := reopened.Commit(sideChild, sideChild.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	sideChildID, _ := sideChild.Header.ID()
	sideGrandchild, _ := mineChild(
		t, reopened, sideChildID, sideChild.Header.Seal.Timestamp+60, "archive-side-grandchild",
	)
	if _, _, err := reopened.Commit(sideGrandchild, sideGrandchild.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	sideGrandchildID, _ := sideGrandchild.Header.ID()
	sideWinner, _ := mineChild(
		t, reopened, sideGrandchildID, sideGrandchild.Header.Seal.Timestamp+60, "archive-side-winner",
	)
	if _, _, err := reopened.Commit(sideWinner, sideWinner.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	selectedTip, err := reopened.Tip()
	if err != nil {
		t.Fatal(err)
	}
	sideWinnerID, _ := sideWinner.Header.ID()
	if selectedTip.ID != sideWinnerID {
		t.Fatalf("heavier side branch tip=%s want=%s", selectedTip.ID, sideWinnerID)
	}
	if _, _, err := reopened.SelectedAncestryCommitment(anchor.ID); !errors.Is(err, ErrPosition) {
		t.Fatalf("reorged anchor commitment error=%v", err)
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

func TestPebbleRotatesBoundedReplayCheckpointsAtomically(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	policy := Policy{
		MaxHistoryBytes: DefaultMaxHistoryBytes,
		CheckpointEvery: 2,
		CheckpointKeep:  2,
	}
	store, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]types.Hash, 0, 6)
	parentID := base.Tip.ID
	timestamp := base.Tip.Timestamp
	for height := 1; height <= 6; height++ {
		timestamp += parameters.TargetSpacing
		block, _ := mineChild(t, store, parentID, timestamp, "checkpoint-"+string(rune('0'+height)))
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		parentID, _ = block.Header.ID()
		ids = append(ids, parentID)
		if height == 1 {
			report, err := store.CreateReplayCheckpoint()
			if err != nil || report.Created || report.CheckpointID != base.Tip.ID {
				t.Fatalf("early checkpoint report=%+v err=%v", report, err)
			}
		}
		if height%2 != 0 {
			continue
		}
		usageBefore, _, err := store.HistoryUsage()
		if err != nil {
			t.Fatal(err)
		}
		if height == 2 {
			injected := errors.New("injected checkpoint failure")
			store.persistence.commitHook = func() error { return injected }
			if _, err := store.CreateReplayCheckpoint(); !errors.Is(err, injected) {
				t.Fatalf("failed checkpoint error=%v", err)
			}
			store.persistence.commitHook = nil
			usageAfterFailure, _, err := store.HistoryUsage()
			if err != nil || usageAfterFailure != usageBefore {
				t.Fatalf("failed checkpoint history=%d want=%d err=%v",
					usageAfterFailure, usageBefore, err)
			}
			if _, err := store.persistence.get(workStateKey(parentID)); !errors.Is(err, pebble.ErrNotFound) {
				t.Fatalf("failed checkpoint wrote state: %v", err)
			}
			if _, err := store.persistence.get(workDeltaKey(parentID)); err != nil {
				t.Fatalf("failed checkpoint removed delta: %v", err)
			}
		}
		report, err := store.CreateReplayCheckpoint()
		if err != nil {
			t.Fatal(err)
		}
		wantRetired := uint32(0)
		if height == 6 {
			wantRetired = 1
		}
		if !report.Created || report.CheckpointID != parentID ||
			report.CheckpointHeight != uint64(height) || report.RetiredCheckpoints != wantRetired ||
			report.CheckpointCount != uint32(min(height/2, 2)) {
			t.Fatalf("checkpoint height=%d report=%+v", height, report)
		}
		usageAfter, _, err := store.HistoryUsage()
		if err != nil || usageBefore < report.ReleasedHistoryBytes ||
			usageAfter != usageBefore-report.ReleasedHistoryBytes+report.AddedHistoryBytes {
			t.Fatalf("checkpoint history before=%d after=%d report=%+v err=%v",
				usageBefore, usageAfter, report, err)
		}
		if _, err := store.persistence.get(workStateKey(parentID)); err != nil {
			t.Fatalf("checkpoint state missing: %v", err)
		}
		if _, err := store.persistence.get(workDeltaKey(parentID)); !errors.Is(err, pebble.ErrNotFound) {
			t.Fatalf("checkpoint retained delta: %v", err)
		}
	}
	if _, err := store.persistence.get(workStateKey(ids[1])); !errors.Is(err, pebble.ErrNotFound) {
		t.Fatalf("retired checkpoint state survived: %v", err)
	}
	if _, err := store.persistence.get(workDeltaKey(ids[1])); err != nil {
		t.Fatalf("retired checkpoint delta missing: %v", err)
	}
	for _, index := range []int{3, 5} {
		if _, err := store.persistence.get(workStateKey(ids[index])); err != nil {
			t.Fatalf("retained checkpoint %d missing: %v", index, err)
		}
	}
	beforeTip, _ := store.Tip()
	beforeState, _ := store.Snapshot()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	afterTip, _ := reopened.Tip()
	afterState, _ := reopened.Snapshot()
	if !storage.EqualTips(beforeTip, afterTip) || beforeState.Root() != afterState.Root() ||
		len(reopened.persistence.checkpoints) != 3 {
		t.Fatalf("checkpoint restart tip/state/checkpoints=%+v/%s/%d want=%+v/%s/3",
			afterTip, afterState.Root(), len(reopened.persistence.checkpoints), beforeTip, beforeState.Root())
	}
	extension, _ := mineChild(
		t, reopened, beforeTip.ID, beforeTip.Timestamp+parameters.TargetSpacing, "checkpoint-extension",
	)
	if _, _, err := reopened.Commit(extension, extension.Header.Seal.Timestamp); err != nil {
		t.Fatalf("post-checkpoint restart extension: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Set(workStateKey(ids[5]), []byte{0}, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithPolicy(path, base, parameters, policy); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("corrupt replay checkpoint error=%v", err)
	}
}

func TestPebblePrunesAStaleCheckpointCarrier(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	policy := Policy{
		MaxHistoryBytes: DefaultMaxHistoryBytes,
		ForkRetention:   1,
		CheckpointEvery: 1,
		CheckpointKeep:  2,
	}
	store, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	staleRoot, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "stale-checkpoint-1")
	if _, _, err := store.Commit(staleRoot, staleRoot.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	staleRootID, _ := staleRoot.Header.ID()
	staleTip, _ := mineChild(t, store, staleRootID, staleRoot.Header.Seal.Timestamp+60, "stale-checkpoint-2")
	if _, _, err := store.Commit(staleTip, staleTip.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	staleTipID, _ := staleTip.Header.ID()
	report, err := store.CreateReplayCheckpoint()
	if err != nil || !report.Created || report.CheckpointID != staleTipID {
		t.Fatalf("stale branch checkpoint report=%+v err=%v", report, err)
	}

	parentID := base.Tip.ID
	timestamp := base.Tip.Timestamp
	for height := 1; height <= 4; height++ {
		timestamp += parameters.TargetSpacing
		block, _ := mineChild(t, store, parentID, timestamp, "winning-checkpoint-"+string(rune('0'+height)))
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		parentID, _ = block.Header.ID()
	}
	pruned, err := store.PruneStaleForks()
	if err != nil {
		t.Fatal(err)
	}
	if pruned.RemovedNodes != 2 || len(store.persistence.checkpoints) != 1 {
		t.Fatalf("checkpoint prune report=%+v checkpoints=%d", pruned, len(store.persistence.checkpoints))
	}
	if _, err := store.persistence.get(workStateKey(staleTipID)); !errors.Is(err, pebble.ErrNotFound) {
		t.Fatalf("stale checkpoint state survived: %v", err)
	}
	if _, err := store.BlockByID(staleRootID); !errors.Is(err, ErrParent) {
		t.Fatalf("stale checkpoint ancestry survived: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.BlockByID(staleTipID); !errors.Is(err, ErrParent) {
		t.Fatalf("restart restored stale checkpoint carrier: %v", err)
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

func TestPebbleRejectsCheckpointAndDeltaForOneNode(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	block, result := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "duplicate-recovery")
	if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	blockID, _ := block.Header.ID()
	stateBytes, err := encodePersistedState(result.State)
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
	if err := database.Set(workStateKey(blockID), stateBytes, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, base, parameters); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("duplicate recovery representation error=%v", err)
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

func TestPebbleReopenRejectsHistoryAboveReducedPolicy(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	usage, _, err := store.HistoryUsage()
	if err != nil || usage < 2 {
		t.Fatalf("initial history usage=%d err=%v", usage, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithPolicy(path, base, parameters, Policy{MaxHistoryBytes: usage - 1}); !errors.Is(err, storage.ErrHistoryLimit) {
		t.Fatalf("reduced reopen budget error=%v", err)
	}
	reopened, err := OpenWithPolicy(path, base, parameters, Policy{MaxHistoryBytes: usage})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
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

func TestPebbleRejectsPreFloorWorkSchemas(t *testing.T) {
	for _, version := range []byte{2, 3} {
		version := version
		t.Run("schema-"+string(rune('0'+version)), func(t *testing.T) {
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
			if err := database.Set(workKeySchema, []byte{0, version}, pebble.Sync); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, base, parameters); !errors.Is(err, storage.ErrCorrupt) {
				t.Fatalf("old schema %d error=%v", version, err)
			}
		})
	}
}

func TestPebbleCanonicalPrefixPruneRetainsVerifiableFloorAcrossRestart(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	policy := DefaultPolicy()
	policy.ForkRetention = 1
	policy.CanonicalRetention = 1
	store, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	blocks := make([]workblock.Block, 0, 5)
	parentID := base.Tip.ID
	timestamp := base.Tip.Timestamp
	for height := 0; height < 5; height++ {
		timestamp += parameters.TargetSpacing
		block, _ := mineChild(t, store, parentID, timestamp, "canonical-floor-"+string(rune('a'+height)))
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, block)
		parentID, _ = block.Header.ID()
	}
	anchorID, _ := blocks[2].Header.ID()
	anchorTip, err := store.TipByID(anchorID)
	if err != nil {
		t.Fatal(err)
	}
	root, count, err := store.SelectedAncestryCommitment(anchorID)
	if err != nil {
		t.Fatal(err)
	}
	boundary := canonicalTestFloor(base.Tip.ID, anchorTip, root, count, "first")
	usageBefore, _, err := store.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected canonical prune failure")
	store.persistence.commitHook = func() error { return injected }
	if _, err := store.PruneCanonicalPrefix(boundary); !errors.Is(err, injected) {
		t.Fatalf("injected canonical prune error=%v", err)
	}
	if floor, err := store.CanonicalFloor(); err != nil || floor.Pruned {
		t.Fatalf("failed canonical prune floor=%+v err=%v", floor, err)
	}
	if _, err := store.BlockByID(anchorID); err != nil {
		t.Fatalf("failed canonical prune changed memory: %v", err)
	}
	store.persistence.commitHook = nil
	report, err := store.PruneCanonicalPrefix(boundary)
	if err != nil {
		t.Fatal(err)
	}
	if report.PreviousFloorID != base.Tip.ID || report.FloorID != anchorID ||
		report.RemovedNodes != 3 || report.RetainedNodes != 3 || report.ArchivedHeaders != 2 ||
		report.ReleasedHistoryBytes == 0 || report.AddedHistoryBytes == 0 {
		t.Fatalf("canonical prune report=%+v", report)
	}
	usageAfter, _, err := store.HistoryUsage()
	if err != nil || usageAfter != usageBefore-report.ReleasedHistoryBytes+report.AddedHistoryBytes ||
		usageAfter >= usageBefore {
		t.Fatalf("canonical prune history before=%d after=%d report=%+v err=%v",
			usageBefore, usageAfter, report, err)
	}
	activationID, _ := blocks[0].Header.ID()
	if _, err := store.BlockByID(activationID); !errors.Is(err, ErrHistoryPruned) {
		t.Fatalf("archived activation payload error=%v", err)
	}
	if archivedTip, err := store.TipByID(activationID); err != nil || archivedTip.ID != activationID {
		t.Fatalf("archived activation tip=%+v err=%v", archivedTip, err)
	}
	if selected, err := store.IsAncestor(activationID, parentID); err != nil || !selected {
		t.Fatalf("archived activation ancestry=%t err=%v", selected, err)
	}
	if gotRoot, gotCount, err := store.SelectedAncestryCommitment(anchorID); err != nil ||
		gotRoot != root || gotCount != count {
		t.Fatalf("retained floor commitment=%s/%d want=%s/%d err=%v",
			gotRoot, gotCount, root, count, err)
	}
	if floor, err := store.CanonicalFloor(); err != nil || !equalCanonicalTestFloor(floor, boundary) {
		t.Fatalf("canonical floor=%+v want=%+v err=%v", floor, boundary, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if floor, err := reopened.CanonicalFloor(); err != nil || !equalCanonicalTestFloor(floor, boundary) {
		t.Fatalf("reopened floor=%+v want=%+v err=%v", floor, boundary, err)
	}
	if gotRoot, gotCount, err := reopened.SelectedAncestryCommitment(anchorID); err != nil ||
		gotRoot != root || gotCount != count {
		t.Fatalf("reopened floor commitment=%s/%d want=%s/%d err=%v",
			gotRoot, gotCount, root, count, err)
	}
	tip, err := reopened.Tip()
	if err != nil {
		t.Fatal(err)
	}
	extension, _ := mineChild(t, reopened, tip.ID, tip.Timestamp+parameters.TargetSpacing, "floor-extension")
	if _, _, err := reopened.Commit(extension, extension.Header.Seal.Timestamp); err != nil {
		t.Fatalf("extend pruned chain: %v", err)
	}
	secondFloorID, _ := blocks[3].Header.ID()
	secondFloorTip, err := reopened.TipByID(secondFloorID)
	if err != nil {
		t.Fatal(err)
	}
	secondRoot, secondCount, err := reopened.SelectedAncestryCommitment(secondFloorID)
	if err != nil {
		t.Fatal(err)
	}
	secondBoundary := canonicalTestFloor(
		base.Tip.ID, secondFloorTip, secondRoot, secondCount, "second",
	)
	secondReport, err := reopened.PruneCanonicalPrefix(secondBoundary)
	if err != nil || secondReport.PreviousFloorID != anchorID || secondReport.FloorID != secondFloorID ||
		secondReport.RemovedNodes != 1 || secondReport.ArchivedHeaders != 3 {
		t.Fatalf("second canonical prune report=%+v err=%v", secondReport, err)
	}
	if _, err := reopened.BlockByID(anchorID); !errors.Is(err, ErrHistoryPruned) {
		t.Fatalf("previous floor payload error=%v", err)
	}
	if gotRoot, gotCount, err := reopened.SelectedAncestryCommitment(anchorID); err != nil ||
		gotRoot != root || gotCount != count {
		t.Fatalf("archived previous floor commitment=%s/%d want=%s/%d err=%v",
			gotRoot, gotCount, root, count, err)
	}
	if gotRoot, gotCount, err := reopened.SelectedAncestryCommitment(secondFloorID); err != nil ||
		gotRoot != secondRoot || gotCount != secondCount {
		t.Fatalf("second floor commitment=%s/%d want=%s/%d err=%v",
			gotRoot, gotCount, secondRoot, secondCount, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	secondReopen, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer secondReopen.Close()
	if floor, err := secondReopen.CanonicalFloor(); err != nil ||
		!equalCanonicalTestFloor(floor, secondBoundary) {
		t.Fatalf("second reopened floor=%+v want=%+v err=%v", floor, secondBoundary, err)
	}
}

func TestPebbleCanonicalPrefixPruneIsDisabledByDefault(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	store, err := Open(t.TempDir(), base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	parentID := base.Tip.ID
	var anchor storage.Tip
	for height := uint64(1); height <= 2; height++ {
		block, _ := mineChild(
			t, store, parentID, base.Tip.Timestamp+height*parameters.TargetSpacing,
			"canonical-default-disabled-"+string(rune('a')+rune(height)),
		)
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		parentID, _ = block.Header.ID()
		if height == 1 {
			anchor, err = store.TipByID(parentID)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	root, count, err := store.SelectedAncestryCommitment(anchor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PruneCanonicalPrefix(
		canonicalTestFloor(base.Tip.ID, anchor, root, count, "default-disabled"),
	); !errors.Is(err, ErrCanonicalPrune) {
		t.Fatalf("default policy canonical prune error=%v", err)
	}
	if floor, err := store.CanonicalFloor(); err != nil || floor.Pruned {
		t.Fatalf("default-disabled canonical prune changed floor=%+v err=%v", floor, err)
	}
}

func TestPebbleCanonicalPrefixReopenRejectsCorruptArchivedHeader(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	policy := DefaultPolicy()
	policy.CanonicalRetention = 1
	store, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	parentID := base.Tip.ID
	var blocks []workblock.Block
	for height := 1; height <= 4; height++ {
		block, _ := mineChild(
			t, store, parentID, base.Tip.Timestamp+uint64(height)*parameters.TargetSpacing,
			"corrupt-archived-header-"+string(rune('a'+height)),
		)
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, block)
		parentID, _ = block.Header.ID()
	}
	anchorID, _ := blocks[2].Header.ID()
	anchor, _ := store.TipByID(anchorID)
	root, count, _ := store.SelectedAncestryCommitment(anchorID)
	if _, err := store.PruneCanonicalPrefix(
		canonicalTestFloor(base.Tip.ID, anchor, root, count, "corrupt-header"),
	); err != nil {
		t.Fatal(err)
	}
	archivedID, _ := blocks[0].Header.ID()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
	if err != nil {
		t.Fatal(err)
	}
	headerBytes := blocks[0].Header.CanonicalBytes()
	headerBytes[len(headerBytes)-1] ^= 1
	if err := database.Set(workArchivedHeaderKey(archivedID), headerBytes, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithPolicy(path, base, parameters, policy); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("corrupt archived header reopen error=%v", err)
	}
}

func TestPebbleCanonicalPrefixPruneRejectsUnresolvedSideBranch(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	policy := DefaultPolicy()
	policy.CanonicalRetention = 1
	store, err := OpenWithPolicy(t.TempDir(), base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	selected, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "canonical-prune-selected")
	side, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+60, "canonical-prune-side")
	for _, block := range []workblock.Block{selected, side} {
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	selectedID, _ := selected.Header.ID()
	child, _ := mineChild(t, store, selectedID, selected.Header.Seal.Timestamp+60, "canonical-prune-child")
	if _, _, err := store.Commit(child, child.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	root, count, err := store.SelectedAncestryCommitment(selectedID)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := store.TipByID(selectedID)
	boundary := canonicalTestFloor(base.Tip.ID, anchor, root, count, "unsafe-side")
	if _, err := store.PruneCanonicalPrefix(boundary); !errors.Is(err, ErrCanonicalPrune) {
		t.Fatalf("canonical prune with unresolved side branch error=%v", err)
	}
	if floor, err := store.CanonicalFloor(); err != nil || floor.Pruned {
		t.Fatalf("unsafe canonical prune changed floor=%+v err=%v", floor, err)
	}
}

func TestPebbleCanonicalPrefixPruneRejectsHistoryGrowthAtomically(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	path := t.TempDir()
	policy := DefaultPolicy()
	policy.CanonicalRetention = 1
	store, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	activation, _ := mineChild(
		t, store, base.Tip.ID, base.Tip.Timestamp+parameters.TargetSpacing,
		"canonical-limit-activation",
	)
	if _, _, err := store.Commit(activation, activation.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	activationID, _ := activation.Header.ID()
	child, _ := mineChild(
		t, store, activationID, activation.Header.Seal.Timestamp+parameters.TargetSpacing,
		"canonical-limit-child",
	)
	if _, _, err := store.Commit(child, child.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	usage, _, err := store.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := store.TipByID(activationID)
	root, count, _ := store.SelectedAncestryCommitment(activationID)
	boundary := canonicalTestFloor(base.Tip.ID, anchor, root, count, "history-limit")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	policy.MaxHistoryBytes = usage
	store, err = OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PruneCanonicalPrefix(boundary); !errors.Is(err, storage.ErrHistoryLimit) {
		_ = store.Close()
		t.Fatalf("canonical prune history limit error=%v", err)
	}
	if floor, err := store.CanonicalFloor(); err != nil || floor.Pruned {
		_ = store.Close()
		t.Fatalf("history-limited canonical prune floor=%+v err=%v", floor, err)
	}
	if _, err := store.BlockByID(activationID); err != nil {
		_ = store.Close()
		t.Fatalf("history-limited canonical prune removed activation: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenWithPolicy(path, base, parameters, policy); err != nil {
		t.Fatal(err)
	} else if floor, floorErr := reopened.CanonicalFloor(); floorErr != nil || floor.Pruned {
		_ = reopened.Close()
		t.Fatalf("reopened history-limited floor=%+v err=%v", floor, floorErr)
	} else if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func canonicalTestFloor(
	baseID types.Hash,
	anchor storage.Tip,
	root types.Hash,
	count uint64,
	label string,
) CanonicalFloor {
	return CanonicalFloor{
		Pruned: true, BaseID: baseID, Anchor: anchor,
		AncestryNodes: count, AncestryRoot: root,
		StatementID:    types.DomainHash("test/workchain/canonical-floor/statement/" + label),
		ManifestID:     types.DomainHash("test/workchain/canonical-floor/manifest/" + label),
		AvailabilityID: types.DomainHash("test/workchain/canonical-floor/availability/" + label),
		VerifiedAt:     100, RetainUntil: 1_000,
	}
}

func equalCanonicalTestFloor(left, right CanonicalFloor) bool {
	return left.Pruned == right.Pruned && left.BaseID == right.BaseID &&
		storage.EqualTips(left.Anchor, right.Anchor) && left.AncestryNodes == right.AncestryNodes &&
		left.AncestryRoot == right.AncestryRoot && left.StatementID == right.StatementID &&
		left.ManifestID == right.ManifestID && left.AvailabilityID == right.AvailabilityID &&
		left.VerifiedAt == right.VerifiedAt && left.RetainUntil == right.RetainUntil
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
