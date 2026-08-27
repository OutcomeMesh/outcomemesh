package pebblestore

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"
	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
	"github.com/outcomemesh/outcomemesh/wallet"
)

func testGenesis() genesis.Document {
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	owner := types.Address(types.DomainHash("test/storage/owner"))
	return genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    23,
		Timestamp:    1_700_000_000,
		Target:       target,
		BlockSubsidy: 50,
		Allocations: []resource.Resource{{
			ID:      types.ResourceID(types.DomainHash("test/storage/allocation")),
			Version: resource.Version0,
			Owner:   owner,
			Asset:   types.NativeAssetID(),
			Amount:  1_000,
		}},
	}
}

func TestAtomicCommitSurvivesReopenAndMatchesReference(t *testing.T) {
	document := testGenesis()
	directory := t.TempDir()
	persistent, err := Open(directory, document)
	if err != nil {
		t.Fatal(err)
	}
	referenceStore, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}

	initialTip, err := persistent.Tip()
	if err != nil {
		t.Fatal(err)
	}
	preState, err := persistent.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	parameters := block.ParametersFromGenesis(document)
	miner := types.Address(types.DomainHash("test/storage/miner"))
	candidate, _, err := block.Prepare(preState, initialTip.Parent(), nil, miner, initialTip.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := block.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	executed, err := block.ValidateAndExecuteAt(preState, initialTip.Parent(), mined, parameters, mined.Header.Timestamp)
	if err != nil {
		t.Fatal(err)
	}

	persistentTip, err := persistent.Commit(initialTip, mined, executed.State)
	if err != nil {
		t.Fatal(err)
	}
	referenceTip, err := referenceStore.Commit(initialTip, mined, executed.State)
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(persistentTip, referenceTip) {
		t.Fatal("persistent and reference tips differ")
	}
	if _, err := persistent.Commit(initialTip, mined, executed.State); !errors.Is(err, storage.ErrBlockExists) {
		t.Fatalf("got %v, want duplicate-block rejection", err)
	}
	if err := persistent.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(directory, document)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedTip, err := reopened.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(reopenedTip, persistentTip) {
		t.Fatal("tip changed after reopen")
	}
	reopenedState, err := reopened.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if reopenedState.Root() != executed.State.Root() {
		t.Fatal("state changed after reopen")
	}
	storedBlock, err := reopened.Block(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedBlock.CanonicalBytes()) != string(mined.CanonicalBytes()) {
		t.Fatal("stored block changed after reopen")
	}
}

func TestForkStateStorageScalesWithDeltaNotFullState(t *testing.T) {
	document := testGenesis()
	document.Allocations = make([]resource.Resource, 256)
	owner := types.Address(types.DomainHash("test/storage/delta/owner"))
	for index := range document.Allocations {
		document.Allocations[index] = resource.Resource{
			ID:      types.ResourceID(types.DomainHash("test/storage/delta/allocation", []byte{byte(index)})),
			Version: resource.Version0,
			Owner:   owner,
			Asset:   types.NativeAssetID(),
			Amount:  uint64(index + 1),
		}
	}
	store, err := Open(t.TempDir(), document)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	genesisTip, err := store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if count := countSnapshotEntries(t, store, genesisTip.ID); count != len(document.Allocations) {
		t.Fatalf("genesis delta entries = %d, want %d", count, len(document.Allocations))
	}
	parameters := block.ParametersFromGenesis(document)
	_, first, _ := commitStoredChild(t, store, genesisTip, types.Address(types.DomainHash("test/storage/delta/miner-a")), parameters)
	if count := countSnapshotEntries(t, store, first.ID); count != 1 {
		t.Fatalf("empty-block delta entries = %d, want one reward instead of a 257-resource snapshot", count)
	}
	_, sibling, _ := commitStoredChild(t, store, genesisTip, types.Address(types.DomainHash("test/storage/delta/miner-b")), parameters)
	if count := countSnapshotEntries(t, store, sibling.ID); count != 1 {
		t.Fatalf("side-fork delta entries = %d, want one reward", count)
	}
	reconstructed, err := store.SnapshotAt(sibling.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconstructed.Len() != len(document.Allocations)+1 || reconstructed.Root() != sibling.StateRoot {
		t.Fatal("delta reconstruction changed side-fork state")
	}
}

func TestHistoryBudgetRejectsBlockAtomicallyAndKeepsStoreReadable(t *testing.T) {
	document := testGenesis()
	store, err := Open(t.TempDir(), document)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	initialTip, candidate, postState := prepareBlockForStore(t, store, document)
	usage, _, err := store.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	store.policy.MaxHistoryBytes = usage
	if _, err := store.Commit(initialTip, candidate, postState); !errors.Is(err, storage.ErrHistoryLimit) {
		t.Fatalf("history limit error = %v", err)
	}
	afterTip, err := store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(initialTip, afterTip) {
		t.Fatalf("history rejection changed tip: before=%+v after=%+v", initialTip, afterTip)
	}
	id, err := candidate.Header.ID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BlockByID(id); !errors.Is(err, storage.ErrBlockNotFound) {
		t.Fatalf("history rejection persisted block: %v", err)
	}
	afterUsage, limit, err := store.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	if afterUsage != usage || limit != usage {
		t.Fatalf("history accounting changed after rejection: usage=%d limit=%d", afterUsage, limit)
	}
	if snapshot, err := store.Snapshot(); err != nil || snapshot.Root() != initialTip.StateRoot {
		t.Fatalf("store unreadable after history rejection: root=%v err=%v", snapshot, err)
	}
}

func countSnapshotEntries(t testing.TB, store *Store, id types.Hash) int {
	t.Helper()
	lower, upper := snapshotBounds(id)
	iterator, err := store.db.NewIter(&pebble.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		t.Fatal(err)
	}
	defer iterator.Close()
	count := 0
	for valid := iterator.First(); valid; valid = iterator.Next() {
		count++
	}
	if err := iterator.Error(); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestRejectsDifferentGenesisOnExistingStore(t *testing.T) {
	document := testGenesis()
	directory := t.TempDir()
	store, err := Open(directory, document)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	document.BlockSubsidy++
	if _, err := Open(directory, document); !errors.Is(err, storage.ErrGenesisMismatch) {
		t.Fatalf("got %v, want genesis mismatch", err)
	}
}

func TestCrashRecoveryAtEveryLogicalCommitBoundary(t *testing.T) {
	document := testGenesis()
	stages := []commitStage{
		stageBeforeBatch,
		stageAfterBlock,
		stageAfterNode,
		stageAfterSnapshot,
		stageAfterStateDelete,
		stageAfterResources,
		stageAfterBlockIndex,
		stageAfterTip,
		stageBeforeCommit,
		stageAfterCommit,
	}
	for _, injectedStage := range stages {
		injectedStage := injectedStage
		t.Run(commitStageName(injectedStage), func(t *testing.T) {
			filesystem := vfs.NewCrashableMem()
			store, err := openWithOptions("ledger", document, filesystem)
			if err != nil {
				t.Fatal(err)
			}
			initialTip, mined, postState := prepareBlockForStore(t, store, document)
			injected := errors.New("injected process stop")
			store.commitHook = func(actual commitStage) error {
				if actual == injectedStage {
					return injected
				}
				return nil
			}
			if _, err := store.Commit(initialTip, mined, postState); !errors.Is(err, injected) {
				t.Fatalf("commit error = %v, want injected stop", err)
			}

			crashedFilesystem := filesystem.CrashClone(vfs.CrashCloneCfg{UnsyncedDataPercent: 0})
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			recovered, err := openWithOptions("ledger", document, crashedFilesystem)
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Close()
			recoveredTip, err := recovered.Tip()
			if err != nil {
				t.Fatal(err)
			}
			recoveredState, err := recovered.Snapshot()
			if err != nil {
				t.Fatal(err)
			}

			committed := injectedStage == stageAfterCommit
			if committed {
				if recoveredTip.Height != 1 || recoveredState.Root() != postState.Root() {
					t.Fatalf("post-commit crash recovered partial/old state: height=%d root=%s", recoveredTip.Height, recoveredState.Root())
				}
				if _, err := recovered.Block(1); err != nil {
					t.Fatalf("committed block missing after crash: %v", err)
				}
				return
			}
			if !storage.EqualTips(recoveredTip, initialTip) || recoveredState.Root() != initialTip.StateRoot {
				t.Fatalf("pre-commit crash exposed partial state: height=%d root=%s", recoveredTip.Height, recoveredState.Root())
			}
			if _, err := recovered.Block(1); !errors.Is(err, storage.ErrBlockNotFound) {
				t.Fatalf("uncommitted block visible after crash: %v", err)
			}
		})
	}
}

func TestReorganizationCrashRecoveryAtEveryLogicalCommitBoundary(t *testing.T) {
	document := testGenesis()
	stages := []commitStage{
		stageBeforeBatch,
		stageAfterBlock,
		stageAfterNode,
		stageAfterSnapshot,
		stageAfterStateDelete,
		stageAfterResources,
		stageAfterBlockIndex,
		stageAfterTip,
		stageBeforeCommit,
		stageAfterCommit,
	}
	for _, injectedStage := range stages {
		injectedStage := injectedStage
		t.Run(commitStageName(injectedStage), func(t *testing.T) {
			filesystem := vfs.NewCrashableMem()
			store, err := openWithOptions("ledger", document, filesystem)
			if err != nil {
				t.Fatal(err)
			}
			parameters := block.ParametersFromGenesis(document)
			genesisTip, err := store.Tip()
			if err != nil {
				t.Fatal(err)
			}
			minerA := types.Address(types.DomainHash("test/storage/crash-reorg/miner-a"))
			minerB := types.Address(types.DomainHash("test/storage/crash-reorg/miner-b"))
			_, a1Node, _ := commitStoredChild(t, store, genesisTip, minerA, parameters)
			_, a2Node, _ := commitStoredChild(t, store, a1Node, minerA, parameters)
			_, b1Node, _ := commitStoredChild(t, store, genesisTip, minerB, parameters)
			_, b2Node, _ := commitStoredChild(t, store, b1Node, minerB, parameters)
			oldTip, err := store.Tip()
			if err != nil {
				t.Fatal(err)
			}
			losingTip := a2Node
			if oldTip.ID == a2Node.ID {
				losingTip = b2Node
			}
			candidate, postState := prepareStoredChild(t, store, losingTip, minerForLosingBranch(losingTip, a2Node, minerA, minerB), parameters)
			candidateTip, err := storage.NextTip(losingTip, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if candidateTip.Height != 3 || !storage.BetterTip(candidateTip, oldTip) {
				t.Fatal("test did not construct a higher-work reorganization")
			}

			injected := errors.New("injected reorganization stop")
			store.commitHook = func(actual commitStage) error {
				if actual == injectedStage {
					return injected
				}
				return nil
			}
			if _, err := store.Commit(losingTip, candidate, postState); !errors.Is(err, injected) {
				t.Fatalf("commit error = %v, want injected stop", err)
			}

			crashedFilesystem := filesystem.CrashClone(vfs.CrashCloneCfg{UnsyncedDataPercent: 0})
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			recovered, err := openWithOptions("ledger", document, crashedFilesystem)
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Close()
			recoveredTip, err := recovered.Tip()
			if err != nil {
				t.Fatal(err)
			}
			if injectedStage == stageAfterCommit {
				if !storage.EqualTips(recoveredTip, candidateTip) {
					t.Fatal("durable reorganization recovered the old or partial tip")
				}
				if _, err := recovered.SnapshotAt(candidateTip.ID); err != nil {
					t.Fatalf("winning branch snapshot missing: %v", err)
				}
				canonical, err := recovered.Block(3)
				if err != nil {
					t.Fatal(err)
				}
				canonicalID, err := canonical.Header.ID()
				if err != nil || canonicalID != candidateTip.ID {
					t.Fatal("canonical index did not recover the new branch")
				}
				return
			}
			if !storage.EqualTips(recoveredTip, oldTip) {
				t.Fatal("pre-commit reorganization exposed a partial/new tip")
			}
			if _, err := recovered.TipByID(candidateTip.ID); !errors.Is(err, storage.ErrNodeNotFound) {
				t.Fatalf("uncommitted fork node is visible: %v", err)
			}
			if _, err := recovered.SnapshotAt(a2Node.ID); err != nil {
				t.Fatalf("existing losing branch was damaged: %v", err)
			}
			if _, err := recovered.SnapshotAt(b2Node.ID); err != nil {
				t.Fatalf("existing competing branch was damaged: %v", err)
			}
		})
	}
}

func minerForLosingBranch(losingTip, a2Node storage.Tip, minerA, minerB types.Address) types.Address {
	if losingTip.ID == a2Node.ID {
		return minerA
	}
	return minerB
}

func TestLongChainDifferentialAndReplay(t *testing.T) {
	const blockCount = 64
	seed := types.DomainHash("test/storage/long-chain-key")
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    404,
		Timestamp:    1_700_100_000,
		Target:       target,
		BlockSubsidy: 25,
		Allocations: []resource.Resource{{
			ID:      types.ResourceID(types.DomainHash("test/storage/long-chain-genesis")),
			Version: resource.Version0,
			Owner:   owner,
			Asset:   types.NativeAssetID(),
			Amount:  100_000,
		}},
	}
	persistent, err := Open(t.TempDir(), document)
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	referenceStore, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	defer referenceStore.Close()
	parameters := block.ParametersFromGenesis(document)
	recipient := types.Address(types.DomainHash("test/storage/long-chain-recipient"))

	for height := uint64(1); height <= blockCount; height++ {
		tip, err := persistent.Tip()
		if err != nil {
			t.Fatal(err)
		}
		preState, err := persistent.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		var transactions []outcome.Transaction
		if height%3 == 0 {
			var nonce [32]byte
			binary.BigEndian.PutUint64(nonce[24:], height)
			transaction, err := wallet.BuildNativeTransfer(preState, privateKey, wallet.TransferRequest{
				NetworkID:     document.NetworkID,
				CurrentHeight: tip.Height,
				ValidFor:      20,
				Recipient:     recipient,
				Amount:        height,
				Fee:           1,
				Nonce:         nonce,
			})
			if err != nil {
				t.Fatalf("height %d: %v", height, err)
			}
			transactions = []outcome.Transaction{transaction}
		}
		parent, err := storage.ParentContext(persistent, tip)
		if err != nil {
			t.Fatal(err)
		}
		candidate, _, err := block.Prepare(preState, parent, transactions, owner, tip.Timestamp+1, parameters)
		if err != nil {
			t.Fatalf("height %d: %v", height, err)
		}
		mined, _, err := block.Mine(context.Background(), candidate, 0)
		if err != nil {
			t.Fatalf("height %d: %v", height, err)
		}
		executed, err := block.ValidateAndExecuteAt(preState, parent, mined, parameters, mined.Header.Timestamp)
		if err != nil {
			t.Fatalf("height %d: %v", height, err)
		}
		persistentTip, err := persistent.Commit(tip, mined, executed.State)
		if err != nil {
			t.Fatalf("height %d persistent commit: %v", height, err)
		}
		referenceTip, err := referenceStore.Commit(tip, mined, executed.State)
		if err != nil {
			t.Fatalf("height %d reference commit: %v", height, err)
		}
		if !storage.EqualTips(persistentTip, referenceTip) {
			t.Fatalf("height %d: storage tips differ", height)
		}
		persistentState, err := persistent.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		referenceState, err := referenceStore.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(persistentState.Resources(), referenceState.Resources()) {
			t.Fatalf("height %d: storage states differ", height)
		}
	}

	storedTip, err := persistent.Tip()
	if err != nil {
		t.Fatal(err)
	}
	replayedState, err := document.State()
	if err != nil {
		t.Fatal(err)
	}
	replayedTip, err := storage.GenesisTip(document)
	if err != nil {
		t.Fatal(err)
	}
	for height := uint64(1); height <= storedTip.Height; height++ {
		storedBlock, err := persistent.Block(height)
		if err != nil {
			t.Fatal(err)
		}
		parent, err := storage.ParentContext(persistent, replayedTip)
		if err != nil {
			t.Fatal(err)
		}
		executed, err := block.ValidateAndExecuteAt(replayedState, parent, storedBlock, parameters, storedBlock.Header.Timestamp)
		if err != nil {
			t.Fatalf("replay height %d: %v", height, err)
		}
		replayedTip, err = storage.NextTip(replayedTip, storedBlock)
		if err != nil {
			t.Fatal(err)
		}
		replayedState = executed.State
	}
	if !storage.EqualTips(replayedTip, storedTip) || replayedState.Root() != storedTip.StateRoot {
		t.Fatal("full replay did not reproduce the stored chain")
	}
}

func TestCompetingForkReorganizesAtomicallyAndSurvivesReopen(t *testing.T) {
	document := testGenesis()
	directory := t.TempDir()
	persistent, err := Open(directory, document)
	if err != nil {
		t.Fatal(err)
	}
	referenceStore, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	defer referenceStore.Close()
	parameters := block.ParametersFromGenesis(document)
	genesisTip, err := persistent.Tip()
	if err != nil {
		t.Fatal(err)
	}
	minerA := types.Address(types.DomainHash("test/storage/fork/miner-a"))
	minerB := types.Address(types.DomainHash("test/storage/fork/miner-b"))

	a1, a1Node, _ := commitForkChild(t, persistent, referenceStore, genesisTip, minerA, parameters)
	_, a2Node, canonicalA := commitForkChild(t, persistent, referenceStore, a1Node, minerA, parameters)
	if canonicalA.ID != a2Node.ID {
		t.Fatal("direct extension did not become canonical")
	}
	a2State, err := persistent.SnapshotAt(a2Node.ID)
	if err != nil {
		t.Fatal(err)
	}

	_, b1Node, canonicalAfterB1 := commitForkChild(t, persistent, referenceStore, genesisTip, minerB, parameters)
	if canonicalAfterB1.ID != a2Node.ID {
		t.Fatal("lower-work side branch replaced canonical tip")
	}
	_, b2Node, _ := commitForkChild(t, persistent, referenceStore, b1Node, minerB, parameters)
	b3, b3Node, canonicalB := commitForkChild(t, persistent, referenceStore, b2Node, minerB, parameters)
	if canonicalB.ID != b3Node.ID || canonicalB.Height != 3 {
		t.Fatalf("higher-work branch did not win: height=%d id=%s", canonicalB.Height, canonicalB.ID)
	}

	canonicalBlock1, err := persistent.Block(1)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBlock3, err := persistent.Block(3)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalBlock1.Header.Miner != minerB || string(canonicalBlock3.CanonicalBytes()) != string(b3.CanonicalBytes()) {
		t.Fatal("canonical height index was not rewritten to the winning branch")
	}
	a1ID, err := a1.Header.ID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistent.BlockByID(a1ID); err != nil {
		t.Fatalf("losing branch block was discarded: %v", err)
	}
	preservedA2State, err := persistent.SnapshotAt(a2Node.ID)
	if err != nil {
		t.Fatalf("losing branch snapshot was discarded: %v", err)
	}
	if preservedA2State.Root() != a2State.Root() {
		t.Fatal("losing branch snapshot changed during reorganization")
	}

	persistentState, err := persistent.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	referenceState, err := referenceStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	referenceTip, err := referenceStore.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(canonicalB, referenceTip) || !reflect.DeepEqual(persistentState.Resources(), referenceState.Resources()) {
		t.Fatal("Pebble/reference fork-choice results differ")
	}

	if err := persistent.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, document)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedTip, err := reopened.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(reopenedTip, canonicalB) {
		t.Fatal("canonical fork choice changed after reopen")
	}
	if _, err := reopened.SnapshotAt(a2Node.ID); err != nil {
		t.Fatalf("side-branch snapshot missing after reopen: %v", err)
	}
}

func commitForkChild(
	t testing.TB,
	persistent *Store,
	referenceStore *reference.Store,
	parentTip storage.Tip,
	miner types.Address,
	parameters block.Parameters,
) (block.Block, storage.Tip, storage.Tip) {
	t.Helper()
	preState, err := persistent.SnapshotAt(parentTip.ID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := storage.ParentContext(persistent, parentTip)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := block.Prepare(preState, parent, nil, miner, parentTip.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, id, err := block.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	executed, err := block.ValidateAndExecuteAt(preState, parent, mined, parameters, mined.Header.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := persistent.Commit(parentTip, mined, executed.State)
	if err != nil {
		t.Fatal(err)
	}
	referenceCanonical, err := referenceStore.Commit(parentTip, mined, executed.State)
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(canonical, referenceCanonical) {
		t.Fatal("Pebble/reference fork choice differs")
	}
	node, err := persistent.TipByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return mined, node, canonical
}

func commitStoredChild(
	t testing.TB,
	store *Store,
	parentTip storage.Tip,
	miner types.Address,
	parameters block.Parameters,
) (block.Block, storage.Tip, storage.Tip) {
	t.Helper()
	mined, postState := prepareStoredChild(t, store, parentTip, miner, parameters)
	canonical, err := store.Commit(parentTip, mined, postState)
	if err != nil {
		t.Fatal(err)
	}
	id, err := mined.Header.ID()
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.TipByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return mined, node, canonical
}

func prepareStoredChild(
	t testing.TB,
	store *Store,
	parentTip storage.Tip,
	miner types.Address,
	parameters block.Parameters,
) (block.Block, *state.Memory) {
	t.Helper()
	preState, err := store.SnapshotAt(parentTip.ID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := storage.ParentContext(store, parentTip)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := block.Prepare(preState, parent, nil, miner, parentTip.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := block.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	executed, err := block.ValidateAndExecuteAt(preState, parent, mined, parameters, mined.Header.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return mined, executed.State
}

func prepareBlockForStore(t testing.TB, store *Store, document genesis.Document) (storage.Tip, block.Block, *state.Memory) {
	t.Helper()
	initialTip, err := store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	preState, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	parameters := block.ParametersFromGenesis(document)
	miner := types.Address(types.DomainHash("test/storage/crash-miner"))
	candidate, _, err := block.Prepare(preState, initialTip.Parent(), nil, miner, initialTip.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := block.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	executed, err := block.ValidateAndExecuteAt(preState, initialTip.Parent(), mined, parameters, mined.Header.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return initialTip, mined, executed.State
}

func commitStageName(stage commitStage) string {
	switch stage {
	case stageBeforeBatch:
		return "before-batch"
	case stageAfterStateDelete:
		return "after-state-delete"
	case stageAfterResources:
		return "after-resources"
	case stageAfterBlock:
		return "after-block"
	case stageAfterNode:
		return "after-node"
	case stageAfterSnapshot:
		return "after-snapshot"
	case stageAfterBlockIndex:
		return "after-block-index"
	case stageAfterTip:
		return "after-tip"
	case stageBeforeCommit:
		return "before-commit"
	case stageAfterCommit:
		return "after-commit"
	default:
		return fmt.Sprintf("stage-%d", stage)
	}
}
