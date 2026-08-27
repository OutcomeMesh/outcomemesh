package chain

import (
	"context"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

func chainFixture(t testing.TB) (*Chain, genesis.Document, *reference.Store) {
	t.Helper()
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    31,
		Timestamp:    1_700_000_000,
		Target:       target,
		BlockSubsidy: 25,
	}
	store, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := New(store, block.ParametersFromGenesis(document))
	if err != nil {
		t.Fatal(err)
	}
	return chain, document, store
}

func TestMineAndCommitConsecutiveBlocks(t *testing.T) {
	t.Parallel()

	chain, document, store := chainFixture(t)
	defer store.Close()
	miner := types.Address(types.DomainHash("test/chain/miner"))
	first, err := chain.Mine(context.Background(), nil, miner, document.Timestamp+1, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := chain.Mine(context.Background(), nil, miner, document.Timestamp+2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Tip.Height != 1 || second.Tip.Height != 2 || second.Block.Header.Parent != first.ID {
		t.Fatalf("unexpected chain heights or parent: first=%d second=%d", first.Tip.Height, second.Tip.Height)
	}
	state, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if balance, err := state.Balance(miner, types.NativeAssetID()); err != nil || balance != 50 {
		t.Fatalf("miner balance = %d, %v; want 50", balance, err)
	}
}

func TestSubmitRejectsDuplicateCandidate(t *testing.T) {
	t.Parallel()

	chain, document, store := chainFixture(t)
	defer store.Close()
	miner := types.Address(types.DomainHash("test/chain/miner"))
	stale, _, err := chain.Prepare(nil, miner, document.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Mine(context.Background(), nil, miner, document.Timestamp+1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Submit(stale); !errors.Is(err, storage.ErrBlockExists) {
		t.Fatalf("got %v, want duplicate block", err)
	}
}

func TestMineDetectsCanceledContext(t *testing.T) {
	t.Parallel()

	chain, document, store := chainFixture(t)
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := chain.Mine(ctx, nil, types.Address(types.DomainHash("test/chain/miner")), document.Timestamp+1, 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
	tip, err := chain.Status()
	if err != nil {
		t.Fatal(err)
	}
	if tip.Height != 0 || len(tip.CumulativeWork) != 0 {
		t.Fatalf("canceled mining changed tip: %+v", tip)
	}
}

func TestSubmitAcceptsSideBranchAndReorganizesToMoreWork(t *testing.T) {
	t.Parallel()

	chain, document, store := chainFixture(t)
	defer store.Close()
	minerA := types.Address(types.DomainHash("test/chain/fork/miner-a"))
	minerB := types.Address(types.DomainHash("test/chain/fork/miner-b"))
	if _, err := chain.Mine(context.Background(), nil, minerA, document.Timestamp+1, 0); err != nil {
		t.Fatal(err)
	}
	canonicalA, err := chain.Mine(context.Background(), nil, minerA, document.Timestamp+2, 0)
	if err != nil {
		t.Fatal(err)
	}

	genesisTip, err := storage.GenesisTip(document)
	if err != nil {
		t.Fatal(err)
	}
	b1 := mineCandidateOn(t, store, document, genesisTip, minerB)
	canonical, err := chain.Submit(b1)
	if err != nil {
		t.Fatalf("side branch rejected: %v", err)
	}
	if canonical.ID != canonicalA.Tip.ID {
		t.Fatal("lower-work side branch replaced the canonical tip")
	}
	b1ID, err := b1.Header.ID()
	if err != nil {
		t.Fatal(err)
	}
	b1Node, err := store.TipByID(b1ID)
	if err != nil {
		t.Fatal(err)
	}
	b2 := mineCandidateOn(t, store, document, b1Node, minerB)
	if _, err := chain.Submit(b2); err != nil {
		t.Fatal(err)
	}
	b2ID, err := b2.Header.ID()
	if err != nil {
		t.Fatal(err)
	}
	b2Node, err := store.TipByID(b2ID)
	if err != nil {
		t.Fatal(err)
	}
	b3 := mineCandidateOn(t, store, document, b2Node, minerB)
	canonical, err = chain.Submit(b3)
	if err != nil {
		t.Fatal(err)
	}
	b3ID, err := b3.Header.ID()
	if err != nil {
		t.Fatal(err)
	}
	if canonical.ID != b3ID || canonical.Height != 3 {
		t.Fatalf("higher-work branch did not win: height=%d id=%s", canonical.Height, canonical.ID)
	}
	canonicalState, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if balance, err := canonicalState.Balance(minerB, types.NativeAssetID()); err != nil || balance != 75 {
		t.Fatalf("winning miner balance = %d, %v; want 75", balance, err)
	}
}

func mineCandidateOn(t testing.TB, store *reference.Store, document genesis.Document, parentTip storage.Tip, miner types.Address) block.Block {
	t.Helper()
	preState, err := store.SnapshotAt(parentTip.ID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := storage.ParentContext(store, parentTip)
	if err != nil {
		t.Fatal(err)
	}
	parameters := block.ParametersFromGenesis(document)
	candidate, _, err := block.Prepare(preState, parent, nil, miner, parentTip.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := block.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	return mined
}
