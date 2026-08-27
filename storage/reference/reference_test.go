package reference

import (
	"context"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCommittedBlockIsDetachedFromCaller(t *testing.T) {
	t.Parallel()

	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    99,
		Timestamp:    1_700_000_000,
		Target:       target,
		BlockSubsidy: 10,
	}
	store, err := New(document)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tip, err := store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	miner := types.Address(types.DomainHash("test/reference/miner"))
	candidate, prepared, err := block.Prepare(state.Empty(), tip.Parent(), nil, miner, tip.Timestamp+1, block.ParametersFromGenesis(document))
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := block.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(tip, mined, prepared.State); err != nil {
		t.Fatal(err)
	}
	wantNonce := mined.Header.Nonce
	mined.Header.Nonce++
	loaded, err := store.Block(1)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Header.Nonce != wantNonce {
		t.Fatal("caller mutation changed the stored block")
	}
	loaded.Header.Nonce++
	reloaded, err := store.Block(1)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Header.Nonce != wantNonce {
		t.Fatal("returned block mutation changed the stored block")
	}
}
