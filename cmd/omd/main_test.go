package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestStoragePolicyRoundTripControlsLedgerHistoryBudget(t *testing.T) {
	directory := t.TempDir()
	limit := uint64(128 << 20)
	if err := writeStoragePolicy(directory, limit); err != nil {
		t.Fatal(err)
	}
	document := commandTestGenesis()
	store, err := openStore(directory, document)
	if err != nil {
		t.Fatal(err)
	}
	usage, loadedLimit, err := store.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	if usage == 0 || loadedLimit != limit {
		t.Fatalf("history usage=%d limit=%d, want nonzero/%d", usage, loadedLimit, limit)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeStoragePolicy(directory, limit); err == nil {
		t.Fatal("storage policy replacement unexpectedly overwrote initialized policy")
	}
}

func TestOpenStoreRejectsMalformedStoragePolicy(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, storagePolicyFilename), []byte("bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(directory, commandTestGenesis()); err == nil {
		t.Fatal("malformed storage policy was accepted")
	}
}

func commandTestGenesis() genesis.Document {
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	owner := types.Address(types.DomainHash("test/cmd/owner"))
	return genesis.Document{
		Version: 0, NetworkID: 99, Timestamp: 1_700_000_000, Target: target, BlockSubsidy: 50,
		Allocations: []resource.Resource{{
			ID: types.ResourceID(types.DomainHash("test/cmd/allocation")), Version: resource.Version0,
			Owner: owner, Asset: types.NativeAssetID(), Amount: 1_000,
		}},
	}
}
