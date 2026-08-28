package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func TestWorkActivationProfileRoundTripAndPendingRecovery(t *testing.T) {
	directory := t.TempDir()
	document := commandTestGenesis()
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	profile := workActivationProfile{
		NetworkID: document.NetworkID, GenesisID: genesisID, ActivationHeight: 7,
		FeeDelay: 3, MaxTrees: 4, MaxHistoryBytes: minimumHistoryBytes,
	}
	encoded := profile.canonicalBytes()
	decoded, err := decodeWorkActivation(encoded)
	if err != nil || decoded != profile || len(encoded) != workActivationSize {
		t.Fatalf("activation profile roundtrip=%+v err=%v", decoded, err)
	}
	for _, malformed := range [][]byte{nil, encoded[:len(encoded)-1], append([]byte{1}, encoded[1:]...)} {
		if _, err := decodeWorkActivation(malformed); err == nil {
			t.Fatal("malformed WorkGraph activation profile was accepted")
		}
	}
	if err := os.WriteFile(filepath.Join(directory, workActivationPending), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkActivation(directory, profile); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadWorkActivation(directory, document)
	if err != nil || loaded != profile {
		t.Fatalf("loaded activation profile=%+v err=%v", loaded, err)
	}
	if err := writeWorkActivation(directory, profile); err == nil {
		t.Fatal("activation profile replacement was accepted")
	}
	if err := rejectWorkActivation(directory, "mine"); err == nil || !strings.Contains(err.Error(), "work-*") {
		t.Fatalf("legacy mutation guard error=%v", err)
	}
	if _, store, _, err := openNode([]string{"--data", directory}, "status"); err == nil || store != nil || !strings.Contains(err.Error(), "work-*") {
		t.Fatalf("legacy open bypassed activation marker: store=%v err=%v", store, err)
	}
	foreign := document
	foreign.NetworkID++
	if _, err := loadWorkActivation(directory, foreign); err == nil {
		t.Fatal("activation profile was accepted for another genesis")
	}
}

func TestExplicitWorkCommandsCrossActivationAndBlockLegacyMutation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "node")
	if err := runInit([]string{
		"--data", directory, "--network", "1001", "--timestamp", "1700000000",
		"--difficulty-bits", "12", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	}); err != nil {
		t.Fatal(err)
	}
	document, err := loadGenesis(directory)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, _ := document.ID()
	if err := runWorkEnable([]string{
		"--data", directory, "--activation-height", "2", "--confirm-genesis", genesisID.String(),
		"--max-trees", "4", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	}); err != nil {
		t.Fatal(err)
	}
	if err := runMine([]string{"--data", directory, "--count", "1"}); err == nil {
		t.Fatal("legacy miner mutated a WorkGraph-enabled directory")
	}
	if err := runWorkMine([]string{"--data", directory, "--count", "3"}); err != nil {
		t.Fatal(err)
	}
	if err := runWorkVerify([]string{"--data", directory}); err != nil {
		t.Fatal(err)
	}
	if err := runWorkBalance([]string{"--data", directory}); err != nil {
		t.Fatal(err)
	}
	_, store, router, profile, err := openWorkNode(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	defer router.Close()
	tip, err := router.Tip()
	if err != nil || tip.Height != 3 || profile.ActivationHeight != 2 {
		t.Fatalf("experimental tip=%+v profile=%+v err=%v", tip, profile, err)
	}
	candidate, err := router.BlockByID(tip.ID)
	if err != nil || candidate.Version() != 1 {
		t.Fatalf("experimental tip version=%d err=%v", candidate.Version(), err)
	}
}

func TestWorkEnableRejectsInexactGenesisTarget(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "node")
	if err := runInit([]string{
		"--data", directory, "--network", "1002", "--timestamp", "1700000000",
		"--difficulty-bits", "8", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	}); err != nil {
		t.Fatal(err)
	}
	document, _ := loadGenesis(directory)
	genesisID, _ := document.ID()
	err := runWorkEnable([]string{
		"--data", directory, "--activation-height", "2", "--confirm-genesis", genesisID.String(),
	})
	if err == nil || !strings.Contains(err.Error(), "512:1") {
		t.Fatalf("inexact target activation error=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(directory, workActivationFilename)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed activation left a profile: %v", statErr)
	}
}

func TestWorkMiningRoundControlCancelsOnlyChangedParent(t *testing.T) {
	control := new(workMiningRoundControl)
	parentA := types.DomainHash("test/omd/round-parent-a")
	parentB := types.DomainHash("test/omd/round-parent-b")
	ctx, _, finish := control.Begin(context.Background(), workgraph.Context{AnchorParent: parentA})
	control.Advance(parentA)
	if err := ctx.Err(); err != nil {
		t.Fatalf("unchanged parent canceled round: %v", err)
	}
	control.Advance(parentB)
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("changed parent did not cancel round: %v", ctx.Err())
	}
	_ = finish()
	second, _, finishSecond := control.Begin(context.Background(), workgraph.Context{AnchorParent: parentB})
	_ = finish()
	if err := second.Err(); err != nil {
		t.Fatalf("old generation finish canceled new round: %v", err)
	}
	_ = finishSecond()
}

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
