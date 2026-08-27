package syncer

import (
	"context"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

type fixture struct {
	document genesis.Document
	store    *reference.Store
	chain    *chain.Chain
	sync     *Service
}

func TestDivergentNodesFindAncestorAndSyncHigherWorkBranch(t *testing.T) {
	t.Parallel()

	source := newFixture(t)
	defer source.store.Close()
	destination := newFixture(t)
	defer destination.store.Close()
	minerA := types.Address(types.DomainHash("test/sync/miner-a"))
	minerB := types.Address(types.DomainHash("test/sync/miner-b"))
	mineBlocks(t, source, minerA, 4)
	mineBlocks(t, destination, minerB, 2)

	remoteStatus, err := source.sync.Status()
	if err != nil {
		t.Fatal(err)
	}
	better, err := destination.sync.PeerIsBetter(remoteStatus)
	if err != nil || !better {
		t.Fatalf("higher-work peer not selected: better=%v err=%v", better, err)
	}
	locators, err := destination.sync.Locators()
	if err != nil {
		t.Fatal(err)
	}
	blocks, done, err := source.sync.BlocksAfter(wire.GetBlocks{
		Version:  wire.Version0,
		Locators: locators,
		Limit:    wire.MaxBlocksPerRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 4 || done.TipID != remoteStatus.TipID {
		t.Fatalf("unexpected batch: blocks=%d done=%s", len(blocks), done.TipID)
	}
	result, err := destination.sync.ApplyBlocks(blocks)
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != remoteStatus.TipID || result.Height != 4 {
		t.Fatalf("destination did not reorganize: height=%d id=%s", result.Height, result.ID)
	}
	for height := uint64(1); height <= result.Height; height++ {
		sourceBlock, _ := source.store.Block(height)
		destinationBlock, _ := destination.store.Block(height)
		if string(sourceBlock.CanonicalBytes()) != string(destinationBlock.CanonicalBytes()) {
			t.Fatalf("canonical block differs at height %d", height)
		}
	}
}

func TestBlockBatchLimitAndNoCommonAncestor(t *testing.T) {
	t.Parallel()

	value := newFixture(t)
	defer value.store.Close()
	mineBlocks(t, value, types.Address(types.DomainHash("test/sync/miner")), 3)
	genesisID, _ := value.document.ID()
	blocks, _, err := value.sync.BlocksAfter(wire.GetBlocks{
		Version:  wire.Version0,
		Locators: []types.Hash{genesisID},
		Limit:    2,
	})
	if err != nil || len(blocks) != 2 {
		t.Fatalf("bounded batch = %d, %v", len(blocks), err)
	}
	_, _, err = value.sync.BlocksAfter(wire.GetBlocks{
		Version:  wire.Version0,
		Locators: []types.Hash{types.DomainHash("test/sync/unknown")},
		Limit:    1,
	})
	if !errors.Is(err, ErrNoCommonAncestor) {
		t.Fatalf("got %v, want no common ancestor", err)
	}
}

func TestHeaderBatchIsBoundedAndContextValidatedBeforeBodies(t *testing.T) {
	t.Parallel()

	source := newFixture(t)
	defer source.store.Close()
	destination := newFixture(t)
	defer destination.store.Close()
	mineBlocks(t, source, types.Address(types.DomainHash("test/sync/header-miner")), 12)
	genesisID, _ := source.document.ID()
	request := wire.GetHeaders{
		Version:  wire.Version0,
		Locators: []types.Hash{genesisID},
		Limit:    5,
	}
	response, err := source.sync.HeadersAfter(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Values) != 5 {
		t.Fatalf("header count = %d, want 5", len(response.Values))
	}
	validationTime := response.Values[len(response.Values)-1].Timestamp
	if err := destination.sync.ValidateHeaders(request, response, validationTime); err != nil {
		t.Fatalf("valid header batch rejected: %v", err)
	}

	invalid := response
	invalid.Values = append([]block.Header(nil), response.Values[:1]...)
	invalid.Values[0].Timestamp = source.document.Timestamp
	if err := destination.sync.ValidateHeaders(request, invalid, validationTime); !errors.Is(err, block.ErrMedianTimePast) {
		t.Fatalf("invalid header context error = %v", err)
	}

	wrongAnchor := response
	wrongAnchor.Values = append([]block.Header(nil), response.Values[:1]...)
	wrongAnchor.Values[0].Parent = types.DomainHash("test/sync/unrequested-header-parent")
	if err := destination.sync.ValidateHeaders(request, wrongAnchor, validationTime); !errors.Is(err, ErrBatch) {
		t.Fatalf("unrequested header anchor error = %v", err)
	}
}

func TestRejectsNetworkAndGenesisMismatch(t *testing.T) {
	t.Parallel()

	value := newFixture(t)
	defer value.store.Close()
	status, _ := value.sync.Status()
	status.NetworkID++
	if err := value.sync.ValidatePeer(status); !errors.Is(err, ErrNetwork) {
		t.Fatalf("network mismatch error = %v", err)
	}
	status.NetworkID--
	status.GenesisID = types.DomainHash("test/sync/other-genesis")
	if err := value.sync.ValidatePeer(status); !errors.Is(err, ErrGenesis) {
		t.Fatalf("genesis mismatch error = %v", err)
	}
}

func TestLocatorsEndAtGenesisAndContainNoDuplicates(t *testing.T) {
	t.Parallel()

	value := newFixture(t)
	defer value.store.Close()
	mineBlocks(t, value, types.Address(types.DomainHash("test/sync/locator-miner")), 40)
	locators, err := value.sync.Locators()
	if err != nil {
		t.Fatal(err)
	}
	genesisID, _ := value.document.ID()
	if len(locators) > wire.MaxLocators || locators[len(locators)-1] != genesisID {
		t.Fatalf("invalid locator tail/count: %d", len(locators))
	}
	seen := make(map[types.Hash]struct{}, len(locators))
	for _, locator := range locators {
		if _, exists := seen[locator]; exists {
			t.Fatal("locator list contains duplicate IDs")
		}
		seen[locator] = struct{}{}
	}
}

func TestReorderedBatchFailsClosedAndDuplicateBatchIsIdempotent(t *testing.T) {
	t.Parallel()

	source := newFixture(t)
	defer source.store.Close()
	destination := newFixture(t)
	defer destination.store.Close()
	mineBlocks(t, source, types.Address(types.DomainHash("test/sync/order-miner")), 3)
	genesisID, _ := source.document.ID()
	blocks, _, err := source.sync.BlocksAfter(wire.GetBlocks{
		Version:  wire.Version0,
		Locators: []types.Hash{genesisID},
		Limit:    3,
	})
	if err != nil {
		t.Fatal(err)
	}
	reordered := append([]block.Block(nil), blocks...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := destination.sync.ApplyBlocks(reordered); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("reordered batch error = %v", err)
	}
	unchanged, _ := destination.store.Tip()
	if unchanged.Height != 0 {
		t.Fatal("reordered batch partially advanced the chain")
	}
	want, err := destination.sync.ApplyBlocks(blocks)
	if err != nil {
		t.Fatal(err)
	}
	got, err := destination.sync.ApplyBlocks(blocks)
	if err != nil {
		t.Fatalf("duplicate delivery failed: %v", err)
	}
	if !storage.EqualTips(got, want) {
		t.Fatal("duplicate delivery changed canonical tip")
	}
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    505,
		Timestamp:    1_700_500_000,
		Target:       target,
		BlockSubsidy: 10,
	}
	store, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	chainService, err := chain.New(store, block.ParametersFromGenesis(document))
	if err != nil {
		t.Fatal(err)
	}
	syncService, err := New(store, chainService, document)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{document: document, store: store, chain: chainService, sync: syncService}
}

func mineBlocks(t testing.TB, value fixture, miner types.Address, count uint64) {
	t.Helper()
	for range count {
		tip, err := value.chain.Status()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := value.chain.Mine(context.Background(), nil, miner, tip.Timestamp+1, 0); err != nil {
			t.Fatal(err)
		}
	}
}

var _ storage.Ledger = (*reference.Store)(nil)
