package storage

import (
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func FuzzDecodeTipNeverPanics(f *testing.F) {
	tip := Tip{
		ID:             types.DomainHash("test/storage/tip"),
		Height:         1,
		Timestamp:      1_700_000_001,
		Target:         types.DomainHash("test/storage/target"),
		StateRoot:      types.DomainHash("test/storage/root"),
		CumulativeWork: []byte{1},
	}
	f.Add(tip.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeTip(input)
	})
}

func TestBetterTipUsesWorkThenDeterministicIDTieBreak(t *testing.T) {
	t.Parallel()

	current := Tip{ID: types.Hash{0xff}, CumulativeWork: []byte{9}}
	moreWork := Tip{ID: types.Hash{0xff}, CumulativeWork: []byte{10}}
	if !BetterTip(moreWork, current) || BetterTip(current, moreWork) {
		t.Fatal("fork choice did not prioritize cumulative work")
	}
	smallerID := Tip{ID: types.Hash{0x01}, CumulativeWork: []byte{10}}
	largerID := Tip{ID: types.Hash{0x02}, CumulativeWork: []byte{10}}
	if !BetterTip(smallerID, largerID) || BetterTip(largerID, smallerID) {
		t.Fatal("equal-work fork choice did not prefer smaller tip ID")
	}
	if MoreWork(smallerID, largerID) || MoreWork(largerID, smallerID) ||
		CompareWork(smallerID, largerID) != 0 {
		t.Fatal("work-only comparison changed an exact tie")
	}
}

type timestampLedger struct {
	blocks map[types.Hash]block.Block
}

func (ledger timestampLedger) Tip() (Tip, error) { return Tip{}, errors.New("unused") }
func (ledger timestampLedger) Snapshot() (*state.Memory, error) {
	return nil, errors.New("unused")
}
func (ledger timestampLedger) TipByID(types.Hash) (Tip, error) {
	return Tip{}, errors.New("unused")
}
func (ledger timestampLedger) SnapshotAt(types.Hash) (*state.Memory, error) {
	return nil, errors.New("unused")
}
func (ledger timestampLedger) Block(height uint64) (block.Block, error) {
	for _, value := range ledger.blocks {
		if value.Header.Height == height {
			return value, nil
		}
	}
	return block.Block{}, ErrBlockNotFound
}
func (ledger timestampLedger) BlockByID(id types.Hash) (block.Block, error) {
	value, exists := ledger.blocks[id]
	if !exists {
		return block.Block{}, ErrBlockNotFound
	}
	return value, nil
}
func (ledger timestampLedger) Commit(Tip, block.Block, *state.Memory) (Tip, error) {
	return Tip{}, errors.New("unused")
}
func (ledger timestampLedger) Close() error { return nil }

func TestParentContextComputesMedianOfLastElevenBlocks(t *testing.T) {
	t.Parallel()

	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	miner := types.Address(types.DomainHash("test/storage/median-miner"))
	ledger := timestampLedger{blocks: make(map[types.Hash]block.Block)}
	var tip Tip
	var parentID types.Hash
	for height := uint64(1); height <= 11; height++ {
		header := block.Header{
			Version:   block.Version0,
			NetworkID: 1,
			Height:    height,
			Parent:    parentID,
			Timestamp: height * 100,
			Target:    target,
			Miner:     miner,
		}
		id, err := header.ID()
		if err != nil {
			t.Fatal(err)
		}
		ledger.blocks[id] = block.Block{Header: header}
		parentID = id
		if height == 11 {
			tip = Tip{ID: id, Height: height, Timestamp: header.Timestamp, Target: target}
		}
	}
	parent, err := ParentContext(ledger, tip)
	if err != nil {
		t.Fatal(err)
	}
	if parent.MedianTimePast != 600 {
		t.Fatalf("median time past = %d, want 600", parent.MedianTimePast)
	}
}
