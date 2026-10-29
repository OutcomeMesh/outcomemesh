package storage

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/pow"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	SchemaVersion      uint16 = 3
	MaxWorkBytes              = 64
	MaxStoredBlockSize        = block.MaxCanonicalBytes
)

var (
	ErrTipChanged      = errors.New("ledger tip changed")
	ErrStateRoot       = errors.New("stored state root mismatch")
	ErrGenesisMismatch = errors.New("genesis document mismatch")
	ErrCorrupt         = errors.New("ledger storage is corrupt")
	ErrBlockNotFound   = errors.New("stored block not found")
	ErrNodeNotFound    = errors.New("stored chain node not found")
	ErrBlockExists     = errors.New("block is already stored")
	ErrHistoryLimit    = errors.New("ledger history budget reached")
	ErrClosed          = errors.New("ledger storage is closed")
	ErrWorkEncoding    = errors.New("invalid cumulative-work encoding")
)

type Tip struct {
	ID             types.Hash
	Height         uint64
	Timestamp      uint64
	Target         types.Hash
	StateRoot      types.Hash
	CumulativeWork []byte
}

type Ledger interface {
	Tip() (Tip, error)
	Snapshot() (*state.Memory, error)
	TipByID(id types.Hash) (Tip, error)
	SnapshotAt(id types.Hash) (*state.Memory, error)
	Block(height uint64) (block.Block, error)
	BlockByID(id types.Hash) (block.Block, error)
	Commit(parent Tip, candidate block.Block, postState *state.Memory) (Tip, error)
	Close() error
}

func GenesisTip(document genesis.Document) (Tip, error) {
	id, err := document.ID()
	if err != nil {
		return Tip{}, err
	}
	root, err := document.StateRoot()
	if err != nil {
		return Tip{}, err
	}
	return Tip{
		ID:        id,
		Timestamp: document.Timestamp,
		Target:    document.Target,
		StateRoot: root,
	}, nil
}

func NextTip(previous Tip, candidate block.Block) (Tip, error) {
	if candidate.Header.Parent != previous.ID || candidate.Header.Height != previous.Height+1 {
		return Tip{}, ErrTipChanged
	}
	id, err := candidate.Header.ID()
	if err != nil {
		return Tip{}, err
	}
	blockWork, err := pow.Work(candidate.Header.Target)
	if err != nil {
		return Tip{}, err
	}
	cumulative := new(big.Int).SetBytes(previous.CumulativeWork)
	cumulative.Add(cumulative, blockWork)
	encodedWork := cumulative.Bytes()
	if len(encodedWork) > MaxWorkBytes {
		return Tip{}, ErrWorkEncoding
	}
	return Tip{
		ID:             id,
		Height:         candidate.Header.Height,
		Timestamp:      candidate.Header.Timestamp,
		Target:         candidate.Header.Target,
		StateRoot:      candidate.Header.StateRoot,
		CumulativeWork: encodedWork,
	}, nil
}

// BetterTip implements version-0 fork choice. More cumulative proof of work
// wins. Equal-work tips are resolved by the lexicographically smaller block ID
// so every implementation makes the same choice.
func BetterTip(candidate, current Tip) bool {
	workOrder := CompareWork(candidate, current)
	if workOrder != 0 {
		return workOrder > 0
	}
	return bytes.Compare(candidate.ID[:], current.ID[:]) < 0
}

// CompareWork compares cumulative proof of work without imposing an
// equal-work block-ID policy. Versioned fork-choice implementations use this
// to keep an already selected incumbent on an exact tie, preventing a late
// publisher from grinding a globally winning identifier.
func CompareWork(left, right Tip) int {
	return new(big.Int).SetBytes(left.CumulativeWork).Cmp(new(big.Int).SetBytes(right.CumulativeWork))
}

// MoreWork reports whether candidate has strictly greater cumulative proof of
// work. Exact ties return false regardless of either tip ID.
func MoreWork(candidate, current Tip) bool {
	return CompareWork(candidate, current) > 0
}

func (tip Tip) Parent() block.Parent {
	return block.Parent{
		ID:             tip.ID,
		Height:         tip.Height,
		Timestamp:      tip.Timestamp,
		MedianTimePast: tip.Timestamp,
		Target:         tip.Target,
	}
}

// ParentContext returns the direct parent together with the median timestamp of
// up to the last 11 mined blocks. At genesis, the genesis timestamp is used.
func ParentContext(ledger Ledger, tip Tip) (block.Parent, error) {
	parent := tip.Parent()
	if tip.Height == 0 {
		return parent, nil
	}

	timestamps := make([]uint64, 0, 11)
	cursor := tip.ID
	for height := tip.Height; height > 0 && len(timestamps) < 11; height-- {
		candidate, err := ledger.BlockByID(cursor)
		if err != nil {
			return block.Parent{}, err
		}
		id, err := candidate.Header.ID()
		if err != nil {
			return block.Parent{}, err
		}
		if id != cursor || candidate.Header.Height != height {
			return block.Parent{}, ErrCorrupt
		}
		timestamps = append(timestamps, candidate.Header.Timestamp)
		cursor = candidate.Header.Parent
	}
	sort.Slice(timestamps, func(left, right int) bool { return timestamps[left] < timestamps[right] })
	parent.MedianTimePast = timestamps[len(timestamps)/2]
	return parent, nil
}

func (tip Tip) Validate() error {
	if tip.ID.IsZero() || tip.Timestamp == 0 || tip.Target.IsZero() || tip.StateRoot.IsZero() {
		return ErrCorrupt
	}
	if len(tip.CumulativeWork) > MaxWorkBytes || (len(tip.CumulativeWork) > 0 && tip.CumulativeWork[0] == 0) {
		return ErrWorkEncoding
	}
	if tip.Height > 0 && len(tip.CumulativeWork) == 0 {
		return ErrWorkEncoding
	}
	return nil
}

func (tip Tip) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(140)
	encoder.Fixed(tip.ID[:])
	encoder.U64(tip.Height)
	encoder.U64(tip.Timestamp)
	encoder.Fixed(tip.Target[:])
	encoder.Fixed(tip.StateRoot[:])
	encoder.BytesField(tip.CumulativeWork)
	return encoder.Bytes()
}

func DecodeTip(input []byte) (Tip, error) {
	decoder := codec.NewDecoder(input)
	var tip Tip
	id, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Tip{}, err
	}
	copy(tip.ID[:], id)
	tip.Height, err = decoder.U64()
	if err != nil {
		return Tip{}, err
	}
	tip.Timestamp, err = decoder.U64()
	if err != nil {
		return Tip{}, err
	}
	target, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Tip{}, err
	}
	copy(tip.Target[:], target)
	root, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Tip{}, err
	}
	copy(tip.StateRoot[:], root)
	tip.CumulativeWork, err = decoder.BytesField(MaxWorkBytes)
	if err != nil {
		return Tip{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Tip{}, err
	}
	if err := tip.Validate(); err != nil {
		return Tip{}, err
	}
	return tip, nil
}

func EqualTips(left, right Tip) bool {
	return bytes.Equal(left.CanonicalBytes(), right.CanonicalBytes())
}

func ValidateCommit(expected, current Tip, candidate block.Block, postState *state.Memory) (Tip, error) {
	if !EqualTips(expected, current) {
		return Tip{}, ErrTipChanged
	}
	return ValidateChild(current, candidate, postState)
}

// ValidateChild validates a block against any known parent node. Storage uses
// this before atomically adding a side branch or changing the canonical tip.
func ValidateChild(parent Tip, candidate block.Block, postState *state.Memory) (Tip, error) {
	if postState == nil {
		return Tip{}, fmt.Errorf("%w: nil post-state", ErrStateRoot)
	}
	if err := candidate.ValidateBasic(); err != nil {
		return Tip{}, err
	}
	if err := ValidateProtocol(candidate.Header.Version, candidate, postState); err != nil {
		return Tip{}, err
	}
	if candidate.Header.StateRoot != postState.Root() {
		return Tip{}, fmt.Errorf("%w: header %s state %s", ErrStateRoot, candidate.Header.StateRoot, postState.Root())
	}
	return NextTip(parent, candidate)
}

// ValidateProtocol binds direct store commits to the original genesis version.
func ValidateProtocol(version uint16, candidate block.Block, postState *state.Memory) error {
	p := block.Parameters{ProtocolVersion: version}
	if (version != block.Version0 && version != block.Version2) || candidate.Header.Version != version {
		return block.ErrUnsupportedVersion
	}
	if postState == nil || postState.CommitmentVersion() != p.StateCommitment() {
		return state.ErrCommitmentVersion
	}
	return nil
}
