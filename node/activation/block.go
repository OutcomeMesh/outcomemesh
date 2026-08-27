package activation

import (
	"encoding/binary"
	"errors"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
)

var (
	ErrBoundary = errors.New("block version is invalid at activation boundary")
	ErrEncoding = errors.New("invalid routed block encoding")
)

// Block is a strict tagged union. Its canonical bytes are the unchanged
// version-specific consensus encoding; the leading uint16 selects the decoder.
type Block struct {
	version uint16
	legacy  legacyblock.Block
	work    workblock.Block
}

func Legacy(candidate legacyblock.Block, activationHeight uint64) (Block, error) {
	result := Block{version: legacyblock.Version0, legacy: candidate}
	if err := result.Validate(activationHeight); err != nil {
		return Block{}, err
	}
	cloned, err := legacyblock.Decode(candidate.CanonicalBytes())
	if err != nil {
		return Block{}, err
	}
	result.legacy = cloned
	return result, nil
}

func Work(candidate workblock.Block, activationHeight uint64) (Block, error) {
	result := Block{version: workblock.Version1, work: candidate}
	if err := result.Validate(activationHeight); err != nil {
		return Block{}, err
	}
	cloned, err := workblock.Decode(candidate.CanonicalBytes())
	if err != nil {
		return Block{}, err
	}
	result.work = cloned
	return result, nil
}

// Decode dispatches only from the canonical leading version and immediately
// applies the configured activation-height rule.
func Decode(input []byte, activationHeight uint64) (Block, error) {
	if len(input) < 2 || len(input) > workblock.MaxCanonicalBytes {
		return Block{}, ErrEncoding
	}
	switch binary.BigEndian.Uint16(input[:2]) {
	case legacyblock.Version0:
		candidate, err := legacyblock.Decode(input)
		if err != nil {
			return Block{}, err
		}
		return Legacy(candidate, activationHeight)
	case workblock.Version1:
		candidate, err := workblock.Decode(input)
		if err != nil {
			return Block{}, err
		}
		return Work(candidate, activationHeight)
	default:
		return Block{}, ErrEncoding
	}
}

func (candidate Block) Validate(activationHeight uint64) error {
	if activationHeight == 0 {
		return ErrBoundary
	}
	switch candidate.version {
	case legacyblock.Version0:
		if err := candidate.legacy.ValidateBasic(); err != nil {
			return err
		}
		if candidate.legacy.Header.Height >= activationHeight {
			return ErrBoundary
		}
	case workblock.Version1:
		if err := candidate.work.ValidateBasic(); err != nil {
			return err
		}
		if candidate.work.Header.Seal.Height < activationHeight {
			return ErrBoundary
		}
	default:
		return ErrEncoding
	}
	return nil
}

func (candidate Block) Version() uint16 { return candidate.version }

func (candidate Block) Height() uint64 {
	if candidate.version == legacyblock.Version0 {
		return candidate.legacy.Header.Height
	}
	return candidate.work.Header.Seal.Height
}

func (candidate Block) ParentID() types.Hash {
	if candidate.version == legacyblock.Version0 {
		return candidate.legacy.Header.Parent
	}
	return candidate.work.Header.Seal.AnchorParent
}

func (candidate Block) ID() (types.Hash, error) {
	if candidate.version == legacyblock.Version0 {
		return candidate.legacy.Header.ID()
	}
	if candidate.version == workblock.Version1 {
		return candidate.work.Header.ID()
	}
	return types.Hash{}, ErrEncoding
}

func (candidate Block) CanonicalBytes() []byte {
	if candidate.version == legacyblock.Version0 {
		return candidate.legacy.CanonicalBytes()
	}
	if candidate.version == workblock.Version1 {
		return candidate.work.CanonicalBytes()
	}
	return nil
}

func (candidate Block) LegacyBlock() (legacyblock.Block, bool) {
	if candidate.version != legacyblock.Version0 {
		return legacyblock.Block{}, false
	}
	cloned, err := legacyblock.Decode(candidate.legacy.CanonicalBytes())
	return cloned, err == nil
}

func (candidate Block) WorkBlock() (workblock.Block, bool) {
	if candidate.version != workblock.Version1 {
		return workblock.Block{}, false
	}
	cloned, err := workblock.Decode(candidate.work.CanonicalBytes())
	return cloned, err == nil
}
