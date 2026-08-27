package activation

import (
	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/chainblock"
	"github.com/outcomemesh/outcomemesh/core/workblock"
)

var (
	ErrBoundary = chainblock.ErrBoundary
	ErrEncoding = chainblock.ErrEncoding
)

type Block = chainblock.Block

func Legacy(candidate legacyblock.Block, activationHeight uint64) (Block, error) {
	result, err := chainblock.Legacy(candidate)
	if err != nil {
		return Block{}, err
	}
	if err := result.Validate(activationHeight); err != nil {
		return Block{}, err
	}
	return result, nil
}

func Work(candidate workblock.Block, activationHeight uint64) (Block, error) {
	result, err := chainblock.Work(candidate)
	if err != nil {
		return Block{}, err
	}
	if err := result.Validate(activationHeight); err != nil {
		return Block{}, err
	}
	return result, nil
}

func Decode(input []byte, activationHeight uint64) (Block, error) {
	return chainblock.Decode(input, activationHeight)
}
