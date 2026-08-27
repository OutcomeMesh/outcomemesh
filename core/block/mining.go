package block

import (
	"context"

	"github.com/outcomemesh/outcomemesh/core/pow"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func Mine(ctx context.Context, candidate Block, startNonce uint64) (Block, types.Hash, error) {
	nonce, id, err := pow.Mine(ctx, candidate.Header.Target, startNonce, func(nonce uint64) (types.Hash, error) {
		header := candidate.Header
		header.Nonce = nonce
		return header.ID()
	})
	if err != nil {
		return Block{}, types.Hash{}, err
	}
	candidate.Header.Nonce = nonce
	return candidate, id, nil
}
