package pow

import (
	"context"
	"errors"
	"math/big"

	"github.com/outcomemesh/outcomemesh/core/types"
)

var ErrInvalidTarget = errors.New("proof-of-work target is zero")

func MeetsTarget(hash, target types.Hash) bool {
	return !target.IsZero() && types.CompareHash(hash, target) <= 0
}

func Work(target types.Hash) (*big.Int, error) {
	if target.IsZero() {
		return nil, ErrInvalidTarget
	}
	targetInteger := new(big.Int).SetBytes(target[:])
	denominator := new(big.Int).Add(targetInteger, big.NewInt(1))
	numerator := new(big.Int).Lsh(big.NewInt(1), 256)
	return numerator.Div(numerator, denominator), nil
}

// Mine searches nonces sequentially and returns the first hash meeting target.
// The caller owns the header encoding through hashNonce, keeping this package
// independent from any particular block version.
func Mine(ctx context.Context, target types.Hash, start uint64, hashNonce func(uint64) (types.Hash, error)) (uint64, types.Hash, error) {
	if target.IsZero() {
		return 0, types.Hash{}, ErrInvalidTarget
	}
	for nonce := start; ; nonce++ {
		if err := ctx.Err(); err != nil {
			return 0, types.Hash{}, err
		}
		hash, err := hashNonce(nonce)
		if err != nil {
			return 0, types.Hash{}, err
		}
		if MeetsTarget(hash, target) {
			return nonce, hash, nil
		}
		if nonce == ^uint64(0) {
			return 0, types.Hash{}, errors.New("proof-of-work nonce space exhausted")
		}
	}
}
