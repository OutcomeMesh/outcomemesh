package pow

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestWorkAtMaximumTargetIsOne(t *testing.T) {
	t.Parallel()

	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	work, err := Work(target)
	if err != nil {
		t.Fatal(err)
	}
	if work.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("work = %s, want 1", work)
	}
}

func TestMineFindsDeterministicNonce(t *testing.T) {
	t.Parallel()

	var target types.Hash
	target[31] = 5
	nonce, hash, err := Mine(context.Background(), target, 0, func(nonce uint64) (types.Hash, error) {
		var value types.Hash
		value[31] = byte(10 - nonce)
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if nonce != 5 || hash[31] != 5 {
		t.Fatalf("got nonce %d hash %s", nonce, hash)
	}
}

func TestRejectsZeroTargetAndCancellation(t *testing.T) {
	t.Parallel()

	if _, err := Work(types.Hash{}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("got %v, want invalid target", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var target types.Hash
	target[0] = 1
	if _, _, err := Mine(ctx, target, 0, func(uint64) (types.Hash, error) { return types.Hash{}, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}
