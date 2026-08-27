package workminer

import (
	"context"
	"errors"
	"math"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workpool"
)

var (
	ErrConfiguration = errors.New("invalid WorkGraph miner configuration")
	ErrNonceSpace    = errors.New("WorkGraph miner exhausted nonce space")
)

type PublishFunc func(workgraph.Share) error

type Result struct {
	Block              workblock.Block
	Execution          workblock.Result
	WeakShares         uint64
	CapacityRejections uint64
	WinningNonce       uint64
}

type Miner struct {
	payload       *workblock.Payload
	pool          *workpool.Pool
	miner         types.Address
	inclusionRoot types.Hash
	publish       PublishFunc
}

func New(
	payload *workblock.Payload,
	pool *workpool.Pool,
	miner types.Address,
	inclusionRoot types.Hash,
	publish PublishFunc,
) (*Miner, error) {
	if payload == nil || pool == nil || miner.IsZero() || inclusionRoot.IsZero() {
		return nil, ErrConfiguration
	}
	template, err := payload.SealTemplate(miner, inclusionRoot, pool.Parents())
	if err != nil {
		return nil, ErrConfiguration
	}
	validation := pool.Context()
	if template.NetworkID != validation.NetworkID || template.Height != validation.Height ||
		template.AnchorParent != validation.AnchorParent || template.Target != validation.AnchorTarget ||
		template.PayloadRoot != validation.PayloadRoot || template.Timestamp != validation.AnchorTimestamp {
		return nil, ErrConfiguration
	}
	return &Miner{
		payload: payload, pool: pool, miner: miner, inclusionRoot: inclusionRoot, publish: publish,
	}, nil
}

// Mine uses exactly one WorkSeal nonce space. A hard result is finalized before
// ordinary pool admission, so it cannot also become a rewarded weak share.
func (miner *Miner) Mine(ctx context.Context, start uint64) (Result, error) {
	if miner == nil || ctx == nil {
		return Result{}, ErrConfiguration
	}
	result := Result{}
	next := start
	for {
		template, err := miner.payload.SealTemplate(
			miner.miner, miner.inclusionRoot, miner.pool.Parents(),
		)
		if err != nil {
			return Result{}, err
		}
		share, _, err := workgraph.Mine(ctx, template, next)
		if err != nil {
			return Result{}, err
		}
		hard, err := workgraph.MeetsAnchor(share)
		if err != nil {
			return Result{}, err
		}
		if hard {
			committed, err := miner.pool.CommittedShares(share)
			if err != nil {
				return Result{}, err
			}
			block, execution, err := miner.payload.Finalize(share, committed)
			if err != nil {
				return Result{}, err
			}
			result.Block = block
			result.Execution = execution
			result.WinningNonce = share.Nonce
			return result, nil
		}
		if _, err := miner.pool.Add(share); err != nil {
			if !errors.Is(err, workpool.ErrCapacity) {
				return Result{}, err
			}
			result.CapacityRejections++
			if share.Nonce == math.MaxUint64 {
				return Result{}, ErrNonceSpace
			}
			next = share.Nonce + 1
			continue
		}
		result.WeakShares++
		if miner.publish != nil {
			published := share
			published.Parents = append([]types.Hash(nil), share.Parents...)
			if err := miner.publish(published); err != nil {
				return Result{}, err
			}
		}
		// Admission makes this share a new accepted tip, changing the work
		// preimage. The nonce range can therefore restart without repetition.
		next = 0
	}
}
