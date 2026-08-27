package chain

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

var ErrInvalidConfiguration = errors.New("invalid chain configuration")

type Chain struct {
	mu         sync.Mutex
	ledger     storage.Ledger
	parameters block.Parameters
	now        func() uint64
}

type MineResult struct {
	Block block.Block
	Tip   storage.Tip
	ID    types.Hash
}

func New(ledger storage.Ledger, parameters block.Parameters) (*Chain, error) {
	if ledger == nil || parameters.Validate() != nil {
		return nil, ErrInvalidConfiguration
	}
	return &Chain{
		ledger:     ledger,
		parameters: parameters,
		now:        func() uint64 { return uint64(time.Now().Unix()) },
	}, nil
}

func (chain *Chain) Status() (storage.Tip, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	return chain.ledger.Tip()
}

func (chain *Chain) Prepare(transactions []outcome.Transaction, miner types.Address, timestamp uint64) (block.Block, storage.Tip, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()

	tip, err := chain.ledger.Tip()
	if err != nil {
		return block.Block{}, storage.Tip{}, err
	}
	preState, err := chain.ledger.Snapshot()
	if err != nil {
		return block.Block{}, storage.Tip{}, err
	}
	if preState.Root() != tip.StateRoot {
		return block.Block{}, storage.Tip{}, storage.ErrStateRoot
	}
	parent, err := storage.ParentContext(chain.ledger, tip)
	if err != nil {
		return block.Block{}, storage.Tip{}, err
	}
	candidate, _, err := block.Prepare(preState, parent, transactions, miner, timestamp, chain.parameters)
	if err != nil {
		return block.Block{}, storage.Tip{}, err
	}
	return candidate, tip, nil
}

func (chain *Chain) Submit(candidate block.Block) (storage.Tip, error) {
	return chain.SubmitAt(candidate, chain.now())
}

// SubmitAt validates and commits with an explicit local admission time. It is
// used by version routers so every consensus version observes one time sample.
func (chain *Chain) SubmitAt(candidate block.Block, validationTime uint64) (storage.Tip, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()

	if err := candidate.ValidateBasic(); err != nil {
		return storage.Tip{}, err
	}
	parentTip, err := chain.ledger.TipByID(candidate.Header.Parent)
	if err != nil {
		return storage.Tip{}, err
	}
	preState, err := chain.ledger.SnapshotAt(parentTip.ID)
	if err != nil {
		return storage.Tip{}, err
	}
	parent, err := storage.ParentContext(chain.ledger, parentTip)
	if err != nil {
		return storage.Tip{}, err
	}
	executed, err := block.ValidateAndExecuteAt(preState, parent, candidate, chain.parameters, validationTime)
	if err != nil {
		return storage.Tip{}, err
	}
	return chain.ledger.Commit(parentTip, candidate, executed.State)
}

func (chain *Chain) Mine(ctx context.Context, transactions []outcome.Transaction, miner types.Address, timestamp, startNonce uint64) (MineResult, error) {
	candidate, preparedAt, err := chain.Prepare(transactions, miner, timestamp)
	if err != nil {
		return MineResult{}, err
	}
	mined, id, err := block.Mine(ctx, candidate, startNonce)
	if err != nil {
		return MineResult{}, err
	}

	current, err := chain.Status()
	if err != nil {
		return MineResult{}, err
	}
	if !storage.EqualTips(current, preparedAt) {
		return MineResult{}, fmt.Errorf("%w while mining", storage.ErrTipChanged)
	}
	next, err := chain.Submit(mined)
	if err != nil {
		return MineResult{}, err
	}
	return MineResult{Block: mined, Tip: next, ID: id}, nil
}
