// Package workblock prototypes the versioned WorkGraph anchor transition
// without changing the active version-0 block, storage, or wire formats.
package workblock

import (
	"errors"
	"fmt"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/difficulty"
	"github.com/outcomemesh/outcomemesh/core/execution"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

const Version1 uint16 = 1

var (
	ErrParameters = errors.New("invalid work block parameters")
	ErrPosition   = errors.New("invalid work block position")
	ErrPrevious   = errors.New("invalid previous WorkGraph earning")
	ErrRoot       = errors.New("work block commitment mismatch")
	ErrReward     = errors.New("work block delayed reward failed")
	ErrFutureTime = errors.New("work block timestamp exceeds allowed future drift")
)

type Parameters struct {
	NetworkID                 uint32
	BlockSubsidy              uint64
	RewardMaturity            uint64
	ActivationHeight          uint64
	DifficultyAnchorTimestamp uint64
	DifficultyAnchorTarget    types.Hash
	TargetSpacing             uint64
	ASERTHalfLife             uint64
	FeeDelay                  uint16
}

type Position struct {
	Height          uint64
	ParentID        types.Hash
	ParentTimestamp uint64
	MedianTimePast  uint64
	Timestamp       uint64
	Target          types.Hash
	FeeQueue        *workgraph.FeeQueue
}

type Header struct {
	Version          uint16
	Seal             workgraph.Share
	TxRoot           types.Hash
	ReceiptRoot      types.Hash
	StateRoot        types.Hash
	PreviousWorkRoot types.Hash
	FeeQueueRoot     types.Hash
	FeeAward         uint64
}

type Block struct {
	Header       Header
	Transactions []outcome.Transaction
	Shares       []workgraph.Share
}

// Earning is the already validated predecessor whose reward becomes state in
// the next block. Shares are revalidated from the predecessor seal's tips.
type Earning struct {
	Seal            workgraph.Share
	Shares          []workgraph.Share
	FeeAward        uint64
	ParentTimestamp uint64
	MedianTimePast  uint64
}

type Result struct {
	State           *state.Memory
	Receipts        []legacyblock.Receipt
	Fees            uint64
	FeeAward        uint64
	FeeQueue        *workgraph.FeeQueue
	PayoutResources []resource.Resource
	PayoutBatch     *workgraph.Batch
	BlockID         types.Hash
}

type Payload struct {
	position     Position
	parameters   Parameters
	header       Header
	transactions []outcome.Transaction
	result       Result
}

// MiningContext returns the exact immutable context shared by weak shares and
// the hard anchor for this prepared payload. The returned context deliberately
// has no anchor miner: each participant chooses its own reward address while
// mining the same payload.
func (payload *Payload) MiningContext() (workgraph.Context, error) {
	if payload == nil {
		return workgraph.Context{}, ErrParameters
	}
	context := contextFromSeal(payload.header.Seal, payload.position.MedianTimePast)
	context.AnchorMiner = types.Address{}
	if context.NetworkID == 0 || context.Height == 0 || context.AnchorParent.IsZero() ||
		context.AnchorTarget.IsZero() || context.PayloadRoot.IsZero() || context.AnchorTimestamp == 0 ||
		context.MedianTimePast == 0 || context.AnchorTimestamp <= context.MedianTimePast {
		return workgraph.Context{}, ErrPosition
	}
	return context, nil
}

func PreparePayload(
	preState *state.Memory,
	position Position,
	previous *Earning,
	transactions []outcome.Transaction,
	parameters Parameters,
) (*Payload, error) {
	if preState == nil || !parameters.valid() {
		return nil, ErrParameters
	}
	if err := validatePosition(position, parameters); err != nil {
		return nil, ErrPosition
	}
	if len(transactions) > legacyblock.MaxTransactions {
		return nil, legacyblock.ErrTransactionCount
	}
	current := preState
	previousWorkRoot := workgraph.EmptyRoot()
	var payoutResources []resource.Resource
	var payoutBatch *workgraph.Batch
	if previous == nil {
		// The only height without a WorkGraph predecessor is the explicit
		// activation block. Its version-0 parent already issued its own reward.
		if position.Height != parameters.ActivationHeight {
			return nil, ErrPrevious
		}
	} else {
		if previous.Seal.Height < parameters.ActivationHeight {
			return nil, ErrPrevious
		}
		if previous.Seal.Height == ^uint64(0) || previous.Seal.Height+1 != position.Height {
			return nil, ErrPrevious
		}
		if previous.Seal.Timestamp != position.ParentTimestamp {
			return nil, ErrPrevious
		}
		previousID, err := previous.Seal.ID()
		if err != nil || previousID != position.ParentID {
			return nil, ErrPrevious
		}
		previousPosition := Position{
			Height: previous.Seal.Height, ParentID: previous.Seal.AnchorParent,
			ParentTimestamp: previous.ParentTimestamp, MedianTimePast: previous.MedianTimePast,
			Timestamp: previous.Seal.Timestamp, Target: previous.Seal.Target,
		}
		if err := validatePosition(previousPosition, parameters); err != nil {
			return nil, ErrPrevious
		}
		previousContext := contextFromSeal(previous.Seal, previous.MedianTimePast)
		payoutBatch, err = workgraph.ValidateCommittedBatch(previousContext, previous.Seal, previous.Shares)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPrevious, err)
		}
		previousWorkRoot = payoutBatch.Root()
		rewards, err := workgraph.AllocateRewards(
			parameters.BlockSubsidy, previous.FeeAward, previous.Seal.Miner, payoutBatch,
		)
		if err != nil {
			return nil, ErrReward
		}
		payoutResources, err = workgraph.RewardResources(
			parameters.NetworkID, previous.Seal.Height, position.Height, previousID, rewards, parameters.RewardMaturity,
		)
		if err != nil {
			return nil, ErrReward
		}
		current, err = current.WithChanges(nil, payoutResources)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrReward, err)
		}
	}

	receipts := make([]legacyblock.Receipt, len(transactions))
	var fees uint64
	for index, transaction := range transactions {
		executed, err := execution.Apply(current, transaction, execution.Context{
			NetworkID: parameters.NetworkID, Height: position.Height,
		})
		if err != nil {
			return nil, fmt.Errorf("transaction %d: %w", index, err)
		}
		fees, err = types.AddAmount(fees, executed.Fee)
		if err != nil {
			return nil, fmt.Errorf("transaction %d fee: %w", index, err)
		}
		current = executed.State
		receipts[index] = legacyblock.Receipt{
			Version: legacyblock.Version0, TxID: executed.TxID, PostStateRoot: executed.StateRoot, Fee: executed.Fee,
		}
	}
	txRoot, err := legacyblock.TransactionRoot(transactions)
	if err != nil {
		return nil, err
	}
	receiptRoot, err := legacyblock.ReceiptRoot(receipts)
	if err != nil {
		return nil, err
	}
	feeQueue, err := feeQueueAt(position, parameters)
	if err != nil {
		return nil, err
	}
	feeAward, nextFeeQueue, err := feeQueue.Advance(fees)
	if err != nil {
		return nil, ErrReward
	}
	feeQueueRoot, err := nextFeeQueue.Root()
	if err != nil {
		return nil, ErrReward
	}
	payloadRoot, err := workgraph.PayloadCommitmentV1(
		txRoot, receiptRoot, current.Root(), previousWorkRoot, feeQueueRoot, feeAward,
	)
	if err != nil {
		return nil, err
	}
	header := Header{
		Version: Version1,
		Seal: workgraph.Share{
			Version: workgraph.Version0, NetworkID: parameters.NetworkID, Height: position.Height,
			AnchorParent: position.ParentID, Timestamp: position.Timestamp, Target: position.Target,
			PayloadRoot: payloadRoot,
		},
		TxRoot: txRoot, ReceiptRoot: receiptRoot, StateRoot: current.Root(), PreviousWorkRoot: previousWorkRoot,
		FeeQueueRoot: feeQueueRoot, FeeAward: feeAward,
	}
	return &Payload{
		position: position, parameters: parameters, header: header,
		transactions: append([]outcome.Transaction(nil), transactions...),
		result: Result{
			State: current, Receipts: receipts, Fees: fees, FeeAward: feeAward, FeeQueue: nextFeeQueue,
			PayoutResources: append([]resource.Resource(nil), payoutResources...), PayoutBatch: payoutBatch,
		},
	}, nil
}

// SealTemplate creates the exact work preimage shared by weak and hard mining.
func (payload *Payload) SealTemplate(
	miner types.Address,
	inclusionRoot types.Hash,
	parents []types.Hash,
) (workgraph.Share, error) {
	if payload == nil || miner.IsZero() || inclusionRoot.IsZero() {
		return workgraph.Share{}, ErrParameters
	}
	seal := payload.header.Seal
	seal.Miner = miner
	seal.InclusionRoot = inclusionRoot
	seal.Parents = append([]types.Hash(nil), parents...)
	if err := seal.ValidateBasic(); err != nil {
		return workgraph.Share{}, err
	}
	return seal, nil
}

func (payload *Payload) Finalize(anchor workgraph.Share, shares []workgraph.Share) (Block, Result, error) {
	if payload == nil {
		return Block{}, Result{}, ErrParameters
	}
	context := contextFromSeal(anchor, payload.position.MedianTimePast)
	if context.NetworkID != payload.parameters.NetworkID || context.Height != payload.position.Height ||
		context.AnchorParent != payload.position.ParentID || context.AnchorTarget != payload.position.Target ||
		context.AnchorTimestamp != payload.position.Timestamp || context.PayloadRoot != payload.header.Seal.PayloadRoot {
		return Block{}, Result{}, ErrPosition
	}
	batch, err := workgraph.ValidateCommittedBatch(context, anchor, shares)
	if err != nil {
		return Block{}, Result{}, err
	}
	header := payload.header
	header.Seal = anchor
	block := Block{
		Header: header, Transactions: append([]outcome.Transaction(nil), payload.transactions...), Shares: batch.Shares(),
	}
	if err := block.ValidateBasic(); err != nil {
		return Block{}, Result{}, err
	}
	result := payload.result
	result.BlockID, _ = anchor.ID()
	return block, result, nil
}

func ValidateAndExecute(
	preState *state.Memory,
	position Position,
	previous *Earning,
	candidate Block,
	parameters Parameters,
) (Result, error) {
	if err := candidate.ValidateBasic(); err != nil {
		return Result{}, err
	}
	payload, err := PreparePayload(preState, position, previous, candidate.Transactions, parameters)
	if err != nil {
		return Result{}, err
	}
	if candidate.Header.TxRoot != payload.header.TxRoot || candidate.Header.ReceiptRoot != payload.header.ReceiptRoot ||
		candidate.Header.StateRoot != payload.header.StateRoot ||
		candidate.Header.PreviousWorkRoot != payload.header.PreviousWorkRoot ||
		candidate.Header.FeeQueueRoot != payload.header.FeeQueueRoot ||
		candidate.Header.FeeAward != payload.header.FeeAward ||
		candidate.Header.Seal.PayloadRoot != payload.header.Seal.PayloadRoot {
		return Result{}, ErrRoot
	}
	_, result, err := payload.Finalize(candidate.Header.Seal, candidate.Shares)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// ValidateHeaderAt performs the checks required by header-first sync before a
// node requests the transaction/share body. Median-time-past and the lagged
// target arrive in Position from the already validated parent chain.
func ValidateHeaderAt(position Position, header Header, parameters Parameters, validationTime uint64) error {
	if !parameters.valid() || validationTime == 0 {
		return ErrParameters
	}
	if err := validatePosition(position, parameters); err != nil {
		return ErrPosition
	}
	if err := header.ValidateBasic(); err != nil {
		return err
	}
	seal := header.Seal
	if seal.NetworkID != parameters.NetworkID || seal.Height != position.Height ||
		seal.AnchorParent != position.ParentID || seal.Timestamp != position.Timestamp || seal.Target != position.Target {
		return ErrPosition
	}
	maximum, err := types.AddAmount(validationTime, legacyblock.MaxFutureDrift)
	if err != nil {
		maximum = ^uint64(0)
	}
	if seal.Timestamp > maximum {
		return ErrFutureTime
	}
	meets, err := workgraph.MeetsAnchor(seal)
	if err != nil {
		return err
	}
	if !meets {
		return workgraph.ErrProofOfWork
	}
	return nil
}

func ValidateAndExecuteAt(
	preState *state.Memory,
	position Position,
	previous *Earning,
	candidate Block,
	parameters Parameters,
	validationTime uint64,
) (Result, error) {
	if err := ValidateHeaderAt(position, candidate.Header, parameters, validationTime); err != nil {
		return Result{}, err
	}
	return ValidateAndExecute(preState, position, previous, candidate, parameters)
}

func (parameters Parameters) valid() bool {
	_, _, rewardErr := workgraph.RewardRates(parameters.BlockSubsidy)
	return parameters.NetworkID != 0 && rewardErr == nil && parameters.RewardMaturity != 0 &&
		parameters.ActivationHeight != 0 && parameters.DifficultyAnchorTimestamp != 0 &&
		workgraph.ExactShareRatio(parameters.DifficultyAnchorTarget) &&
		parameters.TargetSpacing != 0 && parameters.ASERTHalfLife != 0 &&
		parameters.FeeDelay != 0 && parameters.FeeDelay <= workgraph.MaxFeeDelay
}

func feeQueueAt(position Position, parameters Parameters) (*workgraph.FeeQueue, error) {
	if position.FeeQueue == nil {
		if position.Height != parameters.ActivationHeight {
			return nil, ErrParameters
		}
		return workgraph.NewFeeQueue(parameters.FeeDelay)
	}
	if position.FeeQueue.Delay() != parameters.FeeDelay {
		return nil, ErrParameters
	}
	if position.Height == parameters.ActivationHeight &&
		(position.FeeQueue.Balance() != 0 || position.FeeQueue.Cursor() != 0) {
		return nil, ErrParameters
	}
	return position.FeeQueue, nil
}

// validatePosition uses lagged ASERT: the target for height h is fixed from
// the parent timestamp plus one ideal spacing. The current miner's timestamp
// therefore cannot make its own proof easier.
func validatePosition(position Position, parameters Parameters) error {
	if position.Height == 0 || position.ParentID.IsZero() || position.ParentTimestamp == 0 ||
		position.MedianTimePast == 0 || position.Timestamp <= position.MedianTimePast || position.Target.IsZero() {
		return ErrPosition
	}
	evaluationTimestamp, err := types.AddAmount(position.ParentTimestamp, parameters.TargetSpacing)
	if err != nil {
		return ErrPosition
	}
	expected, err := difficulty.ASERT(
		parameters.DifficultyAnchorTarget, parameters.DifficultyAnchorTimestamp,
		position.Height, evaluationTimestamp, parameters.TargetSpacing, parameters.ASERTHalfLife,
	)
	if err != nil || expected != position.Target {
		return ErrPosition
	}
	return nil
}

func contextFromSeal(seal workgraph.Share, medianTimePast uint64) workgraph.Context {
	return workgraph.Context{
		NetworkID: seal.NetworkID, Height: seal.Height, AnchorParent: seal.AnchorParent,
		AnchorTarget: seal.Target, PayloadRoot: seal.PayloadRoot, AnchorMiner: seal.Miner,
		AnchorTimestamp: seal.Timestamp, MedianTimePast: medianTimePast,
	}
}
