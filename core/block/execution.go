package block

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/execution"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/pow"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrParent            = errors.New("block parent mismatch")
	ErrParentHeight      = errors.New("block height does not follow parent")
	ErrMedianTimePast    = errors.New("block timestamp does not exceed median time past")
	ErrFutureTimestamp   = errors.New("block timestamp exceeds allowed future drift")
	ErrUnexpectedTarget  = errors.New("block target differs from parent target")
	ErrInvalidProof      = errors.New("block proof of work is invalid")
	ErrUnexpectedNetwork = errors.New("block belongs to a different network")
	ErrReceiptRoot       = errors.New("block receipt root mismatch")
	ErrStateRoot         = errors.New("block state root mismatch")
	ErrRewardCollision   = errors.New("block reward identifier collision")
	ErrRewardArithmetic  = errors.New("block reward arithmetic failed")
	ErrInvalidParameters = errors.New("invalid block execution parameters")
)

const MaxFutureDrift uint64 = 120

type Parent struct {
	ID             types.Hash
	Height         uint64
	Timestamp      uint64
	MedianTimePast uint64
	Target         types.Hash
}

type ExecutionResult struct {
	State        *state.Memory
	Receipts     []Receipt
	Fees         uint64
	Reward       resource.Resource
	BlockID      types.Hash
	FinalRoot    types.Hash
	ReceiptRoot  types.Hash
	CumulativeTx int
}

func Prepare(preState *state.Memory, parent Parent, transactions []outcome.Transaction, miner types.Address, timestamp uint64, parameters Parameters) (Block, ExecutionResult, error) {
	target, err := parameters.Target(parent.Height+1, timestamp)
	if err != nil {
		return Block{}, ExecutionResult{}, ErrInvalidParameters
	}
	if err := validateContext(parent, parameters, parent.Height+1, parent.ID, timestamp, target); err != nil {
		return Block{}, ExecutionResult{}, err
	}
	txRoot, err := TransactionRoot(transactions)
	if err != nil {
		return Block{}, ExecutionResult{}, err
	}
	postState, receipts, fees, reward, err := executeBody(preState, parent, transactions, miner, parameters)
	if err != nil {
		return Block{}, ExecutionResult{}, err
	}
	receiptRoot, err := ReceiptRoot(receipts)
	if err != nil {
		return Block{}, ExecutionResult{}, err
	}
	result := Block{
		Header: Header{
			Version:     parameters.ProtocolVersion,
			NetworkID:   parameters.NetworkID,
			Height:      parent.Height + 1,
			Parent:      parent.ID,
			Timestamp:   timestamp,
			Target:      target,
			TxRoot:      txRoot,
			ReceiptRoot: receiptRoot,
			StateRoot:   postState.Root(),
			Miner:       miner,
		},
		Transactions: append([]outcome.Transaction(nil), transactions...),
	}
	if err := result.ValidateBasic(); err != nil {
		return Block{}, ExecutionResult{}, err
	}
	return result, ExecutionResult{
		State:        postState,
		Receipts:     receipts,
		Fees:         fees,
		Reward:       reward,
		FinalRoot:    postState.Root(),
		ReceiptRoot:  receiptRoot,
		CumulativeTx: len(transactions),
	}, nil
}

func ValidateAndExecuteAt(preState *state.Memory, parent Parent, candidate Block, parameters Parameters, validationTime uint64) (ExecutionResult, error) {
	if err := candidate.ValidateBasic(); err != nil {
		return ExecutionResult{}, err
	}
	if err := ValidateHeaderAt(parent, candidate.Header, parameters, validationTime); err != nil {
		return ExecutionResult{}, err
	}
	blockID, _ := candidate.Header.ID()

	postState, receipts, fees, reward, err := executeBody(preState, parent, candidate.Transactions, candidate.Header.Miner, parameters)
	if err != nil {
		return ExecutionResult{}, err
	}
	receiptRoot, err := ReceiptRoot(receipts)
	if err != nil {
		return ExecutionResult{}, err
	}
	if receiptRoot != candidate.Header.ReceiptRoot {
		return ExecutionResult{}, fmt.Errorf("%w: got %s want %s", ErrReceiptRoot, candidate.Header.ReceiptRoot, receiptRoot)
	}
	stateRoot := postState.Root()
	if stateRoot != candidate.Header.StateRoot {
		return ExecutionResult{}, fmt.Errorf("%w: got %s want %s", ErrStateRoot, candidate.Header.StateRoot, stateRoot)
	}
	return ExecutionResult{
		State:        postState,
		Receipts:     receipts,
		Fees:         fees,
		Reward:       reward,
		BlockID:      blockID,
		FinalRoot:    stateRoot,
		ReceiptRoot:  receiptRoot,
		CumulativeTx: len(candidate.Transactions),
	}, nil
}

// ValidateHeaderAt performs every context-dependent header check that does not
// require the transaction body or state. Full block execution must still
// verify transaction, receipt, and state roots before commit.
func ValidateHeaderAt(parent Parent, header Header, parameters Parameters, validationTime uint64) error {
	if err := header.ValidateBasic(); err != nil {
		return err
	}
	if header.Version != parameters.ProtocolVersion {
		return ErrUnsupportedVersion
	}
	if header.NetworkID != parameters.NetworkID {
		return fmt.Errorf("%w: got %d want %d", ErrUnexpectedNetwork, header.NetworkID, parameters.NetworkID)
	}
	if err := validateContext(parent, parameters, header.Height, header.Parent, header.Timestamp, header.Target); err != nil {
		return err
	}
	maxTimestamp, err := types.AddAmount(validationTime, MaxFutureDrift)
	if err != nil {
		maxTimestamp = ^uint64(0)
	}
	if header.Timestamp > maxTimestamp {
		return fmt.Errorf("%w: got %d maximum %d", ErrFutureTimestamp, header.Timestamp, maxTimestamp)
	}
	blockID, err := header.ID()
	if err != nil {
		return err
	}
	if !pow.MeetsTarget(blockID, header.Target) {
		return fmt.Errorf("%w: id %s target %s", ErrInvalidProof, blockID, header.Target)
	}
	return nil
}

func validateContext(parent Parent, parameters Parameters, height uint64, parentID types.Hash, timestamp uint64, target types.Hash) error {
	if !parameters.valid() {
		return ErrInvalidParameters
	}
	if parentID != parent.ID {
		return fmt.Errorf("%w: got %s want %s", ErrParent, parentID, parent.ID)
	}
	if parent.Height == ^uint64(0) || height != parent.Height+1 {
		return fmt.Errorf("%w: got %d after %d", ErrParentHeight, height, parent.Height)
	}
	if parent.MedianTimePast == 0 || timestamp <= parent.MedianTimePast {
		return fmt.Errorf("%w: got %d after %d", ErrMedianTimePast, timestamp, parent.MedianTimePast)
	}
	expectedTarget, err := parameters.Target(height, timestamp)
	if err != nil {
		return ErrInvalidParameters
	}
	if target != expectedTarget {
		return fmt.Errorf("%w: got %s want %s", ErrUnexpectedTarget, target, expectedTarget)
	}
	return nil
}

func executeBody(preState *state.Memory, parent Parent, transactions []outcome.Transaction, miner types.Address, parameters Parameters) (*state.Memory, []Receipt, uint64, resource.Resource, error) {
	if preState == nil {
		return nil, nil, 0, resource.Resource{}, execution.ErrStateUnavailable
	}
	if preState.CommitmentVersion() != parameters.StateCommitment() {
		return nil, nil, 0, resource.Resource{}, state.ErrCommitmentVersion
	}
	if miner.IsZero() {
		return nil, nil, 0, resource.Resource{}, ErrMiner
	}

	current := preState
	receipts := make([]Receipt, len(transactions))
	var fees uint64
	for index, transaction := range transactions {
		result, err := execution.Apply(current, transaction, execution.Context{
			StateCommitment: parameters.StateCommitment(),
			NetworkID:       parameters.NetworkID,
			Height:          parent.Height + 1,
		})
		if err != nil {
			return nil, nil, 0, resource.Resource{}, fmt.Errorf("transaction %d: %w", index, err)
		}
		fees, err = types.AddAmount(fees, result.Fee)
		if err != nil {
			return nil, nil, 0, resource.Resource{}, fmt.Errorf("transaction %d: %w: %v", index, ErrRewardArithmetic, err)
		}
		current = result.State
		receipts[index] = Receipt{
			Version:       parameters.ProtocolVersion,
			TxID:          result.TxID,
			PostStateRoot: result.StateRoot,
			Fee:           result.Fee,
		}
	}

	rewardAmount, err := types.AddAmount(parameters.BlockSubsidy, fees)
	if err != nil {
		return nil, nil, 0, resource.Resource{}, fmt.Errorf("%w: %v", ErrRewardArithmetic, err)
	}
	reward := resource.Resource{
		ID:      RewardID(parameters.NetworkID, parent.Height+1, parent.ID, miner),
		Version: resource.Version0,
		Owner:   miner,
		Asset:   types.NativeAssetID(),
		Amount:  rewardAmount,
	}
	reward.SpendAfter, err = types.AddAmount(parent.Height+1, parameters.RewardMaturity)
	if err != nil {
		return nil, nil, 0, resource.Resource{}, fmt.Errorf("%w: reward maturity: %v", ErrRewardArithmetic, err)
	}
	if _, exists := preState.Get(reward.ID); exists {
		return nil, nil, 0, resource.Resource{}, fmt.Errorf("%w: %s", ErrRewardCollision, reward.ID)
	}
	postState, err := current.WithChanges(nil, []resource.Resource{reward})
	if err != nil {
		return nil, nil, 0, resource.Resource{}, err
	}
	return postState, receipts, fees, reward, nil
}

func RewardID(networkID uint32, height uint64, parent types.Hash, miner types.Address) types.ResourceID {
	var networkBytes [4]byte
	var heightBytes [8]byte
	binary.BigEndian.PutUint32(networkBytes[:], networkID)
	binary.BigEndian.PutUint64(heightBytes[:], height)
	hash := types.DomainHash(types.DomainBlockReward, networkBytes[:], heightBytes[:], parent[:], miner[:])
	return types.ResourceID(hash)
}
