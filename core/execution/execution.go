package execution

import (
	"errors"
	"fmt"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/guardvm"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrWrongNetwork      = errors.New("wrong transaction network")
	ErrExpired           = errors.New("transaction expired")
	ErrDuplicateInput    = errors.New("duplicate transaction input")
	ErrInputNotFound     = errors.New("transaction input not found")
	ErrInputVersion      = errors.New("transaction input version mismatch")
	ErrInputOwner        = errors.New("transaction input is not owned by signer")
	ErrInputImmature     = errors.New("transaction input is not spendable at this height")
	ErrOutputCollision   = errors.New("transaction output identifier collision")
	ErrConservation      = errors.New("asset conservation failed")
	ErrGuardRejected     = errors.New("transaction guard rejected")
	ErrStateUnavailable  = errors.New("pre-state is unavailable")
	ErrArithmeticFailure = errors.New("transaction amount arithmetic failed")
)

type Context struct {
	NetworkID uint32
	Height    uint64
}

type Result struct {
	State     *state.Memory
	TxID      types.Hash
	Consumed  []resource.Resource
	Created   []resource.Resource
	Fee       uint64
	StateRoot types.Hash
}

// Transition contains a validated state change without materializing its v0
// commitment. Admission and transaction selection do not need a receipt root.
// Consensus block execution must use Apply, which supplies that commitment.
type Transition struct {
	State             *state.Memory
	TxID              types.Hash
	Consumed, Created []resource.Resource
	Fee               uint64
}

func Apply(preState *state.Memory, transaction outcome.Transaction, context Context) (Result, error) {
	t, err := ApplyTransition(preState, transaction, context)
	if err != nil {
		return Result{}, err
	}
	return Result{State: t.State, TxID: t.TxID, Consumed: t.Consumed, Created: t.Created, Fee: t.Fee, StateRoot: t.State.Root()}, nil
}

// ApplyTransition validates transaction in the consensus-defined order and returns a new
// state only after every check succeeds. The supplied pre-state is never
// mutated, including when GuardVM rejects the candidate post-state.
func ApplyTransition(preState *state.Memory, transaction outcome.Transaction, context Context) (Transition, error) {
	if preState == nil {
		return Transition{}, ErrStateUnavailable
	}
	if err := transaction.ValidateBasic(); err != nil {
		return Transition{}, err
	}
	if transaction.NetworkID != context.NetworkID {
		return Transition{}, fmt.Errorf("%w: got %d want %d", ErrWrongNetwork, transaction.NetworkID, context.NetworkID)
	}
	if context.Height > transaction.ValidUntil {
		return Transition{}, fmt.Errorf("%w: height %d exceeds %d", ErrExpired, context.Height, transaction.ValidUntil)
	}

	inputIDs := make([]types.ResourceID, len(transaction.Inputs))
	seenInputs := make(map[types.ResourceID]struct{}, len(transaction.Inputs))
	for index, input := range transaction.Inputs {
		if _, duplicate := seenInputs[input.ID]; duplicate {
			return Transition{}, fmt.Errorf("input %d: %w: %s", index, ErrDuplicateInput, input.ID)
		}
		seenInputs[input.ID] = struct{}{}
		inputIDs[index] = input.ID
	}

	consumed := make([]resource.Resource, len(transaction.Inputs))
	for index, input := range transaction.Inputs {
		value, exists := preState.Get(input.ID)
		if !exists {
			return Transition{}, fmt.Errorf("input %d: %w: %s", index, ErrInputNotFound, input.ID)
		}
		consumed[index] = value
	}

	signer, err := transaction.SignerAddress()
	if err != nil {
		return Transition{}, err
	}
	for index, input := range transaction.Inputs {
		if consumed[index].Version != input.Version {
			return Transition{}, fmt.Errorf("input %d: %w: reference %d state %d", index, ErrInputVersion, input.Version, consumed[index].Version)
		}
		if consumed[index].Owner != signer {
			return Transition{}, fmt.Errorf("input %d: %w", index, ErrInputOwner)
		}
		if context.Height < consumed[index].SpendAfter {
			return Transition{}, fmt.Errorf("input %d: %w: height %d requires %d", index, ErrInputImmature, context.Height, consumed[index].SpendAfter)
		}
	}

	if err := transaction.VerifySignature(); err != nil {
		return Transition{}, err
	}

	created, err := transaction.MaterializeOutputs()
	if err != nil {
		return Transition{}, err
	}
	for index, value := range created {
		if _, exists := preState.Get(value.ID); exists {
			return Transition{}, fmt.Errorf("output %d: %w: %s", index, ErrOutputCollision, value.ID)
		}
	}

	if err := verifyConservation(consumed, created, transaction.Fee); err != nil {
		return Transition{}, err
	}

	candidate, err := preState.WithChanges(inputIDs, created)
	if err != nil {
		return Transition{}, err
	}
	if err := guardvm.Execute(transaction.Guard, guardvm.Context{
		Before: preState,
		After:  candidate,
		Fee:    transaction.Fee,
		Height: context.Height,
	}); err != nil {
		return Transition{}, fmt.Errorf("%w: %v", ErrGuardRejected, err)
	}

	txID, err := transaction.ID()
	if err != nil {
		return Transition{}, err
	}
	return Transition{
		State:    candidate,
		TxID:     txID,
		Consumed: consumed,
		Created:  created,
		Fee:      transaction.Fee,
	}, nil
}

func verifyConservation(consumed, created []resource.Resource, fee uint64) error {
	inputs := make(map[types.AssetID]uint64)
	outputs := make(map[types.AssetID]uint64)

	for index, value := range consumed {
		total, err := types.AddAmount(inputs[value.Asset], value.Amount)
		if err != nil {
			return fmt.Errorf("input %d: %w: %v", index, ErrArithmeticFailure, err)
		}
		inputs[value.Asset] = total
	}
	for index, value := range created {
		total, err := types.AddAmount(outputs[value.Asset], value.Amount)
		if err != nil {
			return fmt.Errorf("output %d: %w: %v", index, ErrArithmeticFailure, err)
		}
		outputs[value.Asset] = total
	}

	assets := make([]types.AssetID, 0, len(inputs)+len(outputs)+1)
	seen := make(map[types.AssetID]struct{}, len(inputs)+len(outputs)+1)
	addAsset := func(asset types.AssetID) {
		if _, exists := seen[asset]; exists {
			return
		}
		seen[asset] = struct{}{}
		assets = append(assets, asset)
	}
	for asset := range inputs {
		addAsset(asset)
	}
	for asset := range outputs {
		addAsset(asset)
	}
	native := types.NativeAssetID()
	addAsset(native)
	sort.Slice(assets, func(left, right int) bool {
		return types.CompareAssetID(assets[left], assets[right]) < 0
	})

	for _, asset := range assets {
		expected := outputs[asset]
		if asset == native {
			var err error
			expected, err = types.AddAmount(expected, fee)
			if err != nil {
				return fmt.Errorf("native asset: %w: %v", ErrArithmeticFailure, err)
			}
		}
		if inputs[asset] != expected {
			return fmt.Errorf("%w for asset %s: inputs %d expected %d", ErrConservation, asset, inputs[asset], expected)
		}
	}
	return nil
}
