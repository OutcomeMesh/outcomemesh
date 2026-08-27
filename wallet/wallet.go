package wallet

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/guardvm"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrInvalidAmount     = errors.New("transfer amount is zero")
	ErrInvalidValidity   = errors.New("transaction validity window is zero")
	ErrInsufficientFunds = errors.New("insufficient native funds")
)

type TransferRequest struct {
	NetworkID     uint32
	CurrentHeight uint64
	ValidFor      uint64
	Recipient     types.Address
	Amount        uint64
	Fee           uint64
	Nonce         [32]byte
}

func BuildNativeTransfer(preState *state.Memory, privateKey ed25519.PrivateKey, request TransferRequest) (outcome.Transaction, error) {
	if preState == nil {
		return outcome.Transaction{}, errors.New("wallet state is unavailable")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return outcome.Transaction{}, outcome.ErrInvalidPrivateKey
	}
	if request.NetworkID == 0 {
		return outcome.Transaction{}, errors.New("network identifier is zero")
	}
	if request.Recipient.IsZero() {
		return outcome.Transaction{}, resource.ErrZeroOwner
	}
	if request.Amount == 0 {
		return outcome.Transaction{}, ErrInvalidAmount
	}
	if request.ValidFor == 0 || request.CurrentHeight > ^uint64(0)-request.ValidFor {
		return outcome.Transaction{}, ErrInvalidValidity
	}
	required, err := types.AddAmount(request.Amount, request.Fee)
	if err != nil {
		return outcome.Transaction{}, err
	}
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return outcome.Transaction{}, err
	}
	native := types.NativeAssetID()

	inputs := make([]resource.Ref, 0)
	var selected uint64
	for _, value := range preState.Resources() {
		if value.Owner != owner || value.Asset != native {
			continue
		}
		if value.SpendAfter > request.CurrentHeight+1 {
			continue
		}
		selected, err = types.AddAmount(selected, value.Amount)
		if err != nil {
			return outcome.Transaction{}, err
		}
		inputs = append(inputs, resource.Ref{ID: value.ID, Version: value.Version})
		if selected >= required {
			break
		}
	}
	if selected < required {
		return outcome.Transaction{}, fmt.Errorf("%w: have %d need %d", ErrInsufficientFunds, selected, required)
	}
	change, err := types.SubAmount(selected, required)
	if err != nil {
		return outcome.Transaction{}, err
	}
	outputs := []resource.Output{{Owner: request.Recipient, Asset: native, Amount: request.Amount}}
	if change > 0 {
		outputs = append(outputs, resource.Output{Owner: owner, Asset: native, Amount: change})
	}

	transaction := outcome.Transaction{
		Version:    outcome.Version0,
		NetworkID:  request.NetworkID,
		Inputs:     inputs,
		Outputs:    outputs,
		Guard:      maxNativeSpendGuard(owner, native, required, request.Fee),
		Fee:        request.Fee,
		ValidUntil: request.CurrentHeight + request.ValidFor,
		Nonce:      request.Nonce,
	}
	if err := transaction.Sign(privateKey); err != nil {
		return outcome.Transaction{}, err
	}
	return transaction, nil
}

func maxNativeSpendGuard(owner types.Address, asset types.AssetID, maxDecrease, maxFee uint64) guardvm.Program {
	return guardvm.Program{
		Version: guardvm.Version0,
		Instructions: []guardvm.Instruction{
			{Op: guardvm.OpLoadBalanceBefore, Owner: owner, Asset: asset},
			{Op: guardvm.OpLoadBalanceAfter, Owner: owner, Asset: asset},
			{Op: guardvm.OpPushU64, Value: maxDecrease},
			{Op: guardvm.OpAddU64},
			{Op: guardvm.OpLessOrEqualU64},
			{Op: guardvm.OpRequire},
			{Op: guardvm.OpLoadFee},
			{Op: guardvm.OpPushU64, Value: maxFee},
			{Op: guardvm.OpLessOrEqualU64},
			{Op: guardvm.OpRequire},
			{Op: guardvm.OpHalt},
		},
	}
}
