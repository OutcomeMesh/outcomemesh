package wallet

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/execution"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func walletFixture(t testing.TB) (*state.Memory, ed25519.PrivateKey, types.Address) {
	t.Helper()
	seed := types.DomainHash("test/wallet/key")
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	native := types.NativeAssetID()
	preState, err := state.New([]resource.Resource{
		{ID: types.ResourceID(types.DomainHash("test/wallet/input-2")), Version: resource.Version0, Owner: owner, Asset: native, Amount: 60},
		{ID: types.ResourceID(types.DomainHash("test/wallet/input-1")), Version: resource.Version0, Owner: owner, Asset: native, Amount: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	return preState, privateKey, owner
}

func TestBuildNativeTransferExecutes(t *testing.T) {
	t.Parallel()

	preState, privateKey, owner := walletFixture(t)
	recipient := types.Address(types.DomainHash("test/wallet/recipient"))
	transaction, err := BuildNativeTransfer(preState, privateKey, TransferRequest{
		NetworkID:     77,
		CurrentHeight: 10,
		ValidFor:      20,
		Recipient:     recipient,
		Amount:        70,
		Fee:           5,
		Nonce:         [32]byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := execution.Apply(preState, transaction, execution.Context{NetworkID: 77, Height: 11})
	if err != nil {
		t.Fatal(err)
	}
	if balance, err := result.State.Balance(recipient, types.NativeAssetID()); err != nil || balance != 70 {
		t.Fatalf("recipient balance = %d, %v; want 70", balance, err)
	}
	if balance, err := result.State.Balance(owner, types.NativeAssetID()); err != nil || balance != 35 {
		t.Fatalf("sender balance = %d, %v; want 35", balance, err)
	}
}

func TestBuildNativeTransferRejectsInsufficientFunds(t *testing.T) {
	t.Parallel()

	preState, privateKey, _ := walletFixture(t)
	_, err := BuildNativeTransfer(preState, privateKey, TransferRequest{
		NetworkID:     77,
		CurrentHeight: 10,
		ValidFor:      20,
		Recipient:     types.Address(types.DomainHash("test/wallet/recipient")),
		Amount:        110,
		Fee:           1,
	})
	if !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("got %v, want insufficient funds", err)
	}
}

func TestBuildNativeTransferSkipsImmatureResources(t *testing.T) {
	t.Parallel()

	preState, privateKey, _ := walletFixture(t)
	resources := preState.Resources()
	for index := range resources {
		resources[index].SpendAfter = 12
	}
	preState, err := state.New(resources)
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildNativeTransfer(preState, privateKey, TransferRequest{
		NetworkID:     77,
		CurrentHeight: 10,
		ValidFor:      20,
		Recipient:     types.Address(types.DomainHash("test/wallet/recipient")),
		Amount:        1,
	})
	if !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("got %v, want immature funds to be unavailable", err)
	}
}
