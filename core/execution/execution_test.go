package execution

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/guardvm"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const testNetworkID uint32 = 17

func testPrivateKey() ed25519.PrivateKey {
	seed := types.DomainHash("test/execution/private-key")
	return ed25519.NewKeyFromSeed(seed[:])
}

func testFixture(t testing.TB) (*state.Memory, resource.Resource, outcome.Transaction) {
	t.Helper()

	privateKey := testPrivateKey()
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	recipient := types.Address(types.DomainHash("test/execution/recipient"))
	input := resource.Resource{
		ID:      types.ResourceID(types.DomainHash("test/execution/genesis")),
		Version: resource.Version0,
		Owner:   owner,
		Asset:   types.NativeAssetID(),
		Amount:  1_000,
	}
	preState, err := state.New([]resource.Resource{input})
	if err != nil {
		t.Fatal(err)
	}

	transaction := outcome.Transaction{
		Version:   outcome.Version0,
		NetworkID: testNetworkID,
		Inputs: []resource.Ref{{
			ID:      input.ID,
			Version: input.Version,
		}},
		Outputs: []resource.Output{
			{Owner: recipient, Asset: input.Asset, Amount: 900},
			{Owner: owner, Asset: input.Asset, Amount: 95},
		},
		Guard: guardvm.Program{
			Version:      guardvm.Version0,
			Instructions: []guardvm.Instruction{{Op: guardvm.OpHalt}},
		},
		Fee:        5,
		ValidUntil: 100,
		Nonce:      [32]byte{1, 2, 3},
	}
	if err := transaction.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return preState, input, transaction
}

func TestApplyTransferAtomically(t *testing.T) {
	t.Parallel()

	preState, input, transaction := testFixture(t)
	preRoot := preState.Root()
	result, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: 42})
	if err != nil {
		t.Fatal(err)
	}

	if preState.Root() != preRoot || preState.Len() != 1 {
		t.Fatal("successful execution mutated the pre-state")
	}
	if _, exists := preState.Get(input.ID); !exists {
		t.Fatal("input disappeared from the pre-state")
	}
	if result.State.Len() != 2 {
		t.Fatalf("post-state contains %d resources, want 2", result.State.Len())
	}
	if _, exists := result.State.Get(input.ID); exists {
		t.Fatal("input remains in post-state")
	}
	if result.StateRoot != result.State.Root() {
		t.Fatal("reported state root does not match post-state")
	}
	wantID, err := transaction.ID()
	if err != nil {
		t.Fatal(err)
	}
	if result.TxID != wantID {
		t.Fatalf("transaction ID: got %s want %s", result.TxID, wantID)
	}
}

func TestApplyRejectsGuardWithoutMutatingState(t *testing.T) {
	t.Parallel()

	preState, input, transaction := testFixture(t)
	transaction.Guard = guardvm.Program{
		Version: guardvm.Version0,
		Instructions: []guardvm.Instruction{
			{Op: guardvm.OpPushU64, Value: 1},
			{Op: guardvm.OpPushU64, Value: 2},
			{Op: guardvm.OpEqualU64},
			{Op: guardvm.OpRequire},
			{Op: guardvm.OpHalt},
		},
	}
	if err := transaction.Sign(testPrivateKey()); err != nil {
		t.Fatal(err)
	}
	preRoot := preState.Root()

	_, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: 42})
	if !errors.Is(err, ErrGuardRejected) {
		t.Fatalf("got %v, want guard rejection", err)
	}
	assertPreStateUnchanged(t, preState, input, preRoot)
}

func TestApplyRejectsInvalidSignatureWithoutMutatingState(t *testing.T) {
	t.Parallel()

	preState, input, transaction := testFixture(t)
	transaction.Signature[0] ^= 0xff
	preRoot := preState.Root()

	_, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: 42})
	if !errors.Is(err, outcome.ErrInvalidSignature) {
		t.Fatalf("got %v, want invalid signature", err)
	}
	assertPreStateUnchanged(t, preState, input, preRoot)
}

func TestApplyRejectsConservationFailure(t *testing.T) {
	t.Parallel()

	preState, input, transaction := testFixture(t)
	transaction.Outputs[1].Amount++
	if err := transaction.Sign(testPrivateKey()); err != nil {
		t.Fatal(err)
	}
	preRoot := preState.Root()

	_, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: 42})
	if !errors.Is(err, ErrConservation) {
		t.Fatalf("got %v, want conservation failure", err)
	}
	assertPreStateUnchanged(t, preState, input, preRoot)
}

func TestApplyRejectsDuplicateInputBeforeLoading(t *testing.T) {
	t.Parallel()

	preState, _, transaction := testFixture(t)
	transaction.Inputs = append(transaction.Inputs, transaction.Inputs[0])
	if err := transaction.Sign(testPrivateKey()); err != nil {
		t.Fatal(err)
	}

	_, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: 42})
	if !errors.Is(err, ErrDuplicateInput) {
		t.Fatalf("got %v, want duplicate input", err)
	}
}

func TestApplyTreatsValidUntilAsInclusive(t *testing.T) {
	t.Parallel()

	preState, _, transaction := testFixture(t)
	if _, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: transaction.ValidUntil}); err != nil {
		t.Fatalf("transaction should be valid at its final height: %v", err)
	}
	if _, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: transaction.ValidUntil + 1}); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want expired transaction", err)
	}
}

func TestApplyRejectsWrongNetwork(t *testing.T) {
	t.Parallel()

	preState, _, transaction := testFixture(t)
	if _, err := Apply(preState, transaction, Context{NetworkID: testNetworkID + 1, Height: 42}); !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("got %v, want wrong network", err)
	}
}

func TestApplyEnforcesResourceSpendAfterHeight(t *testing.T) {
	t.Parallel()

	_, input, transaction := testFixture(t)
	input.SpendAfter = 50
	preState, err := state.New([]resource.Resource{input})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: 49}); !errors.Is(err, ErrInputImmature) {
		t.Fatalf("got %v, want immature input", err)
	}
	if _, err := Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: 50}); err != nil {
		t.Fatalf("mature input rejected: %v", err)
	}
}

func FuzzApplyNeverMutatesPreState(f *testing.F) {
	preState, _, transaction := testFixture(f)
	f.Add(transaction.CanonicalBytes(), uint64(42))
	f.Add([]byte{}, uint64(0))

	f.Fuzz(func(t *testing.T, encoded []byte, height uint64) {
		transaction, err := outcome.Decode(encoded)
		if err != nil {
			return
		}
		beforeRoot := preState.Root()
		beforeResources := preState.Resources()
		_, _ = Apply(preState, transaction, Context{NetworkID: testNetworkID, Height: height})
		if preState.Root() != beforeRoot {
			t.Fatal("execution mutated the pre-state root")
		}
		afterResources := preState.Resources()
		if len(afterResources) != len(beforeResources) {
			t.Fatal("execution mutated the pre-state resource count")
		}
		for index := range beforeResources {
			if beforeResources[index] != afterResources[index] {
				t.Fatal("execution mutated a pre-state resource")
			}
		}
	})
}

func assertPreStateUnchanged(t testing.TB, preState *state.Memory, input resource.Resource, root types.Hash) {
	t.Helper()
	if preState.Root() != root || preState.Len() != 1 {
		t.Fatal("failed execution mutated the pre-state")
	}
	if got, exists := preState.Get(input.ID); !exists || got != input {
		t.Fatal("failed execution changed the input resource")
	}
}
