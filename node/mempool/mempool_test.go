package mempool

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/execution"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/wallet"
)

const testNetworkID uint32 = 77

type transactionFixture struct {
	state        *state.Memory
	transactions []outcome.Transaction
}

func TestRejectsDuplicateInputConflictAndInvalidTransaction(t *testing.T) {
	t.Parallel()

	fixture := makeFixture(t, 1, []uint64{1})
	pool, err := New(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	context := execution.Context{NetworkID: testNetworkID, Height: 1}
	transaction := fixture.transactions[0]
	if _, err := pool.Add(fixture.state, transaction, context); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Add(fixture.state, transaction, context); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}

	conflictFixture := makeFixture(t, 1, []uint64{2})
	conflict := conflictFixture.transactions[0]
	conflict.Inputs = append([]resource.Ref(nil), transaction.Inputs...)
	conflict.Nonce[31] = 99
	seed := types.DomainHash("test/mempool/key/0")
	if err := conflict.Sign(ed25519.NewKeyFromSeed(seed[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Add(fixture.state, conflict, context); !errors.Is(err, ErrInputConflict) {
		t.Fatalf("conflict error = %v", err)
	}

	invalid := transaction
	invalid.Outputs = append([]resource.Output(nil), transaction.Outputs...)
	invalid.Outputs[0].Amount++
	if _, err := pool.Add(fixture.state, invalid, context); !errors.Is(err, outcome.ErrInvalidSignature) {
		t.Fatalf("invalid signature error = %v", err)
	}
}

func TestCapacityEvictsOnlyLowerPriority(t *testing.T) {
	t.Parallel()

	fixture := makeFixture(t, 4, []uint64{1, 2, 3, 1})
	maxSize := len(fixture.transactions[0].CanonicalBytes())
	pool, err := New(Policy{MaxTransactions: 2, MaxBytes: 2 * maxSize, MaxTxBytes: maxSize, MinFee: 1})
	if err != nil {
		t.Fatal(err)
	}
	context := execution.Context{NetworkID: testNetworkID, Height: 1}
	for _, index := range []int{0, 1, 2} {
		if _, err := pool.Add(fixture.state, fixture.transactions[index], context); err != nil {
			t.Fatal(err)
		}
	}
	entries := pool.Entries()
	if len(entries) != 2 || entries[0].Fee != 3 || entries[1].Fee != 2 {
		t.Fatalf("unexpected retained fees: %+v", entryFees(entries))
	}
	if _, err := pool.Add(fixture.state, fixture.transactions[3], context); !errors.Is(err, ErrCapacity) {
		t.Fatalf("lower-priority admission error = %v", err)
	}
}

func TestSelectionIsDeterministicAcrossAdmissionOrder(t *testing.T) {
	t.Parallel()

	fixture := makeFixture(t, 3, []uint64{1, 3, 2})
	policy := DefaultPolicy()
	left, _ := New(policy)
	right, _ := New(policy)
	context := execution.Context{NetworkID: testNetworkID, Height: 1}
	for _, index := range []int{0, 1, 2} {
		if _, err := left.Add(fixture.state, fixture.transactions[index], context); err != nil {
			t.Fatal(err)
		}
	}
	for _, index := range []int{2, 0, 1} {
		if _, err := right.Add(fixture.state, fixture.transactions[index], context); err != nil {
			t.Fatal(err)
		}
	}
	leftSelected := left.Select(fixture.state, context, 3, 1<<20)
	rightSelected := right.Select(fixture.state, context, 3, 1<<20)
	if len(leftSelected) != 3 || len(rightSelected) != 3 {
		t.Fatal("selection unexpectedly skipped valid independent transactions")
	}
	for index := range leftSelected {
		leftID, _ := leftSelected[index].ID()
		rightID, _ := rightSelected[index].ID()
		if leftID != rightID {
			t.Fatalf("selection differs at %d: %s != %s", index, leftID, rightID)
		}
	}
	if leftSelected[0].Fee != 3 || leftSelected[1].Fee != 2 || leftSelected[2].Fee != 1 {
		t.Fatalf("unexpected priority order: %v", []uint64{leftSelected[0].Fee, leftSelected[1].Fee, leftSelected[2].Fee})
	}
}

func TestRevalidateAndRemoveCommittedReleaseReservations(t *testing.T) {
	t.Parallel()

	fixture := makeFixture(t, 2, []uint64{2, 1})
	pool, _ := New(DefaultPolicy())
	context := execution.Context{NetworkID: testNetworkID, Height: 1}
	for _, transaction := range fixture.transactions {
		if _, err := pool.Add(fixture.state, transaction, context); err != nil {
			t.Fatal(err)
		}
	}
	spentID := fixture.transactions[0].Inputs[0].ID
	postState, err := fixture.state.WithChanges([]types.ResourceID{spentID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	removed := pool.Revalidate(postState, context)
	if len(removed) != 1 || pool.Len() != 1 {
		t.Fatalf("revalidation removed=%d retained=%d", len(removed), pool.Len())
	}
	pool.RemoveCommitted([]outcome.Transaction{fixture.transactions[1]})
	if pool.Len() != 0 || pool.Bytes() != 0 {
		t.Fatal("committed transaction remains or byte accounting leaked")
	}

	if _, err := pool.Add(fixture.state, fixture.transactions[0], context); err != nil {
		t.Fatalf("released reservation prevented readmission: %v", err)
	}
	removed = pool.Revalidate(fixture.state, execution.Context{NetworkID: testNetworkID, Height: 101})
	if len(removed) != 1 || pool.Len() != 0 {
		t.Fatal("expired transaction survived revalidation")
	}
}

func makeFixture(t testing.TB, count int, fees []uint64) transactionFixture {
	t.Helper()
	resources := make([]resource.Resource, count)
	keys := make([]ed25519.PrivateKey, count)
	for index := 0; index < count; index++ {
		seed := types.DomainHash("test/mempool/key/" + string(rune('0'+index)))
		keys[index] = ed25519.NewKeyFromSeed(seed[:])
		owner, err := types.AddressFromPublicKey(keys[index].Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		resources[index] = resource.Resource{
			ID:      types.ResourceID(types.DomainHash("test/mempool/resource/" + string(rune('0'+index)))),
			Version: resource.Version0,
			Owner:   owner,
			Asset:   types.NativeAssetID(),
			Amount:  1_000,
		}
	}
	preState, err := state.New(resources)
	if err != nil {
		t.Fatal(err)
	}
	transactions := make([]outcome.Transaction, count)
	for index := range count {
		var nonce [32]byte
		nonce[31] = byte(index + 1)
		transactions[index], err = wallet.BuildNativeTransfer(preState, keys[index], wallet.TransferRequest{
			NetworkID:     testNetworkID,
			CurrentHeight: 0,
			ValidFor:      100,
			Recipient:     types.Address(types.DomainHash("test/mempool/recipient")),
			Amount:        10,
			Fee:           fees[index],
			Nonce:         nonce,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return transactionFixture{state: preState, transactions: transactions}
}

func entryFees(entries []Entry) []uint64 {
	result := make([]uint64, len(entries))
	for index, entry := range entries {
		result[index] = entry.Fee
	}
	return result
}
