package state

import (
	"errors"
	"math"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func testResource(label string, owner types.Address, asset types.AssetID, amount uint64) resource.Resource {
	return resource.Resource{
		ID:      types.ResourceID(types.DomainHash("test/resource", []byte(label))),
		Version: resource.Version0,
		Owner:   owner,
		Asset:   asset,
		Amount:  amount,
	}
}

func TestRootIsIndependentOfInsertionOrder(t *testing.T) {
	t.Parallel()

	owner := types.Address(types.DomainHash("test/owner", []byte("alice")))
	asset := types.NativeAssetID()
	first := testResource("first", owner, asset, 7)
	second := testResource("second", owner, asset, 9)
	third := testResource("third", owner, asset, 11)

	left, err := New([]resource.Resource{first, second, third})
	if err != nil {
		t.Fatal(err)
	}
	right, err := New([]resource.Resource{third, first, second})
	if err != nil {
		t.Fatal(err)
	}

	if left.Root() != right.Root() {
		t.Fatalf("roots differ: %s != %s", left.Root(), right.Root())
	}
	if got, want := left.Resources()[0].ID, minResourceID(first.ID, second.ID, third.ID); got != want {
		t.Fatalf("snapshot is not sorted: got %s want %s", got, want)
	}
	const wantRoot = "69790007c85c9e268e4abeeebfe44a8ff80824ce4bae80e4646d57adf57a4f4b"
	if got := left.Root().String(); got != wantRoot {
		t.Fatalf("reference state root changed: got %s want %s", got, wantRoot)
	}
}

func TestEmptyRoot(t *testing.T) {
	t.Parallel()

	want := types.DomainHash(types.DomainStateEmpty)
	if got := Empty().Root(); got != want {
		t.Fatalf("empty root: got %s want %s", got, want)
	}
}

func TestWithChangesDoesNotMutatePreState(t *testing.T) {
	t.Parallel()

	owner := types.Address(types.DomainHash("test/owner", []byte("alice")))
	asset := types.NativeAssetID()
	consumed := testResource("consumed", owner, asset, 12)
	created := testResource("created", owner, asset, 12)
	before, err := New([]resource.Resource{consumed})
	if err != nil {
		t.Fatal(err)
	}
	beforeRoot := before.Root()

	after, err := before.WithChanges([]types.ResourceID{consumed.ID}, []resource.Resource{created})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := before.Get(consumed.ID); !exists {
		t.Fatal("pre-state was mutated")
	}
	if before.Root() != beforeRoot {
		t.Fatal("pre-state root changed")
	}
	if _, exists := after.Get(consumed.ID); exists {
		t.Fatal("consumed resource remains in post-state")
	}
	if _, exists := after.Get(created.ID); !exists {
		t.Fatal("created resource is absent from post-state")
	}
}

func TestWithChangesRejectsCollisionBeforeDeleting(t *testing.T) {
	t.Parallel()

	owner := types.Address(types.DomainHash("test/owner", []byte("alice")))
	value := testResource("same", owner, types.NativeAssetID(), 1)
	before, err := New([]resource.Resource{value})
	if err != nil {
		t.Fatal(err)
	}

	_, err = before.WithChanges([]types.ResourceID{value.ID}, []resource.Resource{value})
	if !errors.Is(err, ErrResourceExists) {
		t.Fatalf("got %v, want resource collision", err)
	}
}

func TestBalanceRejectsOverflow(t *testing.T) {
	t.Parallel()

	owner := types.Address(types.DomainHash("test/owner", []byte("alice")))
	asset := types.NativeAssetID()
	state, err := New([]resource.Resource{
		testResource("large", owner, asset, math.MaxUint64),
		testResource("overflow", owner, asset, 1),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := state.Balance(owner, asset); !errors.Is(err, ErrBalanceOverflow) {
		t.Fatalf("got %v, want balance overflow", err)
	}
}

func TestSpendableBalanceExcludesFutureResources(t *testing.T) {
	t.Parallel()

	owner := types.Address(types.DomainHash("test/owner", []byte("alice")))
	asset := types.NativeAssetID()
	available := testResource("available", owner, asset, 7)
	locked := testResource("locked", owner, asset, 11)
	locked.SpendAfter = 50
	value, err := New([]resource.Resource{available, locked})
	if err != nil {
		t.Fatal(err)
	}
	if total, err := value.Balance(owner, asset); err != nil || total != 18 {
		t.Fatalf("total balance = %d, %v; want 18", total, err)
	}
	if spendable, err := value.SpendableBalance(owner, asset, 49); err != nil || spendable != 7 {
		t.Fatalf("height-49 balance = %d, %v; want 7", spendable, err)
	}
	if spendable, err := value.SpendableBalance(owner, asset, 50); err != nil || spendable != 18 {
		t.Fatalf("height-50 balance = %d, %v; want 18", spendable, err)
	}
}

func TestNewRejectsDuplicateResource(t *testing.T) {
	t.Parallel()

	owner := types.Address(types.DomainHash("test/owner", []byte("alice")))
	value := testResource("duplicate", owner, types.NativeAssetID(), 1)
	if _, err := New([]resource.Resource{value, value}); !errors.Is(err, ErrDuplicateResource) {
		t.Fatalf("got %v, want duplicate resource", err)
	}
}

func minResourceID(values ...types.ResourceID) types.ResourceID {
	result := values[0]
	for _, value := range values[1:] {
		if types.CompareResourceID(value, result) < 0 {
			result = value
		}
	}
	return result
}
