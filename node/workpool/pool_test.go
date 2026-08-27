package workpool

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func TestOutOfOrderSharesResolveAndBuildExactAnchorClosure(t *testing.T) {
	t.Parallel()

	validation := testContext()
	pool, err := New(validation)
	if err != nil {
		t.Fatal(err)
	}
	parent := mineWeakOnly(t, testShare(validation, "parent", nil))
	parentID, _ := parent.ID()
	child := mineWeakOnly(t, testShare(validation, "child", []types.Hash{parentID}))
	childID, _ := child.ID()
	if _, err := pool.Add(child); err != nil {
		t.Fatal(err)
	}
	if status := pool.Status(); status.Pending != 1 || status.Accepted != 0 {
		t.Fatalf("child-first status=%+v", status)
	}
	if _, err := pool.Add(parent); err != nil {
		t.Fatal(err)
	}
	if status := pool.Status(); status.Pending != 0 || status.Accepted != 2 || status.Tips != 1 {
		t.Fatalf("resolved status=%+v", status)
	}
	parents := pool.Parents()
	if len(parents) != 1 || parents[0] != childID {
		t.Fatalf("selected parents=%v", parents)
	}
	anchorTemplate := testShare(validation, "anchor", parents)
	anchor, _, err := workgraph.MineAnchor(context.Background(), anchorTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := pool.CommittedShares(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(committed) != 2 {
		t.Fatalf("committed shares=%d", len(committed))
	}
	batch, err := workgraph.ValidateCommittedBatch(validationWithMiner(validation, anchor.Miner), anchor, committed)
	if err != nil || batch.Len() != 2 {
		t.Fatalf("committed batch len=%d err=%v", batch.Len(), err)
	}
}

func TestInventoryMissingAndBodiesStayCanonicalAndDetached(t *testing.T) {
	t.Parallel()

	validation := testContext()
	pool, _ := New(validation)
	first := mineWeakOnly(t, testShare(validation, "first", nil))
	second := mineWeakOnly(t, testShare(validation, "second", nil))
	firstID, _ := pool.Add(first)
	secondID, _ := pool.Add(second)
	ids := pool.Inventory(10)
	if len(ids) != 2 || types.CompareHash(ids[0], ids[1]) >= 0 {
		t.Fatalf("inventory=%v", ids)
	}
	unknown := types.DomainHash("test/workpool/unknown")
	request := []types.Hash{firstID, secondID, unknown}
	sort.Slice(request, func(left, right int) bool { return types.CompareHash(request[left], request[right]) < 0 })
	missing, err := pool.Missing(request, 256)
	if err != nil || len(missing) != 1 || missing[0] != unknown {
		t.Fatalf("missing=%v err=%v", missing, err)
	}
	bodies, err := pool.Shares(ids)
	if err != nil || len(bodies) != 2 {
		t.Fatalf("bodies=%d err=%v", len(bodies), err)
	}
	bodies[0].Parents = append(bodies[0].Parents, unknown)
	if again, _ := pool.Shares(ids[:1]); len(again[0].Parents) != 0 {
		t.Fatal("returned share aliases pool storage")
	}
	if _, err := pool.Add(first); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate error=%v", err)
	}
}

func TestPoolRejectsHardAnchorAndReservesAnchorMinerSlot(t *testing.T) {
	t.Parallel()

	validation := testContext()
	pool, _ := New(validation)
	hardTemplate := testShare(validation, "hard", nil)
	hard, _, err := workgraph.MineAnchor(context.Background(), hardTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Add(hard); !errors.Is(err, ErrAnchorShare) {
		t.Fatalf("hard share error=%v", err)
	}
	for index := 0; index < workgraph.MaxRewardMiners-1; index++ {
		share := testShare(validation, string(rune(index+1)), nil)
		share.Miner = types.Address(types.DomainHash("test/workpool/distinct-miner", []byte{byte(index)}))
		share = mineWeakOnly(t, share)
		if _, err := pool.Add(share); err != nil {
			t.Fatalf("miner %d: %v", index, err)
		}
	}
	extra := testShare(validation, "extra-miner", nil)
	extra.Miner = types.Address(types.DomainHash("test/workpool/extra-miner"))
	extra = mineWeakOnly(t, extra)
	if _, err := pool.Add(extra); !errors.Is(err, ErrCapacity) {
		t.Fatalf("reserved anchor slot error=%v", err)
	}
}

func testContext() workgraph.Context {
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return workgraph.Context{
		NetworkID: 51, Height: 7, AnchorParent: types.DomainHash("test/workpool/anchor-parent"),
		AnchorTarget: target, PayloadRoot: types.DomainHash("test/workpool/payload"),
		AnchorMiner:     types.Address(types.DomainHash("test/workpool/anchor-miner")),
		AnchorTimestamp: 1_700_000_100, MedianTimePast: 1_700_000_000,
	}
}

func testShare(validation workgraph.Context, label string, parents []types.Hash) workgraph.Share {
	inclusion, _ := workgraph.InclusionRoot(nil)
	return workgraph.Share{
		Version: workgraph.Version0, NetworkID: validation.NetworkID, Height: validation.Height,
		AnchorParent: validation.AnchorParent, Timestamp: validation.AnchorTimestamp,
		Target: validation.AnchorTarget, PayloadRoot: validation.PayloadRoot,
		Miner:         types.Address(types.DomainHash("test/workpool/miner", []byte(label))),
		InclusionRoot: inclusion, Parents: append([]types.Hash(nil), parents...),
	}
}

func mineWeakOnly(t testing.TB, template workgraph.Share) workgraph.Share {
	t.Helper()
	for start := uint64(0); ; start++ {
		candidate := template
		candidate.Nonce = start
		id, err := candidate.ID()
		if err != nil {
			t.Fatal(err)
		}
		meets, err := workgraph.MeetsAnchor(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !meets {
			_ = id
			return candidate
		}
	}
}

func validationWithMiner(validation workgraph.Context, miner types.Address) workgraph.Context {
	validation.AnchorMiner = miner
	return validation
}
