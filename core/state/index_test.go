package state

import (
	"fmt"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
)

// Deliberately retains the old flat-map commitment algorithm as an oracle.
func flatRoot(values map[types.ResourceID]resource.Resource) types.Hash {
	ids := make([]types.ResourceID, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return types.CompareResourceID(ids[i], ids[j]) < 0 })
	if len(ids) == 0 {
		return types.DomainHash(types.DomainStateEmpty)
	}
	hashes := make([]types.Hash, 0, len(ids))
	for _, id := range ids {
		hashes = append(hashes, types.DomainHash(types.DomainStateLeaf, values[id].CanonicalBytes()))
	}
	for len(hashes) > 1 {
		next := make([]types.Hash, 0, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			right := hashes[i]
			if i+1 < len(hashes) {
				right = hashes[i+1]
			}
			next = append(next, types.DomainHash(types.DomainStateNode, hashes[i][:], right[:]))
		}
		hashes = next
	}
	return hashes[0]
}
func checkTree[V any](t *testing.T, n *indexNode[V], lo, hi *string) (int, int) {
	t.Helper()
	if n == nil {
		return 0, 0
	}
	if lo != nil && n.key <= *lo || hi != nil && n.key >= *hi {
		t.Fatal("index order")
	}
	lh, ls := checkTree(t, n.left, lo, &n.key)
	rh, rs := checkTree(t, n.right, &n.key, hi)
	if lh-rh > 1 || rh-lh > 1 || n.height != max(lh, rh)+1 || n.size != ls+rs+1 {
		t.Fatal("AVL metadata/balance")
	}
	return n.height, n.size
}
func exerciseIndex(t *testing.T, data []byte) {
	t.Helper()
	s := Empty()
	oracle := map[types.ResourceID]resource.Resource{}
	owner := types.Address{1}
	asset := types.NativeAssetID()
	for i, b := range data {
		old := s
		root := flatRoot(oracle)
		var consumed []types.ResourceID
		if b%3 != 0 && len(oracle) > 0 {
			list := s.Resources()
			id := list[int(b)%len(list)].ID
			consumed = append(consumed, id)
			delete(oracle, id)
		}
		v := testResource(fmt.Sprintf("%d/%d", i, b), types.Address{1 + b%4}, asset, uint64(b)+1)
		v.SpendAfter = uint64(b % 7)
		next, err := s.WithChanges(consumed, []resource.Resource{v})
		if err != nil {
			t.Fatal(err)
		}
		oracle[v.ID] = v
		s = next
		if old.Root() != root || s.Root() != flatRoot(oracle) {
			t.Fatal("root changed vs v0 oracle or parent mutated")
		}
		checkTree(t, s.resources, nil, nil)
		checkTree(t, s.accounts, nil, nil)
		var total, spend uint64
		var selected []resource.Resource
		for _, v := range s.Resources() {
			if v.Owner == owner {
				total += v.Amount
				if v.SpendAfter <= 3 {
					spend += v.Amount
				}
				selected = append(selected, v)
			}
		}
		got, e := s.Balance(owner, asset)
		if e != nil || got != total {
			t.Fatal("balance mismatch")
		}
		got, e = s.SpendableBalance(owner, asset, 3)
		if e != nil || got != spend {
			t.Fatal("spendable mismatch")
		}
		if actual := s.ResourcesFor(owner, asset); len(actual) != len(selected) || (len(actual) > 0 && !reflect.DeepEqual(actual, selected)) {
			t.Fatal("account order mismatch")
		}
	}
}
func TestIndexRandomizedAgainstFlatState(t *testing.T) {
	r := rand.New(rand.NewSource(9302))
	b := make([]byte, 700)
	r.Read(b)
	exerciseIndex(t, b)
}
func FuzzIndexAgainstFlatState(f *testing.F) {
	f.Add([]byte{1, 5, 8, 0, 22, 99})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 128 {
			b = b[:128]
		}
		exerciseIndex(t, b)
	})
}
func TestOverflowRecoversAfterRemovalAndRootConcurrent(t *testing.T) {
	owner := types.Address{1}
	a := testResource("max", owner, types.NativeAssetID(), math.MaxUint64)
	b := testResource("one", owner, types.NativeAssetID(), 1)
	s, e := New([]resource.Resource{a, b})
	if e != nil {
		t.Fatal(e)
	}
	next, e := s.WithChanges([]types.ResourceID{b.ID}, nil)
	if e != nil {
		t.Fatal(e)
	}
	v, e := next.Balance(owner, a.Asset)
	if e != nil || v != math.MaxUint64 {
		t.Fatal(v, e)
	}
	if _, e = s.Balance(owner, a.Asset); e == nil {
		t.Fatal("parent overflow lost")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				if next.Root() != flatRoot(map[types.ResourceID]resource.Resource{a.ID: a}) {
					t.Error("concurrent root")
				}
			}
		})
	}
	wg.Wait()
}
func BenchmarkIndexedState(b *testing.B) {
	for _, count := range []int{1000, 100000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			values := make([]resource.Resource, count)
			for i := range values {
				values[i] = testResource(fmt.Sprint(i), types.Address{byte(i%251 + 1)}, types.NativeAssetID(), 1)
			}
			s, e := New(values)
			if e != nil {
				b.Fatal(e)
			}
			created := testResource("fresh", types.Address{1}, types.NativeAssetID(), 1)
			b.Run("diff", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, e := s.WithChanges([]types.ResourceID{values[0].ID}, []resource.Resource{created}); e != nil {
						b.Fatal(e)
					}
				}
			})
			b.Run("balance", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_, _ = s.Balance(types.Address{1}, types.NativeAssetID())
				}
			})
			b.Run("changed-root", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					next, _ := s.WithChanges([]types.ResourceID{values[0].ID}, []resource.Resource{created})
					_ = next.Root()
				}
			})
		})
	}
}
