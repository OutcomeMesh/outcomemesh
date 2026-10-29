package state

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

// A full sorted rebuild, independent of the incremental tree and its helpers.
func rebuiltRadix(values []resource.Resource) types.Hash {
	values = append([]resource.Resource(nil), values...)
	sort.Slice(values, func(i, j int) bool { return bytes.Compare(values[i].ID[:], values[j].ID[:]) < 0 })
	var walk func([]resource.Resource) types.Hash
	walk = func(v []resource.Resource) types.Hash {
		if len(v) == 0 {
			return types.DomainHash("OMESH/state/radix/v1/empty")
		}
		if len(v) == 1 {
			return types.DomainHash("OMESH/state/radix/v1/leaf", v[0].CanonicalBytes())
		}
		bit := 0
		for (v[0].ID[bit/8]>>uint(7-bit%8))&1 == (v[len(v)-1].ID[bit/8]>>uint(7-bit%8))&1 {
			bit++
		}
		split := sort.Search(len(v), func(i int) bool { return (v[i].ID[bit/8]>>uint(7-bit%8))&1 == 1 })
		var prefix [32]byte
		for i := 0; i < bit; i++ {
			prefix[i/8] |= v[0].ID[i/8] & (1 << uint(7-i%8))
		}
		var depth [2]byte
		binary.BigEndian.PutUint16(depth[:], uint16(bit))
		left, right := walk(v[:split]), walk(v[split:])
		return types.DomainHash("OMESH/state/radix/v1/branch", depth[:], prefix[:], left[:], right[:])
	}
	h := walk(values)
	return types.DomainHash("OMESH/state/radix/v1/root", h[:])
}
func exerciseRadix(t *testing.T, data []byte) {
	t.Helper()
	s, _ := EmptyVersion(CommitmentRadixV1)
	for i, b := range data {
		before := s
		oldRoot := s.Root()
		values := s.Resources()
		var consumed []types.ResourceID
		if b%3 != 0 && len(values) > 0 {
			consumed = []types.ResourceID{values[int(b)%len(values)].ID}
		}
		created := testResource(fmt.Sprintf("radix/%d/%d", i, b), types.Address{b%5 + 1}, types.NativeAssetID(), uint64(b)+1)
		next, e := s.WithChanges(consumed, []resource.Resource{created})
		if e != nil {
			t.Fatal(e)
		}
		s = next
		if s.CommitmentVersion() != CommitmentRadixV1 || s.Root() != rebuiltRadix(s.Resources()) || before.Root() != oldRoot {
			t.Fatal("commitment or parent mismatch")
		}
		shuffled := s.Resources()
		rand.New(rand.NewSource(int64(i))).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		other, e := NewVersion(shuffled, CommitmentRadixV1)
		if e != nil || other.Root() != s.Root() {
			t.Fatal("insertion order")
		}
		queries := []types.ResourceID{created.ID, {}, types.ResourceID(types.DomainHash("absent", []byte{b}))}
		queries = append(queries, consumed...)
		for _, q := range queries {
			p, e := s.Prove(q)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := p.CanonicalBytes()
			if e != nil {
				t.Fatal(e)
			}
			p, e = DecodeRadixProof(raw)
			if e != nil {
				t.Fatal(e)
			}
			v, ok, e := VerifyRadixProof(s.Root(), q, p)
			want, present := s.Get(q)
			if e != nil || ok != present || v != want {
				t.Fatalf("proof %v %v", ok, e)
			}
		}
	}
}
func TestRadixIncrementalRebuildAndProofs(t *testing.T) {
	r := rand.New(rand.NewSource(1103))
	b := make([]byte, 600)
	r.Read(b)
	exerciseRadix(t, b)
}
func FuzzRadixChanges(f *testing.F) {
	f.Add([]byte{0, 1, 255, 18, 22, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 96 {
			b = b[:96]
		}
		exerciseRadix(t, b)
	})
}
func TestRadixMaximumDepthAndCollapse(t *testing.T) {
	base := testResource("comb", types.Address{1}, types.NativeAssetID(), 1)
	for i := range base.ID {
		base.ID[i] = 0xff
	}
	values := []resource.Resource{base}
	for i := 0; i < 256; i++ {
		v := base
		v.ID[i/8] ^= 1 << uint(7-i%8)
		values = append(values, v)
	}
	s, e := NewVersion(values, CommitmentRadixV1)
	if e != nil {
		t.Fatal(e)
	}
	if s.Root() != rebuiltRadix(values) {
		t.Fatal("comb root")
	}
	p, e := s.Prove(base.ID)
	if e != nil || len(p.Steps) != 256 {
		t.Fatal("maximum depth", e, len(p.Steps))
	}
	if _, ok, e := VerifyRadixProof(s.Root(), base.ID, p); e != nil || !ok {
		t.Fatal("deep proof", e)
	}
	root := s.Root()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if s.Root() != root {
					t.Error("concurrent root")
				}
				s.Prove(base.ID)
			}
		}()
	}
	wg.Wait()
	for _, v := range values {
		s, e = s.WithChanges([]types.ResourceID{v.ID}, nil)
		if e != nil {
			t.Fatal(e)
		}
		if s.Root() != rebuiltRadix(s.Resources()) {
			t.Fatal("collapse root")
		}
	}
	if s.radix != nil || s.Len() != 0 {
		t.Fatal("nonempty tree")
	}
	p, e = s.Prove(base.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok, e := VerifyRadixProof(s.Root(), base.ID, p); e != nil || ok {
		t.Fatal("empty absence", e)
	}
}
func TestRadixPathSharingAndVersionBoundary(t *testing.T) {
	var values []resource.Resource
	for i := 0; i < 2048; i++ {
		values = append(values, testResource(fmt.Sprint(i), types.Address{1}, types.NativeAssetID(), 1))
	}
	s, _ := NewVersion(values, CommitmentRadixV1)
	var nodes = map[*radixNode]bool{}
	var collect func(*radixNode)
	collect = func(n *radixNode) {
		if n == nil {
			return
		}
		nodes[n] = true
		collect(n.left)
		collect(n.right)
	}
	collect(s.radix)
	changed, e := s.WithChanges([]types.ResourceID{values[0].ID}, nil)
	if e != nil {
		t.Fatal(e)
	}
	newNodes := 0
	var count func(*radixNode)
	count = func(n *radixNode) {
		if n == nil || nodes[n] {
			return
		}
		newNodes++
		count(n.left)
		count(n.right)
	}
	count(changed.radix)
	if newNodes > 256 || newNodes == 0 {
		t.Fatalf("path copy count %d", newNodes)
	}
	legacy, _ := New(values)
	if legacy.Root() == s.Root() {
		t.Fatal("version domains collide")
	}
	if _, e := legacy.Prove(values[0].ID); e == nil {
		t.Fatal("legacy proof accepted")
	}
	if _, e := NewVersion(values, 2); e == nil {
		t.Fatal("unsupported commitment")
	}
}
func TestRadixProofTampering(t *testing.T) {
	values := []resource.Resource{testResource("a", types.Address{1}, types.NativeAssetID(), 1), testResource("b", types.Address{1}, types.NativeAssetID(), 1), testResource("c", types.Address{1}, types.NativeAssetID(), 1)}
	s, _ := NewVersion(values, CommitmentRadixV1)
	q := values[0].ID
	p, _ := s.Prove(q)
	raw, _ := p.CanonicalBytes()
	for i := range raw {
		mut := append([]byte(nil), raw...)
		mut[i] ^= 0x80
		bad, e := DecodeRadixProof(mut)
		if e == nil {
			if _, _, e = VerifyRadixProof(s.Root(), q, bad); e == nil {
				t.Fatalf("accepted mutated byte %d", i)
			}
		}
	}
	for i := 0; i < len(raw); i++ {
		if _, e := DecodeRadixProof(raw[:i]); e == nil {
			t.Fatal("truncation", i)
		}
	}
	if _, e := DecodeRadixProof(append(raw, 0)); e == nil {
		t.Fatal("trailing byte")
	}
	// Membership cannot be converted into absence of that same query.
	other, _ := s.Prove(values[1].ID)
	other.Query = q
	if _, _, e := VerifyRadixProof(s.Root(), q, other); e == nil {
		t.Fatal("false absence")
	}
	p.Steps = append(p.Steps, p.Steps[len(p.Steps)-1])
	if _, e := p.CanonicalBytes(); e == nil {
		t.Fatal("duplicate depth")
	}
}
func FuzzRadixProofDecode(f *testing.F) {
	s, _ := EmptyVersion(CommitmentRadixV1)
	p, _ := s.Prove(types.ResourceID{1})
	raw, _ := p.CanonicalBytes()
	f.Add(raw)
	values := []resource.Resource{testResource("proof-a", types.Address{1}, types.NativeAssetID(), 1), testResource("proof-b", types.Address{1}, types.NativeAssetID(), 2), testResource("proof-c", types.Address{1}, types.NativeAssetID(), 3)}
	tree, _ := NewVersion(values, CommitmentRadixV1)
	for _, query := range []types.ResourceID{values[0].ID, {9}} {
		proof, _ := tree.Prove(query)
		encoded, _ := proof.CanonicalBytes()
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := DecodeRadixProof(b)
		if e != nil {
			return
		}
		raw, e := p.CanonicalBytes()
		if e != nil || !bytes.Equal(raw, b) {
			t.Fatal("noncanonical proof")
		}
		root, e := p.root()
		if e != nil {
			t.Fatal(e)
		}
		if _, _, e = VerifyRadixProof(root, p.Query, p); e != nil {
			t.Fatal(e)
		}
	})
}
func BenchmarkRadixChangeAndRoot(b *testing.B) {
	for _, n := range []int{1000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			values := make([]resource.Resource, n)
			for i := range values {
				values[i] = testResource(fmt.Sprint(i), types.Address{1}, types.NativeAssetID(), 1)
			}
			s, _ := NewVersion(values, CommitmentRadixV1)
			replacement := testResource("new", types.Address{2}, types.NativeAssetID(), 1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				next, e := s.WithChanges([]types.ResourceID{values[i%n].ID}, []resource.Resource{replacement})
				if e != nil {
					b.Fatal(e)
				}
				_ = next.Root()
			}
		})
	}
}
