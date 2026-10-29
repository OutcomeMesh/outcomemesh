package state

import (
	"errors"
	"fmt"
	"math/bits"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrCommitmentVersion = errors.New("unsupported or mismatched state commitment version")
	ErrDuplicateResource = errors.New("duplicate resource")
	ErrResourceNotFound  = errors.New("resource not found")
	ErrResourceExists    = errors.New("resource already exists")
	ErrBalanceOverflow   = errors.New("balance overflow")
)

// Memory is immutable. Resource and owner/asset indexes share unchanged AVL
// subtrees between snapshots; no mutation can leak into a parent or sibling.
// Root uses the explicitly selected commitment; v0 remains byte-compatible.
type Memory struct {
	version   uint16
	radix     *radixNode
	resources *indexNode[leaf]
	accounts  *indexNode[account]
	rootOnce  sync.Once
	root      types.Hash
}
type leaf struct {
	value resource.Resource
	hash  types.Hash
}
type account struct {
	resources *indexNode[leaf]
	low, high uint64
}

func accountKey(owner types.Address, asset types.AssetID) string {
	var key [64]byte
	copy(key[:32], owner[:])
	copy(key[32:], asset[:])
	return string(key[:])
}
func Empty() *Memory                                     { return &Memory{} }
func New(resources []resource.Resource) (*Memory, error) { return NewVersion(resources, CommitmentV0) }
func build(result *Memory, resources []resource.Resource) (*Memory, error) {
	for i, v := range resources {
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("resource %d: %w", i, err)
		}
		if _, exists := result.Get(v.ID); exists {
			return nil, fmt.Errorf("resource %d: %w: %s", i, ErrDuplicateResource, v.ID)
		}
		result.insert(v)
	}
	return result, nil
}
func (state *Memory) Len() int {
	if state == nil {
		return 0
	}
	return size(state.resources)
}
func (state *Memory) Get(id types.ResourceID) (resource.Resource, bool) {
	if state == nil {
		return resource.Resource{}, false
	}
	v, ok := find(state.resources, string(id[:]))
	return v.value, ok
}

// Resources returns a detached snapshot in the protocol's resource-ID order.
func (state *Memory) Resources() []resource.Resource {
	if state == nil {
		return nil
	}
	return resourceList(state.resources)
}
func resourceList(n *indexNode[leaf]) []resource.Resource {
	result := make([]resource.Resource, 0, size(n))
	walk(n, func(v leaf) { result = append(result, v.value) })
	return result
}

// ResourcesFor visits only the selected owner's asset, retaining the same
// deterministic input-selection order as filtering Resources().
func (state *Memory) ResourcesFor(owner types.Address, asset types.AssetID) []resource.Resource {
	if state == nil {
		return nil
	}
	a, _ := find(state.accounts, accountKey(owner, asset))
	return resourceList(a.resources)
}
func (state *Memory) Balance(owner types.Address, asset types.AssetID) (uint64, error) {
	if state == nil {
		return 0, nil
	}
	a, _ := find(state.accounts, accountKey(owner, asset))
	if a.high != 0 {
		return 0, balanceError(owner, asset)
	}
	return a.low, nil
}
func balanceError(owner types.Address, asset types.AssetID) error {
	return fmt.Errorf("%w for owner %s and asset %s", ErrBalanceOverflow, owner, asset)
}

// SpendableBalance excludes future resources and scans only the selected account.
func (state *Memory) SpendableBalance(owner types.Address, asset types.AssetID, h uint64) (uint64, error) {
	if state == nil {
		return 0, nil
	}
	a, _ := find(state.accounts, accountKey(owner, asset))
	var total uint64
	var overflow bool
	walk(a.resources, func(v leaf) {
		if v.value.SpendAfter <= h {
			next, carry := bits.Add64(total, v.value.Amount, 0)
			total = next
			overflow = overflow || carry != 0
		}
	})
	if overflow {
		return 0, balanceError(owner, asset)
	}
	return total, nil
}
func (state *Memory) Root() types.Hash {
	if state == nil {
		return types.DomainHash(types.DomainStateEmpty)
	}
	state.rootOnce.Do(func() {
		if state.version == CommitmentRadixV1 {
			state.root = radixRoot(state.radix)
			return
		}
		if state.Len() == 0 {
			state.root = types.DomainHash(types.DomainStateEmpty)
			return
		}
		level := make([]types.Hash, 0, state.Len())
		walk(state.resources, func(v leaf) { level = append(level, v.hash) })
		for len(level) > 1 {
			count := (len(level) + 1) / 2
			for i := 0; i < count; i++ {
				left := level[2*i]
				right := left
				if 2*i+1 < len(level) {
					right = level[2*i+1]
				}
				level[i] = types.DomainHash(types.DomainStateNode, left[:], right[:])
			}
			level = level[:count]
		}
		state.root = level[0]
	})
	return state.root
}

// insert/erase operate only on a newly allocated Memory. All shared tree nodes
// and cached resource hashes remain immutable. A 128-bit aggregate preserves
// overflow detection even when a later diff removes resources from that account.
func (state *Memory) insert(value resource.Resource) {
	if state.version == CommitmentRadixV1 {
		state.radix = radixInsert(state.radix, radixLeaf(value))
	}
	v := leaf{value: value, hash: types.DomainHash(types.DomainStateLeaf, value.CanonicalBytes())}
	key := string(value.ID[:])
	group := accountKey(value.Owner, value.Asset)
	a, _ := find(state.accounts, group)
	var carry uint64
	a.low, carry = bits.Add64(a.low, value.Amount, 0)
	a.high += carry
	a.resources = put(a.resources, key, v)
	state.accounts = put(state.accounts, group, a)
	state.resources = put(state.resources, key, v)
}
func (state *Memory) erase(value resource.Resource) {
	if state.version == CommitmentRadixV1 {
		state.radix = radixRemove(state.radix, value.ID)
	}
	key := string(value.ID[:])
	group := accountKey(value.Owner, value.Asset)
	a, _ := find(state.accounts, group)
	var borrow uint64
	a.low, borrow = bits.Sub64(a.low, value.Amount, 0)
	a.high -= borrow
	a.resources = remove(a.resources, key)
	if a.resources == nil {
		state.accounts = remove(state.accounts, group)
	} else {
		state.accounts = put(state.accounts, group, a)
	}
	state.resources = remove(state.resources, key)
}

// WithChanges validates a complete diff against the pre-state and returns a
// new state. Created identifiers may not collide with any pre-state resource,
// including one consumed by the same diff.
func (state *Memory) WithChanges(consumed []types.ResourceID, created []resource.Resource) (*Memory, error) {
	if state == nil {
		state = Empty()
	}

	consumedSet := make(map[types.ResourceID]struct{}, len(consumed))
	for index, id := range consumed {
		if _, duplicate := consumedSet[id]; duplicate {
			return nil, fmt.Errorf("consumed resource %d: %w: %s", index, ErrDuplicateResource, id)
		}
		consumedSet[id] = struct{}{}
		if _, exists := state.Get(id); !exists {
			return nil, fmt.Errorf("consumed resource %d: %w: %s", index, ErrResourceNotFound, id)
		}
	}

	createdSet := make(map[types.ResourceID]struct{}, len(created))
	for index, value := range created {
		if err := value.Validate(); err != nil {
			return nil, fmt.Errorf("created resource %d: %w", index, err)
		}
		if _, duplicate := createdSet[value.ID]; duplicate {
			return nil, fmt.Errorf("created resource %d: %w: %s", index, ErrDuplicateResource, value.ID)
		}
		createdSet[value.ID] = struct{}{}
		if _, exists := state.Get(value.ID); exists {
			return nil, fmt.Errorf("created resource %d: %w: %s", index, ErrResourceExists, value.ID)
		}
	}

	if len(consumed) == 0 && len(created) == 0 {
		return state, nil
	}
	result := &Memory{version: state.version, radix: state.radix, resources: state.resources, accounts: state.accounts}
	for _, id := range consumed {
		v, _ := state.Get(id)
		result.erase(v)
	}
	for _, value := range created {
		result.insert(value)
	}
	return result, nil
}
