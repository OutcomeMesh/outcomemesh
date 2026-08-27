package state

import (
	"errors"
	"fmt"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrDuplicateResource = errors.New("duplicate resource")
	ErrResourceNotFound  = errors.New("resource not found")
	ErrResourceExists    = errors.New("resource already exists")
	ErrBalanceOverflow   = errors.New("balance overflow")
)

// Memory is the deterministic, immutable-by-convention reference state used by
// the first protocol milestone. Its fields are private and every state change
// returns a new value, so failed transaction execution cannot partially mutate
// the pre-state.
type Memory struct {
	resources map[types.ResourceID]resource.Resource
}

func Empty() *Memory {
	return &Memory{resources: make(map[types.ResourceID]resource.Resource)}
}

func New(resources []resource.Resource) (*Memory, error) {
	result := Empty()
	for index, value := range resources {
		if err := value.Validate(); err != nil {
			return nil, fmt.Errorf("resource %d: %w", index, err)
		}
		if _, exists := result.resources[value.ID]; exists {
			return nil, fmt.Errorf("resource %d: %w: %s", index, ErrDuplicateResource, value.ID)
		}
		result.resources[value.ID] = value
	}
	return result, nil
}

func (state *Memory) Len() int {
	if state == nil {
		return 0
	}
	return len(state.resources)
}

func (state *Memory) Get(id types.ResourceID) (resource.Resource, bool) {
	if state == nil {
		return resource.Resource{}, false
	}
	value, exists := state.resources[id]
	return value, exists
}

// Resources returns a detached snapshot sorted by resource identifier.
func (state *Memory) Resources() []resource.Resource {
	if state == nil {
		return nil
	}

	result := make([]resource.Resource, 0, len(state.resources))
	for _, value := range state.resources {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool {
		return types.CompareResourceID(result[left].ID, result[right].ID) < 0
	})
	return result
}

func (state *Memory) Balance(owner types.Address, asset types.AssetID) (uint64, error) {
	return state.balance(owner, asset, nil)
}

// SpendableBalance excludes resources whose spend-after height has not arrived.
// Balance intentionally remains the total amount committed to the owner.
func (state *Memory) SpendableBalance(owner types.Address, asset types.AssetID, height uint64) (uint64, error) {
	return state.balance(owner, asset, &height)
}

func (state *Memory) balance(owner types.Address, asset types.AssetID, height *uint64) (uint64, error) {
	if state == nil {
		return 0, nil
	}

	var balance uint64
	for _, value := range state.resources {
		if value.Owner != owner || value.Asset != asset {
			continue
		}
		if height != nil && value.SpendAfter > *height {
			continue
		}
		var err error
		balance, err = types.AddAmount(balance, value.Amount)
		if err != nil {
			return 0, fmt.Errorf("%w for owner %s and asset %s", ErrBalanceOverflow, owner, asset)
		}
	}
	return balance, nil
}

func (state *Memory) Root() types.Hash {
	resources := state.Resources()
	if len(resources) == 0 {
		return types.DomainHash(types.DomainStateEmpty)
	}

	level := make([]types.Hash, len(resources))
	for index, value := range resources {
		level[index] = types.DomainHash(types.DomainStateLeaf, value.CanonicalBytes())
	}

	for len(level) > 1 {
		next := make([]types.Hash, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			left := level[index]
			right := left
			if index+1 < len(level) {
				right = level[index+1]
			}
			next = append(next, types.DomainHash(types.DomainStateNode, left[:], right[:]))
		}
		level = next
	}
	return level[0]
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
		if _, exists := state.resources[id]; !exists {
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
		if _, exists := state.resources[value.ID]; exists {
			return nil, fmt.Errorf("created resource %d: %w: %s", index, ErrResourceExists, value.ID)
		}
	}

	result := &Memory{resources: make(map[types.ResourceID]resource.Resource, len(state.resources)-len(consumed)+len(created))}
	for id, value := range state.resources {
		result.resources[id] = value
	}
	for _, id := range consumed {
		delete(result.resources, id)
	}
	for _, value := range created {
		result.resources[value.ID] = value
	}
	return result, nil
}
