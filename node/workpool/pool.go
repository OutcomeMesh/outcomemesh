package workpool

import (
	"errors"
	"math"
	"sort"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

var (
	ErrContext       = errors.New("invalid WorkGraph pool context")
	ErrDuplicate     = errors.New("duplicate WorkGraph pool share")
	ErrCapacity      = errors.New("WorkGraph pool capacity exceeded")
	ErrAnchorShare   = errors.New("hard anchor must use the block path")
	ErrUnknownParent = errors.New("anchor references an unknown WorkGraph tip")
)

type Status struct {
	Shares         int
	Accepted       int
	Pending        int
	CanonicalBytes int
	DistinctMiners int
	Tips           int
}

type entry struct {
	share    workgraph.Share
	id       types.Hash
	missing  int
	accepted bool
	coverage uint64
}

// Pool owns detached shares. At most MaxRewardMiners-1 weak-share identities
// are admitted, reserving one consensus slot for an unknown future anchor.
type Pool struct {
	mu         sync.RWMutex
	context    workgraph.Context
	generation uint64
	entries    map[types.Hash]*entry
	waiting    map[types.Hash][]types.Hash
	tips       map[types.Hash]struct{}
	miners     map[types.Address]int
	bytes      int
	accepted   int
}

func New(context workgraph.Context) (*Pool, error) {
	if context.NetworkID == 0 || context.Height == 0 || context.AnchorParent.IsZero() ||
		context.AnchorTarget.IsZero() || context.PayloadRoot.IsZero() || context.AnchorTimestamp == 0 ||
		context.MedianTimePast == 0 || context.AnchorTimestamp <= context.MedianTimePast ||
		!workgraph.ExactShareRatio(context.AnchorTarget) {
		return nil, ErrContext
	}
	context.AnchorMiner = types.Address{}
	return &Pool{
		context: context, entries: make(map[types.Hash]*entry),
		waiting: make(map[types.Hash][]types.Hash), tips: make(map[types.Hash]struct{}),
		miners: make(map[types.Address]int),
	}, nil
}

func (pool *Pool) Context() workgraph.Context {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.context
}

func (pool *Pool) Add(share workgraph.Share) (types.Hash, error) {
	if pool == nil {
		return types.Hash{}, ErrContext
	}
	share.Parents = append([]types.Hash(nil), share.Parents...)
	// Validation is deliberately outside the write lock because proof checking
	// hashes the full share. A generation check makes admission linearizable
	// with a same-parent timestamp rollover: if the context moved meanwhile,
	// the share is validated again before it can enter the pool.
	for {
		pool.mu.RLock()
		context := pool.context
		generation := pool.generation
		pool.mu.RUnlock()
		if err := workgraph.ValidateShare(context, share); err != nil {
			pool.mu.RLock()
			unchanged := generation == pool.generation
			pool.mu.RUnlock()
			if unchanged {
				return types.Hash{}, err
			}
			continue
		}
		hard, err := workgraph.MeetsAnchor(share)
		if err != nil {
			return types.Hash{}, err
		}
		if hard {
			return types.Hash{}, ErrAnchorShare
		}
		id, err := share.ID()
		if err != nil {
			return types.Hash{}, err
		}
		encodedBytes := len(share.CanonicalBytes())

		pool.mu.Lock()
		if generation != pool.generation {
			pool.mu.Unlock()
			continue
		}
		if _, exists := pool.entries[id]; exists {
			pool.mu.Unlock()
			return types.Hash{}, ErrDuplicate
		}
		if len(pool.entries) >= workgraph.MaxShares || pool.bytes > workgraph.MaxBatchCanonicalBytes-encodedBytes {
			pool.mu.Unlock()
			return types.Hash{}, ErrCapacity
		}
		if pool.miners[share.Miner] == 0 && len(pool.miners) >= workgraph.MaxRewardMiners-1 {
			pool.mu.Unlock()
			return types.Hash{}, ErrCapacity
		}
		item := &entry{share: share, id: id}
		pool.entries[id] = item
		pool.bytes += encodedBytes
		pool.miners[share.Miner]++
		for _, parent := range share.Parents {
			parentEntry, exists := pool.entries[parent]
			if !exists || !parentEntry.accepted {
				item.missing++
				pool.waiting[parent] = append(pool.waiting[parent], id)
			}
		}
		if item.missing == 0 {
			pool.acceptLocked(item)
		}
		pool.mu.Unlock()
		return id, nil
	}
}

// RollForward advances only the winner timestamp horizon for the same parent,
// target, payload and MTP. The operation retains the exact DAG and atomically
// changes the validation generation seen by concurrent admissions. Advancing
// the horizon cannot invalidate an already admitted share, but all entries are
// nevertheless revalidated defensively before the new context is published.
func (pool *Pool) RollForward(context workgraph.Context) error {
	if pool == nil {
		return ErrContext
	}
	context.AnchorMiner = types.Address{}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	current := pool.context
	if !sameRoundContext(current, context) || context.AnchorTimestamp <= current.AnchorTimestamp ||
		context.AnchorTimestamp <= context.MedianTimePast || pool.generation == math.MaxUint64 {
		return ErrContext
	}
	for _, item := range pool.entries {
		if err := workgraph.ValidateShare(context, item.share); err != nil {
			return ErrContext
		}
	}
	pool.context = context
	pool.generation++
	return nil
}

// IDs snapshots every admitted share ID in canonical increasing order. It is
// a local handoff primitive used to reseed bounded gossip after a timestamp
// generation changes; network inventories remain capped separately.
func (pool *Pool) IDs() []types.Hash {
	if pool == nil {
		return nil
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	ids := make([]types.Hash, 0, len(pool.entries))
	for id := range pool.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return types.CompareHash(ids[left], ids[right]) < 0 })
	return ids
}

func (pool *Pool) Status() Status {
	if pool == nil {
		return Status{}
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return Status{
		Shares: len(pool.entries), Accepted: pool.accepted,
		Pending: len(pool.entries) - pool.accepted, CanonicalBytes: pool.bytes,
		DistinctMiners: len(pool.miners), Tips: len(pool.tips),
	}
}

// Inventory returns at most limit IDs in strict increasing order. Both
// accepted and pending valid-PoW shares are announced so peers can recover a
// missing ancestor named by a child body.
func (pool *Pool) Inventory(limit int) []types.Hash {
	if pool == nil || limit <= 0 {
		return nil
	}
	if limit > 1_024 {
		limit = 1_024
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	ids := make([]types.Hash, 0, min(limit, len(pool.entries)))
	for id := range pool.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return types.CompareHash(ids[left], ids[right]) < 0 })
	if len(ids) > limit {
		ids = ids[:limit]
	}
	return ids
}

// Known validates that a sorted bounded inventory names shares owned by this
// pool. It lets a relay advertise an explicit unpublished subset without
// trusting caller-supplied IDs or copying share bodies up front.
func (pool *Pool) Known(ids []types.Hash) error {
	if pool == nil || len(ids) == 0 || len(ids) > 1_024 {
		return ErrCapacity
	}
	if err := validateSortedIDs(ids); err != nil {
		return err
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	for _, id := range ids {
		if _, exists := pool.entries[id]; !exists {
			return ErrUnknownParent
		}
	}
	return nil
}

// Missing filters a sorted peer inventory down to unknown IDs.
func (pool *Pool) Missing(ids []types.Hash, limit int) ([]types.Hash, error) {
	if pool == nil || limit <= 0 || limit > 256 || len(ids) > 1_024 {
		return nil, ErrCapacity
	}
	if err := validateSortedIDs(ids); err != nil {
		return nil, err
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	result := make([]types.Hash, 0, min(limit, len(ids)))
	for _, id := range ids {
		if _, exists := pool.entries[id]; !exists {
			result = append(result, id)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

// Shares returns detached bodies in the request's already canonical ID order.
func (pool *Pool) Shares(ids []types.Hash) ([]workgraph.Share, error) {
	if pool == nil || len(ids) == 0 || len(ids) > 256 {
		return nil, ErrCapacity
	}
	if err := validateSortedIDs(ids); err != nil {
		return nil, err
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	result := make([]workgraph.Share, 0, len(ids))
	for _, id := range ids {
		item, exists := pool.entries[id]
		if !exists {
			continue
		}
		share := item.share
		share.Parents = append([]types.Hash(nil), share.Parents...)
		result = append(result, share)
	}
	return result, nil
}

// Parents selects at most four accepted tips by a saturating additive ancestor
// coverage score, then Work ID. The score is bounded O(parents) admission
// policy rather than an exact closure scan and is deterministic for one view.
func (pool *Pool) Parents() []types.Hash {
	if pool == nil {
		return nil
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	tips := make([]types.Hash, 0, len(pool.tips))
	for tip := range pool.tips {
		tips = append(tips, tip)
	}
	sort.Slice(tips, func(left, right int) bool {
		leftCoverage := pool.entries[tips[left]].coverage
		rightCoverage := pool.entries[tips[right]].coverage
		if leftCoverage != rightCoverage {
			return leftCoverage > rightCoverage
		}
		return types.CompareHash(tips[left], tips[right]) < 0
	})
	if len(tips) > workgraph.MaxParents {
		tips = tips[:workgraph.MaxParents]
	}
	return tips
}

// CommittedShares returns the exact canonical closure named by a hard anchor.
func (pool *Pool) CommittedShares(anchor workgraph.Share) ([]workgraph.Share, error) {
	if pool == nil {
		return nil, ErrContext
	}
	pool.mu.RLock()
	closure := make([]workgraph.Share, 0, len(pool.entries))
	seen := make(map[types.Hash]struct{}, len(pool.entries))
	stack := append([]types.Hash(nil), anchor.Parents...)
	for len(stack) > 0 {
		last := len(stack) - 1
		id := stack[last]
		stack = stack[:last]
		if _, exists := seen[id]; exists {
			continue
		}
		item, exists := pool.entries[id]
		if !exists || !item.accepted {
			pool.mu.RUnlock()
			return nil, ErrUnknownParent
		}
		seen[id] = struct{}{}
		share := item.share
		share.Parents = append([]types.Hash(nil), share.Parents...)
		closure = append(closure, share)
		stack = append(stack, share.Parents...)
	}
	context := pool.context
	pool.mu.RUnlock()
	context.AnchorMiner = anchor.Miner
	canonical, err := workgraph.Canonicalize(context, closure)
	if err != nil {
		return nil, err
	}
	batch, err := workgraph.ValidateCommittedBatch(context, anchor, canonical)
	if err != nil {
		return nil, err
	}
	return batch.Shares(), nil
}

func (pool *Pool) acceptLocked(item *entry) {
	if item.accepted {
		return
	}
	item.accepted = true
	item.coverage = 1
	for _, parent := range item.share.Parents {
		parentCoverage := pool.entries[parent].coverage
		if item.coverage > math.MaxUint64-parentCoverage {
			item.coverage = math.MaxUint64
			break
		}
		item.coverage += parentCoverage
	}
	pool.accepted++
	for _, parent := range item.share.Parents {
		delete(pool.tips, parent)
	}
	pool.tips[item.id] = struct{}{}
	children := pool.waiting[item.id]
	delete(pool.waiting, item.id)
	for _, childID := range children {
		child, exists := pool.entries[childID]
		if !exists || child.accepted || child.missing == 0 {
			continue
		}
		child.missing--
		if child.missing == 0 {
			pool.acceptLocked(child)
		}
	}
}

func validateSortedIDs(ids []types.Hash) error {
	if len(ids) == 0 {
		return ErrCapacity
	}
	for index, id := range ids {
		if id.IsZero() || (index > 0 && types.CompareHash(ids[index-1], id) >= 0) {
			return ErrDuplicate
		}
	}
	return nil
}

func sameRoundContext(left, right workgraph.Context) bool {
	left.AnchorMiner = types.Address{}
	right.AnchorMiner = types.Address{}
	left.AnchorTimestamp = 0
	right.AnchorTimestamp = 0
	return left == right
}
