package mempool

import (
	"bytes"
	"errors"
	"math/big"
	"sort"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/execution"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrPolicy           = errors.New("invalid mempool policy")
	ErrDuplicate        = errors.New("transaction already exists in mempool")
	ErrInputConflict    = errors.New("transaction input is reserved by mempool")
	ErrTransactionLarge = errors.New("transaction exceeds mempool per-item limit")
	ErrFeeTooLow        = errors.New("transaction fee is below mempool minimum")
	ErrCapacity         = errors.New("transaction does not outrank bounded mempool capacity")
)

type Policy struct {
	MaxTransactions int
	MaxBytes        int
	MaxTxBytes      int
	MinFee          uint64
}

func DefaultPolicy() Policy {
	return Policy{
		MaxTransactions: 10_000,
		MaxBytes:        64 << 20,
		MaxTxBytes:      1 << 20,
		MinFee:          1,
	}
}

type Entry struct {
	Transaction outcome.Transaction
	ID          types.Hash
	Size        int
	Fee         uint64
}

type Pool struct {
	mu       sync.RWMutex
	policy   Policy
	entries  map[types.Hash]Entry
	reserved map[types.ResourceID]types.Hash
	bytes    int
}

func New(policy Policy) (*Pool, error) {
	if policy.MaxTransactions <= 0 || policy.MaxBytes <= 0 || policy.MaxTxBytes <= 0 ||
		policy.MaxTxBytes > policy.MaxBytes {
		return nil, ErrPolicy
	}
	return &Pool{
		policy:   policy,
		entries:  make(map[types.Hash]Entry),
		reserved: make(map[types.ResourceID]types.Hash),
	}, nil
}

func (pool *Pool) Add(preState *state.Memory, transaction outcome.Transaction, context execution.Context) (types.Hash, error) {
	encoded := transaction.CanonicalBytes()
	if len(encoded) > pool.policy.MaxTxBytes {
		return types.Hash{}, ErrTransactionLarge
	}
	if transaction.Fee < pool.policy.MinFee {
		return types.Hash{}, ErrFeeTooLow
	}
	cloned, err := outcome.Decode(encoded)
	if err != nil {
		return types.Hash{}, err
	}
	if _, err := execution.ApplyTransition(preState, cloned, context); err != nil {
		return types.Hash{}, err
	}
	id, err := cloned.ID()
	if err != nil {
		return types.Hash{}, err
	}
	entry := Entry{Transaction: cloned, ID: id, Size: len(encoded), Fee: cloned.Fee}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if _, exists := pool.entries[id]; exists {
		return types.Hash{}, ErrDuplicate
	}
	for _, input := range cloned.Inputs {
		if _, exists := pool.reserved[input.ID]; exists {
			return types.Hash{}, ErrInputConflict
		}
	}
	if err := pool.makeRoom(entry); err != nil {
		return types.Hash{}, err
	}
	pool.insert(entry)
	return id, nil
}

func (pool *Pool) Len() int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return len(pool.entries)
}

func (pool *Pool) Bytes() int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.bytes
}

func (pool *Pool) Entries() []Entry {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	ordered := pool.sortedEntries(false)
	entries := make([]Entry, 0, len(ordered))
	for _, entry := range ordered {
		cloned, err := outcome.Decode(entry.Transaction.CanonicalBytes())
		if err != nil {
			continue
		}
		entry.Transaction = cloned
		entries = append(entries, entry)
	}
	return entries
}

// Select orders by fee rate, then fee, then transaction ID, and replays each
// candidate against the evolving template state. A policy-valid transaction
// can still be skipped when an earlier guard changes state it observes.
func (pool *Pool) Select(preState *state.Memory, context execution.Context, maxTransactions, maxBytes int) []outcome.Transaction {
	if preState == nil || maxTransactions <= 0 || maxBytes <= 0 {
		return nil
	}
	pool.mu.RLock()
	entries := pool.sortedEntries(false)
	pool.mu.RUnlock()

	current := preState
	selected := make([]outcome.Transaction, 0, min(maxTransactions, len(entries)))
	usedBytes := 0
	for _, entry := range entries {
		if len(selected) == maxTransactions {
			break
		}
		if entry.Size > maxBytes-usedBytes {
			continue
		}
		result, err := execution.ApplyTransition(current, entry.Transaction, context)
		if err != nil {
			continue
		}
		cloned, err := outcome.Decode(entry.Transaction.CanonicalBytes())
		if err != nil {
			continue
		}
		selected = append(selected, cloned)
		usedBytes += entry.Size
		current = result.State
	}
	return selected
}

// Revalidate is called after canonical-tip changes, including reorganizations.
// Conflicting survivors are resolved by the same deterministic priority order.
func (pool *Pool) Revalidate(preState *state.Memory, context execution.Context) []types.Hash {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	entries := pool.sortedEntries(false)
	pool.entries = make(map[types.Hash]Entry, len(entries))
	pool.reserved = make(map[types.ResourceID]types.Hash)
	pool.bytes = 0
	removed := make([]types.Hash, 0)
	for _, entry := range entries {
		if _, err := execution.ApplyTransition(preState, entry.Transaction, context); err != nil || pool.conflicts(entry) {
			removed = append(removed, entry.ID)
			continue
		}
		pool.insert(entry)
	}
	return removed
}

func (pool *Pool) RemoveCommitted(transactions []outcome.Transaction) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, transaction := range transactions {
		id, err := transaction.ID()
		if err != nil {
			continue
		}
		pool.remove(id)
	}
}

func (pool *Pool) makeRoom(candidate Entry) error {
	neededCount := len(pool.entries) + 1 - pool.policy.MaxTransactions
	neededBytes := pool.bytes + candidate.Size - pool.policy.MaxBytes
	if neededCount <= 0 && neededBytes <= 0 {
		return nil
	}
	victims := pool.sortedEntries(true)
	selected := make([]types.Hash, 0)
	freedBytes := 0
	for _, victim := range victims {
		if comparePriority(candidate, victim) <= 0 {
			return ErrCapacity
		}
		selected = append(selected, victim.ID)
		freedBytes += victim.Size
		if len(selected) >= neededCount && freedBytes >= neededBytes {
			break
		}
	}
	if len(selected) < neededCount || freedBytes < neededBytes {
		return ErrCapacity
	}
	for _, id := range selected {
		pool.remove(id)
	}
	return nil
}

func (pool *Pool) conflicts(entry Entry) bool {
	for _, input := range entry.Transaction.Inputs {
		if _, exists := pool.reserved[input.ID]; exists {
			return true
		}
	}
	return false
}

func (pool *Pool) insert(entry Entry) {
	pool.entries[entry.ID] = entry
	pool.bytes += entry.Size
	for _, input := range entry.Transaction.Inputs {
		pool.reserved[input.ID] = entry.ID
	}
}

func (pool *Pool) remove(id types.Hash) {
	entry, exists := pool.entries[id]
	if !exists {
		return
	}
	delete(pool.entries, id)
	pool.bytes -= entry.Size
	for _, input := range entry.Transaction.Inputs {
		if pool.reserved[input.ID] == id {
			delete(pool.reserved, input.ID)
		}
	}
}

func (pool *Pool) sortedEntries(ascending bool) []Entry {
	result := make([]Entry, 0, len(pool.entries))
	for _, entry := range pool.entries {
		result = append(result, entry)
	}
	sort.Slice(result, func(left, right int) bool {
		order := comparePriority(result[left], result[right])
		if ascending {
			return order < 0
		}
		return order > 0
	})
	return result
}

func comparePriority(left, right Entry) int {
	leftRate := new(big.Int).SetUint64(left.Fee)
	leftRate.Mul(leftRate, new(big.Int).SetUint64(uint64(right.Size)))
	rightRate := new(big.Int).SetUint64(right.Fee)
	rightRate.Mul(rightRate, new(big.Int).SetUint64(uint64(left.Size)))
	if order := leftRate.Cmp(rightRate); order != 0 {
		return order
	}
	if left.Fee < right.Fee {
		return -1
	}
	if left.Fee > right.Fee {
		return 1
	}
	// Smaller IDs win a consensus-style deterministic tie. Return positive for
	// the preferred entry because callers sort higher priority first.
	return -bytes.Compare(left.ID[:], right.ID[:])
}
