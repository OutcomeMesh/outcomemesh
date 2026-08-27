// Package reference provides the in-memory differential fork-aware ledger.
package reference

import (
	"sync"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

type Store struct {
	mu        sync.RWMutex
	closed    bool
	tip       storage.Tip
	nodes     map[types.Hash]storage.Tip
	states    map[types.Hash]*state.Memory
	blocks    map[types.Hash]block.Block
	canonical map[uint64]types.Hash
}

func New(document genesis.Document) (*Store, error) {
	tip, err := storage.GenesisTip(document)
	if err != nil {
		return nil, err
	}
	initialState, err := document.State()
	if err != nil {
		return nil, err
	}
	return &Store{
		tip:       tip,
		nodes:     map[types.Hash]storage.Tip{tip.ID: cloneTip(tip)},
		states:    map[types.Hash]*state.Memory{tip.ID: initialState},
		blocks:    make(map[types.Hash]block.Block),
		canonical: make(map[uint64]types.Hash),
	}, nil
}

func (store *Store) Tip() (storage.Tip, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	return cloneTip(store.tip), nil
}

func (store *Store) Snapshot() (*state.Memory, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return nil, storage.ErrClosed
	}
	return cloneState(store.states[store.tip.ID])
}

func (store *Store) TipByID(id types.Hash) (storage.Tip, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	tip, exists := store.nodes[id]
	if !exists {
		return storage.Tip{}, storage.ErrNodeNotFound
	}
	return cloneTip(tip), nil
}

func (store *Store) SnapshotAt(id types.Hash) (*state.Memory, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return nil, storage.ErrClosed
	}
	value, exists := store.states[id]
	if !exists {
		return nil, storage.ErrNodeNotFound
	}
	return cloneState(value)
}

func (store *Store) Block(height uint64) (block.Block, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return block.Block{}, storage.ErrClosed
	}
	id, exists := store.canonical[height]
	if !exists {
		return block.Block{}, storage.ErrBlockNotFound
	}
	return cloneBlock(store.blocks[id])
}

func (store *Store) BlockByID(id types.Hash) (block.Block, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return block.Block{}, storage.ErrClosed
	}
	value, exists := store.blocks[id]
	if !exists {
		return block.Block{}, storage.ErrBlockNotFound
	}
	return cloneBlock(value)
}

func (store *Store) Commit(parent storage.Tip, candidate block.Block, postState *state.Memory) (storage.Tip, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	storedParent, exists := store.nodes[parent.ID]
	if !exists {
		return storage.Tip{}, storage.ErrNodeNotFound
	}
	if !storage.EqualTips(parent, storedParent) {
		return storage.Tip{}, storage.ErrTipChanged
	}
	next, err := storage.ValidateChild(storedParent, candidate, postState)
	if err != nil {
		return storage.Tip{}, err
	}
	if _, exists := store.nodes[next.ID]; exists {
		return storage.Tip{}, storage.ErrBlockExists
	}
	stateCopy, err := cloneState(postState)
	if err != nil {
		return storage.Tip{}, err
	}
	blockCopy, err := cloneBlock(candidate)
	if err != nil {
		return storage.Tip{}, err
	}
	store.nodes[next.ID] = cloneTip(next)
	store.states[next.ID] = stateCopy
	store.blocks[next.ID] = blockCopy

	if storage.BetterTip(next, store.tip) {
		canonical, err := store.canonicalPath(next.ID)
		if err != nil {
			delete(store.nodes, next.ID)
			delete(store.states, next.ID)
			delete(store.blocks, next.ID)
			return storage.Tip{}, err
		}
		store.canonical = canonical
		store.tip = cloneTip(next)
	}
	return cloneTip(store.tip), nil
}

func (store *Store) canonicalPath(tipID types.Hash) (map[uint64]types.Hash, error) {
	result := make(map[uint64]types.Hash)
	cursor := tipID
	for {
		node, exists := store.nodes[cursor]
		if !exists {
			return nil, storage.ErrCorrupt
		}
		if node.Height == 0 {
			return result, nil
		}
		candidate, exists := store.blocks[cursor]
		if !exists || candidate.Header.Height != node.Height {
			return nil, storage.ErrCorrupt
		}
		result[node.Height] = cursor
		cursor = candidate.Header.Parent
	}
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closed = true
	return nil
}

func cloneTip(tip storage.Tip) storage.Tip {
	tip.CumulativeWork = append([]byte(nil), tip.CumulativeWork...)
	return tip
}

func cloneState(value *state.Memory) (*state.Memory, error) {
	if value == nil {
		return nil, storage.ErrCorrupt
	}
	return state.New(value.Resources())
}

func cloneBlock(value block.Block) (block.Block, error) {
	return block.Decode(value.CanonicalBytes())
}
