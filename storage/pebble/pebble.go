// Package pebblestore persists a fork-aware ledger using atomic Pebble batches.
package pebblestore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"
	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	keySchema  = []byte{0x01, 0x01}
	keyGenesis = []byte{0x01, 0x02}
	keyTip     = []byte{0x01, 0x03}

	resourceLower = []byte{0x10}
	resourceUpper = []byte{0x11}
	blockLower    = []byte{0x20}
	blockUpper    = []byte{0x21}
	blockPrefix   = byte(0x20) // canonical height -> block ID
	blockIDPrefix = byte(0x21) // block ID -> canonical block bytes
	nodePrefix    = byte(0x22) // block/genesis ID -> cumulative-work tip
	snapshotByte  = byte(0x30) // node ID + resource ID -> create/delete delta

	snapshotDelete = byte(0x00)
	snapshotCreate = byte(0x01)
)

const DefaultMaxHistoryBytes uint64 = 64 << 30

type Policy struct {
	// MaxHistoryBytes bounds immutable block, node, and resource-delta key/value
	// bytes. Pebble's WAL/LSM overhead is intentionally not part of this logical
	// accounting and needs a separate filesystem reserve in production.
	MaxHistoryBytes uint64
}

func DefaultPolicy() Policy {
	return Policy{MaxHistoryBytes: DefaultMaxHistoryBytes}
}

type Store struct {
	mu           sync.Mutex
	db           *pebble.DB
	policy       Policy
	historyBytes uint64
	closed       bool
	readOnly     bool
	commitHook   func(commitStage) error
}

type commitStage uint8

const (
	stageBeforeBatch commitStage = iota + 1
	stageAfterBlock
	stageAfterNode
	stageAfterSnapshot
	stageAfterStateDelete
	stageAfterResources
	stageAfterBlockIndex
	stageAfterTip
	stageBeforeCommit
	stageAfterCommit
)

func Open(path string, document genesis.Document) (*Store, error) {
	return OpenWithPolicy(path, document, DefaultPolicy())
}

func OpenWithPolicy(path string, document genesis.Document, policy Policy) (*Store, error) {
	return openWithPolicyOptions(path, document, policy, nil)
}

func openWithOptions(path string, document genesis.Document, filesystem vfs.FS) (*Store, error) {
	return openWithPolicyOptions(path, document, DefaultPolicy(), filesystem)
}

func openWithPolicyOptions(path string, document genesis.Document, policy Policy, filesystem vfs.FS) (*Store, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	options := &pebble.Options{FormatMajorVersion: pebble.FormatNewest, FS: filesystem}
	db, err := pebble.Open(path, options)
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, policy: policy}
	if err := store.initialize(document); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := store.Snapshot(); err != nil {
		_ = db.Close()
		return nil, err
	}
	historyBytes, err := store.historyUsageUnlocked()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store.historyBytes = historyBytes
	tip, err := store.Tip()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := store.SnapshotAt(tip.ID); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// HistoryUsage reports exact immutable logical key/value bytes and the local
// admission limit. It remains available after the limit is reached.
func (store *Store) HistoryUsage() (uint64, uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return 0, 0, storage.ErrClosed
	}
	return store.historyBytes, store.policy.MaxHistoryBytes, nil
}

func (store *Store) initialize(document genesis.Document) error {
	storedGenesis, err := store.getCopy(keyGenesis)
	if errors.Is(err, pebble.ErrNotFound) {
		if _, schemaErr := store.getCopy(keySchema); !errors.Is(schemaErr, pebble.ErrNotFound) {
			if schemaErr != nil {
				return schemaErr
			}
			return storage.ErrCorrupt
		}
		tip, err := storage.GenesisTip(document)
		if err != nil {
			return err
		}
		batch := store.db.NewBatch()
		defer batch.Close()
		var schema [2]byte
		binary.BigEndian.PutUint16(schema[:], storage.SchemaVersion)
		if err := batch.Set(keySchema, schema[:], nil); err != nil {
			return err
		}
		if err := batch.Set(keyGenesis, document.CanonicalBytes(), nil); err != nil {
			return err
		}
		if err := batch.Set(keyTip, tip.CanonicalBytes(), nil); err != nil {
			return err
		}
		if err := batch.Set(nodeKey(tip.ID), tip.CanonicalBytes(), nil); err != nil {
			return err
		}
		for _, value := range document.Allocations {
			if err := batch.Set(resourceKey(value.ID), value.CanonicalBytes(), nil); err != nil {
				return err
			}
			if err := batch.Set(snapshotResourceKey(tip.ID, value.ID), snapshotCreateValue(value), nil); err != nil {
				return err
			}
		}
		return batch.Commit(pebble.Sync)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(storedGenesis, document.CanonicalBytes()) {
		return storage.ErrGenesisMismatch
	}
	schema, err := store.getCopy(keySchema)
	if err != nil {
		return err
	}
	if len(schema) != 2 || binary.BigEndian.Uint16(schema) != storage.SchemaVersion {
		return storage.ErrCorrupt
	}
	return nil
}

func (store *Store) Tip() (storage.Tip, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	return store.tipUnlocked()
}

func (store *Store) tipUnlocked() (storage.Tip, error) {
	encoded, err := store.getCopy(keyTip)
	if err != nil {
		return storage.Tip{}, err
	}
	return storage.DecodeTip(encoded)
}

func (store *Store) Snapshot() (*state.Memory, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil, storage.ErrClosed
	}
	tip, err := store.tipUnlocked()
	if err != nil {
		return nil, err
	}
	node, err := store.tipByIDUnlocked(tip.ID)
	if err != nil || !storage.EqualTips(tip, node) {
		return nil, fmt.Errorf("%w: canonical tip node mismatch", storage.ErrCorrupt)
	}
	return store.loadStateUnlocked(tip, resourceLower, resourceUpper, resourceKey)
}

func (store *Store) TipByID(id types.Hash) (storage.Tip, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	return store.tipByIDUnlocked(id)
}

func (store *Store) tipByIDUnlocked(id types.Hash) (storage.Tip, error) {
	encoded, err := store.getCopy(nodeKey(id))
	if errors.Is(err, pebble.ErrNotFound) {
		return storage.Tip{}, storage.ErrNodeNotFound
	}
	if err != nil {
		return storage.Tip{}, err
	}
	result, err := storage.DecodeTip(encoded)
	if err != nil || result.ID != id {
		return storage.Tip{}, fmt.Errorf("%w: invalid node %s", storage.ErrCorrupt, id)
	}
	return result, nil
}

func (store *Store) SnapshotAt(id types.Hash) (*state.Memory, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil, storage.ErrClosed
	}
	tip, err := store.tipByIDUnlocked(id)
	if err != nil {
		return nil, err
	}
	current, err := store.tipUnlocked()
	if err != nil {
		return nil, err
	}
	if storage.EqualTips(tip, current) {
		return store.loadStateUnlocked(tip, resourceLower, resourceUpper, resourceKey)
	}
	return store.snapshotAtUnlocked(tip)
}

func (store *Store) snapshotAtUnlocked(tip storage.Tip) (*state.Memory, error) {
	// Do not trust a persisted height as an allocation size. The parent walk and
	// per-node consistency checks below are the authority for the path length.
	path := make([]storage.Tip, 0)
	cursor := tip
	for {
		path = append(path, cursor)
		if cursor.Height == 0 {
			break
		}
		candidate, err := store.blockByIDUnlocked(cursor.ID)
		if err != nil {
			return nil, err
		}
		if candidate.Header.Height != cursor.Height {
			return nil, storage.ErrCorrupt
		}
		cursor, err = store.tipByIDUnlocked(candidate.Header.Parent)
		if err != nil || cursor.Height+1 != candidate.Header.Height {
			return nil, storage.ErrCorrupt
		}
	}
	current := state.Empty()
	for index := len(path) - 1; index >= 0; index-- {
		var err error
		current, err = store.applySnapshotDeltaUnlocked(current, path[index])
		if err != nil {
			return nil, err
		}
		if current.Root() != path[index].StateRoot {
			return nil, fmt.Errorf("%w: tip %s loaded %s", storage.ErrStateRoot, path[index].StateRoot, current.Root())
		}
	}
	return current, nil
}

func (store *Store) applySnapshotDeltaUnlocked(current *state.Memory, tip storage.Tip) (*state.Memory, error) {
	lower, upper := snapshotBounds(tip.ID)
	iterator, err := store.db.NewIter(&pebble.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, err
	}
	defer iterator.Close()
	resources := make(map[types.ResourceID]resource.Resource, current.Len())
	for _, value := range current.Resources() {
		resources[value.ID] = value
	}
	for valid := iterator.First(); valid; valid = iterator.Next() {
		key := iterator.Key()
		if len(key) != 1+types.HashSize+types.ResourceIDSize || key[0] != snapshotByte ||
			!bytes.Equal(key[1:1+types.HashSize], tip.ID[:]) {
			return nil, storage.ErrCorrupt
		}
		var id types.ResourceID
		copy(id[:], key[1+types.HashSize:])
		encoded := append([]byte(nil), iterator.Value()...)
		if len(encoded) == 0 {
			return nil, storage.ErrCorrupt
		}
		switch encoded[0] {
		case snapshotDelete:
			if len(encoded) != 1 {
				return nil, storage.ErrCorrupt
			}
			if _, exists := resources[id]; !exists {
				return nil, storage.ErrCorrupt
			}
			delete(resources, id)
		case snapshotCreate:
			if len(encoded) != 1+resource.CanonicalSize {
				return nil, storage.ErrCorrupt
			}
			decoder := codec.NewDecoder(encoded[1:])
			value, err := resource.Decode(decoder)
			if err != nil {
				return nil, fmt.Errorf("%w: decode snapshot resource: %v", storage.ErrCorrupt, err)
			}
			if err := decoder.Finish(); err != nil || value.ID != id {
				return nil, storage.ErrCorrupt
			}
			if _, exists := resources[id]; exists {
				return nil, storage.ErrCorrupt
			}
			resources[id] = value
		default:
			return nil, storage.ErrCorrupt
		}
	}
	if err := iterator.Error(); err != nil {
		return nil, err
	}
	values := make([]resource.Resource, 0, len(resources))
	for _, value := range resources {
		values = append(values, value)
	}
	result, err := state.New(values)
	if err != nil {
		return nil, fmt.Errorf("%w: apply snapshot delta: %v", storage.ErrCorrupt, err)
	}
	return result, nil
}

func (store *Store) loadStateUnlocked(
	tip storage.Tip,
	lower []byte,
	upper []byte,
	expectedKey func(types.ResourceID) []byte,
) (*state.Memory, error) {
	iterator, err := store.db.NewIter(&pebble.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	resources := make([]resource.Resource, 0)
	for valid := iterator.First(); valid; valid = iterator.Next() {
		decoder := codec.NewDecoder(append([]byte(nil), iterator.Value()...))
		value, err := resource.Decode(decoder)
		if err != nil {
			return nil, fmt.Errorf("%w: decode resource: %v", storage.ErrCorrupt, err)
		}
		if err := decoder.Finish(); err != nil {
			return nil, fmt.Errorf("%w: decode resource: %v", storage.ErrCorrupt, err)
		}
		if !bytes.Equal(iterator.Key(), expectedKey(value.ID)) {
			return nil, fmt.Errorf("%w: resource key mismatch", storage.ErrCorrupt)
		}
		resources = append(resources, value)
	}
	if err := iterator.Error(); err != nil {
		return nil, err
	}
	result, err := state.New(resources)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", storage.ErrCorrupt, err)
	}
	if result.Root() != tip.StateRoot {
		return nil, fmt.Errorf("%w: tip %s loaded %s", storage.ErrStateRoot, tip.StateRoot, result.Root())
	}
	return result, nil
}

func (store *Store) Block(height uint64) (block.Block, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return block.Block{}, storage.ErrClosed
	}
	encodedID, err := store.getCopy(blockKey(height))
	if errors.Is(err, pebble.ErrNotFound) {
		return block.Block{}, storage.ErrBlockNotFound
	}
	if err != nil {
		return block.Block{}, err
	}
	if len(encodedID) != types.HashSize {
		return block.Block{}, storage.ErrCorrupt
	}
	var id types.Hash
	copy(id[:], encodedID)
	return store.blockByIDUnlocked(id)
}

func (store *Store) BlockByID(id types.Hash) (block.Block, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return block.Block{}, storage.ErrClosed
	}
	return store.blockByIDUnlocked(id)
}

func (store *Store) blockByIDUnlocked(id types.Hash) (block.Block, error) {
	encoded, err := store.getCopy(blockIDKey(id))
	if errors.Is(err, pebble.ErrNotFound) {
		return block.Block{}, storage.ErrBlockNotFound
	}
	if err != nil {
		return block.Block{}, err
	}
	result, err := block.Decode(encoded)
	if err != nil {
		return block.Block{}, fmt.Errorf("%w: decode block %s: %v", storage.ErrCorrupt, id, err)
	}
	actualID, err := result.Header.ID()
	if err != nil || actualID != id {
		return block.Block{}, fmt.Errorf("%w: block ID key mismatch", storage.ErrCorrupt)
	}
	return result, nil
}

func (store *Store) Commit(parent storage.Tip, candidate block.Block, postState *state.Memory) (storage.Tip, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	if store.readOnly {
		return storage.Tip{}, pebble.ErrReadOnly
	}
	storedParent, err := store.tipByIDUnlocked(parent.ID)
	if err != nil {
		return storage.Tip{}, err
	}
	if !storage.EqualTips(parent, storedParent) {
		return storage.Tip{}, storage.ErrTipChanged
	}
	current, err := store.tipUnlocked()
	if err != nil {
		return storage.Tip{}, err
	}
	next, err := storage.ValidateChild(storedParent, candidate, postState)
	if err != nil {
		return storage.Tip{}, err
	}
	if _, err := store.tipByIDUnlocked(next.ID); err == nil {
		return storage.Tip{}, storage.ErrBlockExists
	} else if !errors.Is(err, storage.ErrNodeNotFound) {
		return storage.Tip{}, err
	}
	wins := storage.BetterTip(next, current)
	var parentState *state.Memory
	if storage.EqualTips(storedParent, current) {
		parentState, err = store.loadStateUnlocked(storedParent, resourceLower, resourceUpper, resourceKey)
	} else {
		parentState, err = store.snapshotAtUnlocked(storedParent)
	}
	if err != nil {
		return storage.Tip{}, err
	}
	deleted, created, err := snapshotDiff(parentState, postState)
	if err != nil {
		return storage.Tip{}, err
	}
	candidateBytes := candidate.CanonicalBytes()
	nextBytes := next.CanonicalBytes()
	historyIncrement, err := immutableHistoryIncrement(next, candidateBytes, nextBytes, deleted, created)
	if err != nil || historyIncrement > store.policy.MaxHistoryBytes ||
		store.historyBytes > store.policy.MaxHistoryBytes-historyIncrement {
		return storage.Tip{}, storage.ErrHistoryLimit
	}
	activeDeleted, activeCreated := deleted, created
	var canonical map[uint64]types.Hash
	if wins {
		canonical, err = store.canonicalPathUnlocked(next, candidate)
		if err != nil {
			return storage.Tip{}, err
		}
		if !storage.EqualTips(storedParent, current) {
			currentState, loadErr := store.loadStateUnlocked(current, resourceLower, resourceUpper, resourceKey)
			if loadErr != nil {
				return storage.Tip{}, loadErr
			}
			activeDeleted, activeCreated, err = snapshotDiff(currentState, postState)
			if err != nil {
				return storage.Tip{}, err
			}
		}
	}

	if err := store.runCommitHook(stageBeforeBatch); err != nil {
		return storage.Tip{}, err
	}
	batch := store.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(blockIDKey(next.ID), candidateBytes, nil); err != nil {
		return storage.Tip{}, err
	}
	if err := store.runCommitHook(stageAfterBlock); err != nil {
		return storage.Tip{}, err
	}
	if err := batch.Set(nodeKey(next.ID), nextBytes, nil); err != nil {
		return storage.Tip{}, err
	}
	if err := store.runCommitHook(stageAfterNode); err != nil {
		return storage.Tip{}, err
	}
	for _, id := range deleted {
		if err := batch.Set(snapshotResourceKey(next.ID, id), []byte{snapshotDelete}, nil); err != nil {
			return storage.Tip{}, err
		}
	}
	for _, value := range created {
		if err := batch.Set(snapshotResourceKey(next.ID, value.ID), snapshotCreateValue(value), nil); err != nil {
			return storage.Tip{}, err
		}
	}
	if err := store.runCommitHook(stageAfterSnapshot); err != nil {
		return storage.Tip{}, err
	}
	if wins {
		for _, id := range activeDeleted {
			if err := batch.Delete(resourceKey(id), nil); err != nil {
				return storage.Tip{}, err
			}
		}
		if err := store.runCommitHook(stageAfterStateDelete); err != nil {
			return storage.Tip{}, err
		}
		for _, value := range activeCreated {
			if err := batch.Set(resourceKey(value.ID), value.CanonicalBytes(), nil); err != nil {
				return storage.Tip{}, err
			}
		}
		if err := store.runCommitHook(stageAfterResources); err != nil {
			return storage.Tip{}, err
		}
		if err := batch.DeleteRange(blockLower, blockUpper, nil); err != nil {
			return storage.Tip{}, err
		}
		for height, id := range canonical {
			if err := batch.Set(blockKey(height), id[:], nil); err != nil {
				return storage.Tip{}, err
			}
		}
		if err := store.runCommitHook(stageAfterBlockIndex); err != nil {
			return storage.Tip{}, err
		}
		if err := batch.Set(keyTip, next.CanonicalBytes(), nil); err != nil {
			return storage.Tip{}, err
		}
		if err := store.runCommitHook(stageAfterTip); err != nil {
			return storage.Tip{}, err
		}
	}
	if err := store.runCommitHook(stageBeforeCommit); err != nil {
		return storage.Tip{}, err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return storage.Tip{}, err
	}
	store.historyBytes += historyIncrement
	if err := store.runCommitHook(stageAfterCommit); err != nil {
		return storage.Tip{}, err
	}
	if wins {
		return next, nil
	}
	return current, nil
}

func (store *Store) canonicalPathUnlocked(next storage.Tip, candidate block.Block) (map[uint64]types.Hash, error) {
	result := make(map[uint64]types.Hash, next.Height)
	cursor := next.ID
	for height := next.Height; height > 0; height-- {
		var value block.Block
		if cursor == next.ID {
			value = candidate
		} else {
			var err error
			value, err = store.blockByIDUnlocked(cursor)
			if err != nil {
				return nil, err
			}
		}
		id, err := value.Header.ID()
		if err != nil || id != cursor || value.Header.Height != height {
			return nil, storage.ErrCorrupt
		}
		result[height] = cursor
		cursor = value.Header.Parent
	}
	genesisNode, err := store.tipByIDUnlocked(cursor)
	if err != nil || genesisNode.Height != 0 {
		return nil, storage.ErrCorrupt
	}
	return result, nil
}

func (store *Store) runCommitHook(stage commitStage) error {
	if store.commitHook == nil {
		return nil
	}
	return store.commitHook(stage)
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return store.db.Close()
}

func (store *Store) getCopy(key []byte) ([]byte, error) {
	value, closer, err := store.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return append([]byte(nil), value...), nil
}

func (store *Store) historyUsageUnlocked() (uint64, error) {
	iterator, err := store.db.NewIter(nil)
	if err != nil {
		return 0, err
	}
	defer iterator.Close()
	var total uint64
	for valid := iterator.First(); valid; valid = iterator.Next() {
		key := iterator.Key()
		if len(key) == 0 || (key[0] != blockIDPrefix && key[0] != nodePrefix && key[0] != snapshotByte) {
			continue
		}
		entryBytes := uint64(len(key)) + uint64(len(iterator.Value()))
		if total > ^uint64(0)-entryBytes {
			return 0, storage.ErrCorrupt
		}
		total += entryBytes
	}
	if err := iterator.Error(); err != nil {
		return 0, err
	}
	return total, nil
}

func resourceKey(id types.ResourceID) []byte {
	result := make([]byte, 1+len(id))
	result[0] = resourceLower[0]
	copy(result[1:], id[:])
	return result
}

func blockKey(height uint64) []byte {
	result := make([]byte, 9)
	result[0] = blockPrefix
	binary.BigEndian.PutUint64(result[1:], height)
	return result
}

func blockIDKey(id types.Hash) []byte {
	result := make([]byte, 1+len(id))
	result[0] = blockIDPrefix
	copy(result[1:], id[:])
	return result
}

func nodeKey(id types.Hash) []byte {
	result := make([]byte, 1+len(id))
	result[0] = nodePrefix
	copy(result[1:], id[:])
	return result
}

func snapshotResourceKey(nodeID types.Hash, resourceID types.ResourceID) []byte {
	result := make([]byte, 1+len(nodeID)+len(resourceID))
	result[0] = snapshotByte
	copy(result[1:], nodeID[:])
	copy(result[1+len(nodeID):], resourceID[:])
	return result
}

func snapshotCreateValue(value resource.Resource) []byte {
	result := make([]byte, 1, 1+resource.CanonicalSize)
	result[0] = snapshotCreate
	return append(result, value.CanonicalBytes()...)
}

func immutableHistoryIncrement(
	next storage.Tip,
	candidateBytes []byte,
	nextBytes []byte,
	deleted []types.ResourceID,
	created []resource.Resource,
) (uint64, error) {
	var total uint64
	add := func(size uint64) bool {
		if total > ^uint64(0)-size {
			return false
		}
		total += size
		return true
	}
	if !add(uint64(len(blockIDKey(next.ID)))+uint64(len(candidateBytes))) ||
		!add(uint64(len(nodeKey(next.ID)))+uint64(len(nextBytes))) {
		return 0, storage.ErrHistoryLimit
	}
	for _, id := range deleted {
		if !add(uint64(len(snapshotResourceKey(next.ID, id))) + 1) {
			return 0, storage.ErrHistoryLimit
		}
	}
	for _, value := range created {
		if !add(uint64(len(snapshotResourceKey(next.ID, value.ID))) + 1 + resource.CanonicalSize) {
			return 0, storage.ErrHistoryLimit
		}
	}
	return total, nil
}

func snapshotDiff(parent, next *state.Memory) ([]types.ResourceID, []resource.Resource, error) {
	if parent == nil || next == nil {
		return nil, nil, storage.ErrStateRoot
	}
	before := parent.Resources()
	after := next.Resources()
	deleted := make([]types.ResourceID, 0)
	created := make([]resource.Resource, 0)
	left, right := 0, 0
	for left < len(before) || right < len(after) {
		if left == len(before) {
			created = append(created, after[right:]...)
			break
		}
		if right == len(after) {
			for _, value := range before[left:] {
				deleted = append(deleted, value.ID)
			}
			break
		}
		switch types.CompareResourceID(before[left].ID, after[right].ID) {
		case -1:
			deleted = append(deleted, before[left].ID)
			left++
		case 1:
			created = append(created, after[right])
			right++
		default:
			if before[left] != after[right] {
				return nil, nil, storage.ErrCorrupt
			}
			left++
			right++
		}
	}
	return deleted, created, nil
}

func snapshotBounds(id types.Hash) ([]byte, []byte) {
	lower := make([]byte, 1+len(id))
	lower[0] = snapshotByte
	copy(lower[1:], id[:])
	upper := append([]byte(nil), lower...)
	for index := len(upper) - 1; index >= 0; index-- {
		upper[index]++
		if upper[index] != 0 {
			return lower, upper[:index+1]
		}
	}
	panic("snapshot key prefix has no upper bound")
}
