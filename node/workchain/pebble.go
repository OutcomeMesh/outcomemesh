package workchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	workSchemaVersion      uint16 = 1
	maxNodeMetadataBytes          = 64 << 10
	maxPersistedStateBytes        = 256 << 20
)

var (
	workKeySchema = []byte{0x01, 0x01}
	workKeyConfig = []byte{0x01, 0x02}
	workKeyTip    = []byte{0x01, 0x03}
)

const (
	workNodePrefix  byte = 0x10
	workBlockPrefix byte = 0x11
	workStatePrefix byte = 0x12
)

type workPersistence struct {
	db         *pebble.DB
	commitHook func() error
}

// Open creates or reopens the isolated version-1 Pebble coordinator. All
// branch metadata, block bytes, resource state, fee queue, and canonical-tip
// movement for one commit use a single synchronous batch.
func Open(path string, base Base, parameters workblock.Parameters) (*Store, error) {
	store, err := New(base, parameters)
	if err != nil {
		return nil, err
	}
	db, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
	if err != nil {
		return nil, err
	}
	persistence := &workPersistence{db: db}
	if err := persistence.initializeOrLoad(store, base); err != nil {
		_ = db.Close()
		return nil, err
	}
	store.persistence = persistence
	return store, nil
}

func (persistence *workPersistence) initializeOrLoad(store *Store, base Base) error {
	configured := workConfigHash(base, store.parameters)
	schema, err := persistence.get(workKeySchema)
	if errors.Is(err, pebble.ErrNotFound) {
		return persistence.initialize(store.nodes[store.baseID], configured, store.tipID)
	}
	if err != nil {
		return err
	}
	if len(schema) != 2 || binary.BigEndian.Uint16(schema) != workSchemaVersion {
		return storage.ErrCorrupt
	}
	storedConfig, err := persistence.get(workKeyConfig)
	if err != nil {
		return err
	}
	if !bytes.Equal(storedConfig, configured[:]) {
		return ErrConfiguration
	}
	return persistence.load(store, base)
}

func (persistence *workPersistence) initialize(base *chainNode, config types.Hash, tipID types.Hash) error {
	metadata, err := encodeNodeMetadata(base)
	if err != nil {
		return err
	}
	stateBytes, err := encodePersistedState(base.state)
	if err != nil {
		return err
	}
	batch := persistence.db.NewBatch()
	defer batch.Close()
	var schema [2]byte
	binary.BigEndian.PutUint16(schema[:], workSchemaVersion)
	for _, item := range []struct {
		key   []byte
		value []byte
	}{
		{workKeySchema, schema[:]}, {workKeyConfig, config[:]}, {workKeyTip, tipID[:]},
		{workNodeKey(base.tip.ID), metadata}, {workStateKey(base.tip.ID), stateBytes},
	} {
		if err := batch.Set(item.key, item.value, nil); err != nil {
			return err
		}
	}
	return batch.Commit(pebble.Sync)
}

func (persistence *workPersistence) commitNode(node *chainNode, canonicalTip types.Hash) error {
	if node == nil || node.block == nil || node.result.FeeQueue == nil {
		return storage.ErrCorrupt
	}
	metadata, err := encodeNodeMetadata(node)
	if err != nil {
		return err
	}
	stateBytes, err := encodePersistedState(node.state)
	if err != nil {
		return err
	}
	blockBytes := node.block.CanonicalBytes()
	batch := persistence.db.NewBatch()
	defer batch.Close()
	for _, item := range []struct {
		key   []byte
		value []byte
	}{
		{workNodeKey(node.tip.ID), metadata},
		{workBlockKey(node.tip.ID), blockBytes},
		{workStateKey(node.tip.ID), stateBytes},
		{workKeyTip, canonicalTip[:]},
	} {
		if err := batch.Set(item.key, item.value, nil); err != nil {
			return err
		}
	}
	if persistence.commitHook != nil {
		if err := persistence.commitHook(); err != nil {
			return err
		}
	}
	return batch.Commit(pebble.Sync)
}

func (persistence *workPersistence) load(store *Store, base Base) error {
	nodes := make(map[types.Hash]*chainNode)
	iterator, err := persistence.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{workNodePrefix}, UpperBound: []byte{workNodePrefix + 1},
	})
	if err != nil {
		return err
	}
	defer iterator.Close()
	for valid := iterator.First(); valid; valid = iterator.Next() {
		key := append([]byte(nil), iterator.Key()...)
		if len(key) != 1+types.HashSize || key[0] != workNodePrefix {
			return storage.ErrCorrupt
		}
		var id types.Hash
		copy(id[:], key[1:])
		metadata := append([]byte(nil), iterator.Value()...)
		node, err := decodeNodeMetadata(metadata)
		if err != nil || node.tip.ID != id {
			return storage.ErrCorrupt
		}
		stateBytes, err := persistence.get(workStateKey(id))
		if err != nil {
			return err
		}
		node.state, err = decodePersistedState(stateBytes)
		if err != nil || node.state.Root() != node.tip.StateRoot {
			return storage.ErrCorrupt
		}
		if id != store.baseID {
			blockBytes, err := persistence.get(workBlockKey(id))
			if err != nil {
				return err
			}
			candidate, err := workblock.Decode(blockBytes)
			if err != nil {
				return storage.ErrCorrupt
			}
			blockID, _ := candidate.Header.ID()
			if blockID != id || candidate.Header.StateRoot != node.tip.StateRoot ||
				node.result.FeeQueue == nil {
				return storage.ErrCorrupt
			}
			queueRoot, err := node.result.FeeQueue.Root()
			if err != nil || queueRoot != candidate.Header.FeeQueueRoot {
				return storage.ErrCorrupt
			}
			node.block = &candidate
			node.result.State = node.state
			node.result.FeeAward = candidate.Header.FeeAward
		}
		if _, exists := nodes[id]; exists {
			return storage.ErrCorrupt
		}
		nodes[id] = node
	}
	if err := iterator.Error(); err != nil {
		return err
	}
	baseNode, exists := nodes[store.baseID]
	if !exists || baseNode.block != nil || baseNode.result.FeeQueue != nil ||
		!storage.EqualTips(baseNode.tip, base.Tip) || !equalTimestamps(baseNode.history, store.nodes[store.baseID].history) {
		return storage.ErrCorrupt
	}
	order := make([]*chainNode, 0, len(nodes))
	for id, node := range nodes {
		if id != store.baseID {
			order = append(order, node)
		}
	}
	sort.Slice(order, func(left, right int) bool {
		if order[left].tip.Height != order[right].tip.Height {
			return order[left].tip.Height < order[right].tip.Height
		}
		return types.CompareHash(order[left].tip.ID, order[right].tip.ID) < 0
	})
	for _, node := range order {
		parent, exists := nodes[node.block.Header.Seal.AnchorParent]
		if !exists {
			return storage.ErrCorrupt
		}
		expected, err := nextTip(parent.tip, *node.block)
		if err != nil || !storage.EqualTips(expected, node.tip) ||
			node.position.ParentTimestamp != parent.tip.Timestamp ||
			node.position.MedianTimePast != median(parent.history) {
			return storage.ErrCorrupt
		}
		expectedHistory := append(append([]uint64(nil), parent.history...), node.tip.Timestamp)
		if len(expectedHistory) > 11 {
			expectedHistory = expectedHistory[len(expectedHistory)-11:]
		}
		if !equalTimestamps(expectedHistory, node.history) {
			return storage.ErrCorrupt
		}
	}
	tipBytes, err := persistence.get(workKeyTip)
	if err != nil || len(tipBytes) != types.HashSize {
		return storage.ErrCorrupt
	}
	var tipID types.Hash
	copy(tipID[:], tipBytes)
	if _, exists := nodes[tipID]; !exists {
		return storage.ErrCorrupt
	}
	for _, node := range nodes {
		if storage.BetterTip(node.tip, nodes[tipID].tip) {
			return storage.ErrCorrupt
		}
	}
	store.nodes = nodes
	store.tipID = tipID
	return nil
}

func encodeNodeMetadata(node *chainNode) ([]byte, error) {
	if node == nil || node.tip.Validate() != nil || len(node.history) == 0 || len(node.history) > 11 {
		return nil, storage.ErrCorrupt
	}
	queueBytes := []byte(nil)
	if node.result.FeeQueue != nil {
		var err error
		queueBytes, err = node.result.FeeQueue.CanonicalBytes()
		if err != nil {
			return nil, err
		}
	}
	encoder := codec.NewEncoder(256 + len(queueBytes))
	encoder.BytesField(node.tip.CanonicalBytes())
	encoder.U64(node.position.ParentTimestamp)
	encoder.U64(node.position.MedianTimePast)
	encoder.Uvarint(uint64(len(node.history)))
	for _, timestamp := range node.history {
		encoder.U64(timestamp)
	}
	encoder.BytesField(queueBytes)
	if encoder.Len() > maxNodeMetadataBytes {
		return nil, storage.ErrCorrupt
	}
	return encoder.Bytes(), nil
}

func decodeNodeMetadata(input []byte) (*chainNode, error) {
	if len(input) == 0 || len(input) > maxNodeMetadataBytes {
		return nil, storage.ErrCorrupt
	}
	decoder := codec.NewDecoder(input)
	tipBytes, err := decoder.BytesField(256)
	if err != nil {
		return nil, err
	}
	tip, err := storage.DecodeTip(tipBytes)
	if err != nil {
		return nil, err
	}
	position := workblock.Position{}
	position.ParentTimestamp, err = decoder.U64()
	if err != nil {
		return nil, err
	}
	position.MedianTimePast, err = decoder.U64()
	if err != nil {
		return nil, err
	}
	count, err := decoder.ListLength(11)
	if err != nil || count == 0 {
		return nil, storage.ErrCorrupt
	}
	history := make([]uint64, count)
	for index := range history {
		history[index], err = decoder.U64()
		if err != nil || history[index] == 0 {
			return nil, storage.ErrCorrupt
		}
	}
	queueBytes, err := decoder.BytesField(uint64(workgraph.MaxFeeQueueCanonicalBytes))
	if err != nil {
		return nil, err
	}
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	node := &chainNode{tip: tip, position: position, history: history}
	if len(queueBytes) != 0 {
		node.result.FeeQueue, err = workgraph.DecodeFeeQueue(queueBytes)
		if err != nil {
			return nil, err
		}
	}
	return node, nil
}

func encodePersistedState(value *state.Memory) ([]byte, error) {
	if value == nil {
		return nil, storage.ErrCorrupt
	}
	resources := value.Resources()
	encoder := codec.NewEncoder(10 + len(resources)*resource.CanonicalSize)
	encoder.Uvarint(uint64(len(resources)))
	for _, item := range resources {
		item.EncodeTo(encoder)
	}
	if encoder.Len() > maxPersistedStateBytes {
		return nil, storage.ErrHistoryLimit
	}
	return encoder.Bytes(), nil
}

func decodePersistedState(input []byte) (*state.Memory, error) {
	if len(input) == 0 || len(input) > maxPersistedStateBytes {
		return nil, storage.ErrCorrupt
	}
	decoder := codec.NewDecoder(input)
	maximum := uint64(len(input) / resource.CanonicalSize)
	count, err := decoder.ListLength(maximum)
	if err != nil {
		return nil, err
	}
	resources := make([]resource.Resource, count)
	for index := range resources {
		resources[index], err = resource.Decode(decoder)
		if err != nil || (index > 0 && types.CompareResourceID(resources[index-1].ID, resources[index].ID) >= 0) {
			return nil, storage.ErrCorrupt
		}
	}
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	return state.New(resources)
}

func workConfigHash(base Base, parameters workblock.Parameters) types.Hash {
	encoder := codec.NewEncoder(512)
	encoder.BytesField(base.Tip.CanonicalBytes())
	encoder.Uvarint(uint64(len(base.RecentTimestamps)))
	for _, timestamp := range base.RecentTimestamps {
		encoder.U64(timestamp)
	}
	encoder.U32(parameters.NetworkID)
	encoder.U64(parameters.BlockSubsidy)
	encoder.U64(parameters.RewardMaturity)
	encoder.U64(parameters.ActivationHeight)
	encoder.U64(parameters.DifficultyAnchorTimestamp)
	encoder.Fixed(parameters.DifficultyAnchorTarget[:])
	encoder.U64(parameters.TargetSpacing)
	encoder.U64(parameters.ASERTHalfLife)
	encoder.U16(parameters.FeeDelay)
	return types.DomainHash("OMESH/workchain/config/v0", encoder.Bytes())
}

func workNodeKey(id types.Hash) []byte  { return workIDKey(workNodePrefix, id) }
func workBlockKey(id types.Hash) []byte { return workIDKey(workBlockPrefix, id) }
func workStateKey(id types.Hash) []byte { return workIDKey(workStatePrefix, id) }

func workIDKey(prefix byte, id types.Hash) []byte {
	result := make([]byte, 1+types.HashSize)
	result[0] = prefix
	copy(result[1:], id[:])
	return result
}

func (persistence *workPersistence) get(key []byte) ([]byte, error) {
	value, closer, err := persistence.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return append([]byte(nil), value...), nil
}

func (persistence *workPersistence) close() error { return persistence.db.Close() }

func equalTimestamps(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
