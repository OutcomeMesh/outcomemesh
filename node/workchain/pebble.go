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
	workSchemaVersion      uint16 = 2
	maxNodeMetadataBytes          = 64 << 10
	maxPersistedStateBytes        = 256 << 20
	maxStateDeltaBytes            = 256 << 20
	DefaultMaxHistoryBytes uint64 = 64 << 30
	DefaultForkRetention   uint64 = 4_096
)

var (
	workKeySchema  = []byte{0x01, 0x01}
	workKeyConfig  = []byte{0x01, 0x02}
	workKeyTip     = []byte{0x01, 0x03}
	workKeyHistory = []byte{0x01, 0x04}
)

const (
	workNodePrefix  byte = 0x10
	workBlockPrefix byte = 0x11
	workStatePrefix byte = 0x12
	workDeltaPrefix byte = 0x13
)

type Policy struct {
	// MaxHistoryBytes counts immutable logical node, block, checkpoint, and
	// resource-delta key/value bytes. Pebble WAL/LSM overhead is separate.
	MaxHistoryBytes uint64
	// ForkRetention is the number of heights behind the selected tip within
	// which every side branch is retained. Zero disables side-fork pruning.
	ForkRetention uint64
}

// DefaultPolicy returns the local 64-GiB history budget and a 4,096-height
// side-fork retention window. Pruning still requires an explicit maintenance
// call and never removes canonical history.
func DefaultPolicy() Policy {
	return Policy{MaxHistoryBytes: DefaultMaxHistoryBytes, ForkRetention: DefaultForkRetention}
}

type workPersistence struct {
	db              *pebble.DB
	policy          Policy
	historyBytes    uint64
	commitHook      func() error
	afterCommitHook func()
}

// Open creates or reopens the isolated version-1 Pebble coordinator. All
// branch metadata, block bytes, resource delta, fee queue, logical history,
// and canonical-tip movement for one commit use a single synchronous batch.
func Open(path string, base Base, parameters workblock.Parameters) (*Store, error) {
	return OpenWithPolicy(path, base, parameters, DefaultPolicy())
}

// OpenWithPolicy opens the isolated store with explicit local history and fork
// retention policy. The policy is not a consensus input and may change across
// restarts.
func OpenWithPolicy(path string, base Base, parameters workblock.Parameters, policy Policy) (*Store, error) {
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	store, err := New(base, parameters)
	if err != nil {
		return nil, err
	}
	db, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
	if err != nil {
		return nil, err
	}
	persistence := &workPersistence{db: db, policy: policy}
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
	baseNodeKey := workNodeKey(base.tip.ID)
	baseStateKey := workStateKey(base.tip.ID)
	historyBytes, err := checkedHistoryBytes(
		uint64(len(baseNodeKey)+len(metadata)), uint64(len(baseStateKey)+len(stateBytes)),
	)
	if err != nil || historyBytes > persistence.policy.MaxHistoryBytes {
		return storage.ErrHistoryLimit
	}
	var history [8]byte
	binary.BigEndian.PutUint64(history[:], historyBytes)
	for _, item := range []struct {
		key   []byte
		value []byte
	}{
		{workKeySchema, schema[:]}, {workKeyConfig, config[:]}, {workKeyTip, tipID[:]},
		{workKeyHistory, history[:]}, {baseNodeKey, metadata}, {baseStateKey, stateBytes},
	} {
		if err := batch.Set(item.key, item.value, nil); err != nil {
			return err
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}
	persistence.historyBytes = historyBytes
	return nil
}

func (persistence *workPersistence) commitNode(parent, node *chainNode, canonicalTip types.Hash) error {
	if parent == nil || parent.state == nil || node == nil || node.block == nil || node.result.FeeQueue == nil {
		return storage.ErrCorrupt
	}
	metadata, err := encodeNodeMetadata(node)
	if err != nil {
		return err
	}
	delta, err := buildStateDelta(parent.state, node.state)
	if err != nil {
		return err
	}
	deltaBytes, err := encodeStateDelta(delta)
	if err != nil {
		return err
	}
	blockBytes := node.block.CanonicalBytes()
	nodeKey := workNodeKey(node.tip.ID)
	blockKey := workBlockKey(node.tip.ID)
	deltaKey := workDeltaKey(node.tip.ID)
	increment, err := checkedHistoryBytes(
		uint64(len(nodeKey)+len(metadata)), uint64(len(blockKey)+len(blockBytes)),
		uint64(len(deltaKey)+len(deltaBytes)),
	)
	if err != nil || increment > persistence.policy.MaxHistoryBytes ||
		persistence.historyBytes > persistence.policy.MaxHistoryBytes-increment {
		return storage.ErrHistoryLimit
	}
	nextHistory := persistence.historyBytes + increment
	var history [8]byte
	binary.BigEndian.PutUint64(history[:], nextHistory)
	batch := persistence.db.NewBatch()
	defer batch.Close()
	for _, item := range []struct {
		key   []byte
		value []byte
	}{
		{nodeKey, metadata},
		{blockKey, blockBytes},
		{deltaKey, deltaBytes},
		{workKeyTip, canonicalTip[:]},
		{workKeyHistory, history[:]},
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
	if err := batch.Commit(pebble.Sync); err != nil {
		return err
	}
	persistence.historyBytes = nextHistory
	if persistence.afterCommitHook != nil {
		persistence.afterCommitHook()
	}
	return nil
}

func (persistence *workPersistence) pruneNodes(nodes map[types.Hash]*chainNode, ids []types.Hash) (uint64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	batch := persistence.db.NewBatch()
	defer batch.Close()
	var released uint64
	for _, id := range ids {
		node := nodes[id]
		if node == nil || node.block == nil {
			return 0, storage.ErrCorrupt
		}
		for _, key := range [][]byte{workNodeKey(id), workBlockKey(id), workDeltaKey(id)} {
			value, err := persistence.get(key)
			if errors.Is(err, pebble.ErrNotFound) {
				return 0, storage.ErrCorrupt
			}
			if err != nil {
				return 0, err
			}
			released, err = checkedHistoryBytes(released, uint64(len(key)+len(value)))
			if err != nil {
				return 0, err
			}
			if err := batch.Delete(key, nil); err != nil {
				return 0, err
			}
		}
	}
	if released > persistence.historyBytes {
		return 0, storage.ErrCorrupt
	}
	nextHistory := persistence.historyBytes - released
	var history [8]byte
	binary.BigEndian.PutUint64(history[:], nextHistory)
	if err := batch.Set(workKeyHistory, history[:], nil); err != nil {
		return 0, err
	}
	if persistence.commitHook != nil {
		if err := persistence.commitHook(); err != nil {
			return 0, err
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return 0, err
	}
	persistence.historyBytes = nextHistory
	if persistence.afterCommitHook != nil {
		persistence.afterCommitHook()
	}
	return released, nil
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
	baseStateBytes, err := persistence.get(workStateKey(store.baseID))
	if err != nil {
		return storage.ErrCorrupt
	}
	baseNode.state, err = decodePersistedState(baseStateBytes)
	if err != nil || baseNode.state.Root() != baseNode.tip.StateRoot {
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
		deltaBytes, err := persistence.get(workDeltaKey(node.tip.ID))
		if err != nil {
			return storage.ErrCorrupt
		}
		delta, err := decodeStateDelta(deltaBytes)
		if err != nil {
			return storage.ErrCorrupt
		}
		node.state, err = applyStateDelta(parent.state, delta)
		if err != nil || node.state.Root() != node.tip.StateRoot {
			return storage.ErrCorrupt
		}
		node.result.State = node.state
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
	storedHistory, err := persistence.get(workKeyHistory)
	if err != nil || len(storedHistory) != 8 {
		return storage.ErrCorrupt
	}
	historyBytes, err := persistence.historyUsage(nodes, store.baseID)
	if err != nil || binary.BigEndian.Uint64(storedHistory) != historyBytes {
		return storage.ErrCorrupt
	}
	persistence.historyBytes = historyBytes
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

type stateDelta struct {
	deleted []types.ResourceID
	created []resource.Resource
}

func buildStateDelta(before, after *state.Memory) (stateDelta, error) {
	if before == nil || after == nil {
		return stateDelta{}, storage.ErrCorrupt
	}
	left := before.Resources()
	right := after.Resources()
	result := stateDelta{}
	for leftIndex, rightIndex := 0, 0; leftIndex < len(left) || rightIndex < len(right); {
		if leftIndex == len(left) {
			result.created = append(result.created, right[rightIndex:]...)
			break
		}
		if rightIndex == len(right) {
			for _, item := range left[leftIndex:] {
				result.deleted = append(result.deleted, item.ID)
			}
			break
		}
		switch types.CompareResourceID(left[leftIndex].ID, right[rightIndex].ID) {
		case -1:
			result.deleted = append(result.deleted, left[leftIndex].ID)
			leftIndex++
		case 1:
			result.created = append(result.created, right[rightIndex])
			rightIndex++
		default:
			if !bytes.Equal(left[leftIndex].CanonicalBytes(), right[rightIndex].CanonicalBytes()) {
				return stateDelta{}, storage.ErrCorrupt
			}
			leftIndex++
			rightIndex++
		}
	}
	return result, nil
}

func encodeStateDelta(delta stateDelta) ([]byte, error) {
	for index, id := range delta.deleted {
		if id.IsZero() || (index > 0 && types.CompareResourceID(delta.deleted[index-1], id) >= 0) {
			return nil, storage.ErrCorrupt
		}
	}
	for index, item := range delta.created {
		if err := item.Validate(); err != nil ||
			(index > 0 && types.CompareResourceID(delta.created[index-1].ID, item.ID) >= 0) {
			return nil, storage.ErrCorrupt
		}
	}
	deleted := make(map[types.ResourceID]struct{}, len(delta.deleted))
	for _, id := range delta.deleted {
		deleted[id] = struct{}{}
	}
	for _, item := range delta.created {
		if _, exists := deleted[item.ID]; exists {
			return nil, storage.ErrCorrupt
		}
	}
	encoder := codec.NewEncoder(20 + len(delta.deleted)*types.ResourceIDSize + len(delta.created)*resource.CanonicalSize)
	encoder.Uvarint(uint64(len(delta.deleted)))
	for _, id := range delta.deleted {
		encoder.Fixed(id[:])
	}
	encoder.Uvarint(uint64(len(delta.created)))
	for _, item := range delta.created {
		item.EncodeTo(encoder)
	}
	if encoder.Len() > maxStateDeltaBytes {
		return nil, storage.ErrHistoryLimit
	}
	return encoder.Bytes(), nil
}

func decodeStateDelta(input []byte) (stateDelta, error) {
	if len(input) == 0 || len(input) > maxStateDeltaBytes {
		return stateDelta{}, storage.ErrCorrupt
	}
	decoder := codec.NewDecoder(input)
	deletedCount, err := decoder.ListLength(uint64(len(input)/types.ResourceIDSize + 1))
	if err != nil {
		return stateDelta{}, err
	}
	result := stateDelta{deleted: make([]types.ResourceID, deletedCount)}
	for index := range result.deleted {
		encoded, err := decoder.Fixed(types.ResourceIDSize)
		if err != nil {
			return stateDelta{}, err
		}
		copy(result.deleted[index][:], encoded)
		if result.deleted[index].IsZero() ||
			(index > 0 && types.CompareResourceID(result.deleted[index-1], result.deleted[index]) >= 0) {
			return stateDelta{}, storage.ErrCorrupt
		}
	}
	createdCount, err := decoder.ListLength(uint64(len(input)/resource.CanonicalSize + 1))
	if err != nil {
		return stateDelta{}, err
	}
	result.created = make([]resource.Resource, createdCount)
	for index := range result.created {
		result.created[index], err = resource.Decode(decoder)
		if err != nil || (index > 0 && types.CompareResourceID(result.created[index-1].ID, result.created[index].ID) >= 0) {
			return stateDelta{}, storage.ErrCorrupt
		}
	}
	if err := decoder.Finish(); err != nil {
		return stateDelta{}, err
	}
	deleted := make(map[types.ResourceID]struct{}, len(result.deleted))
	for _, id := range result.deleted {
		deleted[id] = struct{}{}
	}
	for _, item := range result.created {
		if _, exists := deleted[item.ID]; exists {
			return stateDelta{}, storage.ErrCorrupt
		}
	}
	return result, nil
}

func applyStateDelta(before *state.Memory, delta stateDelta) (*state.Memory, error) {
	if before == nil {
		return nil, storage.ErrCorrupt
	}
	resources := make(map[types.ResourceID]resource.Resource, before.Len()+len(delta.created))
	for _, item := range before.Resources() {
		resources[item.ID] = item
	}
	for _, id := range delta.deleted {
		if _, exists := resources[id]; !exists {
			return nil, storage.ErrCorrupt
		}
		delete(resources, id)
	}
	for _, item := range delta.created {
		if _, exists := resources[item.ID]; exists {
			return nil, storage.ErrCorrupt
		}
		resources[item.ID] = item
	}
	values := make([]resource.Resource, 0, len(resources))
	for _, item := range resources {
		values = append(values, item)
	}
	return state.New(values)
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
func workDeltaKey(id types.Hash) []byte { return workIDKey(workDeltaPrefix, id) }

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

func (persistence *workPersistence) historyUsage(nodes map[types.Hash]*chainNode, baseID types.Hash) (uint64, error) {
	iterator, err := persistence.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{workNodePrefix}, UpperBound: []byte{workDeltaPrefix + 1},
	})
	if err != nil {
		return 0, err
	}
	defer iterator.Close()
	var total uint64
	for valid := iterator.First(); valid; valid = iterator.Next() {
		key := iterator.Key()
		if len(key) != 1+types.HashSize {
			return 0, storage.ErrCorrupt
		}
		var id types.Hash
		copy(id[:], key[1:])
		node, exists := nodes[id]
		if !exists {
			return 0, storage.ErrCorrupt
		}
		switch key[0] {
		case workNodePrefix:
		case workStatePrefix:
			if id != baseID {
				return 0, storage.ErrCorrupt
			}
		case workBlockPrefix, workDeltaPrefix:
			if id == baseID || node.block == nil {
				return 0, storage.ErrCorrupt
			}
		default:
			return 0, storage.ErrCorrupt
		}
		total, err = checkedHistoryBytes(total, uint64(len(key)+len(iterator.Value())))
		if err != nil {
			return 0, err
		}
	}
	if err := iterator.Error(); err != nil {
		return 0, err
	}
	return total, nil
}

func checkedHistoryBytes(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		if result > ^uint64(0)-value {
			return 0, storage.ErrHistoryLimit
		}
		result += value
	}
	return result, nil
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
