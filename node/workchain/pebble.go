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
	workSchemaVersion               uint16 = 4
	workEffectSchemaVersion         uint16 = 5 // opt-in, atomically installed with the first ticketed prune
	workBoundSchemaVersion          uint16 = 6 // opt-in storage incarnation, no ticketed effects yet
	workBoundEffectSchemaVersion    uint16 = 7
	workPositionSchemaVersion       uint16 = 8 // opt-in independent per-batch position pins
	workPositionEffectSchemaVersion uint16 = 9
	maxNodeMetadataBytes                   = 64 << 10
	maxPersistedStateBytes                 = 256 << 20
	maxStateDeltaBytes                     = 256 << 20
	maxCanonicalFloorBytes                 = 512
	DefaultMaxHistoryBytes          uint64 = 64 << 30
	DefaultForkRetention            uint64 = 4_096
	DefaultCheckpointEvery          uint64 = 2_048
	DefaultCheckpointKeep           uint32 = 4
	DefaultCanonicalRetention       uint64 = 0
)

var (
	workKeySchema       = []byte{0x01, 0x01}
	workKeyConfig       = []byte{0x01, 0x02}
	workKeyTip          = []byte{0x01, 0x03}
	workKeyHistory      = []byte{0x01, 0x04}
	workKeyFloor        = []byte{0x01, 0x05}
	workKeyStorageID    = []byte{0x01, 0x06}
	workKeyPositionPair = []byte{0x01, 0x07}
	workKeyPosition     = []byte{0x01, 0x08}
)

const (
	workNodePrefix           byte = 0x10
	workBlockPrefix          byte = 0x11
	workStatePrefix          byte = 0x12
	workDeltaPrefix          byte = 0x13
	workArchivedHeaderPrefix byte = 0x14
	workPruneEffectPrefix    byte = 0x15
)

type Policy struct {
	// MaxHistoryBytes counts immutable logical node, block, checkpoint, and
	// resource-delta and retained prune-result key/value bytes. Pebble WAL/LSM
	// overhead is separate. Results are never garbage-collected by maintenance.
	MaxHistoryBytes uint64
	// ForkRetention is the number of heights behind the selected tip within
	// which every side branch is retained. Zero disables side-fork pruning.
	ForkRetention uint64
	// CheckpointEvery is the minimum height distance between replay checkpoints
	// on the selected ancestry. Zero disables checkpoint creation.
	CheckpointEvery uint64
	// CheckpointKeep bounds non-base full-state replay checkpoints. Zero disables
	// checkpoint creation. The activation-base checkpoint is not counted.
	CheckpointKeep uint32
	// CanonicalRetention is the minimum selected-tip distance above an
	// independently authorized archive anchor before it may become the retained
	// floor. Zero disables canonical-prefix pruning.
	CanonicalRetention uint64
}

// DefaultPolicy returns bounded history, side-fork retention, and replay
// checkpoint defaults. Destructive canonical-prefix pruning remains disabled
// until an operator explicitly selects a non-zero CanonicalRetention.
func DefaultPolicy() Policy {
	return Policy{
		MaxHistoryBytes: DefaultMaxHistoryBytes, ForkRetention: DefaultForkRetention,
		CheckpointEvery: DefaultCheckpointEvery, CheckpointKeep: DefaultCheckpointKeep,
		CanonicalRetention: DefaultCanonicalRetention,
	}
}

type workPersistence struct {
	rootPath         string // immutable original path for protected runtime placement checks
	db               *pebble.DB
	policy           Policy
	historyBytes     uint64
	checkpoints      map[types.Hash]struct{}
	commitHook       func() error
	afterCommitHook  func()
	pruneCommitHook  func(*pebble.Batch) error
	effectSchema     bool
	pruneEffects     uint32
	uncertain        bool
	storageID        types.Hash
	initializeCommit func(*pebble.Batch) error
	pins             *storagePositionPins
	position         StoragePosition
	radixMigrationID types.Hash
}

// Open creates or reopens the isolated version-1 Pebble coordinator. All
// branch metadata, block bytes, resource delta, fee queue, logical history,
// and canonical-tip movement for one commit use a single synchronous batch.
func Open(path string, base Base, parameters workblock.Parameters) (*Store, error) {
	return OpenWithPolicy(path, base, parameters, DefaultPolicy())
}

// OpenWithPolicy opens the isolated store with explicit local history and fork
// retention policy. The policy is not a consensus input and may change across
// restarts. Bound-incarnation databases require OpenBoundWithPolicy; independently
// position-pinned databases require OpenPositionPinnedWithPolicy.
func OpenWithPolicy(path string, base Base, parameters workblock.Parameters, policy Policy) (*Store, error) {
	return openWithPolicy(path, base, parameters, policy, types.Hash{}, false, nil)
}

func openWithPolicy(path string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash, existingOnly bool, initializeCommit func(*pebble.Batch) error) (*Store, error) {
	return openWithPositionPins(path, base, parameters, policy, storageID, existingOnly, initializeCommit, nil)
}

// The caller owns pins.lock until a successful return transfers it to Store.
func openWithPositionPins(path string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash, existingOnly bool, initializeCommit func(*pebble.Batch) error, pins *storagePositionPins) (*Store, error) {
	return openWithPositionPinsMigration(path, base, parameters, policy, storageID, existingOnly, initializeCommit, pins, types.Hash{})
}

func openWithPositionPinsMigration(path string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash, existingOnly bool, initializeCommit func(*pebble.Batch) error, pins *storagePositionPins, migrationID types.Hash) (*Store, error) {
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	store, err := New(base, parameters)
	if err != nil {
		return nil, err
	}
	db, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest, ErrorIfNotExists: existingOnly})
	if err != nil {
		return nil, err
	}
	persistence := &workPersistence{
		rootPath: path, radixMigrationID: migrationID,
		db: db, policy: policy, checkpoints: make(map[types.Hash]struct{}), storageID: storageID, initializeCommit: initializeCommit, pins: pins,
	}
	if err := persistence.initializeOrLoad(store, base, !existingOnly); err != nil {
		_ = db.Close()
		return nil, err
	}
	store.persistence = persistence
	return store, nil
}

func (persistence *workPersistence) initializeOrLoad(store *Store, base Base, allowInitialize bool) error {
	configured := workConfigHash(base, store.parameters)
	schema, err := persistence.get(workKeySchema)
	if errors.Is(err, pebble.ErrNotFound) {
		if !allowInitialize {
			return errors.Join(ErrStorageBinding, storage.ErrCorrupt)
		}
		// Missing metadata in a used database is corruption, not bootstrap.
		// In particular, never hide retained effect history behind a fresh base.
		iterator, iterErr := persistence.db.NewIter(nil)
		if iterErr != nil {
			return iterErr
		}
		hasData := iterator.First()
		if err := errors.Join(iterator.Error(), iterator.Close()); err != nil {
			return err
		}
		if hasData {
			return storage.ErrCorrupt
		}
		return persistence.initialize(store.nodes[store.baseID], configured, store.tipID)
	}
	if err != nil {
		return err
	}
	if len(schema) != 2 {
		return storage.ErrCorrupt
	}
	version := binary.BigEndian.Uint16(schema)
	if version != workSchemaVersion && version != workEffectSchemaVersion &&
		version != workBoundSchemaVersion && version != workBoundEffectSchemaVersion &&
		version != workPositionSchemaVersion && version != workPositionEffectSchemaVersion {
		return storage.ErrCorrupt
	}
	pinned := version == workPositionSchemaVersion || version == workPositionEffectSchemaVersion
	if pinned != (persistence.pins != nil) {
		return ErrStoragePosition
	}
	bound := version == workBoundSchemaVersion || version == workBoundEffectSchemaVersion || pinned
	if bound != !persistence.storageID.IsZero() {
		return ErrStorageBinding
	}
	storedID, idErr := persistence.get(workKeyStorageID)
	if bound {
		if idErr != nil || len(storedID) != types.HashSize {
			return errors.Join(ErrStorageBinding, storage.ErrCorrupt, idErr)
		}
		if !bytes.Equal(storedID, persistence.storageID[:]) {
			return ErrStorageBinding
		}
	} else if !errors.Is(idErr, pebble.ErrNotFound) {
		return errors.Join(storage.ErrCorrupt, idErr)
	}
	if err := persistence.loadPosition(pinned); err != nil {
		return err
	}
	persistence.effectSchema = version == workEffectSchemaVersion || version == workBoundEffectSchemaVersion || version == workPositionEffectSchemaVersion
	storedConfig, err := persistence.get(workKeyConfig)
	if err != nil {
		return err
	}
	if !bytes.Equal(storedConfig, configured[:]) {
		return ErrConfiguration
	}
	if err := persistence.validateRadixMigration(base, store.parameters); err != nil {
		return err
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
	if !persistence.storageID.IsZero() {
		binary.BigEndian.PutUint16(schema[:], workBoundSchemaVersion)
		if err := batch.Set(workKeyStorageID, persistence.storageID[:], nil); err != nil {
			return err
		}
	}
	if persistence.pins != nil {
		binary.BigEndian.PutUint16(schema[:], workPositionSchemaVersion)
		persistence.position = persistence.pins.initial
		if err := batch.Set(workKeyPositionPair, persistence.pins.pairID[:], nil); err != nil {
			return err
		}
		if err := batch.Set(workKeyPosition, encodeStoragePosition(persistence.position), nil); err != nil {
			return err
		}
	}
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
	commit := persistence.initializeCommit
	if commit == nil {
		commit = func(batch *pebble.Batch) error { return batch.Commit(pebble.Sync) }
	}
	if err := commit(batch); err != nil {
		return err
	}
	persistence.historyBytes = historyBytes
	persistence.checkpoints[base.tip.ID] = struct{}{}
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
	if err := persistence.commitBatch(batch, nil, nil); err != nil {
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
		stateKey := workDeltaKey(id)
		if _, checkpoint := persistence.checkpoints[id]; checkpoint {
			stateKey = workStateKey(id)
		}
		for _, key := range [][]byte{workNodeKey(id), workBlockKey(id), stateKey} {
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
	if err := persistence.commitBatch(batch, nil, nil); err != nil {
		return 0, err
	}
	persistence.historyBytes = nextHistory
	for _, id := range ids {
		delete(persistence.checkpoints, id)
	}
	if persistence.afterCommitHook != nil {
		persistence.afterCommitHook()
	}
	return released, nil
}

func (persistence *workPersistence) pruneCanonicalPrefix(
	nodes map[types.Hash]*chainNode,
	remove []types.Hash,
	anchor *chainNode,
	boundary *CanonicalFloor,
	authorize func() (uint64, error),
	effect *CanonicalPruneEffect,
	report CanonicalPruneReport,
) (uint64, uint64, error) {
	if len(remove) == 0 || anchor == nil || anchor.block == nil || anchor.state == nil || boundary == nil {
		return 0, 0, ErrCanonicalPrune
	}
	floorBytes, err := encodeCanonicalFloor(*boundary)
	if err != nil {
		return 0, 0, err
	}
	stateBytes, err := encodePersistedState(anchor.state)
	if err != nil {
		return 0, 0, err
	}
	batch := persistence.db.NewBatch()
	defer batch.Close()
	var released uint64
	var added uint64
	for _, id := range remove {
		node := nodes[id]
		if node == nil {
			return 0, 0, storage.ErrCorrupt
		}
		keys := [][]byte{workNodeKey(id)}
		if node.block == nil {
			if id != boundary.BaseID {
				return 0, 0, storage.ErrCorrupt
			}
			keys = append(keys, workStateKey(id))
		} else {
			recoveryKey := workDeltaKey(id)
			if _, checkpoint := persistence.checkpoints[id]; checkpoint {
				recoveryKey = workStateKey(id)
			}
			keys = append(keys, workBlockKey(id), recoveryKey)
			headerKey := workArchivedHeaderKey(id)
			headerBytes := node.block.Header.CanonicalBytes()
			if err := batch.Set(headerKey, headerBytes, nil); err != nil {
				return 0, 0, err
			}
			added, err = checkedHistoryBytes(added, uint64(len(headerKey)+len(headerBytes)))
			if err != nil {
				return 0, 0, err
			}
		}
		for _, key := range keys {
			value, readErr := persistence.get(key)
			if readErr != nil {
				return 0, 0, storage.ErrCorrupt
			}
			released, err = checkedHistoryBytes(released, uint64(len(key)+len(value)))
			if err != nil {
				return 0, 0, err
			}
			if err := batch.Delete(key, nil); err != nil {
				return 0, 0, err
			}
		}
	}
	if _, checkpoint := persistence.checkpoints[anchor.tip.ID]; !checkpoint {
		deltaKey := workDeltaKey(anchor.tip.ID)
		oldDelta, readErr := persistence.get(deltaKey)
		if readErr != nil {
			return 0, 0, storage.ErrCorrupt
		}
		if err := batch.Delete(deltaKey, nil); err != nil {
			return 0, 0, err
		}
		released, err = checkedHistoryBytes(released, uint64(len(deltaKey)+len(oldDelta)))
		if err != nil {
			return 0, 0, err
		}
		stateKey := workStateKey(anchor.tip.ID)
		if err := batch.Set(stateKey, stateBytes, nil); err != nil {
			return 0, 0, err
		}
		added, err = checkedHistoryBytes(added, uint64(len(stateKey)+len(stateBytes)))
		if err != nil {
			return 0, 0, err
		}
	}
	if current, readErr := persistence.get(workKeyFloor); readErr == nil {
		released, err = checkedHistoryBytes(released, uint64(len(workKeyFloor)+len(current)))
		if err != nil {
			return 0, 0, err
		}
	} else if !errors.Is(readErr, pebble.ErrNotFound) {
		return 0, 0, readErr
	}
	if err := batch.Set(workKeyFloor, floorBytes, nil); err != nil {
		return 0, 0, err
	}
	added, err = checkedHistoryBytes(added, uint64(len(workKeyFloor)+len(floorBytes)))
	if err != nil || released > persistence.historyBytes {
		return 0, 0, storage.ErrCorrupt
	}
	var effectSize int
	if effect != nil {
		// All report fields are fixed-width, including accounting itself. Prepare
		// a valid placeholder before the final authorization callback.
		effect.VerifiedAt, effect.Report = boundary.VerifiedAt, report
		effect.Report.AddedHistoryBytes, effect.Report.ReleasedHistoryBytes = added, released
		encoded, err := effect.CanonicalBytes()
		if err != nil {
			return 0, 0, err
		}
		effectSize = len(encoded)
		added, err = checkedHistoryBytes(added, uint64(len(workPruneEffectKey(effect.Operation.TicketID))+effectSize))
		if err != nil {
			return 0, 0, err
		}
		effect.Report.AddedHistoryBytes = added
		encoded, err = effect.CanonicalBytes()
		if err != nil || len(encoded) != effectSize {
			return 0, 0, ErrCanonicalPrune
		}
		if err := batch.Set(workPruneEffectKey(effect.Operation.TicketID), encoded, nil); err != nil {
			return 0, 0, err
		}
		var schema [2]byte
		binary.BigEndian.PutUint16(schema[:], workEffectSchemaVersion)
		if !persistence.storageID.IsZero() {
			binary.BigEndian.PutUint16(schema[:], workBoundEffectSchemaVersion)
		}
		if persistence.pins != nil {
			binary.BigEndian.PutUint16(schema[:], workPositionEffectSchemaVersion)
		}
		if err := batch.Set(workKeySchema, schema[:], nil); err != nil {
			return 0, 0, err
		}
	}
	nextHistory, err := checkedHistoryBytes(persistence.historyBytes-released, added)
	if err != nil || nextHistory > persistence.policy.MaxHistoryBytes {
		return 0, 0, storage.ErrHistoryLimit
	}
	var history [8]byte
	binary.BigEndian.PutUint64(history[:], nextHistory)
	if err := batch.Set(workKeyHistory, history[:], nil); err != nil {
		return 0, 0, err
	}
	if persistence.commitHook != nil {
		if err := persistence.commitHook(); err != nil {
			return 0, 0, err
		}
	}
	prepare := func() error {
		if authorize != nil {
			verifiedAt, err := authorize()
			if err != nil {
				return err
			}
			if verifiedAt < boundary.VerifiedAt || verifiedAt >= boundary.RetainUntil {
				return ErrCanonicalPrune
			}
			boundary.VerifiedAt = verifiedAt
			updatedFloor, err := encodeCanonicalFloor(*boundary)
			if err != nil || len(updatedFloor) != len(floorBytes) {
				return ErrCanonicalPrune
			}
			// Only a fixed-width timestamp changes. Logical-byte accounting above
			// remains exact; none of the prepared deletions is visible yet.
			if err := batch.Set(workKeyFloor, updatedFloor, nil); err != nil {
				return err
			}
		}
		if effect != nil {
			effect.VerifiedAt = boundary.VerifiedAt
			encoded, err := effect.CanonicalBytes()
			if err != nil || len(encoded) != effectSize {
				return ErrCanonicalPrune
			}
			if err := batch.Set(workPruneEffectKey(effect.Operation.TicketID), encoded, nil); err != nil {
				return err
			}
		}
		return nil
	}
	commit := persistence.pruneCommitHook
	if commit == nil {
		commit = func(batch *pebble.Batch) error { return batch.Commit(pebble.Sync) }
	}
	pruneCommit := func(batch *pebble.Batch) error {
		if err := commit(batch); err != nil {
			persistence.uncertain = true
			return errors.Join(ErrUncertain, err)
		}
		return nil
	}
	if err := persistence.commitBatch(batch, prepare, pruneCommit); err != nil {
		return 0, 0, err
	}
	if effect != nil {
		persistence.effectSchema = true
		persistence.pruneEffects++
	}
	persistence.historyBytes = nextHistory
	for _, id := range remove {
		delete(persistence.checkpoints, id)
	}
	persistence.checkpoints[anchor.tip.ID] = struct{}{}
	if persistence.afterCommitHook != nil {
		persistence.afterCommitHook()
	}
	return added, released, nil
}

func (persistence *workPersistence) rotateCheckpoint(
	nodes map[types.Hash]*chainNode,
	tipID types.Hash,
) (CheckpointReport, error) {
	tip := nodes[tipID]
	if tip == nil || tip.block == nil || tip.state == nil || persistence.policy.CheckpointKeep == 0 {
		return CheckpointReport{}, storage.ErrCorrupt
	}
	if _, exists := persistence.checkpoints[tipID]; exists {
		return CheckpointReport{
			CheckpointID: tipID, CheckpointHeight: tip.tip.Height,
			CheckpointCount: uint32(max(0, len(persistence.checkpoints)-1)),
		}, nil
	}
	stateBytes, err := encodePersistedState(tip.state)
	if err != nil {
		return CheckpointReport{}, err
	}
	deltaKey := workDeltaKey(tipID)
	oldDelta, err := persistence.get(deltaKey)
	if errors.Is(err, pebble.ErrNotFound) {
		return CheckpointReport{}, storage.ErrCorrupt
	}
	if err != nil {
		return CheckpointReport{}, err
	}
	candidates := make([]types.Hash, 0, len(persistence.checkpoints))
	for id := range persistence.checkpoints {
		node := nodes[id]
		if node == nil {
			return CheckpointReport{}, storage.ErrCorrupt
		}
		if node.block != nil {
			candidates = append(candidates, id)
		}
	}
	candidates = append(candidates, tipID)
	sort.Slice(candidates, func(left, right int) bool {
		return storage.BetterTip(nodes[candidates[left]].tip, nodes[candidates[right]].tip)
	})
	keep := len(candidates)
	if uint64(keep) > uint64(persistence.policy.CheckpointKeep) {
		keep = int(persistence.policy.CheckpointKeep)
	}
	retired := append([]types.Hash(nil), candidates[keep:]...)
	if keep == 0 || candidates[0] != tipID {
		return CheckpointReport{}, storage.ErrCorrupt
	}

	batch := persistence.db.NewBatch()
	defer batch.Close()
	stateKey := workStateKey(tipID)
	if err := batch.Delete(deltaKey, nil); err != nil {
		return CheckpointReport{}, err
	}
	if err := batch.Set(stateKey, stateBytes, nil); err != nil {
		return CheckpointReport{}, err
	}
	released, err := checkedHistoryBytes(uint64(len(deltaKey) + len(oldDelta)))
	if err != nil {
		return CheckpointReport{}, err
	}
	added, err := checkedHistoryBytes(uint64(len(stateKey) + len(stateBytes)))
	if err != nil {
		return CheckpointReport{}, err
	}
	for _, id := range retired {
		node := nodes[id]
		if node == nil || node.block == nil || node.state == nil {
			return CheckpointReport{}, storage.ErrCorrupt
		}
		parent := nodes[node.block.Header.Seal.AnchorParent]
		if parent == nil || parent.state == nil {
			return CheckpointReport{}, storage.ErrCorrupt
		}
		delta, err := buildStateDelta(parent.state, node.state)
		if err != nil {
			return CheckpointReport{}, err
		}
		deltaBytes, err := encodeStateDelta(delta)
		if err != nil {
			return CheckpointReport{}, err
		}
		oldStateKey := workStateKey(id)
		oldState, err := persistence.get(oldStateKey)
		if errors.Is(err, pebble.ErrNotFound) {
			return CheckpointReport{}, storage.ErrCorrupt
		}
		if err != nil {
			return CheckpointReport{}, err
		}
		newDeltaKey := workDeltaKey(id)
		if err := batch.Delete(oldStateKey, nil); err != nil {
			return CheckpointReport{}, err
		}
		if err := batch.Set(newDeltaKey, deltaBytes, nil); err != nil {
			return CheckpointReport{}, err
		}
		released, err = checkedHistoryBytes(released, uint64(len(oldStateKey)+len(oldState)))
		if err != nil {
			return CheckpointReport{}, err
		}
		added, err = checkedHistoryBytes(added, uint64(len(newDeltaKey)+len(deltaBytes)))
		if err != nil {
			return CheckpointReport{}, err
		}
	}
	if released > persistence.historyBytes {
		return CheckpointReport{}, storage.ErrCorrupt
	}
	nextHistory, err := checkedHistoryBytes(persistence.historyBytes-released, added)
	if err != nil || nextHistory > persistence.policy.MaxHistoryBytes {
		return CheckpointReport{}, storage.ErrHistoryLimit
	}
	var history [8]byte
	binary.BigEndian.PutUint64(history[:], nextHistory)
	if err := batch.Set(workKeyHistory, history[:], nil); err != nil {
		return CheckpointReport{}, err
	}
	if persistence.commitHook != nil {
		if err := persistence.commitHook(); err != nil {
			return CheckpointReport{}, err
		}
	}
	if err := persistence.commitBatch(batch, nil, nil); err != nil {
		return CheckpointReport{}, err
	}
	persistence.historyBytes = nextHistory
	persistence.checkpoints[tipID] = struct{}{}
	for _, id := range retired {
		delete(persistence.checkpoints, id)
	}
	if persistence.afterCommitHook != nil {
		persistence.afterCommitHook()
	}
	return CheckpointReport{
		CheckpointID: tipID, CheckpointHeight: tip.tip.Height, Created: true,
		RetiredCheckpoints: uint32(len(retired)),
		CheckpointCount:    uint32(max(0, len(persistence.checkpoints)-1)),
		AddedHistoryBytes:  added, ReleasedHistoryBytes: released,
	}, nil
}

func (persistence *workPersistence) load(store *Store, base Base) error {
	floorBytes, floorErr := persistence.get(workKeyFloor)
	if floorErr == nil {
		floor, err := decodeCanonicalFloor(floorBytes)
		if err != nil || floor.BaseID != store.baseID {
			return storage.ErrCorrupt
		}
		store.floor = floor
	} else if !errors.Is(floorErr, pebble.ErrNotFound) {
		return floorErr
	}
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
		if id != store.baseID || store.floor.Pruned {
			blockBytes, err := persistence.get(workBlockKey(id))
			if err != nil {
				return err
			}
			candidate, err := workblock.Decode(blockBytes)
			if err != nil {
				return storage.ErrCorrupt
			}
			blockID, _ := candidate.Header.ID()
			if candidate.Header.Version != store.parameters.VersionAt(node.tip.Height) || blockID != id || candidate.Header.StateRoot != node.tip.StateRoot ||
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
	historyBytes, checkpoints, archivedHeaders, err := persistence.historyUsage(
		nodes, store.baseID, store.floor,
	)
	if err != nil {
		return err
	}
	if historyBytes > persistence.policy.MaxHistoryBytes {
		return storage.ErrHistoryLimit
	}
	store.nodes = nodes
	store.archivedHeaders = archivedHeaders
	if err := store.rebuildArchivedIndexLocked(); err != nil {
		return err
	}
	floorID := store.floor.Anchor.ID
	floorNode, floorExists := nodes[floorID]
	if !store.floor.Pruned {
		baseNode := floorNode
		if !floorExists || floorID != store.baseID || baseNode.block != nil ||
			baseNode.result.FeeQueue != nil || !storage.EqualTips(baseNode.tip, base.Tip) ||
			!equalTimestamps(baseNode.history, store.baseHistory) || len(archivedHeaders) != 0 {
			return storage.ErrCorrupt
		}
	} else {
		if !floorExists || floorID == store.baseID || floorNode.block == nil ||
			floorNode.result.FeeQueue == nil || !storage.EqualTips(floorNode.tip, store.floor.Anchor) ||
			store.floor.Anchor.Height < store.parameters.ActivationHeight ||
			uint64(len(archivedHeaders)) != store.floor.Anchor.Height-store.parameters.ActivationHeight {
			return storage.ErrCorrupt
		}
		if _, baseExists := nodes[store.baseID]; baseExists {
			return storage.ErrCorrupt
		}
		parent := cloneTip(store.baseTip)
		if len(archivedHeaders) > 0 {
			lastID, idErr := archivedHeaders[len(archivedHeaders)-1].ID()
			if idErr != nil {
				return storage.ErrCorrupt
			}
			parent = cloneTip(store.archivedTips[lastID])
		}
		expectedFloor, expectedHistory, tipErr := store.archivedHeaderTip(
			parent, store.archivedHistory, floorNode.block.Header,
		)
		if tipErr != nil || !storage.EqualTips(expectedFloor, floorNode.tip) ||
			floorNode.position.ParentTimestamp != parent.Timestamp ||
			floorNode.position.MedianTimePast != median(store.archivedHistory) ||
			!equalTimestamps(expectedHistory, floorNode.history) {
			return storage.ErrCorrupt
		}
	}
	if _, exists := checkpoints[floorID]; !exists {
		return storage.ErrCorrupt
	}
	floorStateBytes, err := persistence.get(workStateKey(floorID))
	if err != nil {
		return storage.ErrCorrupt
	}
	floorNode.state, err = decodePersistedStateVersion(floorStateBytes, commitmentForNode(base, store.parameters, floorNode.tip.Height))
	if err != nil || floorNode.state.Root() != floorNode.tip.StateRoot {
		return storage.ErrCorrupt
	}
	floorNode.result.State = floorNode.state
	order := make([]*chainNode, 0, len(nodes))
	for id, node := range nodes {
		if id != floorID {
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
		if _, checkpoint := checkpoints[node.tip.ID]; checkpoint {
			stateBytes, err := persistence.get(workStateKey(node.tip.ID))
			if err != nil {
				return storage.ErrCorrupt
			}
			node.state, err = decodePersistedStateVersion(stateBytes, store.parameters.CommitmentAt(node.tip.Height))
			if err != nil || node.state.Root() != node.tip.StateRoot {
				return storage.ErrCorrupt
			}
		} else {
			deltaBytes, err := persistence.get(workDeltaKey(node.tip.ID))
			if err != nil {
				return storage.ErrCorrupt
			}
			delta, err := decodeStateDelta(deltaBytes)
			if err != nil {
				return storage.ErrCorrupt
			}
			node.state, err = applyStateDeltaVersion(parent.state, delta, store.parameters.CommitmentAt(node.tip.Height))
			if err != nil || node.state.Root() != node.tip.StateRoot {
				return storage.ErrCorrupt
			}
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
		if storage.MoreWork(node.tip, nodes[tipID].tip) {
			return storage.ErrCorrupt
		}
	}
	storedHistory, err := persistence.get(workKeyHistory)
	if err != nil || len(storedHistory) != 8 {
		return storage.ErrCorrupt
	}
	if binary.BigEndian.Uint64(storedHistory) != historyBytes {
		return storage.ErrCorrupt
	}
	persistence.historyBytes = historyBytes
	persistence.checkpoints = checkpoints
	store.tipID = tipID
	if store.floor.Pruned {
		root, count, commitmentErr := store.selectedAncestryCommitmentLocked(floorID)
		if commitmentErr != nil || root != store.floor.AncestryRoot || count != store.floor.AncestryNodes {
			return storage.ErrCorrupt
		}
	}
	return persistence.verifyPruneEffects(store)
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
	return decodePersistedStateVersion(input, state.CommitmentV0)
}
func decodePersistedStateVersion(input []byte, version uint16) (*state.Memory, error) {
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
	return state.NewVersion(resources, version)
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
	return applyStateDeltaVersion(before, delta, before.CommitmentVersion())
}
func applyStateDeltaVersion(before *state.Memory, delta stateDelta, version uint16) (*state.Memory, error) {
	if before == nil {
		return nil, storage.ErrCorrupt
	}
	current := before
	if before.CommitmentVersion() != version {
		if before.CommitmentVersion() != state.CommitmentV0 || version != state.CommitmentRadixV1 {
			return nil, storage.ErrCorrupt
		}
		var err error
		current, err = state.NewVersion(before.Resources(), version)
		if err != nil {
			return nil, errors.Join(storage.ErrCorrupt, err)
		}
	}
	result, err := current.WithChanges(delta.deleted, delta.created)
	if err != nil {
		return nil, errors.Join(storage.ErrCorrupt, err)
	}
	return result, nil
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
	if parameters.RadixActivationHeight != 0 {
		encoder.U64(parameters.RadixActivationHeight)
		return types.DomainHash("OMESH/workchain/config/v3", encoder.Bytes())
	}
	return types.DomainHash("OMESH/workchain/config/v0", encoder.Bytes())
}

func workNodeKey(id types.Hash) []byte  { return workIDKey(workNodePrefix, id) }
func workBlockKey(id types.Hash) []byte { return workIDKey(workBlockPrefix, id) }
func workStateKey(id types.Hash) []byte { return workIDKey(workStatePrefix, id) }
func workDeltaKey(id types.Hash) []byte { return workIDKey(workDeltaPrefix, id) }
func workArchivedHeaderKey(id types.Hash) []byte {
	return workIDKey(workArchivedHeaderPrefix, id)
}

func workIDKey(prefix byte, id types.Hash) []byte {
	result := make([]byte, 1+types.HashSize)
	result[0] = prefix
	copy(result[1:], id[:])
	return result
}

func encodeCanonicalFloor(floor CanonicalFloor) ([]byte, error) {
	if floor.validate() != nil {
		return nil, ErrCanonicalPrune
	}
	encoder := codec.NewEncoder(maxCanonicalFloorBytes)
	version := uint16(0)
	if !floor.PruneTicketID.IsZero() {
		version = 1
	}
	encoder.U16(version)
	encoder.Fixed(floor.BaseID[:])
	encoder.BytesField(floor.Anchor.CanonicalBytes())
	encoder.U64(floor.AncestryNodes)
	encoder.Fixed(floor.AncestryRoot[:])
	encoder.Fixed(floor.StatementID[:])
	encoder.Fixed(floor.ManifestID[:])
	encoder.Fixed(floor.AvailabilityID[:])
	encoder.U64(floor.VerifiedAt)
	encoder.U64(floor.RetainUntil)
	if version == 1 {
		encoder.Fixed(floor.PruneTicketID[:])
	}
	if encoder.Len() > maxCanonicalFloorBytes {
		return nil, storage.ErrCorrupt
	}
	return encoder.Bytes(), nil
}

func decodeCanonicalFloor(input []byte) (CanonicalFloor, error) {
	if len(input) == 0 || len(input) > maxCanonicalFloorBytes {
		return CanonicalFloor{}, storage.ErrCorrupt
	}
	decoder := codec.NewDecoder(input)
	version, err := decoder.U16()
	if err != nil || version > 1 {
		return CanonicalFloor{}, storage.ErrCorrupt
	}
	result := CanonicalFloor{Pruned: true}
	for _, destination := range []*types.Hash{
		&result.BaseID,
	} {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return CanonicalFloor{}, decodeErr
		}
		copy(destination[:], value)
	}
	tipBytes, err := decoder.BytesField(256)
	if err != nil {
		return CanonicalFloor{}, err
	}
	result.Anchor, err = storage.DecodeTip(tipBytes)
	if err != nil {
		return CanonicalFloor{}, err
	}
	if result.AncestryNodes, err = decoder.U64(); err != nil {
		return CanonicalFloor{}, err
	}
	for _, destination := range []*types.Hash{
		&result.AncestryRoot, &result.StatementID, &result.ManifestID, &result.AvailabilityID,
	} {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return CanonicalFloor{}, decodeErr
		}
		copy(destination[:], value)
	}
	if result.VerifiedAt, err = decoder.U64(); err != nil {
		return CanonicalFloor{}, err
	}
	if result.RetainUntil, err = decoder.U64(); err != nil {
		return CanonicalFloor{}, err
	}
	if version == 1 {
		value, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return CanonicalFloor{}, storage.ErrCorrupt
		}
		copy(result.PruneTicketID[:], value)
		if result.PruneTicketID.IsZero() {
			return CanonicalFloor{}, storage.ErrCorrupt
		}
	}
	if err := decoder.Finish(); err != nil || result.validate() != nil {
		return CanonicalFloor{}, storage.ErrCorrupt
	}
	return result, nil
}

func (persistence *workPersistence) get(key []byte) ([]byte, error) {
	value, closer, err := persistence.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return append([]byte(nil), value...), nil
}

func (persistence *workPersistence) historyUsage(
	nodes map[types.Hash]*chainNode,
	baseID types.Hash,
	floor CanonicalFloor,
) (uint64, map[types.Hash]struct{}, []workblock.Header, error) {
	iterator, err := persistence.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{workNodePrefix}, UpperBound: []byte{workPruneEffectPrefix + 1},
	})
	if err != nil {
		return 0, nil, nil, err
	}
	defer iterator.Close()
	var total uint64
	seenNodes := make(map[types.Hash]struct{}, len(nodes))
	seenBlocks := make(map[types.Hash]struct{}, len(nodes))
	checkpoints := make(map[types.Hash]struct{})
	deltas := make(map[types.Hash]struct{}, len(nodes))
	archived := make(map[types.Hash]workblock.Header)
	var effectCount uint32
	for valid := iterator.First(); valid; valid = iterator.Next() {
		key := iterator.Key()
		if len(key) != 1+types.HashSize {
			return 0, nil, nil, storage.ErrCorrupt
		}
		var id types.Hash
		copy(id[:], key[1:])
		node, exists := nodes[id]
		switch key[0] {
		case workNodePrefix:
			if !exists {
				return 0, nil, nil, storage.ErrCorrupt
			}
			seenNodes[id] = struct{}{}
		case workStatePrefix:
			if !exists {
				return 0, nil, nil, storage.ErrCorrupt
			}
			checkpoints[id] = struct{}{}
		case workBlockPrefix:
			if !exists || (id == baseID && !floor.Pruned) || node.block == nil {
				return 0, nil, nil, storage.ErrCorrupt
			}
			seenBlocks[id] = struct{}{}
		case workDeltaPrefix:
			if !exists || id == floor.Anchor.ID || node.block == nil {
				return 0, nil, nil, storage.ErrCorrupt
			}
			deltas[id] = struct{}{}
		case workArchivedHeaderPrefix:
			if exists || !floor.Pruned {
				return 0, nil, nil, storage.ErrCorrupt
			}
			header, decodeErr := workblock.DecodeHeader(iterator.Value())
			if decodeErr != nil {
				return 0, nil, nil, storage.ErrCorrupt
			}
			headerID, idErr := header.ID()
			if idErr != nil || headerID != id {
				return 0, nil, nil, storage.ErrCorrupt
			}
			archived[id] = header
		case workPruneEffectPrefix:
			if effectCount >= MaximumCanonicalPruneEffects {
				return 0, nil, nil, storage.ErrCorrupt
			}
			effectCount++
			effect, decodeErr := DecodeCanonicalPruneEffect(iterator.Value())
			if !persistence.effectSchema || !floor.Pruned || decodeErr != nil ||
				effect.Operation.TicketID != id || effect.Operation.Boundary.BaseID != baseID ||
				effect.Operation.StorageID != persistence.storageID {
				return 0, nil, nil, storage.ErrCorrupt
			}
		default:
			return 0, nil, nil, storage.ErrCorrupt
		}
		total, err = checkedHistoryBytes(total, uint64(len(key)+len(iterator.Value())))
		if err != nil {
			return 0, nil, nil, err
		}
	}
	if err := iterator.Error(); err != nil {
		return 0, nil, nil, err
	}
	if floor.Pruned {
		encodedFloor, readErr := persistence.get(workKeyFloor)
		if readErr != nil {
			return 0, nil, nil, storage.ErrCorrupt
		}
		total, err = checkedHistoryBytes(total, uint64(len(workKeyFloor)+len(encodedFloor)))
		if err != nil {
			return 0, nil, nil, err
		}
	}
	for id, node := range nodes {
		_, hasNode := seenNodes[id]
		_, hasBlock := seenBlocks[id]
		_, hasCheckpoint := checkpoints[id]
		_, hasDelta := deltas[id]
		if !hasNode {
			return 0, nil, nil, storage.ErrCorrupt
		}
		if id == floor.Anchor.ID {
			if !hasCheckpoint || hasDelta || (floor.Pruned && (!hasBlock || node.block == nil)) ||
				(!floor.Pruned && (hasBlock || node.block != nil)) {
				return 0, nil, nil, storage.ErrCorrupt
			}
		} else if node.block == nil || !hasBlock || hasCheckpoint == hasDelta {
			return 0, nil, nil, storage.ErrCorrupt
		}
	}
	headers := make([]workblock.Header, 0, len(archived))
	for _, header := range archived {
		headers = append(headers, header)
	}
	sort.Slice(headers, func(left, right int) bool {
		if headers[left].Seal.Height != headers[right].Seal.Height {
			return headers[left].Seal.Height < headers[right].Seal.Height
		}
		leftID, _ := headers[left].ID()
		rightID, _ := headers[right].ID()
		return types.CompareHash(leftID, rightID) < 0
	})
	return total, checkpoints, headers, nil
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

func (persistence *workPersistence) close() error {
	err := persistence.db.Close()
	if persistence.pins != nil {
		err = errors.Join(err, persistence.pins.lock.Close())
	}
	return err
}

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

func commitmentForNode(base Base, p workblock.Parameters, height uint64) uint16 {
	if height == base.Tip.Height {
		return base.State.CommitmentVersion()
	}
	return p.CommitmentAt(height)
}
