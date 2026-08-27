package workchain

import (
	"errors"
	"math/big"
	"sort"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/difficulty"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/pow"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrConfiguration = errors.New("invalid WorkGraph chain configuration")
	ErrParent        = errors.New("unknown WorkGraph chain parent")
	ErrPosition      = errors.New("invalid WorkGraph chain position")
	ErrDuplicate     = errors.New("duplicate WorkGraph chain block")
)

type Base struct {
	Tip              storage.Tip
	State            *state.Memory
	RecentTimestamps []uint64
}

// PruneReport describes one completed local side-fork maintenance pass.
type PruneReport struct {
	CutoffHeight         uint64
	RemovedNodes         uint64
	RetainedNodes        uint64
	ReleasedHistoryBytes uint64
}

// CheckpointReport describes one completed replay-checkpoint maintenance pass.
type CheckpointReport struct {
	CheckpointID         types.Hash
	CheckpointHeight     uint64
	Created              bool
	RetiredCheckpoints   uint32
	CheckpointCount      uint32
	AddedHistoryBytes    uint64
	ReleasedHistoryBytes uint64
}

type chainNode struct {
	tip      storage.Tip
	state    *state.Memory
	block    *workblock.Block
	result   workblock.Result
	position workblock.Position
	history  []uint64
}

type Store struct {
	mu          sync.RWMutex
	parameters  workblock.Parameters
	baseID      types.Hash
	tipID       types.Hash
	nodes       map[types.Hash]*chainNode
	persistence *workPersistence
	closed      bool
}

func New(base Base, parameters workblock.Parameters) (*Store, error) {
	_, _, rewardErr := workgraph.RewardRates(parameters.BlockSubsidy)
	if base.State == nil || base.Tip.Validate() != nil || base.Tip.StateRoot != base.State.Root() ||
		base.Tip.Height == ^uint64(0) || base.Tip.Height+1 != parameters.ActivationHeight ||
		parameters.NetworkID == 0 || rewardErr != nil || parameters.RewardMaturity == 0 ||
		parameters.DifficultyAnchorTimestamp == 0 ||
		!workgraph.ExactShareRatio(parameters.DifficultyAnchorTarget) ||
		parameters.TargetSpacing == 0 || parameters.ASERTHalfLife == 0 ||
		parameters.FeeDelay == 0 || parameters.FeeDelay > workgraph.MaxFeeDelay {
		return nil, ErrConfiguration
	}
	history := append([]uint64(nil), base.RecentTimestamps...)
	if len(history) == 0 {
		history = []uint64{base.Tip.Timestamp}
	}
	if len(history) > 11 || history[len(history)-1] != base.Tip.Timestamp {
		return nil, ErrConfiguration
	}
	for _, timestamp := range history {
		if timestamp == 0 {
			return nil, ErrConfiguration
		}
	}
	stateCopy, err := cloneState(base.State)
	if err != nil {
		return nil, err
	}
	baseTip := cloneTip(base.Tip)
	node := &chainNode{tip: baseTip, state: stateCopy, history: history}
	return &Store{
		parameters: parameters, baseID: baseTip.ID, tipID: baseTip.ID,
		nodes: map[types.Hash]*chainNode{baseTip.ID: node},
	}, nil
}

func (store *Store) Tip() (storage.Tip, error) {
	if store == nil {
		return storage.Tip{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	return cloneTip(store.nodes[store.tipID].tip), nil
}

// BaseID returns the immutable version-0 activation parent anchoring this
// tree. It lets a multi-tree coordinator bind a reopened database to its
// directory identity without exposing internal nodes.
func (store *Store) BaseID() (types.Hash, error) {
	if store == nil {
		return types.Hash{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return types.Hash{}, storage.ErrClosed
	}
	return store.baseID, nil
}

// NodeIDs returns a sorted detached inventory including the activation base.
// Reopening coordinators use it to rebuild their block-to-tree index only
// after the store has verified every persisted node and state transition.
func (store *Store) NodeIDs() ([]types.Hash, error) {
	if store == nil {
		return nil, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return nil, storage.ErrClosed
	}
	result := make([]types.Hash, 0, len(store.nodes))
	for id := range store.nodes {
		result = append(result, id)
	}
	sort.Slice(result, func(left, right int) bool {
		return types.CompareHash(result[left], result[right]) < 0
	})
	return result, nil
}

// TipByID returns detached fork metadata for header-first continuation without
// making that node the selected tip.
func (store *Store) TipByID(id types.Hash) (storage.Tip, error) {
	if store == nil {
		return storage.Tip{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	node, exists := store.nodes[id]
	if !exists {
		return storage.Tip{}, storage.ErrNodeNotFound
	}
	return cloneTip(node.tip), nil
}

func (store *Store) Snapshot() (*state.Memory, error) {
	if store == nil {
		return nil, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return nil, storage.ErrClosed
	}
	return cloneState(store.nodes[store.tipID].state)
}

func (store *Store) BlockByID(id types.Hash) (workblock.Block, error) {
	if store == nil {
		return workblock.Block{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return workblock.Block{}, storage.ErrClosed
	}
	node, exists := store.nodes[id]
	if !exists || node.block == nil {
		return workblock.Block{}, ErrParent
	}
	return cloneBlock(*node.block)
}

// Prepare reconstructs every fork-local input needed to mine a child.
func (store *Store) Prepare(
	parentID types.Hash,
	timestamp uint64,
	transactions []outcome.Transaction,
) (*workblock.Payload, workblock.Position, error) {
	if store == nil {
		return nil, workblock.Position{}, ErrConfiguration
	}
	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return nil, workblock.Position{}, storage.ErrClosed
	}
	parent, exists := store.nodes[parentID]
	if !exists {
		store.mu.RUnlock()
		return nil, workblock.Position{}, ErrParent
	}
	position, previous, preState, err := store.childInputsLocked(parent, timestamp, types.Hash{})
	store.mu.RUnlock()
	if err != nil {
		return nil, workblock.Position{}, err
	}
	payload, err := workblock.PreparePayload(preState, position, previous, transactions, store.parameters)
	if err != nil {
		return nil, workblock.Position{}, err
	}
	return payload, position, nil
}

func (store *Store) Commit(
	candidate workblock.Block,
	validationTime uint64,
) (storage.Tip, workblock.Result, error) {
	if store == nil {
		return storage.Tip{}, workblock.Result{}, ErrConfiguration
	}
	if err := candidate.ValidateBasic(); err != nil {
		return storage.Tip{}, workblock.Result{}, err
	}
	parentID := candidate.Header.Seal.AnchorParent
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return storage.Tip{}, workblock.Result{}, storage.ErrClosed
	}
	parent, exists := store.nodes[parentID]
	if !exists {
		return storage.Tip{}, workblock.Result{}, ErrParent
	}
	position, previous, preState, err := store.childInputsLocked(
		parent, candidate.Header.Seal.Timestamp, candidate.Header.Seal.Target,
	)
	if err != nil {
		return storage.Tip{}, workblock.Result{}, err
	}
	result, err := workblock.ValidateAndExecuteAt(
		preState, position, previous, candidate, store.parameters, validationTime,
	)
	if err != nil {
		return storage.Tip{}, workblock.Result{}, err
	}
	next, err := nextTip(parent.tip, candidate)
	if err != nil {
		return storage.Tip{}, workblock.Result{}, err
	}
	if _, exists := store.nodes[next.ID]; exists {
		return storage.Tip{}, workblock.Result{}, ErrDuplicate
	}
	stateCopy, err := cloneState(result.State)
	if err != nil {
		return storage.Tip{}, workblock.Result{}, err
	}
	blockCopy, err := cloneBlock(candidate)
	if err != nil {
		return storage.Tip{}, workblock.Result{}, err
	}
	history := append(append([]uint64(nil), parent.history...), next.Timestamp)
	if len(history) > 11 {
		history = append([]uint64(nil), history[len(history)-11:]...)
	}
	node := &chainNode{
		tip: cloneTip(next), state: stateCopy, block: &blockCopy, result: result,
		position: position, history: history,
	}
	better := storage.BetterTip(next, store.nodes[store.tipID].tip)
	if store.persistence != nil {
		canonicalTip := store.tipID
		if better {
			canonicalTip = next.ID
		}
		if err := store.persistence.commitNode(parent, node, canonicalTip); err != nil {
			return storage.Tip{}, workblock.Result{}, err
		}
	}
	store.nodes[next.ID] = node
	if better {
		store.tipID = next.ID
	}
	return cloneTip(store.nodes[store.tipID].tip), result, nil
}

// HistoryUsage reports immutable logical WorkGraph history bytes and the local
// admission limit. In-memory stores report zero values.
func (store *Store) HistoryUsage() (uint64, uint64, error) {
	if store == nil {
		return 0, 0, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return 0, 0, storage.ErrClosed
	}
	if store.persistence == nil {
		return 0, 0, nil
	}
	return store.persistence.historyBytes, store.persistence.policy.MaxHistoryBytes, nil
}

// PruneStaleForks atomically removes side-branch subtrees that have not reached
// the configured retention window. Canonical history and every ancestor of a
// retained side branch remain available. A zero retention policy disables the
// operation; in-memory stores have no persistent pruning policy and are no-ops.
func (store *Store) PruneStaleForks() (PruneReport, error) {
	if store == nil {
		return PruneReport{}, ErrConfiguration
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return PruneReport{}, storage.ErrClosed
	}
	if store.persistence == nil || store.persistence.policy.ForkRetention == 0 {
		return PruneReport{RetainedNodes: uint64(len(store.nodes))}, nil
	}
	tip := store.nodes[store.tipID]
	if tip == nil {
		return PruneReport{}, storage.ErrCorrupt
	}
	retention := store.persistence.policy.ForkRetention
	if tip.tip.Height <= retention {
		return PruneReport{RetainedNodes: uint64(len(store.nodes))}, nil
	}
	cutoff := tip.tip.Height - retention
	keep := make(map[types.Hash]struct{}, len(store.nodes))
	if err := store.markAncestorsLocked(store.tipID, keep); err != nil {
		return PruneReport{}, err
	}
	for id, node := range store.nodes {
		if node == nil {
			return PruneReport{}, storage.ErrCorrupt
		}
		if node.tip.Height >= cutoff {
			if err := store.markAncestorsLocked(id, keep); err != nil {
				return PruneReport{}, err
			}
		}
	}
	remove := make([]types.Hash, 0, len(store.nodes)-len(keep))
	for id := range store.nodes {
		if _, retained := keep[id]; !retained {
			remove = append(remove, id)
		}
	}
	sort.Slice(remove, func(left, right int) bool {
		return types.CompareHash(remove[left], remove[right]) < 0
	})
	released, err := store.persistence.pruneNodes(store.nodes, remove)
	if err != nil {
		return PruneReport{}, err
	}
	for _, id := range remove {
		delete(store.nodes, id)
	}
	return PruneReport{
		CutoffHeight: cutoff, RemovedNodes: uint64(len(remove)),
		RetainedNodes: uint64(len(store.nodes)), ReleasedHistoryBytes: released,
	}, nil
}

// CreateReplayCheckpoint atomically replaces the selected tip's resource delta
// with a full-state checkpoint after the configured interval. The bounded
// checkpoint set is rotated in the same batch: retired full states are turned
// back into their exact parent deltas. This is local recovery policy and does
// not change fork choice or prune canonical blocks.
func (store *Store) CreateReplayCheckpoint() (CheckpointReport, error) {
	if store == nil {
		return CheckpointReport{}, ErrConfiguration
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return CheckpointReport{}, storage.ErrClosed
	}
	if store.persistence == nil || store.persistence.policy.CheckpointEvery == 0 ||
		store.persistence.policy.CheckpointKeep == 0 {
		return CheckpointReport{}, nil
	}
	checkpointCount := uint32(max(0, len(store.persistence.checkpoints)-1))
	tip := store.nodes[store.tipID]
	if tip == nil {
		return CheckpointReport{}, storage.ErrCorrupt
	}
	cursor := tip
	for {
		if _, checkpoint := store.persistence.checkpoints[cursor.tip.ID]; checkpoint {
			if tip.tip.Height < cursor.tip.Height {
				return CheckpointReport{}, storage.ErrCorrupt
			}
			if tip.tip.ID == cursor.tip.ID ||
				tip.tip.Height-cursor.tip.Height < store.persistence.policy.CheckpointEvery {
				return CheckpointReport{
					CheckpointID: cursor.tip.ID, CheckpointHeight: cursor.tip.Height,
					CheckpointCount: checkpointCount,
				}, nil
			}
			break
		}
		if cursor.block == nil {
			return CheckpointReport{}, storage.ErrCorrupt
		}
		parent := store.nodes[cursor.block.Header.Seal.AnchorParent]
		if parent == nil {
			return CheckpointReport{}, storage.ErrCorrupt
		}
		cursor = parent
	}
	return store.persistence.rotateCheckpoint(store.nodes, store.tipID)
}

func (store *Store) Close() error {
	if store == nil {
		return ErrConfiguration
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return storage.ErrClosed
	}
	store.closed = true
	if store.persistence != nil {
		return store.persistence.close()
	}
	return nil
}

func (store *Store) markAncestorsLocked(id types.Hash, keep map[types.Hash]struct{}) error {
	for {
		if _, exists := keep[id]; exists {
			return nil
		}
		node, exists := store.nodes[id]
		if !exists || node == nil {
			return storage.ErrCorrupt
		}
		keep[id] = struct{}{}
		if node.block == nil {
			if id != store.baseID {
				return storage.ErrCorrupt
			}
			return nil
		}
		id = node.block.Header.Seal.AnchorParent
	}
}

func (store *Store) childInputsLocked(
	parent *chainNode,
	timestamp uint64,
	declaredTarget types.Hash,
) (workblock.Position, *workblock.Earning, *state.Memory, error) {
	if parent == nil || timestamp == 0 || parent.tip.Height == ^uint64(0) {
		return workblock.Position{}, nil, nil, ErrPosition
	}
	height := parent.tip.Height + 1
	evaluation, err := types.AddAmount(parent.tip.Timestamp, store.parameters.TargetSpacing)
	if err != nil {
		return workblock.Position{}, nil, nil, ErrPosition
	}
	target, err := difficulty.ASERT(
		store.parameters.DifficultyAnchorTarget, store.parameters.DifficultyAnchorTimestamp,
		height, evaluation, store.parameters.TargetSpacing, store.parameters.ASERTHalfLife,
	)
	if err != nil || (!declaredTarget.IsZero() && declaredTarget != target) {
		return workblock.Position{}, nil, nil, ErrPosition
	}
	position := workblock.Position{
		Height: height, ParentID: parent.tip.ID, ParentTimestamp: parent.tip.Timestamp,
		MedianTimePast: median(parent.history), Timestamp: timestamp, Target: target,
	}
	var previous *workblock.Earning
	if height == store.parameters.ActivationHeight {
		if parent.tip.ID != store.baseID || parent.block != nil {
			return workblock.Position{}, nil, nil, ErrPosition
		}
	} else {
		if parent.block == nil || parent.result.FeeQueue == nil {
			return workblock.Position{}, nil, nil, ErrPosition
		}
		position.FeeQueue = parent.result.FeeQueue
		previous = &workblock.Earning{
			Seal: parent.block.Header.Seal, Shares: append([]workgraph.Share(nil), parent.block.Shares...),
			FeeAward:        parent.block.Header.FeeAward,
			ParentTimestamp: parent.position.ParentTimestamp, MedianTimePast: parent.position.MedianTimePast,
		}
	}
	preState, err := cloneState(parent.state)
	if err != nil {
		return workblock.Position{}, nil, nil, err
	}
	return position, previous, preState, nil
}

func nextTip(parent storage.Tip, candidate workblock.Block) (storage.Tip, error) {
	seal := candidate.Header.Seal
	if seal.AnchorParent != parent.ID || seal.Height != parent.Height+1 || candidate.Header.StateRoot.IsZero() {
		return storage.Tip{}, ErrPosition
	}
	id, err := candidate.Header.ID()
	if err != nil {
		return storage.Tip{}, err
	}
	work, err := pow.Work(seal.Target)
	if err != nil {
		return storage.Tip{}, err
	}
	cumulative := new(big.Int).SetBytes(parent.CumulativeWork)
	cumulative.Add(cumulative, work)
	encoded := cumulative.Bytes()
	if len(encoded) > storage.MaxWorkBytes {
		return storage.Tip{}, storage.ErrWorkEncoding
	}
	return storage.Tip{
		ID: id, Height: seal.Height, Timestamp: seal.Timestamp, Target: seal.Target,
		StateRoot: candidate.Header.StateRoot, CumulativeWork: encoded,
	}, nil
}

func median(values []uint64) uint64 {
	copyValues := append([]uint64(nil), values...)
	sort.Slice(copyValues, func(left, right int) bool { return copyValues[left] < copyValues[right] })
	return copyValues[len(copyValues)/2]
}

func cloneTip(value storage.Tip) storage.Tip {
	value.CumulativeWork = append([]byte(nil), value.CumulativeWork...)
	return value
}

func cloneState(value *state.Memory) (*state.Memory, error) {
	if value == nil {
		return nil, ErrConfiguration
	}
	return state.New(value.Resources())
}

func cloneBlock(value workblock.Block) (workblock.Block, error) {
	return workblock.Decode(value.CanonicalBytes())
}
