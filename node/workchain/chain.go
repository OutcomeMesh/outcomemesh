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
		if err := store.persistence.commitNode(node, canonicalTip); err != nil {
			return storage.Tip{}, workblock.Result{}, err
		}
	}
	store.nodes[next.ID] = node
	if better {
		store.tipID = next.ID
	}
	return cloneTip(store.nodes[store.tipID].tip), result, nil
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
