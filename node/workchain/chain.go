package workchain

import (
	"encoding/binary"
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
	ErrConfiguration  = errors.New("invalid WorkGraph chain configuration")
	ErrParent         = errors.New("unknown WorkGraph chain parent")
	ErrPosition       = errors.New("invalid WorkGraph chain position")
	ErrDuplicate      = errors.New("duplicate WorkGraph chain block")
	ErrHistoryPruned  = errors.New("WorkGraph block payload was archived and pruned")
	ErrCanonicalPrune = errors.New("unsafe WorkGraph canonical-prefix prune")
	ErrUncertain      = errors.New("uncertain WorkGraph storage commit; close and reopen required")
)

const (
	selectedAncestrySeedDomain = "OMESH/workgraph/archive/selected-ancestry-seed/v0"
	selectedAncestryStepDomain = "OMESH/workgraph/archive/selected-ancestry-step/v0"
	selectedAncestryRootDomain = "OMESH/workgraph/archive/selected-ancestry-root/v0"
)

type Base struct {
	Tip              storage.Tip
	State            *state.Memory
	RecentTimestamps []uint64
}

// SelectedHistory is a detached, point-in-time inventory of one selected
// ancestry. BlockIDs run from the activation block through Anchor; the
// immutable activation parent is represented separately by BaseID.
type SelectedHistory struct {
	BaseID        types.Hash
	Anchor        storage.Tip
	BlockIDs      []types.Hash
	AncestryNodes uint64
	AncestryRoot  types.Hash
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

// CanonicalFloor is the durable recovery boundary left after an independently
// authorized canonical-prefix prune. The immutable activation BaseID remains
// the tree identity; Anchor is the oldest locally executable block.
type CanonicalFloor struct {
	Pruned         bool
	BaseID         types.Hash
	Anchor         storage.Tip
	AncestryNodes  uint64
	AncestryRoot   types.Hash
	StatementID    types.Hash
	ManifestID     types.Hash
	AvailabilityID types.Hash
	VerifiedAt     uint64
	RetainUntil    uint64
	// PruneTicketID links a ticketed prune to its result in the same transaction.
	// It is local provenance, not a remotely verified authority grant.
	PruneTicketID types.Hash
}

// CanonicalPruneReport describes one atomic replacement of full canonical
// history with verified headers plus a full-state retained floor.
type CanonicalPruneReport struct {
	PreviousFloorID      types.Hash
	FloorID              types.Hash
	RemovedNodes         uint64
	RetainedNodes        uint64
	ArchivedHeaders      uint64
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
	mu              sync.RWMutex
	parameters      workblock.Parameters
	baseID          types.Hash
	baseTip         storage.Tip
	baseHistory     []uint64
	floor           CanonicalFloor
	tipID           types.Hash
	nodes           map[types.Hash]*chainNode
	archivedHeaders []workblock.Header
	archivedTips    map[types.Hash]storage.Tip
	archivedIndex   map[types.Hash]int
	archivedHistory []uint64
	persistence     *workPersistence
	closed          bool
}

func New(base Base, parameters workblock.Parameters) (*Store, error) {
	_, _, rewardErr := workgraph.RewardRates(parameters.BlockSubsidy)
	if base.State == nil || base.State.CommitmentVersion() != state.CommitmentV0 || base.Tip.Validate() != nil || base.Tip.StateRoot != base.State.Root() ||
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
		parameters: parameters, baseID: baseTip.ID, baseTip: cloneTip(baseTip),
		baseHistory: append([]uint64(nil), history...), tipID: baseTip.ID,
		floor:        CanonicalFloor{BaseID: baseTip.ID, Anchor: cloneTip(baseTip), AncestryNodes: 1},
		nodes:        map[types.Hash]*chainNode{baseTip.ID: node},
		archivedTips: make(map[types.Hash]storage.Tip), archivedIndex: make(map[types.Hash]int),
	}, nil
}

func (store *Store) Tip() (storage.Tip, error) {
	if store == nil {
		return storage.Tip{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return storage.Tip{}, err
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
	if err := store.openErrorLocked(); err != nil {
		return types.Hash{}, err
	}
	return store.baseID, nil
}

// NodeIDs returns the sorted locally executable inventory. Before canonical
// pruning it includes the activation base; afterwards it starts at the retained
// floor. Archived headers cannot be used as new block parents.
func (store *Store) NodeIDs() ([]types.Hash, error) {
	if store == nil {
		return nil, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return nil, err
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
	if err := store.openErrorLocked(); err != nil {
		return storage.Tip{}, err
	}
	if node, exists := store.nodes[id]; exists {
		return cloneTip(node.tip), nil
	}
	if id == store.baseID {
		return cloneTip(store.baseTip), nil
	}
	if tip, exists := store.archivedTips[id]; exists {
		return cloneTip(tip), nil
	}
	return storage.Tip{}, storage.ErrNodeNotFound
}

// CanonicalFloor returns the detached local archival recovery boundary. A
// false Pruned value means the immutable activation base is still present.
func (store *Store) CanonicalFloor() (CanonicalFloor, error) {
	if store == nil {
		return CanonicalFloor{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return CanonicalFloor{}, err
	}
	return cloneCanonicalFloor(store.floor), nil
}

// IsAncestor reports whether ancestor lies on descendant's verified local
// WorkGraph ancestry. It does not imply that either node is on the selected
// branch; archive policy uses SelectedAncestryCommitment for that stronger
// check.
func (store *Store) IsAncestor(ancestor, descendant types.Hash) (bool, error) {
	if store == nil || ancestor.IsZero() || descendant.IsZero() {
		return false, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return false, err
	}
	return store.isAncestorLocked(ancestor, descendant)
}

// SelectedAncestryCommitment returns an order-sensitive commitment to the
// exact selected ancestry from anchor back through the immutable activation
// base. The backward hash chain needs constant auxiliary memory; the final
// node count prevents alternate-length interpretations. It is local evidence
// for independently attested archive anchors and never changes fork choice.
func (store *Store) SelectedAncestryCommitment(
	anchor types.Hash,
) (types.Hash, uint64, error) {
	if store == nil || anchor.IsZero() {
		return types.Hash{}, 0, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return types.Hash{}, 0, err
	}
	return store.selectedAncestryCommitmentLocked(anchor)
}

// SelectedHistorySnapshot returns a bounded inventory and commitment captured
// under one read lock. Blocks remain immutable after admission, so an archive
// exporter can fetch the detached IDs after releasing the lock and then
// recheck selection before publication.
func (store *Store) SelectedHistorySnapshot(
	anchor types.Hash,
	maximumBlocks uint64,
) (SelectedHistory, error) {
	if store == nil || anchor.IsZero() || maximumBlocks == 0 {
		return SelectedHistory{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return SelectedHistory{}, err
	}
	selected, err := store.isAncestorLocked(anchor, store.tipID)
	if err != nil {
		return SelectedHistory{}, err
	}
	if !selected {
		return SelectedHistory{}, ErrPosition
	}
	anchorNode := store.nodes[anchor]
	if anchorNode == nil || anchorNode.tip.Height < store.baseTip.Height {
		return SelectedHistory{}, storage.ErrCorrupt
	}
	blockCount := anchorNode.tip.Height - store.baseTip.Height
	if blockCount > maximumBlocks || blockCount > uint64(^uint(0)>>1) {
		return SelectedHistory{}, storage.ErrHistoryLimit
	}
	ids, err := store.selectedAncestryIDsLocked(anchor, int(blockCount))
	if err != nil {
		return SelectedHistory{}, err
	}
	root, count, err := store.selectedAncestryCommitmentLocked(anchor)
	if err != nil || count != blockCount+1 {
		return SelectedHistory{}, storage.ErrCorrupt
	}
	return SelectedHistory{
		BaseID: store.baseID, Anchor: cloneTip(anchorNode.tip), BlockIDs: ids,
		AncestryNodes: count, AncestryRoot: root,
	}, nil
}

func (store *Store) selectedAncestryCommitmentLocked(
	anchor types.Hash,
) (types.Hash, uint64, error) {
	selected, err := store.isAncestorLocked(anchor, store.tipID)
	if err != nil {
		return types.Hash{}, 0, err
	}
	if !selected {
		return types.Hash{}, 0, ErrPosition
	}
	root := types.DomainHash(selectedAncestrySeedDomain, anchor[:])
	count := uint64(1)
	if anchor == store.baseID {
		return finalizeSelectedAncestryRoot(root, count), count, nil
	}
	if archivedAt, archived := store.archivedIndex[anchor]; archived {
		for index := archivedAt - 1; index >= 0; index-- {
			parent, idErr := store.archivedHeaders[index].ID()
			if idErr != nil || count == ^uint64(0) {
				return types.Hash{}, 0, storage.ErrCorrupt
			}
			root = types.DomainHash(selectedAncestryStepDomain, root[:], parent[:])
			count++
		}
		if count == ^uint64(0) {
			return types.Hash{}, 0, storage.ErrCorrupt
		}
		root = types.DomainHash(selectedAncestryStepDomain, root[:], store.baseID[:])
		count++
		return finalizeSelectedAncestryRoot(root, count), count, nil
	}
	cursor := anchor
	for cursor != store.floor.Anchor.ID {
		node := store.nodes[cursor]
		if node == nil || node.block == nil || count == ^uint64(0) {
			return types.Hash{}, 0, storage.ErrCorrupt
		}
		parent := node.block.Header.Seal.AnchorParent
		if _, exists := store.nodes[parent]; !exists {
			return types.Hash{}, 0, storage.ErrCorrupt
		}
		root = types.DomainHash(selectedAncestryStepDomain, root[:], parent[:])
		count++
		cursor = parent
	}
	for index := len(store.archivedHeaders) - 1; index >= 0; index-- {
		parent, idErr := store.archivedHeaders[index].ID()
		if idErr != nil || count == ^uint64(0) {
			return types.Hash{}, 0, storage.ErrCorrupt
		}
		root = types.DomainHash(selectedAncestryStepDomain, root[:], parent[:])
		count++
	}
	if store.floor.Anchor.ID != store.baseID {
		if count == ^uint64(0) {
			return types.Hash{}, 0, storage.ErrCorrupt
		}
		root = types.DomainHash(selectedAncestryStepDomain, root[:], store.baseID[:])
		count++
	}
	return finalizeSelectedAncestryRoot(root, count), count, nil
}

func finalizeSelectedAncestryRoot(root types.Hash, count uint64) types.Hash {
	var countBytes [8]byte
	binary.BigEndian.PutUint64(countBytes[:], count)
	return types.DomainHash(selectedAncestryRootDomain, root[:], countBytes[:])
}

func (store *Store) Snapshot() (*state.Memory, error) {
	if store == nil {
		return nil, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return nil, err
	}
	return cloneState(store.nodes[store.tipID].state)
}

func (store *Store) BlockByID(id types.Hash) (workblock.Block, error) {
	if store == nil {
		return workblock.Block{}, ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return workblock.Block{}, err
	}
	node, exists := store.nodes[id]
	if !exists || node.block == nil {
		if store.floor.Pruned && (id == store.baseID || store.archivedIndexContains(id)) {
			return workblock.Block{}, ErrHistoryPruned
		}
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
	if err := store.openErrorLocked(); err != nil {
		store.mu.RUnlock()
		return nil, workblock.Position{}, err
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
	if err := store.openErrorLocked(); err != nil {
		return storage.Tip{}, workblock.Result{}, err
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
	// Version 1 keeps the incumbent on exact cumulative-work ties. A universal
	// block-ID tie-break can be selectively ground by a withheld publisher;
	// strictly greater hard work is the only automatic reorganization trigger.
	better := storage.MoreWork(next, store.nodes[store.tipID].tip)
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
	if err := store.openErrorLocked(); err != nil {
		return 0, 0, err
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
	if err := store.openErrorLocked(); err != nil {
		return PruneReport{}, err
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

// PruneCanonicalPrefix atomically replaces full blocks, node metadata, and
// recovery data strictly before boundary.Anchor with canonical headers. The
// anchor itself becomes a full-state retained floor. Callers must construct the
// boundary only after independently verifying the checkpoint, archive, and
// replica-availability bundle; this low-level method rechecks all chain-local
// facts but cannot establish remote custody by itself.
func (store *Store) PruneCanonicalPrefix(
	boundary CanonicalFloor,
) (CanonicalPruneReport, error) {
	return store.pruneCanonicalPrefix(boundary, nil)
}

// PruneCanonicalPrefixAuthorized additionally calls authorize after acquiring
// the store lock and preparing the entire deletion batch, immediately before
// issuing the synchronous commit. An error discards the batch without changing
// memory or disk. The returned time becomes the durable floor's VerifiedAt and
// must not precede its initial value. This is an authorization time, not a claim
// about when the disk completes its write.
//
// The callback must be bounded and must not call this store (its lock is held).
// It does not itself provide a remote revocation protocol: a mutable external
// authority must remain guarded through completion of this method, not merely
// be read once in the callback. A nil callback is rejected.
func (store *Store) PruneCanonicalPrefixAuthorized(
	boundary CanonicalFloor, authorize func() (uint64, error),
) (CanonicalPruneReport, error) {
	if authorize == nil {
		return CanonicalPruneReport{}, ErrCanonicalPrune
	}
	return store.pruneCanonicalPrefix(boundary, authorize)
}

func (store *Store) pruneCanonicalPrefix(
	boundary CanonicalFloor, authorize func() (uint64, error),
) (CanonicalPruneReport, error) {
	if store == nil || boundary.validate() != nil || !boundary.PruneTicketID.IsZero() {
		return CanonicalPruneReport{}, ErrCanonicalPrune
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openErrorLocked(); err != nil {
		return CanonicalPruneReport{}, err
	}
	return store.pruneCanonicalPrefixLocked(boundary, authorize, nil)
}

func (store *Store) pruneCanonicalPrefixLocked(
	boundary CanonicalFloor, authorize func() (uint64, error), effect *CanonicalPruneEffect,
) (CanonicalPruneReport, error) {
	if store.persistence != nil && !store.persistence.storageID.IsZero() && effect == nil {
		return CanonicalPruneReport{}, ErrStorageBinding
	}
	if store.persistence == nil || store.persistence.policy.CanonicalRetention == 0 ||
		boundary.BaseID != store.baseID || boundary.Anchor.ID == store.floor.Anchor.ID {
		return CanonicalPruneReport{}, ErrCanonicalPrune
	}
	anchor := store.nodes[boundary.Anchor.ID]
	tip := store.nodes[store.tipID]
	if anchor == nil || anchor.block == nil || anchor.state == nil || tip == nil ||
		!storage.EqualTips(anchor.tip, boundary.Anchor) || tip.tip.Height < anchor.tip.Height ||
		tip.tip.Height-anchor.tip.Height < store.persistence.policy.CanonicalRetention {
		return CanonicalPruneReport{}, ErrCanonicalPrune
	}
	selected, err := store.isAncestorLocked(boundary.Anchor.ID, store.tipID)
	if err != nil || !selected {
		return CanonicalPruneReport{}, errors.Join(ErrCanonicalPrune, err)
	}
	root, count, err := store.selectedAncestryCommitmentLocked(boundary.Anchor.ID)
	if err != nil || root != boundary.AncestryRoot || count != boundary.AncestryNodes {
		return CanonicalPruneReport{}, errors.Join(ErrCanonicalPrune, err)
	}

	prefix := make([]types.Hash, 0)
	cursor := boundary.Anchor.ID
	for cursor != store.floor.Anchor.ID {
		node := store.nodes[cursor]
		if node == nil || node.block == nil {
			return CanonicalPruneReport{}, storage.ErrCorrupt
		}
		prefix = append(prefix, cursor)
		cursor = node.block.Header.Seal.AnchorParent
	}
	prefix = append(prefix, store.floor.Anchor.ID)
	for left, right := 0, len(prefix)-1; left < right; left, right = left+1, right-1 {
		prefix[left], prefix[right] = prefix[right], prefix[left]
	}
	if len(prefix) < 2 {
		return CanonicalPruneReport{}, ErrCanonicalPrune
	}
	prefixSet := make(map[types.Hash]struct{}, len(prefix))
	for _, id := range prefix {
		prefixSet[id] = struct{}{}
	}
	for id := range store.nodes {
		if _, onPrefix := prefixSet[id]; onPrefix {
			continue
		}
		descendant, descendantErr := store.isAncestorLocked(boundary.Anchor.ID, id)
		if descendantErr != nil || !descendant {
			return CanonicalPruneReport{}, errors.Join(ErrCanonicalPrune, descendantErr)
		}
	}
	remove := append([]types.Hash(nil), prefix[:len(prefix)-1]...)
	newHeaders := append([]workblock.Header(nil), store.archivedHeaders...)
	for _, id := range remove {
		node := store.nodes[id]
		if node == nil {
			return CanonicalPruneReport{}, storage.ErrCorrupt
		}
		if node.block != nil {
			newHeaders = append(newHeaders, node.block.Header)
		} else if id != store.baseID {
			return CanonicalPruneReport{}, storage.ErrCorrupt
		}
	}
	archivedIndex, archivedTips, archivedHistory, err := store.buildArchivedIndex(newHeaders)
	if err != nil {
		return CanonicalPruneReport{}, err
	}
	report := CanonicalPruneReport{
		PreviousFloorID: store.floor.Anchor.ID, FloorID: boundary.Anchor.ID,
		RemovedNodes: uint64(len(remove)), RetainedNodes: uint64(len(store.nodes) - len(remove)),
		ArchivedHeaders: uint64(len(newHeaders)),
	}
	added, released, err := store.persistence.pruneCanonicalPrefix(
		store.nodes, remove, anchor, &boundary, authorize, effect, report,
	)
	if err != nil {
		return CanonicalPruneReport{}, err
	}
	for _, id := range remove {
		delete(store.nodes, id)
	}
	store.floor = cloneCanonicalFloor(boundary)
	store.archivedHeaders = newHeaders
	store.archivedIndex = archivedIndex
	store.archivedTips = archivedTips
	store.archivedHistory = archivedHistory
	report.AddedHistoryBytes, report.ReleasedHistoryBytes = added, released
	return report, nil
}

// The caller holds store.mu. Close remains available after an uncertain commit.
func (store *Store) openErrorLocked() error {
	if store.closed {
		return storage.ErrClosed
	}
	if store.persistence != nil && store.persistence.uncertain {
		return ErrUncertain
	}
	if store.persistence != nil && store.persistence.pins != nil && store.persistence.pins.pending != nil {
		return ErrStoragePinPending
	}
	return nil
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
	if err := store.openErrorLocked(); err != nil {
		return CheckpointReport{}, err
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
		if id == store.floor.Anchor.ID {
			return nil
		}
		if node.block == nil {
			if id != store.baseID || store.floor.Pruned {
				return storage.ErrCorrupt
			}
			return nil
		}
		id = node.block.Header.Seal.AnchorParent
	}
}

func (store *Store) isAncestorLocked(ancestor, descendant types.Hash) (bool, error) {
	ancestorPosition, ancestorArchived := store.archivedPositionLocked(ancestor)
	if _, exists := store.nodes[ancestor]; !exists && !ancestorArchived {
		return false, storage.ErrNodeNotFound
	}
	if descendantPosition, descendantArchived := store.archivedPositionLocked(descendant); descendantArchived {
		return ancestorArchived && ancestorPosition <= descendantPosition, nil
	}
	cursor, exists := store.nodes[descendant]
	if !exists || cursor == nil {
		return false, storage.ErrNodeNotFound
	}
	if ancestorArchived {
		return true, nil
	}
	for {
		if cursor.tip.ID == ancestor {
			return true, nil
		}
		if cursor.tip.ID == store.floor.Anchor.ID {
			return false, nil
		}
		if cursor.block == nil {
			return false, storage.ErrCorrupt
		}
		cursor, exists = store.nodes[cursor.block.Header.Seal.AnchorParent]
		if !exists || cursor == nil {
			return false, storage.ErrCorrupt
		}
	}
}

func (store *Store) selectedAncestryIDsLocked(anchor types.Hash, blockCount int) ([]types.Hash, error) {
	if blockCount < 0 || len(store.archivedHeaders) > blockCount {
		return nil, storage.ErrCorrupt
	}
	result := make([]types.Hash, blockCount)
	for index, header := range store.archivedHeaders {
		id, err := header.ID()
		if err != nil {
			return nil, storage.ErrCorrupt
		}
		result[index] = id
	}
	cursor := anchor
	for index := len(result) - 1; index >= len(store.archivedHeaders); index-- {
		node := store.nodes[cursor]
		if node == nil || node.block == nil {
			return nil, storage.ErrCorrupt
		}
		result[index] = cursor
		if cursor == store.floor.Anchor.ID {
			if index != len(store.archivedHeaders) {
				return nil, storage.ErrCorrupt
			}
			break
		}
		cursor = node.block.Header.Seal.AnchorParent
	}
	if cursor != store.floor.Anchor.ID {
		return nil, storage.ErrCorrupt
	}
	return result, nil
}

func (store *Store) archivedIndexContains(id types.Hash) bool {
	_, exists := store.archivedIndex[id]
	return exists
}

// archivedPositionLocked maps the immutable base to -1 and pruned block
// headers to their activation-first index.
func (store *Store) archivedPositionLocked(id types.Hash) (int, bool) {
	if id == store.baseID {
		return -1, true
	}
	index, exists := store.archivedIndex[id]
	return index, exists
}

func (store *Store) rebuildArchivedIndexLocked() error {
	index, tips, history, err := store.buildArchivedIndex(store.archivedHeaders)
	if err != nil {
		return err
	}
	store.archivedIndex = index
	store.archivedTips = tips
	store.archivedHistory = history
	return nil
}

func (store *Store) buildArchivedIndex(
	headers []workblock.Header,
) (map[types.Hash]int, map[types.Hash]storage.Tip, []uint64, error) {
	index := make(map[types.Hash]int, len(headers))
	tips := make(map[types.Hash]storage.Tip, len(headers))
	parent := cloneTip(store.baseTip)
	history := append([]uint64(nil), store.baseHistory...)
	for position, header := range headers {
		id, err := header.ID()
		if err != nil || header.Seal.AnchorParent != parent.ID || header.Seal.Height != parent.Height+1 {
			return nil, nil, nil, storage.ErrCorrupt
		}
		next, nextHistory, err := store.archivedHeaderTip(parent, history, header)
		if err != nil {
			return nil, nil, nil, storage.ErrCorrupt
		}
		if _, exists := index[id]; exists {
			return nil, nil, nil, storage.ErrCorrupt
		}
		index[id] = position
		tips[id] = cloneTip(next)
		parent = next
		history = nextHistory
	}
	return index, tips, append([]uint64(nil), history...), nil
}

func (store *Store) archivedHeaderTip(
	parent storage.Tip,
	history []uint64,
	header workblock.Header,
) (storage.Tip, []uint64, error) {
	if len(history) == 0 || len(history) > 11 || header.Seal.Height != parent.Height+1 ||
		header.Seal.AnchorParent != parent.ID || header.Seal.Timestamp <= median(history) {
		return storage.Tip{}, nil, storage.ErrCorrupt
	}
	evaluation, err := types.AddAmount(parent.Timestamp, store.parameters.TargetSpacing)
	if err != nil {
		return storage.Tip{}, nil, storage.ErrCorrupt
	}
	target, err := difficulty.ASERT(
		store.parameters.DifficultyAnchorTarget, store.parameters.DifficultyAnchorTimestamp,
		header.Seal.Height, evaluation, store.parameters.TargetSpacing, store.parameters.ASERTHalfLife,
	)
	if err != nil || target != header.Seal.Target {
		return storage.Tip{}, nil, storage.ErrCorrupt
	}
	next, err := nextTip(parent, workblock.Block{Header: header})
	if err != nil {
		return storage.Tip{}, nil, storage.ErrCorrupt
	}
	nextHistory := append(append([]uint64(nil), history...), header.Seal.Timestamp)
	if len(nextHistory) > 11 {
		nextHistory = append([]uint64(nil), nextHistory[len(nextHistory)-11:]...)
	}
	return next, nextHistory, nil
}

func (floor CanonicalFloor) validate() error {
	if !floor.Pruned || floor.BaseID.IsZero() || floor.Anchor.Validate() != nil ||
		floor.Anchor.ID == floor.BaseID || floor.AncestryNodes < 2 || floor.AncestryRoot.IsZero() ||
		floor.StatementID.IsZero() || floor.ManifestID.IsZero() || floor.AvailabilityID.IsZero() ||
		floor.VerifiedAt == 0 || floor.RetainUntil <= floor.VerifiedAt {
		return ErrCanonicalPrune
	}
	return nil
}

func cloneCanonicalFloor(value CanonicalFloor) CanonicalFloor {
	value.Anchor = cloneTip(value.Anchor)
	return value
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
