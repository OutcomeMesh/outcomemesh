package activation

import (
	"errors"
	"sort"
	"sync"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrConfiguration = errors.New("invalid activation router configuration")
	ErrParent        = errors.New("unknown routed block parent")
	ErrTreeLimit     = errors.New("activation tree limit reached")
)

const (
	DefaultMaxWorkTrees = 64
	MaxWorkTreesLimit   = 1_024
)

type Config struct {
	Legacy legacyblock.Parameters
	Work   workblock.Parameters
	Now    func() uint64
	// WorkRoot enables the catalog-free persistent v1 forest. Empty keeps the
	// router in memory. WorkPolicy.MaxHistoryBytes is a forest-wide logical
	// ceiling split evenly across MaxWorkTrees, not a per-tree allowance.
	WorkRoot     string
	WorkPolicy   workchain.Policy
	MaxWorkTrees int
	// ObserveWork receives one immutable event after a new v1 block is durably
	// admitted and after the router lock is released. It is operational
	// telemetry only and cannot accept, reject, or reorder consensus work.
	ObserveWork func(WorkAdmission)
}

type WorkAdmission struct {
	Sequence       uint64
	ID             types.Hash
	ParentID       types.Hash
	Height         uint64
	BlockTimestamp uint64
	ObservedAt     uint64
	Miner          types.Address
	SelectedID     types.Hash
	Selected       bool
}

// ForestStatus reports bounded local v1 persistence without treating local
// retention policy as consensus state.
type ForestStatus struct {
	Persistent      bool
	Trees           uint32
	Nodes           uint64
	HistoryBytes    uint64
	MaxHistoryBytes uint64
	MaxTrees        uint32
}

// Router is the sole block-version admission boundary. Each distinct v0 node
// at activationHeight-1 owns an independent v1 fork tree; Tip compares their
// best hard-work tips with the best pre-activation v0 tip.
type Router struct {
	mu              sync.Mutex
	observeGate     sync.RWMutex
	observeOrderMu  sync.Mutex
	observeOrder    *sync.Cond
	nextAdmission   uint64
	nextObservation uint64
	ledger          storage.Ledger
	legacy          *chain.Chain
	config          Config
	trees           map[types.Hash]*workchain.Store
	workBases       map[types.Hash]types.Hash
	selectedID      types.Hash
	selectDirty     bool
	closed          bool
}

func New(ledger storage.Ledger, config Config) (*Router, error) {
	if config.MaxWorkTrees == 0 {
		config.MaxWorkTrees = DefaultMaxWorkTrees
	}
	if config.WorkRoot != "" && config.WorkPolicy == (workchain.Policy{}) {
		config.WorkPolicy = workchain.DefaultPolicy()
	}
	if ledger == nil || !validConfig(config) {
		return nil, ErrConfiguration
	}
	tip, err := ledger.Tip()
	if err != nil {
		return nil, err
	}
	if tip.Height >= config.Work.ActivationHeight {
		return nil, ErrConfiguration
	}
	legacy, err := chain.New(ledger, config.Legacy)
	if err != nil {
		return nil, err
	}
	result := &Router{
		ledger: ledger, legacy: legacy, config: config,
		trees: make(map[types.Hash]*workchain.Store), workBases: make(map[types.Hash]types.Hash),
		selectedID:      tip.ID,
		nextObservation: 1,
	}
	result.observeOrder = sync.NewCond(&result.observeOrderMu)
	if config.WorkRoot != "" {
		if err := result.openPersistentTrees(); err != nil {
			_ = result.closeTreesLocked()
			return nil, err
		}
	}
	return result, nil
}

func validConfig(config Config) bool {
	legacy := config.Legacy
	work := config.Work
	_, _, rewardErr := workgraph.RewardRates(work.BlockSubsidy)
	return config.Now != nil && legacy.Validate() == nil && work.ActivationHeight > 0 &&
		legacy.NetworkID == work.NetworkID && legacy.BlockSubsidy == work.BlockSubsidy &&
		legacy.RewardMaturity == work.RewardMaturity &&
		legacy.AnchorTimestamp == work.DifficultyAnchorTimestamp &&
		legacy.AnchorTarget == work.DifficultyAnchorTarget &&
		legacy.TargetSpacing == work.TargetSpacing && legacy.ASERTHalfLife == work.ASERTHalfLife &&
		workgraph.ExactShareRatio(work.DifficultyAnchorTarget) && rewardErr == nil &&
		work.FeeDelay > 0 && work.FeeDelay <= workgraph.MaxFeeDelay &&
		config.MaxWorkTrees > 0 && config.MaxWorkTrees <= MaxWorkTreesLimit &&
		((config.WorkRoot == "" && config.WorkPolicy == (workchain.Policy{})) ||
			(config.WorkRoot != "" && config.WorkPolicy.MaxHistoryBytes >= uint64(config.MaxWorkTrees)))
}

func (router *Router) Submit(candidate Block) (storage.Tip, error) {
	if router == nil {
		return storage.Tip{}, ErrConfiguration
	}
	router.mu.Lock()
	if router.closed {
		router.mu.Unlock()
		return storage.Tip{}, storage.ErrClosed
	}
	if err := router.persistSelectionLocked(); err != nil {
		router.mu.Unlock()
		return storage.Tip{}, err
	}
	tip, admission, err := router.submitLocked(candidate)
	observer := router.config.ObserveWork
	// Once Commit succeeds, the admission must be observable even if the
	// subsequent best-tip scan detects a separate local-state error. A retry
	// would be a duplicate and could not reconstruct this event.
	observing := admission != nil && observer != nil
	if observing {
		// Acquire the read side before releasing the router lock. Close first
		// marks the router closed under that lock and then takes the write side,
		// so every already-committed admission finishes its callback before
		// Close returns.
		router.observeGate.RLock()
	}
	router.mu.Unlock()
	if observing {
		defer router.observeGate.RUnlock()
		router.observeAdmission(observer, *admission)
	}
	return tip, err
}

func (router *Router) submitLocked(candidate Block) (storage.Tip, *WorkAdmission, error) {
	if err := candidate.Validate(router.config.Work.ActivationHeight); err != nil {
		return storage.Tip{}, nil, err
	}
	var admission *WorkAdmission
	switch candidate.Version() {
	case legacyblock.Version0:
		legacy, ok := candidate.LegacyBlock()
		if !ok {
			return storage.Tip{}, nil, ErrEncoding
		}
		if _, err := router.legacy.SubmitAt(legacy, router.config.Now()); err != nil {
			return storage.Tip{}, nil, err
		}
	case workblock.Version1:
		work, ok := candidate.WorkBlock()
		if !ok {
			return storage.Tip{}, nil, ErrEncoding
		}
		tree, baseID, err := router.treeForWorkLocked(work)
		if err != nil {
			return storage.Tip{}, nil, err
		}
		observedAt := router.config.Now()
		if _, _, err := tree.Commit(work, observedAt); err != nil {
			if errors.Is(err, workchain.ErrDuplicate) {
				return storage.Tip{}, nil, storage.ErrBlockExists
			}
			return storage.Tip{}, nil, err
		}
		id, _ := work.Header.ID()
		router.workBases[id] = baseID
		router.nextAdmission++
		admission = &WorkAdmission{
			Sequence: router.nextAdmission,
			ID:       id, ParentID: work.Header.Seal.AnchorParent, Height: work.Header.Seal.Height,
			BlockTimestamp: work.Header.Seal.Timestamp, ObservedAt: observedAt,
			Miner: work.Header.Seal.Miner,
		}
	default:
		return storage.Tip{}, nil, ErrEncoding
	}
	tip, _, err := router.bestLocked()
	if err != nil {
		return storage.Tip{}, admission, err
	}
	if admission != nil {
		admission.SelectedID = tip.ID
		admission.Selected = admission.ID == tip.ID
	}
	if err := router.persistSelectionLocked(); err != nil {
		return tip, admission, err
	}
	return tip, admission, nil
}

func (router *Router) observeAdmission(observer func(WorkAdmission), admission WorkAdmission) {
	router.observeOrderMu.Lock()
	for admission.Sequence != router.nextObservation {
		router.observeOrder.Wait()
	}
	router.observeOrderMu.Unlock()
	defer func() {
		router.observeOrderMu.Lock()
		router.nextObservation++
		router.observeOrder.Broadcast()
		router.observeOrderMu.Unlock()
	}()
	observer(admission)
}

func (router *Router) Tip() (storage.Tip, error) {
	if router == nil {
		return storage.Tip{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	tip, _, err := router.bestLocked()
	return tip, err
}

// TipByID resolves either legacy-ledger or WorkChain fork metadata.
func (router *Router) TipByID(id types.Hash) (storage.Tip, error) {
	if router == nil {
		return storage.Tip{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return storage.Tip{}, storage.ErrClosed
	}
	if baseID, exists := router.workBases[id]; exists {
		tree := router.trees[baseID]
		if tree == nil {
			return storage.Tip{}, storage.ErrCorrupt
		}
		return tree.TipByID(id)
	}
	return router.ledger.TipByID(id)
}

// Parameters returns the immutable v0/v1 consensus parameters used by the
// router so a detached session cannot negotiate a different boundary.
func (router *Router) Parameters() (legacyblock.Parameters, workblock.Parameters, error) {
	if router == nil {
		return legacyblock.Parameters{}, workblock.Parameters{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return legacyblock.Parameters{}, workblock.Parameters{}, storage.ErrClosed
	}
	return router.config.Legacy, router.config.Work, nil
}

// AdmissionTime samples the same explicit local clock used by Submit.
func (router *Router) AdmissionTime() (uint64, error) {
	if router == nil {
		return 0, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return 0, storage.ErrClosed
	}
	return router.config.Now(), nil
}

func (router *Router) WorkForestStatus() (ForestStatus, error) {
	if router == nil {
		return ForestStatus{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return ForestStatus{}, storage.ErrClosed
	}
	result := ForestStatus{
		Persistent: router.config.WorkRoot != "", Trees: uint32(len(router.trees)),
		MaxTrees: uint32(router.config.MaxWorkTrees),
	}
	if result.Persistent {
		result.MaxHistoryBytes = router.config.WorkPolicy.MaxHistoryBytes
	}
	for _, tree := range router.trees {
		ids, err := tree.NodeIDs()
		if err != nil || uint64(len(ids)) > ^uint64(0)-result.Nodes {
			return ForestStatus{}, storage.ErrCorrupt
		}
		result.Nodes += uint64(len(ids))
		usage, _, err := tree.HistoryUsage()
		if err != nil || usage > ^uint64(0)-result.HistoryBytes {
			return ForestStatus{}, storage.ErrCorrupt
		}
		result.HistoryBytes += usage
	}
	if result.Persistent && result.HistoryBytes > result.MaxHistoryBytes {
		return ForestStatus{}, storage.ErrCorrupt
	}
	return result, nil
}

func (router *Router) Snapshot() (*state.Memory, error) {
	if router == nil {
		return nil, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return nil, storage.ErrClosed
	}
	tip, tree, err := router.bestLocked()
	if err != nil {
		return nil, err
	}
	if tree == nil {
		return router.ledger.SnapshotAt(tip.ID)
	}
	return tree.Snapshot()
}

func (router *Router) PrepareLegacy(
	transactions []outcome.Transaction,
	miner types.Address,
	timestamp uint64,
) (Block, error) {
	if router == nil {
		return Block{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return Block{}, storage.ErrClosed
	}
	tip, err := router.ledger.Tip()
	if err != nil {
		return Block{}, err
	}
	if tip.Height == ^uint64(0) || tip.Height+1 >= router.config.Work.ActivationHeight {
		return Block{}, ErrBoundary
	}
	candidate, _, err := router.legacy.Prepare(transactions, miner, timestamp)
	if err != nil {
		return Block{}, err
	}
	return Legacy(candidate, router.config.Work.ActivationHeight)
}

func (router *Router) PrepareWork(
	parentID types.Hash,
	timestamp uint64,
	transactions []outcome.Transaction,
) (*workblock.Payload, workblock.Position, error) {
	if router == nil {
		return nil, workblock.Position{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return nil, workblock.Position{}, storage.ErrClosed
	}
	tree, err := router.treeForParentLocked(parentID)
	if err != nil {
		return nil, workblock.Position{}, err
	}
	return tree.Prepare(parentID, timestamp, transactions)
}

func (router *Router) BlockByID(id types.Hash) (Block, error) {
	if router == nil {
		return Block{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.closed {
		return Block{}, storage.ErrClosed
	}
	if baseID, exists := router.workBases[id]; exists {
		candidate, err := router.trees[baseID].BlockByID(id)
		if err != nil {
			return Block{}, err
		}
		return Work(candidate, router.config.Work.ActivationHeight)
	}
	candidate, err := router.ledger.BlockByID(id)
	if err != nil {
		return Block{}, err
	}
	return Legacy(candidate, router.config.Work.ActivationHeight)
}

// Close releases every v1 tree owned by the router. The caller retains
// ownership of the version-0 ledger and must close it separately.
func (router *Router) Close() error {
	if router == nil {
		return ErrConfiguration
	}
	router.mu.Lock()
	if router.closed {
		router.mu.Unlock()
		return storage.ErrClosed
	}
	selectionErr := router.persistSelectionLocked()
	router.closed = true
	err := errors.Join(selectionErr, router.closeTreesLocked())
	router.mu.Unlock()
	// Wait until callbacks for admissions committed before closed=true have
	// durably handed their events to the operational observer.
	router.observeGate.Lock()
	router.observeGate.Unlock()
	return err
}

func (router *Router) closeTreesLocked() error {
	ids := make([]types.Hash, 0, len(router.trees))
	for id := range router.trees {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool {
		return types.CompareHash(ids[left], ids[right]) < 0
	})
	var failures []error
	for _, id := range ids {
		if tree := router.trees[id]; tree != nil {
			if err := tree.Close(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (router *Router) treeForWorkLocked(candidate workblock.Block) (*workchain.Store, types.Hash, error) {
	height := candidate.Header.Seal.Height
	parentID := candidate.Header.Seal.AnchorParent
	if height == router.config.Work.ActivationHeight {
		tree, err := router.treeForBoundaryLocked(parentID)
		return tree, parentID, err
	}
	baseID, exists := router.workBases[parentID]
	if !exists {
		return nil, types.Hash{}, ErrParent
	}
	tree := router.trees[baseID]
	if tree == nil {
		return nil, types.Hash{}, storage.ErrCorrupt
	}
	return tree, baseID, nil
}

func (router *Router) treeForParentLocked(parentID types.Hash) (*workchain.Store, error) {
	if baseID, exists := router.workBases[parentID]; exists {
		tree := router.trees[baseID]
		if tree == nil {
			return nil, storage.ErrCorrupt
		}
		return tree, nil
	}
	return router.treeForBoundaryLocked(parentID)
}

func (router *Router) treeForBoundaryLocked(baseID types.Hash) (*workchain.Store, error) {
	if tree := router.trees[baseID]; tree != nil {
		return tree, nil
	}
	base, err := router.workBase(baseID)
	if err != nil {
		return nil, err
	}
	if len(router.trees) >= router.config.MaxWorkTrees {
		return nil, ErrTreeLimit
	}
	tree, err := router.openWorkTree(base)
	if err != nil {
		return nil, err
	}
	if err := router.registerTreeLocked(baseID, tree); err != nil {
		_ = tree.Close()
		return nil, err
	}
	return tree, nil
}

func (router *Router) registerTreeLocked(baseID types.Hash, tree *workchain.Store) error {
	if tree == nil || router.trees[baseID] != nil {
		return storage.ErrCorrupt
	}
	storedBase, err := tree.BaseID()
	if err != nil || storedBase != baseID {
		return storage.ErrCorrupt
	}
	ids, err := tree.NodeIDs()
	if err != nil || len(ids) == 0 {
		return storage.ErrCorrupt
	}
	foundBase := false
	for _, id := range ids {
		if id == baseID {
			foundBase = true
			continue
		}
		if existing, exists := router.workBases[id]; exists && existing != baseID {
			return storage.ErrCorrupt
		}
	}
	if !foundBase {
		return storage.ErrCorrupt
	}
	for _, id := range ids {
		if id != baseID {
			router.workBases[id] = baseID
		}
	}
	router.trees[baseID] = tree
	return nil
}

func (router *Router) recentLegacyTimestampsLocked(tip storage.Tip) ([]uint64, error) {
	if tip.Height == 0 {
		return []uint64{tip.Timestamp}, nil
	}
	result := make([]uint64, 0, 11)
	cursor := tip.ID
	for height := tip.Height; height > 0 && len(result) < 11; height-- {
		candidate, err := router.ledger.BlockByID(cursor)
		if err != nil {
			return nil, err
		}
		id, err := candidate.Header.ID()
		if err != nil || id != cursor || candidate.Header.Height != height {
			return nil, storage.ErrCorrupt
		}
		result = append(result, candidate.Header.Timestamp)
		cursor = candidate.Header.Parent
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result, nil
}

func (router *Router) bestLocked() (storage.Tip, *workchain.Store, error) {
	legacyTip, err := router.ledger.Tip()
	if err != nil {
		return storage.Tip{}, nil, err
	}
	if legacyTip.Height >= router.config.Work.ActivationHeight {
		return storage.Tip{}, nil, storage.ErrCorrupt
	}
	best := legacyTip
	var selected *workchain.Store
	migrating := router.selectedID.IsZero()
	if !router.selectedID.IsZero() {
		incumbent, incumbentTree, err := router.selectedTipLocked()
		if err != nil {
			return storage.Tip{}, nil, err
		}
		if incumbent.Height >= router.config.Work.ActivationHeight {
			best = incumbent
			selected = incumbentTree
		}
	}
	ids := make([]types.Hash, 0, len(router.trees))
	for id := range router.trees {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return types.CompareHash(ids[left], ids[right]) < 0 })
	for _, id := range ids {
		tree := router.trees[id]
		tip, err := tree.Tip()
		if err != nil {
			return storage.Tip{}, nil, err
		}
		if (migrating && storage.BetterTip(tip, best)) || (!migrating && storage.MoreWork(tip, best)) {
			best = tip
			selected = tree
		}
	}
	if router.selectedID != best.ID {
		router.selectedID = best.ID
		router.selectDirty = true
	}
	return best, selected, nil
}

func (router *Router) selectedTipLocked() (storage.Tip, *workchain.Store, error) {
	if baseID, exists := router.workBases[router.selectedID]; exists {
		tree := router.trees[baseID]
		if tree == nil {
			return storage.Tip{}, nil, storage.ErrCorrupt
		}
		tip, err := tree.TipByID(router.selectedID)
		if err != nil {
			return storage.Tip{}, nil, storage.ErrCorrupt
		}
		current, err := tree.Tip()
		if err != nil {
			return storage.Tip{}, nil, storage.ErrCorrupt
		}
		workOrder := storage.CompareWork(current, tip)
		if workOrder < 0 || (workOrder == 0 && current.ID != tip.ID) {
			return storage.Tip{}, nil, storage.ErrCorrupt
		}
		return tip, tree, nil
	}
	tip, err := router.ledger.TipByID(router.selectedID)
	if err != nil {
		return storage.Tip{}, nil, storage.ErrCorrupt
	}
	return tip, nil, nil
}

func (router *Router) persistSelectionLocked() error {
	if !router.selectDirty {
		return nil
	}
	if router.config.WorkRoot == "" {
		router.selectDirty = false
		return nil
	}
	if err := saveWorkForestSelection(router.config.WorkRoot, router.selectedID); err != nil {
		return err
	}
	router.selectDirty = false
	return nil
}
