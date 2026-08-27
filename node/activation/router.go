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
)

type Config struct {
	Legacy legacyblock.Parameters
	Work   workblock.Parameters
	Now    func() uint64
}

// Router is the sole block-version admission boundary. Each distinct v0 node
// at activationHeight-1 owns an independent v1 fork tree; Tip compares their
// best hard-work tips with the best pre-activation v0 tip.
type Router struct {
	mu        sync.Mutex
	ledger    storage.Ledger
	legacy    *chain.Chain
	config    Config
	trees     map[types.Hash]*workchain.Store
	workBases map[types.Hash]types.Hash
}

func New(ledger storage.Ledger, config Config) (*Router, error) {
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
	return &Router{
		ledger: ledger, legacy: legacy, config: config,
		trees: make(map[types.Hash]*workchain.Store), workBases: make(map[types.Hash]types.Hash),
	}, nil
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
		work.FeeDelay > 0 && work.FeeDelay <= workgraph.MaxFeeDelay
}

func (router *Router) Submit(candidate Block) (storage.Tip, error) {
	if router == nil {
		return storage.Tip{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if err := candidate.Validate(router.config.Work.ActivationHeight); err != nil {
		return storage.Tip{}, err
	}
	switch candidate.Version() {
	case legacyblock.Version0:
		legacy, ok := candidate.LegacyBlock()
		if !ok {
			return storage.Tip{}, ErrEncoding
		}
		if _, err := router.legacy.SubmitAt(legacy, router.config.Now()); err != nil {
			return storage.Tip{}, err
		}
	case workblock.Version1:
		work, ok := candidate.WorkBlock()
		if !ok {
			return storage.Tip{}, ErrEncoding
		}
		tree, baseID, err := router.treeForWorkLocked(work)
		if err != nil {
			return storage.Tip{}, err
		}
		if _, _, err := tree.Commit(work, router.config.Now()); err != nil {
			if errors.Is(err, workchain.ErrDuplicate) {
				return storage.Tip{}, storage.ErrBlockExists
			}
			return storage.Tip{}, err
		}
		id, _ := work.Header.ID()
		router.workBases[id] = baseID
	default:
		return storage.Tip{}, ErrEncoding
	}
	tip, _, err := router.bestLocked()
	return tip, err
}

func (router *Router) Tip() (storage.Tip, error) {
	if router == nil {
		return storage.Tip{}, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
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
	return router.config.Legacy, router.config.Work, nil
}

// AdmissionTime samples the same explicit local clock used by Submit.
func (router *Router) AdmissionTime() (uint64, error) {
	if router == nil {
		return 0, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	return router.config.Now(), nil
}

func (router *Router) Snapshot() (*state.Memory, error) {
	if router == nil {
		return nil, ErrConfiguration
	}
	router.mu.Lock()
	defer router.mu.Unlock()
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
	baseTip, err := router.ledger.TipByID(baseID)
	if err != nil {
		return nil, ErrParent
	}
	if baseTip.Height == ^uint64(0) || baseTip.Height+1 != router.config.Work.ActivationHeight {
		return nil, ErrBoundary
	}
	baseState, err := router.ledger.SnapshotAt(baseID)
	if err != nil {
		return nil, err
	}
	history, err := router.recentLegacyTimestampsLocked(baseTip)
	if err != nil {
		return nil, err
	}
	tree, err := workchain.New(workchain.Base{
		Tip: baseTip, State: baseState, RecentTimestamps: history,
	}, router.config.Work)
	if err != nil {
		return nil, err
	}
	router.trees[baseID] = tree
	return tree, nil
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
	best, err := router.ledger.Tip()
	if err != nil {
		return storage.Tip{}, nil, err
	}
	if best.Height >= router.config.Work.ActivationHeight {
		return storage.Tip{}, nil, storage.ErrCorrupt
	}
	ids := make([]types.Hash, 0, len(router.trees))
	for id := range router.trees {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return types.CompareHash(ids[left], ids[right]) < 0 })
	var selected *workchain.Store
	for _, id := range ids {
		tree := router.trees[id]
		tip, err := tree.Tip()
		if err != nil {
			return storage.Tip{}, nil, err
		}
		if storage.BetterTip(tip, best) {
			best = tip
			selected = tree
		}
	}
	return best, selected, nil
}
