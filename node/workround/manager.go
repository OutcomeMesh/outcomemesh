package workround

import (
	"errors"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/worksession"
	"github.com/outcomemesh/outcomemesh/storage"
)

var ErrUnstableChain = errors.New("chain changed while preparing WorkGraph round")

const maxBuildAttempts = 3

// Source is the narrow activation-router surface needed to build an ephemeral
// mining round. Keeping this interface small makes the round lifecycle
// independently testable and leaves fork choice in the router.
type Source interface {
	Tip() (storage.Tip, error)
	PrepareWork(types.Hash, uint64, []outcome.Transaction) (*workblock.Payload, workblock.Position, error)
}

// Manager keeps at most one share pool for the current best parent. It never
// carries shares into a different parent or payload, including after a reorg.
type Manager struct {
	mu            sync.Mutex
	source        Source
	now           func() uint64
	sessionConfig worksession.Config
	current       *Round
}

func NewManager(source Source, now func() uint64, sessionConfig worksession.Config) (*Manager, error) {
	if source == nil || now == nil {
		return nil, ErrConfiguration
	}
	return &Manager{source: source, now: now, sessionConfig: sessionConfig}, nil
}

// Current returns the existing round while the best parent is unchanged, or
// builds a fresh empty-payload round. Parent stability is checked after build;
// bounded retries avoid caching a torn view during rapid chain movement.
func (manager *Manager) Current() (*Round, error) {
	if manager == nil || manager.source == nil || manager.now == nil {
		return nil, ErrConfiguration
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for attempt := 0; attempt < maxBuildAttempts; attempt++ {
		tip, err := manager.source.Tip()
		if err != nil {
			return nil, err
		}
		if tip.Height == ^uint64(0) {
			return nil, ErrConfiguration
		}
		if manager.current != nil {
			miningContext, err := manager.current.Context()
			if err != nil {
				return nil, err
			}
			if miningContext.AnchorParent == tip.ID && miningContext.Height == tip.Height+1 {
				return manager.current, nil
			}
		}
		timestamp, err := nextTimestamp(manager.now(), tip.Timestamp)
		if err != nil {
			return nil, err
		}
		payload, _, err := manager.source.PrepareWork(tip.ID, timestamp, nil)
		if err != nil {
			return nil, err
		}
		round, err := New(payload, manager.sessionConfig)
		if err != nil {
			return nil, err
		}
		confirmed, err := manager.source.Tip()
		if err != nil {
			return nil, err
		}
		if confirmed.ID == tip.ID && confirmed.Height == tip.Height {
			manager.current = round
			return round, nil
		}
	}
	return nil, ErrUnstableChain
}

// Invalidate forces the next Current call to rebuild even if the source has
// not advanced yet. It is used after a local hard solution and in tests of
// explicit lifecycle boundaries.
func (manager *Manager) Invalidate() error {
	if manager == nil {
		return ErrConfiguration
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.current = nil
	return nil
}

func nextTimestamp(now, parent uint64) (uint64, error) {
	if now > parent {
		return now, nil
	}
	if parent == ^uint64(0) {
		return 0, ErrConfiguration
	}
	return parent + 1, nil
}
