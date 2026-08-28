package workround

import (
	"errors"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/worksession"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrUnstableChain = errors.New("chain changed while preparing WorkGraph round")
	ErrRoundChanged  = errors.New("WorkGraph round changed before timestamp rollover")
)

const maxBuildAttempts = 3

// RolloverSeconds advances the local winner timestamp halfway through the
// admission lead. This leaves another full half-window for honest clock and
// network skew while preserving all same-parent work in the shared DAG.
const RolloverSeconds uint64 = workgraph.MaxShareTimestampLead / 2

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
				now := manager.now()
				if !rolloverDue(miningContext.AnchorTimestamp, now) {
					return manager.current, nil
				}
				next, stable, err := manager.rollForwardLocked(manager.current, tip, now)
				if err != nil {
					return nil, err
				}
				if stable {
					return next, nil
				}
				continue
			}
			manager.current.retire()
			manager.current = nil
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

// RollForward explicitly advances an expected current round. It is used by a
// miner's wall-clock timer when no inbound session has called Current recently.
// The parent is checked before and after payload preparation; a moving chain is
// never mistaken for a timestamp-only generation change.
func (manager *Manager) RollForward(expected *Round) (*Round, error) {
	if manager == nil || manager.source == nil || manager.now == nil || expected == nil {
		return nil, ErrConfiguration
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.current != expected {
		return nil, ErrRoundChanged
	}
	tip, err := manager.source.Tip()
	if err != nil {
		return nil, err
	}
	next, stable, err := manager.rollForwardLocked(expected, tip, manager.now())
	if err != nil {
		return nil, err
	}
	if !stable {
		return nil, ErrUnstableChain
	}
	return next, nil
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
	if manager.current != nil {
		manager.current.retire()
	}
	manager.current = nil
	return nil
}

func (manager *Manager) rollForwardLocked(
	expected *Round,
	tip storage.Tip,
	now uint64,
) (*Round, bool, error) {
	miningContext, err := expected.Context()
	if err != nil {
		return nil, false, err
	}
	if tip.Height == ^uint64(0) || miningContext.AnchorParent != tip.ID ||
		miningContext.Height != tip.Height+1 {
		expected.retire()
		manager.current = nil
		return nil, false, nil
	}
	base := tip.Timestamp
	if miningContext.AnchorTimestamp > base {
		base = miningContext.AnchorTimestamp
	}
	timestamp, err := nextTimestamp(now, base)
	if err != nil {
		return nil, false, err
	}
	payload, _, err := manager.source.PrepareWork(tip.ID, timestamp, nil)
	if err != nil {
		return nil, false, err
	}
	confirmed, err := manager.source.Tip()
	if err != nil {
		return nil, false, err
	}
	if confirmed.ID != tip.ID || confirmed.Height != tip.Height {
		expected.retire()
		manager.current = nil
		return nil, false, nil
	}
	next, err := expected.RollForward(payload)
	if err != nil {
		expected.retire()
		manager.current = nil
		return nil, false, err
	}
	manager.current = next
	return next, true, nil
}

func rolloverDue(timestamp, now uint64) bool {
	if now < timestamp {
		return false
	}
	return now-timestamp >= RolloverSeconds
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
