package peers

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrPolicy       = errors.New("invalid peer policy")
	ErrPeerID       = errors.New("invalid peer identity")
	ErrPeerCapacity = errors.New("peer table capacity reached")
	ErrSessionLimit = errors.New("peer concurrent-session limit reached")
	ErrRateLimit    = errors.New("peer inbound byte-rate limit reached")
	ErrOutboundRate = errors.New("peer outbound byte-rate limit reached")
	ErrBanned       = errors.New("peer is temporarily banned")
	ErrDialBackoff  = errors.New("peer dial is in progress or backed off")
	ErrDialState    = errors.New("peer dial state is invalid")
	ErrLatency      = errors.New("invalid peer latency sample")
)

const (
	ScoreMagnitudeLimit = 1_000_000
	MaxObservedLatency  = time.Hour
	latencyEWMAWeight   = 8
)

type Event uint8

const (
	EventValidMessage Event = iota + 1
	EventUsefulSync
	EventStaleData
	EventInvalidObject
	EventInvalidMessage
	EventTimeout
)

type Policy struct {
	MaxTrackedPeers        int
	MaxSessionsPerPeer     int
	MaxInboundWindowBytes  uint64
	MaxOutboundWindowBytes uint64
	Window                 time.Duration
	Retention              time.Duration
	BanDuration            time.Duration
	BanThreshold           int
	MaxScore               int
	DialBaseBackoff        time.Duration
	DialMaxBackoff         time.Duration
	ScoreDecayInterval     time.Duration
}

func DefaultPolicy() Policy {
	return Policy{
		MaxTrackedPeers:        4_096,
		MaxSessionsPerPeer:     4,
		MaxInboundWindowBytes:  64 << 20,
		MaxOutboundWindowBytes: 128 << 20,
		Window:                 time.Minute,
		Retention:              24 * time.Hour,
		BanDuration:            30 * time.Minute,
		BanThreshold:           -100,
		MaxScore:               100,
		DialBaseBackoff:        time.Second,
		DialMaxBackoff:         10 * time.Minute,
		ScoreDecayInterval:     time.Hour,
	}
}

type Snapshot struct {
	Score               int
	Sessions            int
	WindowBytes         uint64
	OutboundWindowBytes uint64
	BannedUntil         time.Time
	LastSeen            time.Time
	DialFailures        int
	NextDial            time.Time
	ValidEvents         uint64
	UsefulSyncs         uint64
	StaleEvents         uint64
	InvalidEvents       uint64
	Timeouts            uint64
	LatencyMillis       uint64
	LatencySamples      uint64
}

type record struct {
	Snapshot
	inboundWindowStart  time.Time
	outboundWindowStart time.Time
	lastScoreUpdate     time.Time
	dialing             bool
}

type Manager struct {
	mu      sync.Mutex
	policy  Policy
	now     func() time.Time
	lastNow time.Time
	records map[types.Hash]*record
}

func New(policy Policy, now func() time.Time) (*Manager, error) {
	defaults := DefaultPolicy()
	if policy.DialBaseBackoff == 0 {
		policy.DialBaseBackoff = defaults.DialBaseBackoff
	}
	if policy.DialMaxBackoff == 0 {
		policy.DialMaxBackoff = defaults.DialMaxBackoff
	}
	if policy.ScoreDecayInterval == 0 {
		policy.ScoreDecayInterval = defaults.ScoreDecayInterval
	}
	if policy.MaxOutboundWindowBytes == 0 {
		policy.MaxOutboundWindowBytes = defaults.MaxOutboundWindowBytes
	}
	if policy.MaxTrackedPeers <= 0 || policy.MaxSessionsPerPeer <= 0 || policy.MaxInboundWindowBytes == 0 ||
		policy.MaxOutboundWindowBytes == 0 ||
		policy.Window <= 0 || policy.Retention <= 0 || policy.BanDuration <= 0 ||
		policy.BanThreshold >= 0 || policy.BanThreshold < -ScoreMagnitudeLimit ||
		policy.MaxScore <= 0 || policy.MaxScore > ScoreMagnitudeLimit || policy.DialBaseBackoff <= 0 ||
		policy.DialMaxBackoff < policy.DialBaseBackoff || policy.ScoreDecayInterval <= 0 {
		return nil, ErrPolicy
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{policy: policy, now: now, records: make(map[types.Hash]*record)}, nil
}

// BeginDial atomically reserves one outbound attempt for a peer.
func (manager *Manager) BeginDial(id types.Hash) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	entry, err := manager.entry(id, now)
	if err != nil {
		return err
	}
	if now.Before(entry.BannedUntil) {
		return ErrBanned
	}
	if !entry.BannedUntil.IsZero() {
		entry.BannedUntil = time.Time{}
		entry.Score = 0
		entry.lastScoreUpdate = now
	}
	if entry.dialing || now.Before(entry.NextDial) {
		return ErrDialBackoff
	}
	entry.dialing = true
	entry.LastSeen = now
	return nil
}

// EndDial releases a reserved attempt. Failures back off exponentially and a
// successful authenticated connection resets the entire dial penalty.
func (manager *Manager) EndDial(id types.Hash, succeeded bool) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	entry := manager.records[id]
	if entry == nil || !entry.dialing {
		return ErrDialState
	}
	manager.decayScore(entry, now)
	entry.dialing = false
	entry.LastSeen = now
	if succeeded {
		entry.DialFailures = 0
		entry.NextDial = time.Time{}
		manager.applyEvent(entry, EventValidMessage, now)
		return nil
	}
	if entry.DialFailures < math.MaxInt {
		entry.DialFailures++
	}
	delay := manager.policy.DialBaseBackoff
	for step := 1; step < entry.DialFailures && delay < manager.policy.DialMaxBackoff; step++ {
		if delay > manager.policy.DialMaxBackoff/2 {
			delay = manager.policy.DialMaxBackoff
		} else {
			delay *= 2
		}
	}
	if delay > manager.policy.DialMaxBackoff {
		delay = manager.policy.DialMaxBackoff
	}
	entry.NextDial = now.Add(delay)
	manager.applyEvent(entry, EventTimeout, now)
	return nil
}

func (manager *Manager) Acquire(id types.Hash) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	entry, err := manager.entry(id, now)
	if err != nil {
		return err
	}
	if now.Before(entry.BannedUntil) {
		return ErrBanned
	}
	if !entry.BannedUntil.IsZero() {
		entry.BannedUntil = time.Time{}
		entry.Score = 0
		entry.lastScoreUpdate = now
	}
	if entry.Sessions >= manager.policy.MaxSessionsPerPeer {
		return ErrSessionLimit
	}
	entry.Sessions++
	entry.LastSeen = now
	return nil
}

func (manager *Manager) Release(id types.Hash) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if entry := manager.records[id]; entry != nil {
		now := manager.currentTime()
		manager.decayScore(entry, now)
		if entry.Sessions > 0 {
			entry.Sessions--
		}
		entry.LastSeen = now
	}
}

func (manager *Manager) AllowInbound(id types.Hash, count uint64) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	entry, err := manager.entry(id, now)
	if err != nil {
		return err
	}
	if now.Before(entry.BannedUntil) {
		return ErrBanned
	}
	if entry.inboundWindowStart.IsZero() || now.Sub(entry.inboundWindowStart) >= manager.policy.Window {
		entry.inboundWindowStart = now
		entry.WindowBytes = 0
	}
	if count > manager.policy.MaxInboundWindowBytes || entry.WindowBytes > manager.policy.MaxInboundWindowBytes-count {
		manager.applyEvent(entry, EventInvalidMessage, now)
		return ErrRateLimit
	}
	entry.WindowBytes += count
	entry.LastSeen = now
	return nil
}

// AllowOutbound applies a conservative plaintext-byte budget before a server
// write. Charging the attempted length means short-write retries cannot bypass
// the cap.
func (manager *Manager) AllowOutbound(id types.Hash, count uint64) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	entry, err := manager.entry(id, now)
	if err != nil {
		return err
	}
	if now.Before(entry.BannedUntil) {
		return ErrBanned
	}
	if entry.outboundWindowStart.IsZero() || now.Sub(entry.outboundWindowStart) >= manager.policy.Window {
		entry.outboundWindowStart = now
		entry.OutboundWindowBytes = 0
	}
	if count > manager.policy.MaxOutboundWindowBytes ||
		entry.OutboundWindowBytes > manager.policy.MaxOutboundWindowBytes-count {
		return ErrOutboundRate
	}
	entry.OutboundWindowBytes += count
	entry.LastSeen = now
	return nil
}

func (manager *Manager) Record(id types.Hash, event Event) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	entry, err := manager.entry(id, now)
	if err != nil {
		return err
	}
	manager.applyEvent(entry, event, now)
	return nil
}

// ObserveLatency records local transport quality without changing consensus or
// the behavioral score. Durations are rounded up to a millisecond so a valid
// sub-millisecond loopback observation never becomes the "unknown" zero value.
// Extremely delayed observations are capped to keep persisted policy state
// bounded and useful after process suspension.
func (manager *Manager) ObserveLatency(id types.Hash, duration time.Duration) error {
	if duration <= 0 {
		return ErrLatency
	}
	if duration > MaxObservedLatency {
		duration = MaxObservedLatency
	}
	milliseconds := uint64((duration + time.Millisecond - 1) / time.Millisecond)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.currentTime()
	entry, err := manager.entry(id, now)
	if err != nil {
		return err
	}
	if entry.LatencySamples == 0 {
		entry.LatencyMillis = milliseconds
	} else {
		entry.LatencyMillis = (entry.LatencyMillis*(latencyEWMAWeight-1) + milliseconds) / latencyEWMAWeight
		if entry.LatencyMillis == 0 {
			entry.LatencyMillis = 1
		}
	}
	saturatingIncrement(&entry.LatencySamples)
	entry.LastSeen = now
	return nil
}

func (manager *Manager) Get(id types.Hash) (Snapshot, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, exists := manager.records[id]
	if !exists {
		return Snapshot{}, false
	}
	manager.decayScore(entry, manager.currentTime())
	return entry.Snapshot, true
}

func (manager *Manager) Len() int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return len(manager.records)
}

// currentTime clamps a process-local wall-clock rollback. Production clocks
// normally carry Go's monotonic component, but an explicit clamp also keeps
// injected clocks and platforms without it from extending windows, bans, or
// dial reservations unpredictably.
func (manager *Manager) currentTime() time.Time {
	now := manager.now()
	if !manager.lastNow.IsZero() && now.Before(manager.lastNow) {
		return manager.lastNow
	}
	manager.lastNow = now
	return now
}

func (manager *Manager) entry(id types.Hash, now time.Time) (*record, error) {
	if id.IsZero() {
		return nil, ErrPeerID
	}
	if entry := manager.records[id]; entry != nil {
		manager.decayScore(entry, now)
		return entry, nil
	}
	if len(manager.records) >= manager.policy.MaxTrackedPeers {
		manager.prune(now)
		if len(manager.records) >= manager.policy.MaxTrackedPeers {
			return nil, ErrPeerCapacity
		}
	}
	entry := &record{
		Snapshot:           Snapshot{LastSeen: now},
		inboundWindowStart: now, outboundWindowStart: now, lastScoreUpdate: now,
	}
	manager.records[id] = entry
	return entry, nil
}

func (manager *Manager) prune(now time.Time) {
	for id, entry := range manager.records {
		if entry.Sessions == 0 && !entry.dialing && !now.Before(entry.LastSeen.Add(manager.policy.Retention)) && !now.Before(entry.BannedUntil) {
			delete(manager.records, id)
		}
	}
}

func (manager *Manager) applyEvent(entry *record, event Event, now time.Time) {
	manager.decayScore(entry, now)
	delta := 0
	switch event {
	case EventValidMessage:
		delta = 1
		saturatingIncrement(&entry.ValidEvents)
	case EventUsefulSync:
		delta = 5
		saturatingIncrement(&entry.UsefulSyncs)
	case EventStaleData:
		delta = -1
		saturatingIncrement(&entry.StaleEvents)
	case EventInvalidObject:
		delta = -10
		saturatingIncrement(&entry.InvalidEvents)
	case EventInvalidMessage:
		delta = -25
		saturatingIncrement(&entry.InvalidEvents)
	case EventTimeout:
		delta = -5
		saturatingIncrement(&entry.Timeouts)
	default:
		delta = -25
		saturatingIncrement(&entry.InvalidEvents)
	}
	if delta > 0 && entry.Score > manager.policy.MaxScore-delta {
		entry.Score = manager.policy.MaxScore
	} else if delta < 0 && entry.Score < manager.policy.BanThreshold-delta {
		entry.Score = manager.policy.BanThreshold
	} else {
		entry.Score += delta
	}
	entry.lastScoreUpdate = now
	entry.LastSeen = now
	if entry.Score <= manager.policy.BanThreshold {
		entry.BannedUntil = now.Add(manager.policy.BanDuration)
	}
}

func (manager *Manager) decayScore(entry *record, now time.Time) {
	if entry.lastScoreUpdate.IsZero() {
		entry.lastScoreUpdate = now
		return
	}
	elapsed := now.Sub(entry.lastScoreUpdate)
	if elapsed < manager.policy.ScoreDecayInterval || entry.Score == 0 {
		return
	}
	steps := int(elapsed / manager.policy.ScoreDecayInterval)
	if entry.Score > 0 {
		if steps >= entry.Score {
			entry.Score = 0
		} else {
			entry.Score -= steps
		}
	} else {
		magnitude := -entry.Score
		if steps >= magnitude {
			entry.Score = 0
		} else {
			entry.Score += steps
		}
	}
	entry.lastScoreUpdate = entry.lastScoreUpdate.Add(time.Duration(steps) * manager.policy.ScoreDecayInterval)
}

func saturatingIncrement(value *uint64) {
	if *value != ^uint64(0) {
		*value++
	}
}
