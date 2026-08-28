package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

const maxWorkMiningPeers = 8

const (
	defaultWorkRelayInterval = 8 * time.Second
	maxWorkRelayInterval     = time.Minute
	workAnchorNotifyTimeout  = 30 * time.Second
)

type repeatedStringFlag []string

func (values *repeatedStringFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value is empty")
	}
	*values = append(*values, value)
	return nil
}

func (values *repeatedStringFlag) String() string {
	if values == nil {
		return ""
	}
	return strings.Join(*values, ",")
}

type workPeerTarget struct {
	address string
	id      types.Hash
}

func parseWorkPeerTargets(addresses, pins repeatedStringFlag) ([]workPeerTarget, error) {
	if len(addresses) > maxWorkMiningPeers {
		return nil, fmt.Errorf("peer may be repeated at most %d times", maxWorkMiningPeers)
	}
	if len(pins) != 0 && len(pins) != len(addresses) {
		return nil, errors.New("peer-id must be omitted or repeated once for every peer")
	}
	result := make([]workPeerTarget, 0, len(addresses))
	seen := make(map[types.Hash]struct{}, len(addresses))
	for index, address := range addresses {
		id, err := libp2ptransport.PeerIDFromAddress(address)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %w", index+1, err)
		}
		if len(pins) != 0 {
			pinned, err := parseHash(pins[index])
			if err != nil {
				return nil, fmt.Errorf("peer-id %d: %w", index+1, err)
			}
			if pinned != id {
				return nil, fmt.Errorf("peer-id %d does not match the multiaddress identity", index+1)
			}
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("peer %d repeats OutcomeMesh identity %s", index+1, id)
		}
		seen[id] = struct{}{}
		result = append(result, workPeerTarget{address: address, id: id})
	}
	return result, nil
}

type workShareRelayFunc func(context.Context, workPeerTarget, []types.Hash) (worksession.Stats, error)

type workShareFanoutStats struct {
	Peers        int
	ReachedPeers int
	FailedPeers  int
	Queued       uint64
	Relayed      uint64
	Rejected     uint64
	Failures     uint64
	Dropped      uint64
	Pending      uint64
}

type workSharePublisher struct {
	cancel    context.CancelFunc
	workers   []*workShareWorker
	wait      sync.WaitGroup
	closeOnce sync.Once
}

type workShareWorker struct {
	target     workPeerTarget
	relayEvery int
	interval   time.Duration
	input      chan types.Hash
	relay      workShareRelayFunc

	mu       sync.Mutex
	queued   uint64
	relayed  uint64
	rejected uint64
	failures uint64
	dropped  uint64
}

func newWorkSharePublisher(
	parent context.Context,
	targets []workPeerTarget,
	relayEvery int,
	relayInterval time.Duration,
	relay workShareRelayFunc,
) (*workSharePublisher, error) {
	if parent == nil || len(targets) == 0 || len(targets) > maxWorkMiningPeers || relay == nil ||
		relayEvery <= 0 || relayEvery > wire.MaxShareInventoryIDs ||
		relayInterval <= 0 || relayInterval > maxWorkRelayInterval {
		return nil, errors.New("invalid WorkGraph share fanout")
	}
	ctx, cancel := context.WithCancel(parent)
	result := &workSharePublisher{cancel: cancel, workers: make([]*workShareWorker, 0, len(targets))}
	for _, target := range targets {
		worker := &workShareWorker{
			target: target, relayEvery: relayEvery, interval: relayInterval,
			input: make(chan types.Hash, workgraph.MaxShares), relay: relay,
		}
		result.workers = append(result.workers, worker)
		result.wait.Add(1)
		go func() {
			defer result.wait.Done()
			worker.run(ctx)
		}()
	}
	return result, nil
}

// Publish performs no network I/O. Each peer owns a full-round bounded queue,
// so a slow or unreachable target cannot stall objective hard-PoW search or a
// healthy peer's worker.
func (publisher *workSharePublisher) Publish(share workgraph.Share) error {
	_, err := publisher.publishExcept(types.Hash{}, share)
	return err
}

// Forward queues a newly admitted remote share for every configured peer
// except its authenticated source. The pool remains the deduplication boundary,
// so one share can trigger this forwarding path at most once per round.
func (publisher *workSharePublisher) Forward(source types.Hash, share workgraph.Share) (int, error) {
	if source.IsZero() {
		return 0, errors.New("WorkGraph forwarding source is zero")
	}
	return publisher.publishExcept(source, share)
}

func (publisher *workSharePublisher) publishExcept(source types.Hash, share workgraph.Share) (int, error) {
	if publisher == nil {
		return 0, errors.New("WorkGraph share publisher is nil")
	}
	id, err := share.ID()
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, worker := range publisher.workers {
		if worker.target.id != source && worker.enqueue(id) {
			queued++
		}
	}
	return queued, nil
}

func (worker *workShareWorker) enqueue(id types.Hash) bool {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.queued >= workgraph.MaxShares {
		worker.dropped++
		return false
	}
	select {
	case worker.input <- id:
		worker.queued++
		return true
	default:
		worker.dropped++
		return false
	}
}

func (worker *workShareWorker) run(ctx context.Context) {
	pending := make([]types.Hash, 0, workgraph.MaxShares)
	sinceAttempt := 0
	flushTimer := time.NewTicker(worker.interval)
	defer flushTimer.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case id := <-worker.input:
			pending = append(pending, id)
			sinceAttempt++
			if sinceAttempt < worker.relayEvery {
				continue
			}
			sinceAttempt = 0
			pending = worker.flush(ctx, pending)
		case <-flushTimer.C:
			sinceAttempt = 0
			pending = worker.flush(ctx, pending)
		}
	}
}

func (worker *workShareWorker) flush(ctx context.Context, pending []types.Hash) []types.Hash {
	if len(pending) == 0 {
		return pending
	}
	sort.Slice(pending, func(left, right int) bool {
		return types.CompareHash(pending[left], pending[right]) < 0
	})
	for len(pending) > 0 && ctx.Err() == nil {
		count := min(len(pending), wire.MaxShareInventoryIDs)
		selected := append([]types.Hash(nil), pending[:count]...)
		stats, err := worker.relay(ctx, worker.target, selected)
		if err != nil || stats.Announced <= 0 || stats.Announced > len(selected) || stats.Accepted < 0 ||
			stats.Rejected < 0 || stats.Accepted+stats.Rejected > stats.Announced {
			if ctx.Err() != nil {
				return pending
			}
			worker.mu.Lock()
			worker.failures++
			worker.mu.Unlock()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "publish WorkGraph shares to %s: %v\n", worker.target.id, err)
			}
			return pending
		}
		worker.mu.Lock()
		worker.relayed += uint64(stats.Announced)
		worker.rejected += uint64(stats.Rejected)
		worker.mu.Unlock()
		pending = pending[stats.Announced:]
	}
	return pending
}

// Close cancels any in-flight relay and returns copy-counted delivery stats.
// A share sent to two peers is two relayed deliveries; Pending is likewise the
// sum of peer-local unsent copies.
func (publisher *workSharePublisher) Close() workShareFanoutStats {
	if publisher == nil {
		return workShareFanoutStats{}
	}
	publisher.closeOnce.Do(func() {
		publisher.cancel()
		publisher.wait.Wait()
	})
	result := workShareFanoutStats{Peers: len(publisher.workers)}
	for _, worker := range publisher.workers {
		worker.mu.Lock()
		result.Queued += worker.queued
		result.Relayed += worker.relayed
		result.Rejected += worker.rejected
		result.Failures += worker.failures
		result.Dropped += worker.dropped
		if worker.relayed > 0 {
			result.ReachedPeers++
		}
		if worker.failures > 0 {
			result.FailedPeers++
		}
		worker.mu.Unlock()
	}
	if result.Queued >= result.Relayed {
		result.Pending = result.Queued - result.Relayed
	}
	return result
}

type workAnchorNotifyFunc func(context.Context, workPeerTarget) error

type workAnchorFanoutStats struct {
	Peers     int
	Queued    uint64
	Coalesced uint64
	Attempts  uint64
	Succeeded uint64
	Failed    uint64
}

type workAnchorNotifier struct {
	cancel    context.CancelFunc
	workers   []*workAnchorWorker
	wait      sync.WaitGroup
	closeOnce sync.Once
	stats     workAnchorFanoutStats
}

type workAnchorWorker struct {
	target   workPeerTarget
	requests chan struct{}
	notify   workAnchorNotifyFunc

	mu        sync.Mutex
	closed    bool
	queued    uint64
	coalesced uint64
	attempts  uint64
	succeeded uint64
	failed    uint64
}

func newWorkAnchorNotifier(
	parent context.Context,
	targets []workPeerTarget,
	notify workAnchorNotifyFunc,
) (*workAnchorNotifier, error) {
	if parent == nil || len(targets) == 0 || len(targets) > maxWorkMiningPeers || notify == nil {
		return nil, errors.New("invalid WorkGraph anchor notifier")
	}
	ctx, cancel := context.WithCancel(parent)
	result := &workAnchorNotifier{cancel: cancel, workers: make([]*workAnchorWorker, 0, len(targets))}
	for _, target := range targets {
		worker := &workAnchorWorker{target: target, requests: make(chan struct{}, 1), notify: notify}
		result.workers = append(result.workers, worker)
		result.wait.Add(1)
		go func() {
			defer result.wait.Done()
			worker.run(ctx)
		}()
	}
	return result, nil
}

// Notify schedules one best-tip notification per peer. A busy peer retains at
// most one extra signal; that later session serves the newest selected tip.
func (notifier *workAnchorNotifier) Notify() int {
	if notifier == nil {
		return 0
	}
	queued := 0
	for _, worker := range notifier.workers {
		if worker.enqueue() {
			queued++
		}
	}
	return queued
}

func (worker *workAnchorWorker) enqueue() bool {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.closed {
		return false
	}
	select {
	case worker.requests <- struct{}{}:
		worker.queued++
		return true
	default:
		worker.coalesced++
		return false
	}
}

func (worker *workAnchorWorker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-worker.requests:
			if !open {
				return
			}
			attemptContext, cancel := context.WithTimeout(ctx, workAnchorNotifyTimeout)
			err := worker.notify(attemptContext, worker.target)
			cancel()
			worker.mu.Lock()
			worker.attempts++
			if err == nil {
				worker.succeeded++
			} else {
				worker.failed++
			}
			worker.mu.Unlock()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "notify WorkGraph anchor to %s: %v\n", worker.target.id, err)
			}
		}
	}
}

// Close drains the one coalesced notification per peer in parallel. Normal
// mining continues while notifications run; only command shutdown waits for
// their bounded chain sessions to finish.
func (notifier *workAnchorNotifier) Close() workAnchorFanoutStats {
	if notifier == nil {
		return workAnchorFanoutStats{}
	}
	notifier.closeOnce.Do(func() {
		for _, worker := range notifier.workers {
			worker.mu.Lock()
			worker.closed = true
			close(worker.requests)
			worker.mu.Unlock()
		}
		notifier.wait.Wait()
		notifier.cancel()
		result := workAnchorFanoutStats{Peers: len(notifier.workers)}
		for _, worker := range notifier.workers {
			worker.mu.Lock()
			result.Queued += worker.queued
			result.Coalesced += worker.coalesced
			result.Attempts += worker.attempts
			result.Succeeded += worker.succeeded
			result.Failed += worker.failed
			worker.mu.Unlock()
		}
		notifier.stats = result
	})
	return notifier.stats
}
