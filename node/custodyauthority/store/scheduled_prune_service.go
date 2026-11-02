package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// ScheduledPruneCommandService supervises one fixed original-owner command.
// Construction inspects and closes the original owners; idle service holds no
// owner locks. Every accepted call validates those owners again. Close drains
// all admitted handlers before reporting completion, including filesystem work
// which cannot be interrupted by a stream deadline.
type ScheduledPruneCommandService struct {
	mu         sync.Mutex
	gate       sync.Mutex
	inflight   sync.WaitGroup
	accepting  bool
	failure    error
	server     *ScheduledPruneCommandServer
	assignment custodyauthority.Assignment
	host       *libp2ptransport.Host
	cancel     context.CancelFunc
	stopWatch  func() bool
	closed     bool
	closeErr   error
	done       chan struct{}
	hooks      storeHooks
}

// PrepareScheduledPruneCommandService creates no roots and listens nowhere.
// The exact receiver review and all retained terminal evidence are checked
// under original ownership. Unknown writes require explicit local recovery.
func PrepareScheduledPruneCommandService(ctx context.Context, config ScheduledPruneCommandConfig, intent scheduledwire.Intent, expectedID types.Hash, timeout time.Duration) (*ScheduledPruneCommandService, error) {
	if ctx == nil {
		return nil, ErrScheduledPrune
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	server, err := NewScheduledPruneCommandServer(config, intent, expectedID, timeout)
	if err != nil {
		return nil, err
	}
	plan, err := LoadScheduledPrunePlan(config.PlanPath, config.PlanID)
	if err != nil {
		return nil, err
	}
	// The receiver also opens the primary executor. Neither endpoint may reuse
	// any authority, consumer, replica or auditor role from this fixed plan.
	for _, replica := range plan.Replicas {
		if err := validatePruneRuntimePeers(replica.Assignment, intent.ServerPeerID, intent.ClientPeerID); err != nil {
			return nil, err
		}
	}
	selected, err := plan.Replica(config.AssignmentID)
	if err != nil {
		return nil, err
	}
	if _, err := runScheduledPruneCommandOwned(ctx, server.config, "apply", intent.ReviewID, storeHooks{}, &intent, true); err != nil {
		return nil, err
	}
	return &ScheduledPruneCommandService{server: server, assignment: selected.Assignment, done: make(chan struct{})}, nil
}

func (s *ScheduledPruneCommandService) Start(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config) error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.host != nil {
		return ErrPruneServiceStarted
	}
	if ctx == nil {
		return ErrPruneRuntime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	run, cancel := context.WithCancel(ctx)
	i := s.server.intent
	host, err := newPruneRuntimeHost(run, s.assignment, i.ServerPeerID, i.ClientPeerID, key, config)
	if err != nil {
		cancel()
		return err
	}
	fail := func(err error) error { cancel(); return errors.Join(err, host.Close()) }
	s.server.hooks = s.hooks
	if err := host.SetScheduledPruneHandler(i.ClientPeerID, s.handle); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	s.gate.Lock()
	s.host, s.cancel, s.accepting = host, cancel, true
	s.gate.Unlock()
	s.stopWatch = context.AfterFunc(run, func() { _ = s.Close() })
	return nil
}

func (s *ScheduledPruneCommandService) handle(ctx context.Context, peer types.Hash, stream network.Stream) {
	s.gate.Lock()
	if !s.accepting {
		s.gate.Unlock()
		_ = stream.Reset()
		return
	}
	s.inflight.Add(1)
	s.gate.Unlock()
	defer s.inflight.Done()
	err := s.server.Serve(ctx, peer, stream)
	if err != nil {
		_ = stream.Reset()
	}
	if !errors.Is(err, ErrUncertain) && !errors.Is(err, ErrClosed) {
		return
	}
	s.gate.Lock()
	s.failure = errors.Join(s.failure, err)
	s.accepting = false
	cancel := s.cancel
	s.gate.Unlock()
	cancel()
}

func (s *ScheduledPruneCommandService) Addresses() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.host == nil {
		return nil
	}
	return s.host.Addresses()
}

// Done closes only after transport shutdown and original-owner release.
func (s *ScheduledPruneCommandService) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *ScheduledPruneCommandService) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.gate.Lock()
	s.accepting = false
	s.gate.Unlock()
	if s.stopWatch != nil {
		s.stopWatch()
	}
	if s.cancel != nil {
		s.cancel()
	}
	var err error
	if s.host != nil {
		err = s.host.Close()
	}
	s.inflight.Wait()
	s.gate.Lock()
	err = errors.Join(err, s.failure)
	s.gate.Unlock()
	s.closeErr, s.closed = err, true
	close(s.done)
	return err
}
