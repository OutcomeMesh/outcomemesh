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
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// PruneCommandServiceConfig names four EXISTING independently configured roots.
// IDs and peers must come from external pins, not discovery or a queried head.
// Paths cannot establish physical independence, fencing or all-replica coverage.
type PruneCommandServiceConfig struct {
	AuthorityPath, AuthorityPinsPath string
	ExecutorPath, ExecutorPinsPath   string
	Assignment                       custodyauthority.Assignment
	AssignmentID, RequestID          types.Hash
	ServerPeerID, ClientPeerID       types.Hash
	Timeout                          time.Duration
}

// PruneCommandService exclusively owns one original coordinator/pinned executor.
// Its network surface has no request creation, signing, execution, cancellation,
// retirement or generic operation API. EnterMaintenance explicitly drains that
// surface for reviewed local cancellation while retaining the original owners.
// Start enables only the existing Admit/Complete command adapters; it is not
// integration into live archive acceptance or cross-host execution authority.
type PruneCommandService struct {
	mu                         sync.Mutex // lifecycle only; handlers never acquire this mutex
	gate                       sync.Mutex
	inflight                   sync.WaitGroup
	accepting                  bool
	failure                    error
	coordinator                *Coordinator
	executor                   *PruneExecutor
	admission                  *PruneAdmissionServer
	completion                 *PruneCompletionServer
	preparedSecondary          *preparedSecondaryService
	serverPeerID, clientPeerID types.Hash
	timeout                    time.Duration
	host                       *libp2ptransport.Host
	cancel                     context.CancelFunc
	stopWatch                  func() bool
	quiesced                   bool
	quiesceErr                 error
	maintenance                *PruneMaintenance
	closed                     bool
	closeErr                   error
	done                       chan struct{}
	hooks                      storeHooks // private session checkpoints for tests
}

// OpenPruneCommandService opens retained pins before their writers and owns all
// four locks until Close. It creates nothing, listens nowhere, sends no command
// and never resumes an attempt. Any failure releases only the locks it acquired.
func OpenPruneCommandService(config PruneCommandServiceConfig) (_ *PruneCommandService, err error) {
	id, err := config.Assignment.ID()
	if err != nil || config.AssignmentID.IsZero() || id != config.AssignmentID ||
		config.RequestID.IsZero() || config.Timeout < admissionwire.MinimumTimeout || config.Timeout > admissionwire.MaximumTimeout {
		return nil, errors.Join(ErrPruneRuntime, err)
	}
	if err := validatePruneRuntimePeers(config.Assignment, config.ServerPeerID, config.ClientPeerID); err != nil {
		return nil, err
	}
	paths := []string{config.AuthorityPath, config.AuthorityPinsPath, config.ExecutorPath, config.ExecutorPinsPath}
	// Resolve every pair before acquiring any owner. Reuse the journal's alias,
	// symlink and containment checks; no partial initialization fallback exists.
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			paths[i], paths[j], err = coordinatorPaths(paths[i], paths[j])
			if err != nil {
				return nil, err
			}
		}
	}
	executor, err := OpenPinnedPruneExecutor(paths[2], paths[3], config.Assignment, config.RequestID)
	if err != nil {
		return nil, err
	}
	coordinator, err := OpenCoordinator(paths[0], paths[1], config.Assignment, config.AssignmentID)
	if err != nil {
		return nil, errors.Join(err, executor.Close())
	}
	return &PruneCommandService{coordinator: coordinator, executor: executor,
		serverPeerID: config.ServerPeerID, clientPeerID: config.ClientPeerID,
		timeout: config.Timeout, done: make(chan struct{})}, nil
}

// Start explicitly creates the owned transport and enables the selected command
// handlers (both for the original primary service).
// It neither submits retained attempts nor performs work. A second Start is an
// error, including when the first server's context has been cancelled; reopen
// existing roots in a new service after Done. Failed startup does not release
// journal ownership: the caller must Close or explicitly correct and retry Start.
func (service *PruneCommandService) Start(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config) error {
	if service == nil {
		return ErrClosed
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.executor == nil || service.coordinator == nil {
		return ErrClosed
	}
	if service.quiesced {
		return ErrPruneServiceQuiesced
	}
	if service.host != nil {
		return ErrPruneServiceStarted
	}
	if ctx == nil {
		return ErrPruneRuntime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var admission *PruneAdmissionServer
	var completion *PruneCompletionServer
	var err error
	if scope := service.preparedSecondary; scope != nil {
		if scope.mode != PruneSecondaryCompletion {
			admission, err = NewPreparedArchiveSecondaryAdmissionServer(service.executor, scope.primary, service.coordinator, scope.config)
		}
		if err == nil && scope.mode != PruneSecondaryAdmission {
			completion, err = NewPreparedArchiveSecondaryCompletionServer(service.executor, service.coordinator, scope.config)
		}
	} else {
		admission, err = NewPruneAdmissionServer(service.executor, service.coordinator, service.clientPeerID, service.timeout)
		if err == nil {
			completion, err = NewPruneCompletionServer(service.executor, service.coordinator, service.clientPeerID, service.timeout)
		}
	}
	if err != nil {
		return err
	}
	if admission != nil {
		admission.hooks = service.hooks
	}
	if completion != nil {
		completion.hooks = service.hooks
	}
	runContext, cancel := context.WithCancel(ctx)
	host, err := newPruneRuntimeHost(runContext, service.executor.assignment, service.serverPeerID, service.clientPeerID, key, config)
	if err != nil {
		cancel()
		return err
	}
	fail := func(err error) error {
		cancel()
		return errors.Join(err, host.Close())
	}
	if admission != nil {
		if err := host.SetPruneAdmissionHandler(service.clientPeerID, func(ctx context.Context, peer types.Hash, stream network.Stream) {
			service.handle(ctx, peer, stream, true)
		}); err != nil {
			return fail(err)
		}
	}
	if completion != nil {
		if err := host.SetPruneCompletionHandler(service.clientPeerID, func(ctx context.Context, peer types.Hash, stream network.Stream) {
			service.handle(ctx, peer, stream, false)
		}); err != nil {
			return fail(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	service.gate.Lock()
	service.host, service.cancel = host, cancel
	service.admission, service.completion = admission, completion
	service.accepting = true
	service.gate.Unlock()
	// Cancellation closes the listener, drains accepted handlers, THEN releases
	// journal locks. The callback never runs Close inline inside a handler.
	service.stopWatch = context.AfterFunc(runContext, func() { _ = service.Close() })
	return nil
}

func (service *PruneCommandService) handle(ctx context.Context, peer types.Hash, stream network.Stream, admit bool) {
	service.gate.Lock()
	if !service.accepting {
		service.gate.Unlock()
		_ = stream.Reset()
		return
	}
	// The same gate forbids Add after Close starts waiting, including when no
	// handler was previously active. Transport shutdown alone is not that guard.
	service.inflight.Add(1)
	service.gate.Unlock()
	defer service.inflight.Done()
	err := service.hooks.reach("runtime-handler-entered")
	if err != nil {
		_ = stream.Reset()
	} else if admit {
		_, err = service.admission.Serve(ctx, peer, stream)
	} else {
		_, err = service.completion.Serve(ctx, peer, stream)
	}
	if !errors.Is(err, ErrUncertain) && !errors.Is(err, ErrClosed) {
		return
	}
	service.gate.Lock()
	if service.failure == nil {
		service.failure = err
	}
	service.accepting = false
	cancel := service.cancel
	service.gate.Unlock()
	cancel()
}

// Addresses is empty before Start and after Close. It contains routes, never
// bootstrap identity pins. No raw transport or writer pointer is exposed.
func (service *PruneCommandService) Addresses() []string {
	if service == nil {
		return nil
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.quiesced || service.host == nil {
		return nil
	}
	return service.host.Addresses()
}

// Done closes only after the listener, accepted handlers and all journal owners
// have closed. Call Close to read any retained shutdown/storage error.
func (service *PruneCommandService) Done() <-chan struct{} {
	if service == nil {
		return nil
	}
	return service.done
}

// Close prevents new handler admission, interrupts network I/O, waits for all
// accepted handlers, then closes every original owner in reverse acquisition
// order for the secondary wrapper (the primary service keeps its existing order).
// It does not forcibly release locks during fsync or roll back retained work.
// Concurrent/repeated Close calls return the same final result.
func (service *PruneCommandService) Close() error {
	if service == nil {
		return nil
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed {
		return service.closeErr
	}
	service.gate.Lock()
	service.accepting = false
	service.gate.Unlock()
	if service.stopWatch != nil {
		service.stopWatch()
	}
	if service.cancel != nil {
		service.cancel()
	}
	var err error
	if service.host != nil {
		err = service.host.Close()
	}
	service.inflight.Wait()
	service.gate.Lock()
	err = errors.Join(err, service.failure, service.quiesceErr)
	service.gate.Unlock()
	if prepared := service.preparedSecondary; prepared != nil {
		for i := len(prepared.owners) - 1; i >= 0; i-- {
			err = errors.Join(err, prepared.owners[i].Close())
		}
		err = errors.Join(err, service.executor.Close())
	} else {
		err = errors.Join(err, service.executor.Close(), service.coordinator.Close())
	}
	service.closeErr, service.closed = err, true
	if service.done != nil {
		close(service.done)
	}
	return err
}
