package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var (
	ErrManagedCustodyServeService = errors.New("invalid managed custody serve service")
	ErrManagedCustodyServeStarted = errors.New("managed custody serve service already started")
)

// ManagedCustodyServeServiceConfig names existing original owners and one exact
// admitted Serve operation. Session.Objects must be nil: the service privately
// opens ObjectPath without initialization, repair or import. ServerPeerID and
// Session.AuditorPeerID are independently pinned transport identities.
type ManagedCustodyServeServiceConfig struct {
	AuthorityPath, AuthorityPinsPath string
	Assignment                       custodyauthority.Assignment
	Session                          ManagedCustodyServeConfig
	ObjectPath                       string
	ObjectPolicy                     workarchive.ObjectStorePolicy
	ServerPeerID                     types.Hash
}

// ManagedCustodyServeService owns the original coordinator, private object
// handle and managed replica session. Close stops handler admission, cancels
// streams, drains every admitted handler, then releases the original authority.
// The service exposes no signer, coordinator, raw session or completion API.
type ManagedCustodyServeService struct {
	mu          sync.Mutex // lifecycle; never acquired by handlers
	gate        sync.Mutex
	inflight    sync.WaitGroup
	accepting   bool
	failure     error
	coordinator *Coordinator
	session     *ManagedCustodyServeSession
	serverPeer  types.Hash
	auditorPeer types.Hash
	host        *libp2ptransport.Host
	runContext  context.Context
	cancel      context.CancelFunc
	stopWatch   func() bool
	closed      bool
	closeErr    error
	done        chan struct{}
	hooks       storeHooks // private lifecycle checkpoints for tests
}

func OpenManagedCustodyServeService(config ManagedCustodyServeServiceConfig) (*ManagedCustodyServeService, error) {
	return OpenManagedCustodyServeServiceContext(context.Background(), config)
}

// OpenManagedCustodyServeServiceContext opens existing owners before creating
// any listener. It does not admit, complete, retire, sign, initialize or resume
// work. Failure closes only the coordinator acquired by this construction.
func OpenManagedCustodyServeServiceContext(ctx context.Context, config ManagedCustodyServeServiceConfig) (_ *ManagedCustodyServeService, returnErr error) {
	if ctx == nil || config.Session.Objects != nil || config.AuthorityPath == "" || config.AuthorityPinsPath == "" ||
		config.ObjectPath == "" || config.Session.JournalPath == "" || config.ObjectPolicy.Validate() != nil {
		return nil, ErrManagedCustodyServeService
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := config.Assignment.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrManagedCustodyServeService, err)
	}
	assignment, err := custodyauthority.DecodeAssignment(encoded)
	if err != nil {
		return nil, errors.Join(ErrManagedCustodyServeService, err)
	}
	id, err := assignment.ID()
	if err != nil || config.Session.AssignmentID.IsZero() || id != config.Session.AssignmentID ||
		config.ServerPeerID.IsZero() || config.ServerPeerID == config.Session.AuditorPeerID {
		return nil, errors.Join(ErrManagedCustodyServeService, err)
	}
	if err := managedCustodyAuditorPeer(assignment, config.ServerPeerID); err != nil {
		return nil, errors.Join(ErrManagedCustodyServeService, err)
	}
	if err := managedCustodyAuditorPeer(assignment, config.Session.AuditorPeerID); err != nil {
		return nil, errors.Join(ErrManagedCustodyServeService, err)
	}
	roots := []string{config.AuthorityPath, config.AuthorityPinsPath, config.Session.JournalPath, config.ObjectPath}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			roots[i], roots[j], err = coordinatorPaths(roots[i], roots[j])
			if err != nil {
				return nil, err
			}
		}
	}
	objects, err := workarchive.OpenExistingObjectStoreContext(ctx, roots[3], config.ObjectPolicy)
	if err != nil {
		return nil, err
	}
	missing, err := objects.Missing(config.Session.Manifest)
	if err != nil || len(missing) != 0 {
		return nil, errors.Join(ErrManagedCustodyServeService, err)
	}
	coordinator, err := OpenCoordinator(roots[0], roots[1], assignment, id)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, coordinator.Close())
		}
	}()
	config.Session.JournalPath, config.Session.Objects = roots[2], objects
	session, err := NewManagedCustodyServeSession(ctx, coordinator, config.Session)
	if err != nil {
		return nil, err
	}
	return &ManagedCustodyServeService{coordinator: coordinator, session: session,
		serverPeer: config.ServerPeerID, auditorPeer: config.Session.AuditorPeerID, done: make(chan struct{})}, nil
}

// Start explicitly installs the owned transport. Failed startup retains the
// original owner until Close; no transport key is generated, persisted or logged.
// A successful Start is one-shot, including after its context is cancelled.
func (service *ManagedCustodyServeService) Start(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config) error {
	if service == nil {
		return ErrClosed
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.coordinator == nil || service.session == nil {
		return ErrClosed
	}
	if service.host != nil {
		return ErrManagedCustodyServeStarted
	}
	if ctx == nil {
		return ErrManagedCustodyServeService
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// This shared private helper canonicalizes/copies the transport key and
	// checks its identity against the already role-separated server pin.
	ownedKey, err := pruneRuntimeKey(key, service.serverPeer)
	if err != nil {
		return errors.Join(ErrManagedCustodyServeService, err)
	}
	runContext, cancel := context.WithCancel(ctx)
	host, err := libp2ptransport.New(runContext, ownedKey, config, nil)
	if err != nil {
		cancel()
		return err
	}
	fail := func(err error) error {
		cancel()
		return errors.Join(err, host.Close())
	}
	if host.ID() != service.serverPeer {
		return fail(ErrManagedCustodyServeService)
	}
	if err := host.SetArchiveCustodyHandler([]types.Hash{service.auditorPeer}, service.handle); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	service.gate.Lock()
	service.host, service.runContext, service.cancel, service.accepting = host, runContext, cancel, true
	service.gate.Unlock()
	service.stopWatch = context.AfterFunc(runContext, func() { _ = service.Close() })
	return nil
}

func (service *ManagedCustodyServeService) handle(_ context.Context, peer types.Hash, stream network.Stream) {
	service.gate.Lock()
	if !service.accepting {
		service.gate.Unlock()
		_ = stream.Reset()
		return
	}
	service.inflight.Add(1) // same gate prevents Add after Close starts waiting
	ctx := service.runContext
	service.gate.Unlock()
	defer service.inflight.Done()
	if err := service.hooks.reach("managed-serve-handler-entered"); err != nil {
		_ = stream.Reset()
		return
	}
	// Retain the actual cleanup result separately from ordinary protocol/read
	// failures. A handler cannot silently discard a failed stream retirement.
	owned := &managedCustodyServeStream{CustodySessionStream: stream}
	_, err := service.session.Serve(ctx, peer, owned)
	closeErr := owned.Close()
	if closeErr == nil && !errors.Is(err, ErrUncertain) && !errors.Is(err, ErrClosed) {
		return
	}
	service.gate.Lock()
	if service.failure == nil {
		service.failure = errors.Join(err, closeErr)
	}
	service.accepting = false
	cancel := service.cancel
	service.gate.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (service *ManagedCustodyServeService) Addresses() []string {
	if service == nil {
		return nil
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.host == nil {
		return nil
	}
	return service.host.Addresses()
}

// Done closes only after listener shutdown, accepted handler drain and original
// coordinator Close. Call Close to inspect any retained shutdown/owner error.
func (service *ManagedCustodyServeService) Done() <-chan struct{} {
	if service == nil {
		return nil
	}
	return service.done
}

func (service *ManagedCustodyServeService) Close() error {
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
	err = errors.Join(err, service.failure)
	service.gate.Unlock()
	err = errors.Join(err, service.coordinator.Close())
	service.closeErr, service.closed = err, true
	if service.done != nil {
		close(service.done)
	}
	return err
}
