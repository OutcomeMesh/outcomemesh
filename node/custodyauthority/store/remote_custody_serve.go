package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type RemoteCustodyServeServiceConfig struct {
	Scope                                RemoteCustodyScope
	WorkerPath, JournalPath, ObjectPath  string
	ObjectPolicy                         workarchive.ObjectStorePolicy
	JournalLimits                        workarchive.CustodyJournalLimits
	ReplicaPrivateKey, ControlPrivateKey ed25519.PrivateKey
	SessionConfig                        workarchive.CustodySessionConfig
}

// RemoteCustodyServeService owns B's original worker journal and exact local
// custody source. It has no A authority root or key. Only an authenticated
// A-control Start may arm one same-runtime fresh attempt after durable Started.
// A must independently enforce confirmed Begin before dispatching that request;
// a signed proposal or this service's Started reply is not a current grant.
type RemoteCustodyServeService struct {
	mu                                                           sync.Mutex
	opMu                                                         sync.Mutex
	gate                                                         sync.Mutex
	controlWG, dataWG                                            sync.WaitGroup
	scope                                                        RemoteCustodyScope
	worker                                                       *remoteworker.Journal
	journal                                                      *workarchive.CustodyJournal
	objects                                                      *workarchive.ObjectStore
	sourceIdentity                                               map[string]os.FileInfo
	replicaKey, controlKey                                       ed25519.PrivateKey
	sessionConfig                                                workarchive.CustodySessionConfig
	controllerPeer, auditorPeer, serverPeer                      types.Hash
	host                                                         *libp2ptransport.Host
	runCtx, dataCtx                                              context.Context
	cancelRun, cancelData                                        context.CancelFunc
	stopWatch                                                    func() bool
	acceptingControl, acceptingData, freshAvailable, startedHere bool
	closing, closed                                              bool
	done                                                         chan struct{}
	failure, closeErr                                            error
	hooks                                                        storeHooks
}

func OpenRemoteCustodyServeService(ctx context.Context, config RemoteCustodyServeServiceConfig) (_ *RemoteCustodyServeService, returnErr error) {
	if ctx == nil || config.SessionConfig.Validate() != nil || config.SessionConfig.RequestTimeout > remotewire.MaximumTimeout ||
		config.ObjectPolicy.Validate() != nil || config.JournalLimits.Validate() != nil {
		return nil, ErrRemoteCustody
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope, err := freezeRemoteCustodyScope(config.Scope)
	if err != nil {
		return nil, err
	}
	paths := []string{config.WorkerPath, config.JournalPath, config.ObjectPath}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			paths[i], paths[j], err = coordinatorPaths(paths[i], paths[j])
			if err != nil {
				return nil, err
			}
		}
	}
	replicaKey, err := managedCustodyReplicaKey(config.ReplicaPrivateKey, scope.Worker.Assignment.ReplicaPublicKey)
	if err != nil {
		return nil, err
	}
	controlKey, err := remoteCustodyOwnedKey(config.ControlPrivateKey, scope.Worker.Assignment.RemoteControlPublicKey)
	if err != nil {
		return nil, err
	}
	worker, err := remoteworker.Open(ctx, paths[0], scope.Worker)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, worker.Close())
		}
	}()
	journal, _, err := workarchive.OpenExistingCustodyJournalWithLimits(ctx, paths[1], scope.Manifest, scope.InitialReceipt, scope.CustodyPolicy, config.JournalLimits)
	if err != nil {
		return nil, err
	}
	objects, err := workarchive.OpenExistingObjectStoreContext(ctx, paths[2], config.ObjectPolicy)
	if err != nil {
		return nil, err
	}
	missing, err := objects.Missing(scope.Manifest)
	if err != nil || len(missing) != 0 {
		return nil, errors.Join(ErrRemoteCustody, err)
	}
	service := &RemoteCustodyServeService{scope: scope, worker: worker, journal: journal, objects: objects, replicaKey: replicaKey, controlKey: controlKey,
		sessionConfig: config.SessionConfig, sourceIdentity: make(map[string]os.FileInfo), done: make(chan struct{})}
	for _, path := range []string{journal.Directory(), filepath.Join(journal.Directory(), "journal.lock")} {
		info, e := os.Lstat(path)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(ErrRemoteCustody, e)
		}
		service.sourceIdentity[path] = info
	}
	for _, role := range []struct {
		key    [32]byte
		target *types.Hash
	}{{scope.Worker.Plan.AuthorityTransportPublicKey, &service.controllerPeer},
		{scope.Worker.Plan.AuditorTransportPublicKey, &service.auditorPeer}, {scope.Worker.Assignment.RemoteTransportPublicKey, &service.serverPeer}} {
		*role.target, err = transport.PeerIDFromPublicKey(role.key[:])
		if err != nil {
			return nil, err
		}
	}
	// Open observes only. Even a pending Started marker receives no fresh
	// allowance, and an existing sealing branch is never repaired here.
	if _, err := worker.Snapshot(ctx); err != nil {
		return nil, err
	}
	if err := service.checkSourceIdentity(); err != nil {
		return nil, err
	}
	return service, nil
}

func remoteCustodyOwnedKey(key ed25519.PrivateKey, public [32]byte) (ed25519.PrivateKey, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrRemoteCustody
	}
	owned := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(key, owned) || [32]byte(owned.Public().(ed25519.PublicKey)) != public {
		return nil, ErrRemoteCustody
	}
	return owned, nil
}

// Start installs the private transport only; it never starts a custody effect.
// Caller cancellation requests the same irreversible Close/seal procedure.
func (service *RemoteCustodyServeService) Start(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config) error {
	if service == nil {
		return ErrClosed
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closing || service.closed || service.worker == nil {
		return ErrClosed
	}
	if service.host != nil {
		return ErrManagedCustodyServeStarted
	}
	if ctx == nil {
		return ErrRemoteCustody
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owned, err := remoteCustodyOwnedKey(key, service.scope.Worker.Assignment.RemoteTransportPublicKey)
	if err != nil {
		return err
	}
	run, cancelRun := context.WithCancel(context.Background())
	data, cancelData := context.WithCancel(context.Background())
	host, err := libp2ptransport.New(run, owned, config, nil)
	if err != nil {
		cancelRun()
		cancelData()
		return err
	}
	fail := func(err error) error { cancelRun(); cancelData(); return errors.Join(err, host.Close()) }
	if host.ID() != service.serverPeer {
		return fail(ErrRemoteCustody)
	}
	if err := host.SetRemoteCustodyControlHandler(service.controllerPeer, service.handleControl); err != nil {
		return fail(err)
	}
	if err := host.SetArchiveCustodyHandler([]types.Hash{service.auditorPeer}, service.handleData); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	service.gate.Lock()
	service.host, service.runCtx, service.dataCtx = host, run, data
	service.cancelRun, service.cancelData = cancelRun, cancelData
	service.acceptingControl = true
	service.gate.Unlock()
	service.stopWatch = context.AfterFunc(ctx, func() { _ = service.Close() })
	return nil
}

func (service *RemoteCustodyServeService) handleControl(_ context.Context, peer types.Hash, stream network.Stream) {
	service.gate.Lock()
	if !service.acceptingControl || peer != service.controllerPeer {
		service.gate.Unlock()
		_ = stream.Reset()
		return
	}
	service.controlWG.Add(1)
	ctx := service.runCtx
	service.gate.Unlock()
	defer service.controlWG.Done()
	owned := &remoteCustodyNetworkStream{Stream: stream}
	defer func() { service.rememberFailure(owned.Close()) }()
	bounded, cleanup, err := remotewire.BoundStream(ctx, owned, service.sessionConfig.RequestTimeout)
	if err != nil {
		return
	}
	defer cleanup()
	request, err := remotewire.ReadRequest(owned)
	if err != nil {
		return
	}
	if err := request.Validate(service.scope.Worker.Assignment, service.scope.Worker.PlanID, service.scope.Worker.BeginID); err != nil {
		return
	}
	if err := remotewire.RequireEOF(owned); err != nil {
		return
	}
	service.opMu.Lock()
	service.mu.Lock()
	closing := service.closing || service.closed
	service.mu.Unlock()
	if closing {
		service.opMu.Unlock()
		return
	}
	response, err := service.controlLocked(bounded, request)
	service.opMu.Unlock()
	if err != nil {
		return
	}
	if err := remotewire.WriteResponse(owned, response); err != nil {
		return
	}
	_ = owned.CloseWrite()
}

func (service *RemoteCustodyServeService) controlLocked(ctx context.Context, request remotewire.Request) (remotewire.Response, error) {
	w := service.scope.Worker
	response := remotewire.Response{Version: remotewire.Version0, Nonce: request.Nonce, PlanID: w.PlanID, BeginID: w.BeginID}
	switch request.Kind {
	case remotewire.Start:
		if err := service.admitStartLocked(ctx); err != nil {
			return remotewire.Response{}, err
		}
		response.Status = remotewire.StatusStarted
	case remotewire.Reconcile:
		snapshot, err := service.worker.Snapshot(ctx)
		if err != nil {
			return remotewire.Response{}, err
		}
		if snapshot.Pending != 0 {
			return remotewire.Response{}, remoteworker.ErrUncertain
		}
		if snapshot.Stage == remoteworker.Started {
			response.Status = remotewire.StatusStarted
			break
		}
		if snapshot.Stage != remoteworker.Sealed || snapshot.Seal == nil {
			return remotewire.Response{}, remoteworker.ErrTransition
		}
		return service.drainedResponseLocked(ctx, request, response, *snapshot.Seal)
	case remotewire.Seal:
		seal, err := service.sealLocked(ctx, true)
		if err != nil {
			return remotewire.Response{}, err
		}
		return service.drainedResponseLocked(ctx, request, response, seal)
	default:
		return remotewire.Response{}, ErrRemoteCustody
	}
	if err := remotewire.ValidateResponse(w.Assignment, request, response); err != nil {
		return remotewire.Response{}, err
	}
	return response, nil
}

func (service *RemoteCustodyServeService) drainedResponseLocked(ctx context.Context, request remotewire.Request, response remotewire.Response, seal remoteworker.Seal) (remotewire.Response, error) {
	w := service.scope.Worker
	sealID, err := seal.ID()
	if err != nil {
		return remotewire.Response{}, err
	}
	draft, err := service.worker.DrainedDraft(ctx, sealID, custodyauthority.Position{Sequence: w.Begin.Command.ExpectedSequence + 1, HeadID: w.BeginID})
	if err != nil {
		return remotewire.Response{}, err
	}
	review, err := custodyauthority.RemoteCommandReviewID(w.Assignment, draft)
	if err != nil {
		return remotewire.Response{}, err
	}
	command, err := custodyauthority.SignReviewedRemoteCommand(w.Assignment, draft, review, service.controlKey)
	if err != nil {
		return remotewire.Response{}, err
	}
	if err := ValidateRemoteCustodyDrain(service.scope, seal, command); err != nil {
		return remotewire.Response{}, err
	}
	response.Status, response.Seal, response.Drain = remotewire.StatusDrained, seal, command
	if err := remotewire.ValidateResponse(w.Assignment, request, response); err != nil {
		return remotewire.Response{}, err
	}
	return response, nil
}

func (service *RemoteCustodyServeService) admitStartLocked(ctx context.Context) error {
	snapshot, err := service.worker.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Stage >= remoteworker.Sealing {
		return remoteworker.ErrTransition
	}
	if snapshot.Stage == remoteworker.Prepared && snapshot.Pending == 0 {
		if err := service.withSourceDecision(ctx, func(decision *workarchive.CustodyJournalDecision) error { return service.requirePredecessor(decision) }); err != nil {
			return err
		}
		state, err := service.worker.Start(ctx, service.scope.Worker.BeginID)
		if err != nil {
			return err
		}
		if state.Stage != remoteworker.Started || state.Pending != 0 {
			return ErrRemoteCustody
		}
		service.gate.Lock()
		service.startedHere, service.freshAvailable, service.acceptingData = true, true, true
		service.gate.Unlock()
		return nil
	}
	// An exact same-runtime duplicate never renews the one fresh allowance.
	service.gate.Lock()
	sameRuntime := service.startedHere && service.freshAvailable
	service.gate.Unlock()
	if sameRuntime && snapshot.Pending == 0 {
		return nil
	}
	if snapshot.Pending != 0 {
		return remoteworker.ErrUncertain
	}
	if err := service.withSourceDecision(ctx, func(decision *workarchive.CustodyJournalDecision) error {
		_, err := service.currentResult(decision)
		return err
	}); err != nil {
		return err
	}
	service.gate.Lock()
	service.acceptingData = true
	service.freshAvailable = false
	service.gate.Unlock()
	return nil
}

func (service *RemoteCustodyServeService) handleData(_ context.Context, peer types.Hash, stream network.Stream) {
	service.gate.Lock()
	if !service.acceptingData || peer != service.auditorPeer {
		service.gate.Unlock()
		_ = stream.Reset()
		return
	}
	fresh := service.freshAvailable
	service.freshAvailable = false
	service.dataWG.Add(1)
	ctx := service.dataCtx
	service.gate.Unlock()
	defer service.dataWG.Done()
	owned := &remoteCustodyNetworkStream{Stream: stream, beforeWrite: func() error {
		return service.hooks.reach("remote-data-before-response-write")
	}}
	drained := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(drained); _ = owned.Close() })
	defer func() {
		closeErr := owned.Close()
		if !stop() {
			<-drained
		}
		service.rememberFailure(closeErr)
	}()
	if err := service.hooks.reach("remote-data-admitted"); err != nil {
		return
	}
	if err := service.withSourceDecision(ctx, func(decision *workarchive.CustodyJournalDecision) error {
		if fresh {
			return service.requirePredecessor(decision)
		}
		_, err := service.currentResult(decision)
		return err
	}); err != nil {
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}
	// This private session cannot be obtained by a caller. Reopened Started
	// reaches it only after the exact recovery head was verified above. With a
	// fixed expected challenge, an absent/different cache cannot mint a fresh
	// response against a later receipt; challenge verification fails closed.
	session, err := workarchive.NewJournalCustodyReplicaSession(service.journal, service.objects, service.replicaKey, service.sessionConfig)
	if err != nil {
		return
	}
	_, _ = session.ServeExpected(ctx, owned, service.scope.Worker.Plan.Admission.Command.OperationID)
}

// sealLocked requires opMu. The admission gate stays locked while BeginSeal is
// retained; no new data handler can slip between that marker and gate closure.
// An explicit Seal may finish an already-retained Start confirmation, but
// never arms the fresh flag or invokes a custody effect.
func (service *RemoteCustodyServeService) sealLocked(ctx context.Context, resolvePending bool) (seal remoteworker.Seal, returnErr error) {
	snapshot, err := service.worker.Snapshot(ctx)
	if err != nil {
		service.stopData()
		return seal, err
	}
	if snapshot.Stage == remoteworker.Sealed && snapshot.Pending == 0 && snapshot.Seal != nil {
		service.stopData()
		service.dataWG.Wait()
		return *snapshot.Seal, service.retainedFailure()
	}
	if snapshot.Stage == remoteworker.Sealed && snapshot.Pending == remoteworker.Sealed && snapshot.Seal != nil {
		service.stopData()
		service.dataWG.Wait()
		if !resolvePending {
			return seal, remoteworker.ErrUncertain
		}
		if err := service.retainedFailure(); err != nil {
			return seal, err
		}
		return service.worker.CommitSeal(ctx, snapshot.Seal.Disposition, snapshot.Seal.ResultID)
	}
	if snapshot.Pending == remoteworker.Started {
		if !resolvePending {
			service.stopData()
			service.dataWG.Wait()
			return seal, remoteworker.ErrUncertain
		}
		if _, err := service.worker.Start(ctx, service.scope.Worker.BeginID); err != nil {
			service.stopData()
			service.dataWG.Wait()
			return seal, err
		}
	}
	service.gate.Lock()
	_, err = service.worker.BeginSeal(ctx)
	service.acceptingData, service.freshAvailable = false, false
	cancel := service.cancelData
	service.gate.Unlock()
	if cancel != nil {
		cancel()
	}
	service.dataWG.Wait()
	if err != nil {
		return seal, err
	}
	if err := service.retainedFailure(); err != nil {
		return seal, err
	}
	if err := service.hooks.reach("remote-data-drained"); err != nil {
		return seal, err
	}
	returnErr = service.withSourceDecision(ctx, func(decision *workarchive.CustodyJournalDecision) error {
		state, err := service.worker.Snapshot(ctx)
		if err != nil {
			return err
		}
		disposition := remoteworker.Unseen
		var resultID types.Hash
		if state.Started {
			entry, resultErr := service.currentResult(decision)
			if resultErr == nil {
				disposition = remoteworker.RetainedResult
				resultID, err = entry.ID()
				if err != nil {
					return err
				}
			} else {
				if err := service.requirePredecessor(decision); err != nil {
					return errors.Join(resultErr, err)
				}
				disposition = remoteworker.NoResult
			}
		} else if err := service.requirePredecessor(decision); err != nil {
			return err
		}
		seal, err = service.worker.CommitSeal(ctx, disposition, resultID)
		return err
	})
	return seal, returnErr
}

func (service *RemoteCustodyServeService) stopData() {
	service.gate.Lock()
	service.acceptingData, service.freshAvailable = false, false
	cancel := service.cancelData
	service.gate.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (service *RemoteCustodyServeService) rememberFailure(err error) {
	if err == nil {
		return
	}
	service.mu.Lock()
	service.failure = errors.Join(service.failure, err)
	service.mu.Unlock()
}
func (service *RemoteCustodyServeService) retainedFailure() error {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.failure
}

func (service *RemoteCustodyServeService) checkSourceIdentity() error {
	for path, before := range service.sourceIdentity {
		now, err := os.Lstat(path)
		if err != nil || now.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, now) {
			return errors.Join(ErrRemoteCustody, err)
		}
	}
	return nil
}

func (service *RemoteCustodyServeService) withSourceDecision(ctx context.Context, action func(*workarchive.CustodyJournalDecision) error) (returnErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := service.checkSourceIdentity(); err != nil {
		return err
	}
	decision, err := service.journal.AcquireDecision()
	if err != nil {
		return err
	}
	defer func() { err := decision.Close(); service.rememberFailure(err); returnErr = errors.Join(returnErr, err) }()
	if err := service.checkSourceIdentity(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return action(decision)
}

func (service *RemoteCustodyServeService) requirePredecessor(decision *workarchive.CustodyJournalDecision) error {
	state, err := decision.State()
	if err != nil {
		return err
	}
	p := service.scope.Worker.Plan
	id, err := state.CurrentReceipt.ID()
	if err != nil || state.InitialReceipt != service.scope.InitialReceipt || state.CurrentReceipt != service.scope.PreviousReceipt || state.Sequence != p.PriorSequence || state.HeadEntryID != p.PriorHeadID || id != p.PriorReceiptID {
		return errors.Join(ErrRemoteCustody, err)
	}
	return nil
}

func (service *RemoteCustodyServeService) currentResult(decision *workarchive.CustodyJournalDecision) (workarchive.CustodyJournalEntry, error) {
	entry, ok, err := decision.Head()
	if err != nil || !ok {
		return workarchive.CustodyJournalEntry{}, errors.Join(ErrRemoteCustody, err)
	}
	state, err := decision.State()
	if err != nil {
		return workarchive.CustodyJournalEntry{}, err
	}
	p := service.scope.Worker.Plan
	id, err := entry.ID()
	challenge, challengeErr := entry.Record.Challenge.ID()
	if err != nil || challengeErr != nil || state.InitialReceipt != service.scope.InitialReceipt || state.Sequence != p.PriorSequence+1 || entry.Sequence != state.Sequence || state.HeadEntryID != id ||
		entry.PreviousEntryID != p.PriorHeadID || entry.PreviousReceipt != service.scope.PreviousReceipt || challenge != p.Admission.Command.OperationID || state.CurrentReceipt != entry.Record.RenewedReceipt {
		return workarchive.CustodyJournalEntry{}, errors.Join(ErrRemoteCustody, err, challengeErr)
	}
	want, _ := service.scope.Challenge.CanonicalBytes()
	got, err := entry.Record.Challenge.CanonicalBytes()
	if err != nil || !bytes.Equal(want, got) {
		return workarchive.CustodyJournalEntry{}, errors.Join(ErrRemoteCustody, err)
	}
	if err := entry.Verify(service.scope.Manifest, service.scope.CustodyPolicy, p.PriorSequence+1, p.PriorHeadID, service.scope.PreviousReceipt); err != nil {
		return workarchive.CustodyJournalEntry{}, err
	}
	return entry, nil
}

func (service *RemoteCustodyServeService) Addresses() []string {
	if service == nil {
		return nil
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.host == nil || service.closing || service.closed {
		return nil
	}
	return service.host.Addresses()
}

// Close permanently stops Start through Sealing/Sealed, or returns retained
// uncertainty. It never implicitly releases A's durable hold. No worker lock
// is released while any accepted data/control callback can still use a key.
func (service *RemoteCustodyServeService) Close() error {
	if service == nil {
		return nil
	}
	service.mu.Lock()
	if service.closing {
		done := service.done
		service.mu.Unlock()
		<-done
		service.mu.Lock()
		defer service.mu.Unlock()
		return service.closeErr
	}
	service.closing = true
	stopWatch := service.stopWatch
	service.mu.Unlock()
	if stopWatch != nil {
		stopWatch()
	}
	service.gate.Lock()
	service.acceptingControl = false
	service.gate.Unlock()
	service.opMu.Lock()
	_, sealErr := service.sealLocked(context.Background(), false)
	service.opMu.Unlock()
	service.stopData()
	if service.cancelRun != nil {
		service.cancelRun()
	}
	var hostErr error
	if service.host != nil {
		hostErr = service.host.Close()
	}
	service.dataWG.Wait()
	service.controlWG.Wait()
	workerErr := service.worker.Close()
	service.mu.Lock()
	service.closeErr = errors.Join(sealErr, hostErr, workerErr, service.failure)
	service.closed = true
	close(service.done)
	result := service.closeErr
	service.mu.Unlock()
	return result
}

type remoteCustodyNetworkStream struct {
	network.Stream
	once        sync.Once
	err         error
	beforeWrite func() error
	writeOnce   sync.Once
	writeErr    error
}

func (stream *remoteCustodyNetworkStream) Write(p []byte) (int, error) {
	stream.writeOnce.Do(func() {
		if stream.beforeWrite != nil {
			stream.writeErr = stream.beforeWrite()
		}
	})
	if stream.writeErr != nil {
		return 0, stream.writeErr
	}
	return stream.Stream.Write(p)
}

func (stream *remoteCustodyNetworkStream) Close() error {
	stream.once.Do(func() {
		if closeErr := stream.Stream.Close(); closeErr != nil {
			// The peer may have cancelled its half after rejecting the proof.
			// A successful actual Reset conclusively aborts the local channel;
			// it says nothing about delivery or acceptance. The service still
			// waits for the complete handler before signing any drain.
			if resetErr := stream.Stream.Reset(); resetErr != nil {
				stream.err = errors.Join(closeErr, resetErr)
			}
		}
	})
	return stream.err
}
