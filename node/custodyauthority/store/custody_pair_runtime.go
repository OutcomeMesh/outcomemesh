package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type ManagedCustodyPairRuntimeConfig struct {
	AuthorityPath, AuthorityPinsPath string
	Assignment                       custodyauthority.Assignment
	Audit                            ManagedCustodyAuditConfig
	Serve                            ManagedCustodyServeConfig
	ObjectPath                       string
	ObjectPolicy                     workarchive.ObjectStorePolicy
	AuditorPeerID, ReplicaPeerID     types.Hash
}

type ManagedCustodyPairReview struct {
	Audit                                  ManagedCustodyAuditReview
	ServeTicketID, ChallengeID             types.Hash
	ReplicaJournalSequence                 uint64
	ReplicaJournalHeadID, ReplicaReceiptID types.Hash
	ReplicaJournalPath, ObjectPath         string
	ReplicaJournalLimits                   workarchive.CustodyJournalLimits
	ReplicaRequestTimeout                  time.Duration
	ObjectPolicy                           workarchive.ObjectStorePolicy
}

func (review ManagedCustodyPairReview) ID() (types.Hash, error) {
	auditID, err := review.Audit.ID()
	if err != nil || review.ServeTicketID.IsZero() || review.ChallengeID.IsZero() || review.ReplicaReceiptID.IsZero() ||
		review.ReplicaJournalLimits.Validate() != nil || review.ObjectPolicy.Validate() != nil || review.ReplicaRequestTimeout <= 0 {
		return types.Hash{}, errors.Join(ErrManagedCustodyReview, err)
	}
	e := codec.NewEncoder(1024)
	for _, id := range []types.Hash{auditID, review.ServeTicketID, review.ChallengeID, review.ReplicaJournalHeadID, review.ReplicaReceiptID} {
		e.Fixed(id[:])
	}
	e.U64(review.ReplicaJournalSequence)
	e.U64(review.ReplicaJournalLimits.MaximumBytes)
	e.U64(review.ReplicaJournalLimits.MaximumPaths)
	e.U64(uint64(review.ReplicaRequestTimeout))
	e.U64(review.ObjectPolicy.MaximumObjects)
	e.U64(review.ObjectPolicy.MaximumBytes)
	for _, path := range []string{review.ReplicaJournalPath, review.ObjectPath} {
		if path == "" || len(path) > 32<<10 {
			return types.Hash{}, ErrManagedCustodyReview
		}
		e.BytesField([]byte(path))
	}
	return types.DomainHash("OMESH/local/custody-pair-runtime-review/v0", e.Bytes()), nil
}

// ManagedCustodyPairRuntime owns one original coordinator and two private local
// participants. Each explicit ExchangeQUIC owns and drains both transport hosts
// and all accepted callbacks. It is not a distributed authority broker.
type ManagedCustodyPairRuntime struct {
	audit          *ManagedCustodyAuditRuntime
	pair           *ManagedCustodyAuditServePair
	replicaJournal *workarchive.CustodyJournal
	replicaLimits  workarchive.CustodyJournalLimits
	replicaTimeout time.Duration
	objectPolicy   workarchive.ObjectStorePolicy
	hooks          storeHooks
}

func OpenManagedCustodyPairRuntime(ctx context.Context, config ManagedCustodyPairRuntimeConfig) (_ *ManagedCustodyPairRuntime, returnErr error) {
	if ctx == nil || config.Serve.Objects != nil || config.ObjectPath == "" || config.ObjectPolicy.Validate() != nil ||
		config.Serve.AuditorPeerID != config.AuditorPeerID || config.AuditorPeerID == config.ReplicaPeerID {
		return nil, ErrManagedCustodyRuntime
	}
	audit, err := OpenManagedCustodyAuditRuntime(ctx, ManagedCustodyAuditRuntimeConfig{AuthorityPath: config.AuthorityPath,
		AuthorityPinsPath: config.AuthorityPinsPath, Assignment: config.Assignment, Audit: config.Audit, AuditorPeerID: config.AuditorPeerID})
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, audit.Close())
		}
	}()
	if audit.session.cycle.Intent().ReplicaPeerID != config.ReplicaPeerID {
		return nil, ErrManagedCustodyRuntime
	}
	objects, err := workarchive.OpenExistingObjectStoreContext(ctx, config.ObjectPath, config.ObjectPolicy)
	if err != nil {
		return nil, err
	}
	missing, err := objects.Missing(config.Serve.Manifest)
	if err != nil || len(missing) != 0 {
		return nil, errors.Join(ErrManagedCustodyRuntime, err)
	}
	config.Serve.Objects = objects
	serve, err := NewManagedCustodyServeSession(ctx, audit.life.owner, config.Serve)
	if err != nil {
		return nil, err
	}
	pair, err := NewManagedCustodyAuditServePair(audit.session, serve)
	if err != nil {
		return nil, err
	}
	journal, _, err := workarchive.OpenExistingCustodyJournalWithLimits(ctx, serve.journalPath, config.Serve.Manifest,
		config.Serve.InitialReceipt, config.Serve.CustodyPolicy, config.Serve.JournalLimits)
	if err != nil {
		return nil, err
	}
	runtime := &ManagedCustodyPairRuntime{audit: audit, pair: pair, replicaJournal: journal, replicaLimits: config.Serve.JournalLimits,
		replicaTimeout: config.Serve.SessionConfig.RequestTimeout, objectPolicy: config.ObjectPolicy}
	if _, err := runtime.Review(ctx); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (runtime *ManagedCustodyPairRuntime) Review(ctx context.Context) (review ManagedCustodyPairReview, returnErr error) {
	if runtime == nil || runtime.audit == nil {
		return review, ErrClosed
	}
	run, finish, err := runtime.audit.life.begin(ctx)
	if err != nil {
		return review, err
	}
	defer finish()
	err = runtime.audit.life.owner.WithOperation(run, runtime.audit.session.binding, func() error {
		var err error
		review, err = runtime.reviewLocked(run)
		return err
	})
	if err != nil {
		return ManagedCustodyPairReview{}, err
	}
	return review, nil
}

func (runtime *ManagedCustodyPairRuntime) reviewLocked(ctx context.Context) (ManagedCustodyPairReview, error) {
	if err := runtime.audit.life.owner.checkOperation(runtime.pair.serve.binding); err != nil {
		return ManagedCustodyPairReview{}, err
	}
	if err := runtime.pair.validateRoots(); err != nil {
		return ManagedCustodyPairReview{}, err
	}
	audit, err := runtime.audit.reviewLocked(ctx)
	if err != nil {
		return ManagedCustodyPairReview{}, err
	}
	state, err := runtime.replicaJournal.State()
	if err != nil {
		return ManagedCustodyPairReview{}, err
	}
	receipt, err := state.CurrentReceipt.ID()
	if err != nil {
		return ManagedCustodyPairReview{}, err
	}
	if err := ctx.Err(); err != nil {
		return ManagedCustodyPairReview{}, err
	}
	return ManagedCustodyPairReview{Audit: audit, ServeTicketID: runtime.pair.serve.binding.TicketID, ChallengeID: runtime.pair.serve.challengeID,
		ReplicaJournalSequence: state.Sequence, ReplicaJournalHeadID: state.HeadEntryID, ReplicaReceiptID: receipt,
		ReplicaJournalPath: runtime.pair.serve.journalPath, ObjectPath: runtime.pair.serve.objects.Directory(),
		ReplicaJournalLimits: runtime.replicaLimits, ReplicaRequestTimeout: runtime.replicaTimeout, ObjectPolicy: runtime.objectPolicy}, nil
}

func (runtime *ManagedCustodyPairRuntime) ExchangeQUIC(ctx context.Context, auditorKey, replicaKey ed25519.PrivateKey, config libp2ptransport.Config) (ManagedCustodyAuditServeResult, error) {
	return runtime.exchangeQUIC(ctx, nil, auditorKey, replicaKey, config)
}

func (runtime *ManagedCustodyPairRuntime) ExchangeQUICReviewed(ctx context.Context, id types.Hash, auditorKey, replicaKey ed25519.PrivateKey, config libp2ptransport.Config) (ManagedCustodyAuditServeResult, error) {
	return runtime.exchangeQUIC(ctx, &id, auditorKey, replicaKey, config)
}

func (runtime *ManagedCustodyPairRuntime) compareLocked(ctx context.Context, expected *types.Hash) error {
	review, err := runtime.reviewLocked(ctx)
	if err != nil {
		return err
	}
	if expected == nil {
		return nil
	}
	id, err := review.ID()
	if err != nil || expected.IsZero() || id != *expected {
		return errors.Join(ErrManagedCustodyReview, err)
	}
	return nil
}

func (runtime *ManagedCustodyPairRuntime) exchangeQUIC(ctx context.Context, expected *types.Hash, auditorKey, replicaKey ed25519.PrivateKey, config libp2ptransport.Config) (result ManagedCustodyAuditServeResult, returnErr error) {
	if runtime == nil || runtime.audit == nil {
		return result, ErrClosed
	}
	run, finish, err := runtime.audit.life.begin(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	// Fail invalid/stale review before even transport setup, then repeat the
	// comparison under the joint guard immediately before application effects.
	if err := runtime.audit.life.owner.WithOperation(run, runtime.audit.session.binding, func() error { return runtime.compareLocked(run, expected) }); err != nil {
		return result, err
	}
	auditorOwnedKey, err := pruneRuntimeKey(auditorKey, runtime.audit.auditorPeer)
	if err != nil {
		return result, err
	}
	replicaOwnedKey, err := pruneRuntimeKey(replicaKey, runtime.audit.session.cycle.Intent().ReplicaPeerID)
	if err != nil {
		return result, err
	}
	if err := runtime.hooks.reach("pair-runtime-before-hosts"); err != nil {
		return result, err
	}
	networkContext, cancel := context.WithTimeout(run, min(runtime.audit.timeout, runtime.replicaTimeout))
	defer cancel()
	client, err := newCustodyRuntimeHost(networkContext, auditorOwnedKey, config)
	if err != nil {
		return result, err
	}
	defer func() {
		closeErr := client.closeAndDrain()
		runtime.audit.life.recordCleanup(closeErr)
		returnErr = errors.Join(returnErr, closeErr)
		if returnErr != nil {
			result = ManagedCustodyAuditServeResult{}
		}
	}()
	replica, err := newCustodyRuntimeHost(networkContext, replicaOwnedKey, config)
	if err != nil {
		return result, err
	}
	registry := newCustodyPairCallbacks()
	registry.hooks = runtime.hooks
	defer func() {
		registry.stop()
		cancel()
		closeErr := replica.closeAndDrain()
		registry.wait.Wait()
		closeErr = errors.Join(closeErr, registry.failure())
		runtime.audit.life.recordCleanup(closeErr)
		returnErr = errors.Join(returnErr, closeErr)
		if returnErr != nil {
			result = ManagedCustodyAuditServeResult{}
		}
	}()
	if err := replica.host.SetArchiveCustodyHandler([]types.Hash{runtime.audit.auditorPeer}, registry.handle); err != nil {
		return result, err
	}
	if err := runtime.hooks.reach("pair-runtime-hosts-opened"); err != nil {
		return result, err
	}
	addresses := replica.host.Addresses()
	if len(addresses) == 0 {
		return result, ErrManagedCustodyRuntime
	}
	left, replicaID, err := client.host.OpenArchiveCustodyStream(networkContext, addresses[0], runtime.audit.session.cycle.Intent().ReplicaPeerID)
	if err != nil {
		return result, err
	}
	if replicaID != runtime.audit.session.cycle.Intent().ReplicaPeerID {
		return result, errors.Join(ErrManagedCustodyRuntime, left.Close())
	}
	ownedLeft := &managedCustodyServeStream{CustodySessionStream: left}
	leftIO := &managedCustodyPairDuplexStream{managedCustodyServeStream: ownedLeft, half: left}
	defer func() {
		closeErr := ownedLeft.Close()
		runtime.audit.life.recordCleanup(closeErr)
		returnErr = errors.Join(returnErr, closeErr)
	}()
	if err := left.SetDeadline(time.Now().Add(min(runtime.audit.timeout, runtime.replicaTimeout))); err != nil {
		return result, err
	}
	// No custody frame is sent: this only flushes libp2p's lazy protocol
	// negotiation so both authenticated stream ends exist before the guard.
	if _, err := left.Write(nil); err != nil {
		return result, err
	}
	var right custodyPairInbound
	select {
	case right = <-registry.inbound:
	case <-networkContext.Done():
		return result, networkContext.Err()
	}
	if err := runtime.hooks.reach("pair-runtime-streams-ready"); err != nil {
		return result, err
	}
	result, err = runtime.pair.exchange(networkContext, replicaID, right.peer, leftIO, right.stream,
		func() error { return runtime.compareLocked(networkContext, expected) })
	return result, err
}

func (runtime *ManagedCustodyPairRuntime) Close() error {
	if runtime == nil || runtime.audit == nil {
		return nil
	}
	return runtime.audit.Close()
}

type custodyPairInbound struct {
	peer   types.Hash
	stream *managedCustodyServeStream
}
type custodyPairCallbacks struct {
	mu        sync.Mutex
	accepting bool
	wait      sync.WaitGroup
	inbound   chan custodyPairInbound
	release   chan struct{}
	closeErr  error
	hooks     storeHooks
}

func newCustodyPairCallbacks() *custodyPairCallbacks {
	return &custodyPairCallbacks{accepting: true, inbound: make(chan custodyPairInbound, 1), release: make(chan struct{})}
}
func (callbacks *custodyPairCallbacks) handle(ctx context.Context, peer types.Hash, stream network.Stream) {
	callbacks.mu.Lock()
	if !callbacks.accepting {
		callbacks.mu.Unlock()
		_ = stream.Reset()
		return
	}
	callbacks.wait.Add(1)
	callbacks.mu.Unlock()
	owned := &managedCustodyServeStream{CustodySessionStream: stream}
	defer callbacks.wait.Done()
	defer func() {
		err := errors.Join(callbacks.hooks.reach("pair-runtime-handler-before-return"), owned.Close())
		callbacks.mu.Lock()
		callbacks.closeErr = errors.Join(callbacks.closeErr, err)
		callbacks.mu.Unlock()
	}()
	select {
	case callbacks.inbound <- custodyPairInbound{peer: peer, stream: owned}:
	case <-ctx.Done():
		return
	default:
		_ = stream.Reset()
		return
	}
	select {
	case <-callbacks.release:
	case <-ctx.Done():
	}
}
func (callbacks *custodyPairCallbacks) stop() {
	callbacks.mu.Lock()
	callbacks.accepting = false
	close(callbacks.release)
	callbacks.mu.Unlock()
}
func (callbacks *custodyPairCallbacks) failure() error {
	callbacks.mu.Lock()
	defer callbacks.mu.Unlock()
	return callbacks.closeErr
}
