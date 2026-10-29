package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var (
	ErrManagedCustodyRuntime     = errors.New("invalid owned custody runtime")
	ErrManagedCustodyRuntimeBusy = errors.New("owned custody runtime already has an active action")
	ErrManagedCustodyReview      = errors.New("owned custody runtime review changed")
)

type ManagedCustodyAuditRuntimeConfig struct {
	AuthorityPath, AuthorityPinsPath string
	Assignment                       custodyauthority.Assignment
	Audit                            ManagedCustodyAuditConfig
	AuditorPeerID                    types.Hash
}

// ManagedCustodyAuditReview is a detached local observation, never an execution
// grant. Its comparison ID includes original placement, immutable scope, local
// limits and observed positions. It contains no nonce or private signing key.
type ManagedCustodyAuditReview struct {
	ScheduleID                                                               types.Hash
	AssignmentID, AuditTicketID, IntentID                                    types.Hash
	AuditorPeerID, ReplicaPeerID                                             types.Hash
	AuthorityPosition                                                        custodyauthority.Position
	JournalSequence                                                          uint64
	JournalHeadID, CurrentReceiptID                                          types.Hash
	AuthorityPath, AuthorityPinsPath, IntentPath, ArtifactsPath, JournalPath string
	JournalLimits                                                            workarchive.CustodyJournalLimits
	RequestTimeout                                                           time.Duration
}

func (review ManagedCustodyAuditReview) ID() (types.Hash, error) {
	if review.AssignmentID.IsZero() || review.AuditTicketID.IsZero() || review.IntentID.IsZero() ||
		review.AuditorPeerID.IsZero() || review.ReplicaPeerID.IsZero() || review.CurrentReceiptID.IsZero() ||
		review.RequestTimeout <= 0 || review.JournalLimits.Validate() != nil {
		return types.Hash{}, ErrManagedCustodyReview
	}
	e := codec.NewEncoder(2048)
	for _, id := range []types.Hash{review.AssignmentID, review.AuditTicketID, review.IntentID, review.AuditorPeerID, review.ReplicaPeerID,
		review.AuthorityPosition.HeadID, review.JournalHeadID, review.CurrentReceiptID} {
		e.Fixed(id[:])
	}
	e.U64(review.AuthorityPosition.Sequence)
	e.U64(review.JournalSequence)
	e.U64(review.JournalLimits.MaximumBytes)
	e.U64(review.JournalLimits.MaximumPaths)
	e.U64(uint64(review.RequestTimeout))
	for _, path := range []string{review.AuthorityPath, review.AuthorityPinsPath, review.IntentPath, review.ArtifactsPath, review.JournalPath} {
		if path == "" || len(path) > 32<<10 {
			return types.Hash{}, ErrManagedCustodyReview
		}
		// Raw bytes preserve even non-UTF8 filesystem placement. This local
		// comparison is not a network or retained journal encoding.
		e.BytesField([]byte(path))
	}
	if !review.ScheduleID.IsZero() {
		e.Fixed(review.ScheduleID[:])
		return types.DomainHash("OMESH/local/custody-audit-runtime-review/v1", e.Bytes()), nil
	}
	return types.DomainHash("OMESH/local/custody-audit-runtime-review/v0", e.Bytes()), nil
}

// ManagedCustodyAuditRuntime owns the original coordinator. Open and Review
// create no listener, challenge, intent or recovery output. Actions are explicit,
// serial and bounded by their supplied context and existing filesystem waits.
type ManagedCustodyAuditRuntime struct {
	life        *custodyRuntimeLifetime
	session     *ManagedCustodyAuditSession
	journal     *workarchive.CustodyJournal
	auditorPeer types.Hash
	limits      workarchive.CustodyJournalLimits
	timeout     time.Duration
	hooks       storeHooks
}

func OpenManagedCustodyAuditRuntime(ctx context.Context, config ManagedCustodyAuditRuntimeConfig) (_ *ManagedCustodyAuditRuntime, returnErr error) {
	if ctx == nil || config.AuthorityPath == "" || config.AuthorityPinsPath == "" || config.AuditorPeerID.IsZero() {
		return nil, ErrManagedCustodyRuntime
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := config.Assignment.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	assignment, err := custodyauthority.DecodeAssignment(b)
	if err != nil {
		return nil, err
	}
	id, err := assignment.ID()
	if err != nil || config.Audit.AssignmentID != id {
		return nil, errors.Join(ErrManagedCustodyRuntime, err)
	}
	intent, err := workarchive.LoadCustodyAuditIntent(config.Audit.IntentPath, config.Audit.IntentID)
	if err != nil {
		return nil, err
	}
	if err := validatePruneRuntimePeers(assignment, config.AuditorPeerID, intent.ReplicaPeerID); err != nil {
		return nil, err
	}
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, assignment, id)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, owner.Close())
		}
	}()
	session, err := NewManagedCustodyAuditSession(ctx, owner, config.Audit)
	if err != nil {
		return nil, err
	}
	journal, _, err := workarchive.OpenExistingCustodyJournalWithLimits(ctx, session.journalPath, config.Audit.Manifest,
		config.Audit.InitialReceipt, config.Audit.CustodyPolicy, config.Audit.JournalLimits)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &ManagedCustodyAuditRuntime{life: newCustodyRuntimeLifetime(owner), session: session, journal: journal,
		auditorPeer: config.AuditorPeerID, limits: config.Audit.JournalLimits, timeout: config.Audit.SessionConfig.RequestTimeout}, nil
}

func (runtime *ManagedCustodyAuditRuntime) Review(ctx context.Context) (review ManagedCustodyAuditReview, returnErr error) {
	if runtime == nil || runtime.life == nil {
		return review, ErrClosed
	}
	run, finish, err := runtime.life.begin(ctx)
	if err != nil {
		return review, err
	}
	defer finish()
	err = runtime.life.owner.WithOperation(run, runtime.session.binding, func() error {
		var err error
		review, err = runtime.reviewLocked(run)
		return err
	})
	if err != nil {
		return ManagedCustodyAuditReview{}, err
	}
	return review, nil
}

func (runtime *ManagedCustodyAuditRuntime) reviewLocked(ctx context.Context) (ManagedCustodyAuditReview, error) {
	if err := runtime.session.revalidate(); err != nil {
		return ManagedCustodyAuditReview{}, err
	}
	state, err := runtime.journal.State()
	if err != nil {
		return ManagedCustodyAuditReview{}, err
	}
	current, err := runtime.life.owner.snapshot()
	if err != nil {
		return ManagedCustodyAuditReview{}, err
	}
	receipt, err := state.CurrentReceipt.ID()
	if err != nil {
		return ManagedCustodyAuditReview{}, err
	}
	if err := ctx.Err(); err != nil {
		return ManagedCustodyAuditReview{}, err
	}
	return ManagedCustodyAuditReview{ScheduleID: runtime.session.binding.ScheduleID, AssignmentID: runtime.session.binding.AssignmentID, AuditTicketID: runtime.session.binding.TicketID,
		IntentID: runtime.session.intentID, AuditorPeerID: runtime.auditorPeer, ReplicaPeerID: runtime.session.cycle.Intent().ReplicaPeerID,
		AuthorityPosition: current.Confirmed, JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID, CurrentReceiptID: receipt,
		AuthorityPath: runtime.life.owner.authority.path, AuthorityPinsPath: runtime.life.owner.journal.path, IntentPath: runtime.session.intentPath,
		ArtifactsPath: runtime.session.artifactsPath, JournalPath: runtime.session.journalPath, JournalLimits: runtime.limits, RequestTimeout: runtime.timeout}, nil
}

func (runtime *ManagedCustodyAuditRuntime) action(ctx context.Context, expected *types.Hash, effect func(context.Context) error) error {
	if runtime == nil || runtime.life == nil {
		return ErrClosed
	}
	run, finish, err := runtime.life.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	return runtime.life.owner.WithOperation(run, runtime.session.binding, func() error {
		if err := runtime.session.revalidate(); err != nil {
			return err
		}
		if expected != nil {
			review, err := runtime.reviewLocked(run)
			if err != nil {
				return err
			}
			id, err := review.ID()
			if err != nil || expected.IsZero() || id != *expected {
				return errors.Join(ErrManagedCustodyReview, err)
			}
		}
		if err := runtime.hooks.reach("audit-runtime-action-entered"); err != nil {
			return err
		}
		if err := run.Err(); err != nil {
			return err
		}
		return effect(run)
	})
}

func (runtime *ManagedCustodyAuditRuntime) PrepareChallenge(ctx context.Context) (workarchive.CustodyChallenge, error) {
	return runtime.prepare(ctx, nil)
}
func (runtime *ManagedCustodyAuditRuntime) PrepareChallengeReviewed(ctx context.Context, id types.Hash) (workarchive.CustodyChallenge, error) {
	return runtime.prepare(ctx, &id)
}
func (runtime *ManagedCustodyAuditRuntime) prepare(ctx context.Context, expected *types.Hash) (challenge workarchive.CustodyChallenge, err error) {
	err = runtime.action(ctx, expected, func(run context.Context) error {
		var err error
		challenge, err = runtime.session.cycle.PrepareChallenge(run)
		return err
	})
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	return challenge, nil
}
func (runtime *ManagedCustodyAuditRuntime) Recover(ctx context.Context) (workarchive.CustodyAuditResult, error) {
	return runtime.recover(ctx, nil)
}
func (runtime *ManagedCustodyAuditRuntime) RecoverReviewed(ctx context.Context, id types.Hash) (workarchive.CustodyAuditResult, error) {
	return runtime.recover(ctx, &id)
}
func (runtime *ManagedCustodyAuditRuntime) recover(ctx context.Context, expected *types.Hash) (result workarchive.CustodyAuditResult, err error) {
	err = runtime.action(ctx, expected, func(run context.Context) error {
		var err error
		result, err = runtime.session.cycle.Recover(run)
		return err
	})
	if err != nil {
		return workarchive.CustodyAuditResult{}, err
	}
	return result, nil
}
func (runtime *ManagedCustodyAuditRuntime) AuditQUIC(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config, address string) (workarchive.CustodyAuditResult, error) {
	return runtime.auditQUIC(ctx, nil, key, config, address)
}
func (runtime *ManagedCustodyAuditRuntime) AuditQUICReviewed(ctx context.Context, id types.Hash, key ed25519.PrivateKey, config libp2ptransport.Config, address string) (workarchive.CustodyAuditResult, error) {
	return runtime.auditQUIC(ctx, &id, key, config, address)
}
func (runtime *ManagedCustodyAuditRuntime) auditQUIC(ctx context.Context, expected *types.Hash, key ed25519.PrivateKey, config libp2ptransport.Config, address string) (result workarchive.CustodyAuditResult, err error) {
	err = runtime.action(ctx, expected, func(run context.Context) (returnErr error) {
		ownedKey, err := pruneRuntimeKey(key, runtime.auditorPeer)
		if err != nil {
			return err
		}
		networkContext, cancel := context.WithTimeout(run, runtime.timeout)
		defer cancel()
		host, err := newCustodyRuntimeHost(networkContext, ownedKey, config)
		if err != nil {
			return err
		}
		defer func() {
			closeErr := host.closeAndDrain()
			runtime.life.recordCleanup(closeErr)
			returnErr = errors.Join(returnErr, closeErr)
		}()
		stream, peer, err := host.host.OpenArchiveCustodyStream(networkContext, address, runtime.session.cycle.Intent().ReplicaPeerID)
		if err != nil {
			return err
		}
		if peer != runtime.session.cycle.Intent().ReplicaPeerID {
			closeErr := stream.Close()
			runtime.life.recordCleanup(closeErr)
			return errors.Join(ErrManagedCustodyRuntime, closeErr)
		}
		owned := &managedCustodyServeStream{CustodySessionStream: stream}
		duplex := &managedCustodyPairDuplexStream{managedCustodyServeStream: owned, half: stream}
		defer func() {
			closeErr := owned.Close()
			runtime.life.recordCleanup(closeErr)
			returnErr = errors.Join(returnErr, closeErr)
		}()
		result, err = runtime.session.auditGuarded(networkContext, duplex)
		return err
	})
	if err != nil {
		return workarchive.CustodyAuditResult{}, err
	}
	return result, nil
}
func (runtime *ManagedCustodyAuditRuntime) Close() error {
	if runtime == nil || runtime.life == nil {
		return nil
	}
	return runtime.life.close()
}

// This admission gate prevents Add after Close begins waiting. No lifecycle
// mutex remains held during an action, so Close can cancel blocked network I/O.
type custodyRuntimeLifetime struct {
	mu                      sync.Mutex
	owner                   *Coordinator
	active, closing, closed bool
	cancel                  context.CancelFunc
	inflight                sync.WaitGroup
	done                    chan struct{}
	closeErr                error
	cleanupErr              error
}

func newCustodyRuntimeLifetime(owner *Coordinator) *custodyRuntimeLifetime {
	return &custodyRuntimeLifetime{owner: owner, done: make(chan struct{})}
}
func (life *custodyRuntimeLifetime) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrManagedCustodyRuntime
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	life.mu.Lock()
	defer life.mu.Unlock()
	if life.closing || life.closed {
		return nil, nil, ErrClosed
	}
	if life.active {
		return nil, nil, ErrManagedCustodyRuntimeBusy
	}
	run, cancel := context.WithCancel(ctx)
	life.active, life.cancel = true, cancel
	life.inflight.Add(1)
	return run, func() {
		cancel()
		life.mu.Lock()
		life.active, life.cancel = false, nil
		life.mu.Unlock()
		life.inflight.Done()
	}, nil
}
func (life *custodyRuntimeLifetime) close() error {
	life.mu.Lock()
	if life.closing {
		done := life.done
		life.mu.Unlock()
		<-done
		life.mu.Lock()
		defer life.mu.Unlock()
		return life.closeErr
	}
	life.closing = true
	cancel := life.cancel
	life.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	life.inflight.Wait()
	err := life.owner.Close()
	life.mu.Lock()
	err = errors.Join(err, life.cleanupErr)
	life.closeErr, life.closed = err, true
	close(life.done)
	life.mu.Unlock()
	return err
}

func (life *custodyRuntimeLifetime) recordCleanup(err error) {
	if err == nil {
		return
	}
	life.mu.Lock()
	life.cleanupErr = errors.Join(life.cleanupErr, err)
	life.mu.Unlock()
}

type custodyRuntimeHost struct {
	host    *libp2ptransport.Host
	once    sync.Once
	err     error
	stop    func() bool
	drained chan struct{}
}

func newCustodyRuntimeHost(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config) (*custodyRuntimeHost, error) {
	host, err := libp2ptransport.New(ctx, key, config, nil)
	if err != nil {
		return nil, err
	}
	owned := &custodyRuntimeHost{host: host, drained: make(chan struct{})}
	owned.stop = context.AfterFunc(ctx, func() { defer close(owned.drained); _ = owned.close() })
	return owned, nil
}
func (owned *custodyRuntimeHost) close() error {
	owned.once.Do(func() { owned.err = owned.host.Close() })
	return owned.err
}
func (owned *custodyRuntimeHost) closeAndDrain() error {
	err := owned.close()
	if !owned.stop() {
		<-owned.drained
	}
	return err
}
