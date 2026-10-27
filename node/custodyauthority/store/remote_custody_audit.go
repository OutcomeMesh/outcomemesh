package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// RemoteCustodyAuditRuntimeConfig selects one pre-existing original A owner,
// one unsigned Audit intent and one independently pinned remote session. The
// authority key is retained only for co-signing an explicitly requested drain;
// it is never sent to B. Opening creates no challenge, Begin or network host.
type RemoteCustodyAuditRuntimeConfig struct {
	AuthorityPath, AuthorityPinsPath string
	Scope                            RemoteCustodyScope
	Audit                            ManagedCustodyAuditConfig
	AuthorityPrivateKey              ed25519.PrivateKey
}

// RemoteCustodyAuditRuntime keeps the original coordinator through every
// synchronous remote action and its complete transport cleanup. Its narrow
// active-hold checks do not change the generic WithOperation barrier. Neither
// an I/O result nor Close completes an ordinary Audit or Serve ticket.
type RemoteCustodyAuditRuntime struct {
	life           *custodyRuntimeLifetime
	scope          RemoteCustodyScope
	intent         workarchive.CustodyAuditIntent
	admission      custodyauthority.Entry
	session        *ManagedCustodyAuditSession
	journal        *workarchive.CustodyJournal
	authorityKey   ed25519.PrivateKey
	controlPeer    types.Hash
	auditorPeer    types.Hash
	replicaPeer    types.Hash
	sourceIdentity map[string]os.FileInfo
	timeout        time.Duration
	journalLimits  workarchive.CustodyJournalLimits
	hooks          storeHooks
}

func OpenRemoteCustodyAuditRuntime(ctx context.Context, config RemoteCustodyAuditRuntimeConfig) (_ *RemoteCustodyAuditRuntime, returnErr error) {
	if ctx == nil || config.AuthorityPath == "" || config.AuthorityPinsPath == "" || config.Audit.IntentPath == "" ||
		config.Audit.JournalPath == "" || config.Audit.ArtifactsPath == "" || config.Audit.IntentID.IsZero() ||
		config.Audit.SessionConfig.Validate() != nil || config.Audit.JournalLimits.Validate() != nil {
		return nil, ErrRemoteCustody
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope, err := freezeRemoteCustodyScope(config.Scope)
	if err != nil {
		return nil, err
	}
	w := scope.Worker
	if config.Audit.AssignmentID != w.Plan.AssignmentID {
		return nil, ErrRemoteCustody
	}
	// Check the redundant legacy-shaped archive fields instead of silently
	// ignoring a caller's different manifest, receipt or policy.
	a := w.Assignment
	derived, err := workarchive.CreateRemoteCustodyAuthorityAssignment(config.Audit.Manifest, config.Audit.InitialReceipt, config.Audit.CustodyPolicy,
		a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
	if err != nil {
		return nil, errors.Join(ErrRemoteCustody, err)
	}
	id, err := derived.ID()
	if err != nil || id != w.Plan.AssignmentID {
		return nil, errors.Join(ErrRemoteCustody, err)
	}
	intent, err := workarchive.LoadCustodyAuditIntent(config.Audit.IntentPath, config.Audit.IntentID)
	if err != nil {
		return nil, err
	}
	if err := validateRemoteAuditScope(scope, intent, config.Audit.Admission); err != nil {
		return nil, err
	}
	if len(config.AuthorityPrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrRemoteCustody
	}
	key := ed25519.NewKeyFromSeed(config.AuthorityPrivateKey[:ed25519.SeedSize])
	if !bytes.Equal(key, config.AuthorityPrivateKey) || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(a.AuthorityPublicKey[:])) {
		return nil, ErrRemoteCustody
	}
	controlPeer, err := transport.PeerIDFromPublicKey(w.Plan.AuthorityTransportPublicKey[:])
	if err != nil {
		return nil, err
	}
	auditorPeer, err := transport.PeerIDFromPublicKey(w.Plan.AuditorTransportPublicKey[:])
	if err != nil {
		return nil, err
	}
	replicaPeer, err := transport.PeerIDFromPublicKey(a.RemoteTransportPublicKey[:])
	if err != nil || replicaPeer != intent.ReplicaPeerID {
		return nil, errors.Join(ErrRemoteCustody, err)
	}
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, a, id)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, owner.Close())
		}
	}()
	if err := managedCustodyAuditRoots(owner, config.Audit.IntentPath, config.Audit.JournalPath, config.Audit.ArtifactsPath); err != nil {
		return nil, err
	}
	journal, _, err := workarchive.OpenExistingCustodyJournalWithLimits(ctx, config.Audit.JournalPath, scope.Manifest,
		scope.InitialReceipt, scope.CustodyPolicy, config.Audit.JournalLimits)
	if err != nil {
		return nil, err
	}
	cycle, err := workarchive.NewCustodyAuditCycle(ctx, journal, config.Audit.ArtifactsPath, intent, config.Audit.AuditorPrivateKey, config.Audit.SessionConfig)
	if err != nil {
		return nil, err
	}
	intentParent, err := filepath.EvalSymlinks(filepath.Dir(config.Audit.IntentPath))
	if err != nil {
		return nil, err
	}
	intentParent, err = filepath.Abs(intentParent)
	if err != nil {
		return nil, err
	}
	ticket, _ := config.Audit.Admission.ID()
	session := &ManagedCustodyAuditSession{coordinator: owner,
		binding:  OperationBinding{AssignmentID: id, TicketID: ticket, ConsumerPublicKey: intent.ConsumerPublicKey, OperationID: config.Audit.IntentID, Purpose: custodyauthority.Audit},
		intentID: config.Audit.IntentID, intentPath: filepath.Join(intentParent, filepath.Base(config.Audit.IntentPath)), journalPath: journal.Directory(),
		artifactsPath: cycle.ArtifactsDirectory(), cycle: cycle}
	if err := session.revalidate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtime := &RemoteCustodyAuditRuntime{life: newCustodyRuntimeLifetime(owner), scope: scope, intent: intent, admission: config.Audit.Admission, session: session, journal: journal,
		authorityKey: key, controlPeer: controlPeer, auditorPeer: auditorPeer, replicaPeer: replicaPeer, timeout: config.Audit.SessionConfig.RequestTimeout,
		sourceIdentity: make(map[string]os.FileInfo), journalLimits: config.Audit.JournalLimits}
	for _, path := range []string{session.journalPath, filepath.Join(session.journalPath, "journal.lock"), session.artifactsPath, filepath.Join(session.artifactsPath, "custody.lock")} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(ErrRemoteCustody, err)
		}
		runtime.sourceIdentity[path] = info
	}
	return runtime, runtime.checkSourceIdentity()
}

// Retain the original source and permanent lock inodes, including across waits
// for decisions. An identically encoded B copy is still a different A source.
func (runtime *RemoteCustodyAuditRuntime) checkSourceIdentity() error {
	for path, before := range runtime.sourceIdentity {
		now, err := os.Lstat(path)
		if err != nil || now.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, now) {
			return errors.Join(ErrRemoteCustody, err)
		}
	}
	return nil
}

// action owns the original coordinator, never a detached permission. Every
// callback is private, synchronous and must finish all transport cleanup before
// returning. Close cancels the run and waits before releasing that owner.
func (runtime *RemoteCustodyAuditRuntime) action(ctx context.Context, effect func(context.Context) error) error {
	if runtime == nil || runtime.life == nil {
		return ErrClosed
	}
	run, finish, err := runtime.life.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	owner := runtime.life.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := runtime.checkSourceIdentity(); err != nil {
		return err
	}
	if err := runtime.session.revalidate(); err != nil {
		return err
	}
	if err := run.Err(); err != nil {
		return err
	}
	if expected, ok := run.Value(remoteCustodyReviewKey{}).(types.Hash); ok {
		review, err := runtime.reviewLocked(run)
		if err != nil {
			return err
		}
		actual, err := review.ID()
		if err != nil || actual != expected {
			return errors.Join(ErrManagedCustodyReview, err)
		}
	}
	return errors.Join(effect(run), runtime.checkSourceIdentity())
}

// pendingTicketsLocked checks both exact admissions in the original owner. It
// is not exposed as a capability and does not authorize a generic callback.
func (runtime *RemoteCustodyAuditRuntime) pendingTicketsLocked(current Coordination) error {
	if current.Pending != nil {
		return ErrPendingAttempt
	}
	return runtime.pendingOperationsLocked(current)
}

func (runtime *RemoteCustodyAuditRuntime) pendingOperationsLocked(current Coordination) error {
	w := runtime.scope.Worker
	if current.Authority.AssignmentID != w.Plan.AssignmentID ||
		(current.Authority.Phase != custodyauthority.Accepting && current.Authority.Phase != custodyauthority.Stopping) {
		return ErrRemoteCustody
	}
	serveID, _ := w.Plan.Admission.ID()
	audit, serve := false, false
	for _, operation := range current.Authority.Operations {
		if operation.TicketID == runtime.session.binding.TicketID {
			audit = operation.Purpose == custodyauthority.Audit && operation.ConsumerPublicKey == runtime.session.binding.ConsumerPublicKey &&
				operation.OperationID == runtime.session.intentID && operation.CompletionID.IsZero() && operation.RemoteBeginID.IsZero()
		}
		if operation.TicketID == serveID {
			c := w.Plan.Admission.Command
			serve = operation.Purpose == custodyauthority.Serve && operation.ConsumerPublicKey == c.ActorPublicKey &&
				operation.OperationID == c.OperationID && operation.CompletionID.IsZero()
		}
	}
	if !audit || !serve {
		return custodyauthority.ErrOperation
	}
	return nil
}

// holdLocked is the only live exception for this exact remote Audit. Pending
// Begin/Drain attempts are insufficient even when the authority observed them.
func (runtime *RemoteCustodyAuditRuntime) holdLocked() (Coordination, error) {
	current, err := runtime.life.owner.snapshot()
	if err != nil {
		return Coordination{}, err
	}
	if err := runtime.pendingTicketsLocked(current); err != nil {
		return Coordination{}, err
	}
	w := runtime.scope.Worker
	serveID, _ := w.Plan.Admission.ID()
	r := current.Authority.Remote
	if r == nil || r.BeginEntryID != w.BeginID || r.PlanID != w.PlanID || r.TicketID != serveID ||
		r.ChallengeID != w.Plan.Admission.Command.OperationID || r.RemoteControlPublicKey != w.Assignment.RemoteControlPublicKey ||
		current.Confirmed.Sequence != w.Begin.Command.ExpectedSequence+1 || current.Confirmed.HeadID != w.BeginID {
		return Coordination{}, ErrRemoteCustody
	}
	for _, operation := range current.Authority.Operations {
		if operation.TicketID == serveID && (operation.RemoteBeginID != w.BeginID || operation.RemotePlanID != w.PlanID ||
			!operation.RemoteDrainID.IsZero() || !operation.RemoteTombstoneID.IsZero()) {
			return Coordination{}, ErrRemoteCustody
		}
	}
	return current, nil
}

func (runtime *RemoteCustodyAuditRuntime) preparedChallengeLocked() (workarchive.CustodyChallenge, error) {
	path := filepath.Join(runtime.session.artifactsPath, fmt.Sprintf("cycle-%020d", runtime.session.cycle.Intent().PriorSequence+1), "challenge.omcc")
	b, err := readRegular(path, workarchive.MaximumCustodyChallengeBytes)
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	challenge, err := workarchive.DecodeCustodyChallenge(b)
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	selected, _ := runtime.scope.Challenge.CanonicalBytes()
	if !bytes.Equal(b, selected) {
		return workarchive.CustodyChallenge{}, ErrRemoteCustody
	}
	return challenge, nil
}

// sourceLocked rejects unrelated or advanced A journals before enabling Start.
// The cycle independently acquires its own decision again for the actual audit;
// this observation is never retained as a permission or imported from B.
func (runtime *RemoteCustodyAuditRuntime) sourceLocked(accepted bool) (returnErr error) {
	if err := runtime.checkSourceIdentity(); err != nil {
		return err
	}
	decision, err := runtime.journal.AcquireDecision()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	if err := runtime.checkSourceIdentity(); err != nil {
		return err
	}
	state, err := decision.State()
	if err != nil {
		return err
	}
	w := runtime.scope.Worker
	receiptID, err := state.CurrentReceipt.ID()
	if err != nil {
		return err
	}
	if state.Sequence == w.Plan.PriorSequence && state.HeadEntryID == w.Plan.PriorHeadID && receiptID == w.Plan.PriorReceiptID {
		return nil
	}
	if !accepted || state.Sequence != w.Plan.PriorSequence+1 {
		return ErrRemoteCustody
	}
	head, exists, err := decision.Head()
	if err != nil || !exists || head.Verify(runtime.scope.Manifest, runtime.scope.CustodyPolicy,
		w.Plan.PriorSequence+1, w.Plan.PriorHeadID, runtime.scope.PreviousReceipt) != nil {
		return errors.Join(ErrRemoteCustody, err)
	}
	challengeID, err := head.Record.Challenge.ID()
	if err != nil || challengeID != w.Plan.Admission.Command.OperationID {
		return errors.Join(ErrRemoteCustody, err)
	}
	return nil
}

// PrepareChallenge is explicit and only usable before the configured remote
// ticket has ever begun. The independently pinned signed challenge is checked
// at Open, before this method may sign or publish anything.
func (runtime *RemoteCustodyAuditRuntime) PrepareChallenge(ctx context.Context) (challenge workarchive.CustodyChallenge, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) error {
		owner := runtime.life.owner
		if err := owner.checkOperation(runtime.session.binding); err != nil {
			return err
		}
		current, err := owner.snapshot()
		if err != nil {
			return err
		}
		if err := runtime.pendingTicketsLocked(current); err != nil {
			return err
		}
		serveID, _ := runtime.scope.Worker.Plan.Admission.ID()
		for _, operation := range current.Authority.Operations {
			if operation.TicketID == serveID && !operation.RemoteBeginID.IsZero() {
				return custodyauthority.ErrOperation
			}
		}
		if err := runtime.sourceLocked(false); err != nil {
			return err
		}
		challenge, err = runtime.session.cycle.PrepareChallenge(run)
		if err != nil {
			return err
		}
		id, err := challenge.ID()
		if err != nil || id != runtime.scope.Worker.Plan.Admission.Command.OperationID {
			return errors.Join(ErrRemoteCustody, err)
		}
		return nil
	})
	if err != nil {
		return workarchive.CustodyChallenge{}, err
	}
	return challenge, nil
}

// Begin submits only the pinned co-signed proposal. A retained attempt is not
// automatically resumed, and challenge preparation is never implicit.
func (runtime *RemoteCustodyAuditRuntime) Begin(ctx context.Context) (commit Commit, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) error {
		owner := runtime.life.owner
		current, err := owner.snapshot()
		if err != nil {
			return err
		}
		if err := runtime.pendingTicketsLocked(current); err != nil {
			return err
		}
		w := runtime.scope.Worker
		if current.Authority.Remote != nil {
			if _, err := runtime.holdLocked(); err != nil {
				return err
			}
		} else {
			if current.Confirmed.Sequence != w.Begin.Command.ExpectedSequence || current.Confirmed.HeadID != w.Begin.Command.ExpectedHead {
				return custodyauthority.ErrHead
			}
			serveID, _ := w.Plan.Admission.ID()
			for _, operation := range current.Authority.Operations {
				if operation.TicketID == serveID && !operation.RemoteBeginID.IsZero() {
					return custodyauthority.ErrOperation
				}
			}
			if err := runtime.sourceLocked(false); err != nil {
				return err
			}
		}
		if _, err := runtime.preparedChallengeLocked(); err != nil {
			return err
		}
		if err := runtime.sourceLocked(true); err != nil {
			return err
		}
		commit, err = owner.append(run, w.Begin)
		return err
	})
	return commit, err
}

// ResumeBegin confirms only the exact retained Begin. It cannot submit any
// other authority command or infer confirmation from an observed snapshot.
func (runtime *RemoteCustodyAuditRuntime) ResumeBegin(ctx context.Context) (commit Commit, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) error {
		owner := runtime.life.owner
		current, err := owner.snapshot()
		if err != nil {
			return err
		}
		if current.Pending == nil {
			return ErrNoAttempt
		}
		if *current.Pending != runtime.scope.Worker.Begin {
			return ErrPendingAttempt
		}
		commit, err = owner.resume(run)
		return err
	})
	return commit, err
}

func (runtime *RemoteCustodyAuditRuntime) controlRequest(kind remotewire.Kind) (remotewire.Request, error) {
	var nonce types.Hash
	if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
		return remotewire.Request{}, errors.Join(ErrRemoteCustody, err)
	}
	w := runtime.scope.Worker
	return remotewire.Request{Version: remotewire.Version0, Kind: kind, Nonce: nonce, Plan: w.Plan, Begin: w.Begin}, nil
}

// exchangeControl closes and drains its owned host before returning a reply.
// A complete metadata reply is separately checked against the pinned scope.
func (runtime *RemoteCustodyAuditRuntime) exchangeControl(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config,
	address string, kind remotewire.Kind,
) (response remotewire.Response, returnErr error) {
	if address == "" {
		return response, ErrRemoteCustody
	}
	ownedKey, err := pruneRuntimeKey(key, runtime.controlPeer)
	if err != nil {
		return response, err
	}
	request, err := runtime.controlRequest(kind)
	if err != nil {
		return response, err
	}
	host, err := newCustodyRuntimeHost(ctx, ownedKey, config)
	if err != nil {
		return response, err
	}
	defer func() {
		err := host.closeAndDrain()
		runtime.life.recordCleanup(err)
		returnErr = errors.Join(returnErr, err, ctx.Err())
		if returnErr != nil {
			response = remotewire.Response{}
		}
	}()
	stream, peer, err := host.host.OpenRemoteCustodyControlStream(ctx, address, runtime.replicaPeer)
	if err != nil {
		return response, err
	}
	if peer != runtime.replicaPeer {
		return response, errors.Join(ErrRemoteCustody, stream.Close())
	}
	timeout := runtime.timeout
	if timeout > remotewire.MaximumTimeout {
		timeout = remotewire.MaximumTimeout
	}
	response, err = remotewire.Exchange(ctx, stream, request, timeout)
	if err != nil {
		return remotewire.Response{}, err
	}
	if err := remotewire.ValidateResponse(runtime.scope.Worker.Assignment, request, response); err != nil {
		return remotewire.Response{}, err
	}
	if response.Status == remotewire.StatusDrained {
		if err := ValidateRemoteCustodyDrain(runtime.scope, response.Seal, response.Drain); err != nil {
			return remotewire.Response{}, err
		}
	}
	return response, nil
}

// ExecuteQUIC sends Start only after this original owner independently confirmed
// the exact Begin. It then audits on a distinct pinned auditor connection. An
// error preserves the durable obligation and never sends Seal or Complete.
func (runtime *RemoteCustodyAuditRuntime) ExecuteQUIC(ctx context.Context, controlKey, auditorKey ed25519.PrivateKey,
	config libp2ptransport.Config, address string,
) (result workarchive.CustodyAuditResult, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) (returnErr error) {
		if _, err := runtime.holdLocked(); err != nil {
			return err
		}
		if _, err := runtime.preparedChallengeLocked(); err != nil {
			return err
		}
		if err := runtime.sourceLocked(true); err != nil {
			return err
		}
		ownedAuditorKey, err := pruneRuntimeKey(auditorKey, runtime.auditorPeer)
		if err != nil {
			return err
		}
		// Validate both role keys before creating the first network host.
		if _, err := pruneRuntimeKey(controlKey, runtime.controlPeer); err != nil {
			return err
		}
		networkContext, cancel := context.WithTimeout(run, runtime.timeout)
		defer cancel()
		if err := runtime.hooks.reach("remote-audit-before-start"); err != nil {
			return err
		}
		response, err := runtime.exchangeControl(networkContext, controlKey, config, address, remotewire.Start)
		if err != nil {
			return err
		}
		if response.Status != remotewire.StatusStarted {
			return ErrRemoteCustody
		}
		if err := runtime.hooks.reach("remote-audit-start-confirmed"); err != nil {
			return err
		}
		host, err := newCustodyRuntimeHost(networkContext, ownedAuditorKey, config)
		if err != nil {
			return err
		}
		defer func() {
			err := host.closeAndDrain()
			runtime.life.recordCleanup(err)
			returnErr = errors.Join(returnErr, err, networkContext.Err())
		}()
		stream, peer, err := host.host.OpenArchiveCustodyStream(networkContext, address, runtime.replicaPeer)
		if err != nil {
			return err
		}
		if peer != runtime.replicaPeer {
			return errors.Join(ErrRemoteCustody, stream.Close())
		}
		var auditErr error
		result, auditErr = runtime.session.auditGuarded(networkContext, stream)
		return auditErr
	})
	if err != nil {
		return workarchive.CustodyAuditResult{}, err
	}
	return result, nil
}

// SealQUIC explicitly requests irreversible B sealing and verifies B's signed
// exact tombstone. Only after that exchange and client cleanup may A co-sign,
// append and independently confirm Drain. No proof or ordinary completion is
// inferred from Unseen, NoResult, RetainedResult or a successful drain.
func (runtime *RemoteCustodyAuditRuntime) SealQUIC(ctx context.Context, controlKey ed25519.PrivateKey,
	config libp2ptransport.Config, address string,
) (response remotewire.Response, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) error {
		if _, err := runtime.holdLocked(); err != nil {
			return err
		}
		networkContext, cancel := context.WithTimeout(run, runtime.timeout)
		defer cancel()
		var err error
		response, err = runtime.exchangeControl(networkContext, controlKey, config, address, remotewire.Seal)
		if err != nil {
			return err
		}
		if response.Status != remotewire.StatusDrained {
			return ErrRemoteCustody
		}
		entry, err := custodyauthority.SignEntry(response.Drain, runtime.authorityKey)
		if err != nil {
			return err
		}
		if err := runtime.hooks.reach("remote-audit-before-drain-append"); err != nil {
			return err
		}
		_, err = runtime.life.owner.append(run, entry)
		return err
	})
	if err != nil {
		return remotewire.Response{}, err
	}
	return response, nil
}

// ReconcileQUIC returns authenticated exact metadata without Start, signing,
// applying a drain, refreshing a proof or resubmitting an authority attempt.
func (runtime *RemoteCustodyAuditRuntime) ReconcileQUIC(ctx context.Context, controlKey ed25519.PrivateKey,
	config libp2ptransport.Config, address string,
) (response remotewire.Response, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) error {
		if err := runtime.metadataScopeLocked(); err != nil {
			return err
		}
		networkContext, cancel := context.WithTimeout(run, runtime.timeout)
		defer cancel()
		var err error
		response, err = runtime.exchangeControl(networkContext, controlKey, config, address, remotewire.Reconcile)
		return err
	})
	if err != nil {
		return remotewire.Response{}, err
	}
	return response, nil
}

// Historical metadata can recover a lost publication after Drain confirmation.
// It never enables work, signs, resumes or changes the original authority.
func (runtime *RemoteCustodyAuditRuntime) metadataScopeLocked() error {
	c, err := runtime.life.owner.snapshot()
	if err != nil {
		return err
	}
	w := runtime.scope.Worker
	if c.Confirmed.Sequence < w.Begin.Command.ExpectedSequence+1 {
		return ErrRemoteCustody
	}
	serveID, _ := w.Plan.Admission.ID()
	for _, op := range c.Authority.Operations {
		if op.TicketID == serveID && op.RemoteBeginID == w.BeginID && op.RemotePlanID == w.PlanID {
			if c.Authority.Remote != nil {
				if c.Authority.Remote.BeginEntryID != w.BeginID || c.Authority.Remote.PlanID != w.PlanID {
					return ErrRemoteCustody
				}
			} else if op.RemoteDrainID.IsZero() {
				return ErrRemoteCustody
			}
			return nil
		}
	}
	return ErrRemoteCustody
}

// ResumeDrainQUIC reconciles B's already sealed branch and confirms only the
// exact retained local Drain. It cannot Start, seal a different branch, replace
// an uncertain command, or treat B's metadata as accepted custody evidence.
func (runtime *RemoteCustodyAuditRuntime) ResumeDrainQUIC(ctx context.Context, controlKey ed25519.PrivateKey,
	config libp2ptransport.Config, address string,
) (response remotewire.Response, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) error {
		owner := runtime.life.owner
		current, err := owner.snapshot()
		if err != nil {
			return err
		}
		if current.Pending == nil {
			return ErrNoAttempt
		}
		if err := runtime.pendingOperationsLocked(current); err != nil {
			return err
		}
		w := runtime.scope.Worker
		c := current.Pending.Command
		serveID, _ := w.Plan.Admission.ID()
		if current.Pending.AuthorityPublicKey != w.Assignment.AuthorityPublicKey || c.Version != custodyauthority.Version1 ||
			c.Kind != custodyauthority.RemoteDrained || c.AssignmentID != w.Plan.AssignmentID || c.TicketID != serveID ||
			c.ActorPublicKey != w.Assignment.RemoteControlPublicKey || c.OperationID != w.BeginID ||
			c.ExpectedSequence != w.Begin.Command.ExpectedSequence+1 || c.ExpectedHead != w.BeginID ||
			current.Confirmed.Sequence != c.ExpectedSequence || current.Confirmed.HeadID != c.ExpectedHead {
			return ErrPendingAttempt
		}
		networkContext, cancel := context.WithTimeout(run, runtime.timeout)
		defer cancel()
		response, err = runtime.exchangeControl(networkContext, controlKey, config, address, remotewire.Reconcile)
		if err != nil {
			return err
		}
		if response.Status != remotewire.StatusDrained {
			return ErrRemoteCustody
		}
		entry, err := custodyauthority.SignEntry(response.Drain, runtime.authorityKey)
		if err != nil || entry != *current.Pending {
			return errors.Join(ErrPendingAttempt, err)
		}
		_, err = owner.resume(run)
		return err
	})
	if err != nil {
		return remotewire.Response{}, err
	}
	return response, nil
}

func (runtime *RemoteCustodyAuditRuntime) Close() error {
	if runtime == nil || runtime.life == nil {
		return nil
	}
	return runtime.life.close()
}
