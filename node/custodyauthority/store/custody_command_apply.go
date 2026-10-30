package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var ErrManagedCustodyCommand = errors.New("owned custody command does not match its selected local evidence")

// ManagedCustodyCommandServiceConfig selects one already signed entry. Open
// acquires only the existing original owner; it creates, signs and resumes
// nothing. Paths name bounded canonical artifacts, not alternate owners.
type ManagedCustodyCommandServiceConfig struct {
	AuthorityPath, AuthorityPinsPath string
	Scope                            CustodyCommandScope
	Entry                            custodyauthority.Entry
	EntryID                          types.Hash
	JournalPath                      string
	JournalLimits                    workarchive.CustodyJournalLimits
	Challenge                        workarchive.CustodyChallenge
	Terminal                         CustodyTerminal
	IntentPath, EntryPath            string
	ChallengePath, TerminalPath      string
}

// ManagedCustodyCommandReview is a detached local comparison, never a grant.
// AlreadyApplied means exact retained history; its current position may include
// later commands. Pending requires a separate explicit Resume of the same entry.
type ManagedCustodyCommandReview struct {
	ScopeID, EntryID                 types.Hash
	AuthorityPosition                custodyauthority.Position
	ObservedAuthorityPosition        custodyauthority.Position
	Pending                          bool
	PendingEntryID                   types.Hash
	AlreadyApplied                   bool
	JournalSequence                  uint64
	JournalHeadID, CurrentReceiptID  types.Hash
	AuthorityPath, AuthorityPinsPath string
	IntentPath, EntryPath            string
	ChallengePath, TerminalPath      string
	JournalPath                      string
	JournalLimits                    workarchive.CustodyJournalLimits
}

func (review ManagedCustodyCommandReview) ID() (types.Hash, error) {
	if review.ScopeID.IsZero() || review.EntryID.IsZero() || review.AuthorityPosition.HeadID.IsZero() || review.ObservedAuthorityPosition.HeadID.IsZero() ||
		review.CurrentReceiptID.IsZero() || review.JournalLimits.Validate() != nil || review.Pending != !review.PendingEntryID.IsZero() {
		return types.Hash{}, ErrManagedCustodyReview
	}
	e := codec.NewEncoder(2048)
	for _, id := range []types.Hash{review.ScopeID, review.EntryID, review.AuthorityPosition.HeadID, review.ObservedAuthorityPosition.HeadID,
		review.PendingEntryID, review.JournalHeadID, review.CurrentReceiptID} {
		e.Fixed(id[:])
	}
	e.U64(review.AuthorityPosition.Sequence)
	e.U64(review.ObservedAuthorityPosition.Sequence)
	e.U64(review.JournalSequence)
	flags := uint16(0)
	if review.Pending {
		flags |= 1
	}
	if review.AlreadyApplied {
		flags |= 2
	}
	e.U16(flags)
	e.U64(review.JournalLimits.MaximumBytes)
	e.U64(review.JournalLimits.MaximumPaths)
	for index, path := range []string{review.AuthorityPath, review.AuthorityPinsPath, review.IntentPath, review.EntryPath,
		review.JournalPath, review.ChallengePath, review.TerminalPath} {
		if (index < 5 && path == "") || len(path) > 32<<10 {
			return types.Hash{}, ErrManagedCustodyReview
		}
		e.BytesField([]byte(path))
	}
	return types.DomainHash("OMESH/local/custody-command-apply-review/v0", e.Bytes()), nil
}

// ManagedCustodyCommandService owns one original coordinator for its lifetime.
// Each action locks that owner before the active source journal and holds both
// through authority append AND intent confirmation. No capability escapes.
type ManagedCustodyCommandService struct {
	life                                   *custodyRuntimeLifetime
	source                                 *managedCustodyCommandSource
	entry                                  custodyauthority.Entry
	entryID                                types.Hash
	challenge                              workarchive.CustodyChallenge
	terminal                               CustodyTerminal
	entryPath, challengePath, terminalPath string
	hooks                                  storeHooks
	remoteAdmission                        bool
}

func OpenManagedCustodyCommandService(ctx context.Context, config ManagedCustodyCommandServiceConfig) (_ *ManagedCustodyCommandService, returnErr error) {
	return openManagedCustodyCommandService(ctx, config, false)
}

// OpenRemoteCustodyAdmissionService is V1 admission-only preparation under the
// original A owner and source. It cannot apply Begin, Drain or Complete and does
// not widen the V0 constructor. Execution remains a separate owned protocol.
func OpenRemoteCustodyAdmissionService(ctx context.Context, config ManagedCustodyCommandServiceConfig) (*ManagedCustodyCommandService, error) {
	if config.Entry.Command.Kind != custodyauthority.Admit {
		return nil, ErrManagedCustodyCommand
	}
	return openManagedCustodyCommandService(ctx, config, true)
}

func openManagedCustodyCommandService(ctx context.Context, config ManagedCustodyCommandServiceConfig, remote bool) (_ *ManagedCustodyCommandService, returnErr error) {
	if ctx == nil {
		return nil, ErrManagedCustodyCommand
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	version := custodyauthority.Version0
	if remote {
		version = custodyauthority.Version1
	}
	scope, err := cloneCustodyCommandScopeVersion(config.Scope, version)
	if err != nil {
		return nil, err
	}
	entryID, err := config.Entry.ID()
	if err != nil || config.EntryID.IsZero() || entryID != config.EntryID ||
		config.Entry.Command.AssignmentID != scope.AssignmentID || config.Entry.AuthorityPublicKey != scope.Assignment.AuthorityPublicKey {
		return nil, errors.Join(ErrManagedCustodyCommand, err)
	}
	service := &ManagedCustodyCommandService{entry: config.Entry, entryID: entryID, remoteAdmission: remote}
	entryBytes, err := config.Entry.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	artifacts := []managedCustodyCommandArtifact{{path: config.EntryPath, bytes: entryBytes, maximum: custodyauthority.MaximumEntryBytes}}
	c := config.Entry.Command
	position := custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead}
	var draft custodyauthority.Command
	switch c.Kind {
	case custodyauthority.Admit:
		if config.TerminalPath != "" || !reflect.DeepEqual(config.Terminal, CustodyTerminal{}) {
			return nil, ErrManagedCustodyCommand
		}
		if c.Purpose == custodyauthority.Serve {
			b, encodeErr := config.Challenge.CanonicalBytes()
			if encodeErr != nil {
				return nil, encodeErr
			}
			service.challenge, err = workarchive.DecodeCustodyChallenge(b)
			if err != nil {
				return nil, err
			}
			artifacts = append(artifacts, managedCustodyCommandArtifact{path: config.ChallengePath, bytes: b, maximum: workarchive.MaximumCustodyChallengeBytes})
		} else if config.ChallengePath != "" || !emptyCustodyChallenge(config.Challenge) {
			return nil, ErrManagedCustodyCommand
		}
		if remote {
			draft, err = BuildRemoteCustodyAdmitCommand(scope, c.Purpose, c.ActorPublicKey, position, service.challenge)
		} else {
			draft, err = BuildCustodyAdmitCommand(scope, c.Purpose, c.ActorPublicKey, position, service.challenge)
		}
	case custodyauthority.Complete:
		if config.ChallengePath != "" || !emptyCustodyChallenge(config.Challenge) {
			return nil, ErrManagedCustodyCommand
		}
		b, encodeErr := config.Terminal.CanonicalBytes()
		if encodeErr != nil {
			return nil, encodeErr
		}
		service.terminal, err = DecodeCustodyTerminal(b)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, managedCustodyCommandArtifact{path: config.TerminalPath, bytes: b, maximum: MaximumCustodyTerminalBytes})
		draft, err = BuildCustodyCompleteCommand(scope, service.terminal.Admission, service.terminal, position)
	default:
		return nil, ErrManagedCustodyCommand
	}
	if err != nil {
		return nil, err
	}
	draft.Signature = c.Signature
	if draft != c {
		return nil, ErrManagedCustodyCommand
	}
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, scope.Assignment, scope.AssignmentID)
	if err != nil {
		return nil, err
	}
	service.life = newCustodyRuntimeLifetime(owner)
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, service.Close())
		}
	}()
	service.source, err = openManagedCustodyCommandSource(ctx, owner, scope, config.IntentPath, config.JournalPath, config.JournalLimits, artifacts)
	if err != nil {
		return nil, err
	}
	service.entryPath = service.source.artifacts[1].path
	for _, artifact := range service.source.artifacts[2:] {
		if c.Kind == custodyauthority.Complete {
			service.terminalPath = artifact.path
		} else {
			service.challengePath = artifact.path
		}
	}
	if _, err := service.Review(ctx); err != nil {
		return nil, err
	}
	return service, nil
}

func (service *ManagedCustodyCommandService) Review(ctx context.Context) (review ManagedCustodyCommandReview, returnErr error) {
	if service == nil || service.life == nil {
		return review, ErrClosed
	}
	run, finish, err := service.life.begin(ctx)
	if err != nil {
		return review, err
	}
	defer finish()
	owner := service.life.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	err = service.source.withDecision(run, service.life, func(decision *workarchive.CustodyJournalDecision) error {
		var err error
		review, err = service.reviewLocked(run, decision)
		return err
	})
	if err != nil {
		return ManagedCustodyCommandReview{}, err
	}
	return review, nil
}

func (service *ManagedCustodyCommandService) reviewLocked(ctx context.Context, decision *workarchive.CustodyJournalDecision) (ManagedCustodyCommandReview, error) {
	current, err := service.life.owner.snapshot()
	if err != nil {
		return ManagedCustodyCommandReview{}, err
	}
	already, err := service.validateSelectedLocked(current)
	if err != nil {
		return ManagedCustodyCommandReview{}, err
	}
	if err := service.validateSourceLocked(ctx, decision); err != nil {
		return ManagedCustodyCommandReview{}, err
	}
	state, err := decision.State()
	if err != nil {
		return ManagedCustodyCommandReview{}, err
	}
	receiptID, err := state.CurrentReceipt.ID()
	if err != nil {
		return ManagedCustodyCommandReview{}, err
	}
	review := ManagedCustodyCommandReview{ScopeID: service.source.scopeID, EntryID: service.entryID, AuthorityPosition: current.Confirmed,
		ObservedAuthorityPosition: custodyauthority.Position{Sequence: current.Authority.Sequence, HeadID: current.Authority.HeadID},
		AlreadyApplied:            already, JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID, CurrentReceiptID: receiptID,
		AuthorityPath: service.life.owner.authority.path, AuthorityPinsPath: service.life.owner.journal.path,
		IntentPath: service.source.artifacts[0].path, EntryPath: service.entryPath, ChallengePath: service.challengePath,
		TerminalPath: service.terminalPath, JournalPath: service.source.journal.Directory(), JournalLimits: service.source.limits}
	if current.Pending != nil {
		review.Pending = true
		review.PendingEntryID, err = current.Pending.ID()
		if err != nil {
			return ManagedCustodyCommandReview{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return ManagedCustodyCommandReview{}, err
	}
	return review, nil
}

// validateSelectedLocked compares exact history without append/resume. A
// selected pending attempt is observable but only Resume may submit it.
func (service *ManagedCustodyCommandService) validateSelectedLocked(current Coordination) (bool, error) {
	owner, entry := service.life.owner, service.entry
	if service.remoteAdmission && current.Authority.Remote != nil {
		return false, ErrRemoteCustody
	}
	if current.Pending != nil {
		return false, nil
	}
	if entry.Command.ExpectedSequence < current.Confirmed.Sequence {
		if err := retainedCustodyCommand(owner, entry, true); err != nil {
			return false, err
		}
		return true, nil
	}
	if entry.Command.ExpectedSequence != current.Confirmed.Sequence || entry.Command.ExpectedHead != current.Confirmed.HeadID {
		return false, custodyauthority.ErrHead
	}
	if entry.Command.Kind == custodyauthority.Complete {
		if err := owner.checkOperation(custodyAdmissionBinding(service.source.scope, service.terminal.Admission)); err != nil {
			return false, err
		}
		if err := retainedCustodyCommand(owner, service.terminal.Admission, false); err != nil {
			return false, err
		}
	}
	owner.authority.mu.Lock()
	defer owner.authority.mu.Unlock()
	if err := owner.authority.check(); err != nil {
		return false, err
	}
	return false, owner.authority.state.ValidateNext(entry)
}

func (service *ManagedCustodyCommandService) validateSourceLocked(ctx context.Context, decision *workarchive.CustodyJournalDecision) error {
	if service.entry.Command.Kind == custodyauthority.Complete {
		return validateCustodyTerminalDecision(ctx, service.source.scope, service.terminal, decision)
	}
	state, err := decision.State()
	if err != nil {
		return err
	}
	intent := service.source.scope.Intent
	receiptID, err := state.CurrentReceipt.ID()
	if err != nil || state.InitialReceipt != service.source.scope.InitialReceipt || state.CurrentReceipt != service.source.scope.PreviousReceipt ||
		state.Sequence != intent.PriorSequence || state.HeadEntryID != intent.PriorHeadID || receiptID != intent.PriorReceiptID {
		return errors.Join(ErrManagedCustodyCommand, err)
	}
	return nil
}

func (service *ManagedCustodyCommandService) Apply(ctx context.Context, expectedReviewID types.Hash) (Commit, error) {
	return service.apply(ctx, expectedReviewID, false)
}

// Resume is an explicit retry of the exact retained pending entry. Neither
// Open, Review nor Apply enters this recovery path, including on lost output.
func (service *ManagedCustodyCommandService) Resume(ctx context.Context, expectedReviewID types.Hash) (Commit, error) {
	return service.apply(ctx, expectedReviewID, true)
}

func (service *ManagedCustodyCommandService) apply(ctx context.Context, expectedReviewID types.Hash, resume bool) (result Commit, returnErr error) {
	if service == nil || service.life == nil {
		return result, ErrClosed
	}
	if expectedReviewID.IsZero() {
		return result, ErrManagedCustodyReview
	}
	run, finish, err := service.life.begin(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	owner := service.life.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	err = service.source.withDecision(run, service.life, func(decision *workarchive.CustodyJournalDecision) error {
		review, err := service.reviewLocked(run, decision)
		if err != nil {
			return err
		}
		id, err := review.ID()
		if err != nil || id != expectedReviewID {
			return errors.Join(ErrManagedCustodyReview, err)
		}
		if resume {
			if !review.Pending {
				return ErrNoAttempt
			}
			if review.PendingEntryID != service.entryID || owner.journal.pending == nil || *owner.journal.pending != service.entry {
				return ErrPendingAttempt
			}
			if err := service.validateResumeLocked(); err != nil {
				return err
			}
		} else if review.Pending {
			// Coordinator.append intentionally resumes an equal pending entry;
			// this public surface requires the separately reviewed Resume verb.
			return ErrPendingAttempt
		}
		if err := service.hooks.reach("command-before-append"); err != nil {
			return err
		}
		if err := run.Err(); err != nil {
			return err
		}
		if resume {
			result, err = owner.resume(run)
		} else {
			result, err = owner.append(run, service.entry)
		}
		if service.remoteAdmission {
			return errors.Join(err, service.source.validate())
		}
		return err
	})
	if err != nil {
		return Commit{}, err
	}
	return result, nil
}

func (service *ManagedCustodyCommandService) validateResumeLocked() error {
	owner := service.life.owner
	current, err := owner.snapshot()
	if err != nil {
		return err
	}
	entry := service.entry
	if entry.Command.ExpectedSequence != current.Confirmed.Sequence || entry.Command.ExpectedHead != current.Confirmed.HeadID {
		return custodyauthority.ErrHead
	}
	if current.Authority.Sequence == current.Confirmed.Sequence {
		if entry.Command.Kind == custodyauthority.Complete {
			if err := validateCustodyOperationSnapshot(current.Authority, custodyAdmissionBinding(service.source.scope, service.terminal.Admission)); err != nil {
				return err
			}
			if err := retainedCustodyCommand(owner, service.terminal.Admission, false); err != nil {
				return err
			}
		}
		owner.authority.mu.Lock()
		defer owner.authority.mu.Unlock()
		if err := owner.authority.check(); err != nil {
			return err
		}
		return owner.authority.state.ValidateNext(entry)
	}
	if current.Authority.Sequence != current.Confirmed.Sequence+1 || current.Authority.HeadID != service.entryID {
		return custodyauthority.ErrHead
	}
	// The exact attempted entry already exists; only its independent intent
	// confirmation remains. It confers no new execution permission.
	return retainedCustodyCommand(owner, entry, false)
}

func (service *ManagedCustodyCommandService) Close() error {
	if service == nil || service.life == nil {
		return nil
	}
	return service.life.close()
}

func retainedCustodyCommand(owner *Coordinator, entry custodyauthority.Entry, includeIntent bool) error {
	want, err := entry.CanonicalBytes()
	if err != nil {
		return err
	}
	paths := []string{filepath.Join(owner.authority.path, entriesName, entryName(entry.Command.ExpectedSequence+1))}
	if includeIntent {
		paths = append(paths, filepath.Join(owner.journal.path, intentsName, entryName(entry.Command.ExpectedSequence+1)))
	}
	for _, path := range paths {
		got, err := readRegular(path, custodyauthority.MaximumEntryBytes)
		if err != nil || !bytes.Equal(want, got) {
			return errors.Join(custodyauthority.ErrHead, err)
		}
	}
	return nil
}

func custodyAdmissionBinding(scope CustodyCommandScope, admission custodyauthority.Entry) OperationBinding {
	ticket, _ := admission.ID() // callers validate canonical admission first
	c := admission.Command
	return OperationBinding{AssignmentID: scope.AssignmentID, TicketID: ticket, ConsumerPublicKey: c.ActorPublicKey,
		OperationID: c.OperationID, Purpose: c.Purpose, ScheduleID: scope.scheduleID()}
}

func validateCustodyOperationSnapshot(snapshot custodyauthority.Snapshot, binding OperationBinding) error {
	if snapshot.AssignmentID != binding.AssignmentID || snapshot.ScheduleID != binding.ScheduleID {
		return custodyauthority.ErrAssignment
	}
	if snapshot.Phase != custodyauthority.Accepting && snapshot.Phase != custodyauthority.Stopping {
		return custodyauthority.ErrPhase
	}
	for _, operation := range snapshot.Operations {
		if operation.TicketID == binding.TicketID {
			if operation.ConsumerPublicKey == binding.ConsumerPublicKey && operation.OperationID == binding.OperationID &&
				operation.Purpose == binding.Purpose && operation.CompletionID.IsZero() {
				return nil
			}
			break
		}
	}
	return custodyauthority.ErrOperation
}

type managedCustodyCommandArtifact struct {
	path    string
	bytes   []byte
	maximum int
}

type managedCustodyCommandSource struct {
	scope      CustodyCommandScope
	scopeID    types.Hash
	journal    *workarchive.CustodyJournal
	limits     workarchive.CustodyJournalLimits
	artifacts  []managedCustodyCommandArtifact
	identities map[string]os.FileInfo
}

func cloneCustodyCommandScope(scope CustodyCommandScope) (CustodyCommandScope, error) {
	return cloneCustodyCommandScopeVersion(scope, custodyauthority.Version0)
}

func cloneCustodyCommandScopeVersion(scope CustodyCommandScope, version uint16) (CustodyCommandScope, error) {
	if err := validateCustodyCommandScopeVersion(scope, version); err != nil {
		return CustodyCommandScope{}, err
	}
	b, err := scope.Assignment.CanonicalBytes()
	if err != nil {
		return CustodyCommandScope{}, err
	}
	scope.Assignment, err = custodyauthority.DecodeAssignment(b)
	if err != nil {
		return CustodyCommandScope{}, err
	}
	b, err = scope.Manifest.CanonicalBytes()
	if err != nil {
		return CustodyCommandScope{}, err
	}
	scope.Manifest, err = workarchive.DecodeManifest(b)
	if err != nil {
		return CustodyCommandScope{}, err
	}
	scope.Schedule, _, err = scope.Schedule.detached()
	if err != nil {
		return CustodyCommandScope{}, err
	}
	scope.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), scope.CustodyPolicy.TrustedAuditors...)
	return scope, nil
}

func openManagedCustodyCommandSource(ctx context.Context, owner *Coordinator, scope CustodyCommandScope, intentPath, journalPath string,
	limits workarchive.CustodyJournalLimits, artifacts []managedCustodyCommandArtifact) (*managedCustodyCommandSource, error) {
	if limits.Validate() != nil || journalPath == "" {
		return nil, ErrManagedCustodyCommand
	}
	for _, root := range []string{owner.authority.path, owner.journal.path} {
		if _, _, err := coordinatorPaths(root, journalPath); err != nil {
			return nil, err
		}
	}
	journal, _, err := openManagedCustodyJournal(ctx, journalPath, scope.Manifest, scope.InitialReceipt, scope.CustodyPolicy, limits, scope.Schedule, scope.Assignment)
	if err != nil {
		return nil, err
	}
	intentBytes, err := scope.Intent.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	source := &managedCustodyCommandSource{scope: scope, journal: journal, limits: limits, identities: make(map[string]os.FileInfo)}
	source.artifacts = append([]managedCustodyCommandArtifact{{path: intentPath, bytes: intentBytes, maximum: workarchive.MaximumCustodyAuditIntentBytes}}, artifacts...)
	for index := range source.artifacts {
		artifact := &source.artifacts[index]
		path, err := storePath(artifact.path)
		if err != nil {
			return nil, err
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		artifact.path = filepath.Join(parent, filepath.Base(path))
		for _, root := range []string{owner.authority.path, owner.journal.path, journal.Directory()} {
			if workarchive.CustodyEvidencePathsOverlap(root, artifact.path) {
				return nil, ErrManagedCustodyCommand
			}
		}
		artifact.bytes = append([]byte(nil), artifact.bytes...)
		if err := source.retainIdentity(parent, true); err != nil {
			return nil, err
		}
	}
	if err := source.retainIdentity(journal.Directory(), true); err != nil {
		return nil, err
	}
	if err := source.retainIdentity(filepath.Join(journal.Directory(), "journal.lock"), false); err != nil {
		return nil, err
	}
	intentID, _ := scope.Intent.ID()
	previousID, _ := scope.PreviousReceipt.ID()
	e := codec.NewEncoder(128)
	for _, id := range []types.Hash{scope.AssignmentID, intentID, previousID} {
		e.Fixed(id[:])
	}
	domain := "OMESH/local/custody-command-scope/v0"
	if scope.Schedule != nil {
		id := scope.scheduleID()
		e.Fixed(id[:])
		domain = "OMESH/local/custody-command-scope/v1"
	}
	source.scopeID = types.DomainHash(domain, e.Bytes())
	if err := source.validate(); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *managedCustodyCommandSource) retainIdentity(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.Join(ErrManagedCustodyCommand, err)
	}
	source.identities[path] = info
	return nil
}

func (source *managedCustodyCommandSource) validate() error {
	for path, before := range source.identities {
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, current) || current.Mode()&os.ModeSymlink != 0 {
			return errors.Join(ErrManagedCustodyCommand, err)
		}
	}
	for _, artifact := range source.artifacts {
		got, err := readRegular(artifact.path, artifact.maximum)
		if err != nil || !bytes.Equal(got, artifact.bytes) {
			return errors.Join(ErrManagedCustodyCommand, err)
		}
	}
	return nil
}

func (source *managedCustodyCommandSource) withDecision(ctx context.Context, life *custodyRuntimeLifetime,
	action func(*workarchive.CustodyJournalDecision) error) (returnErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := source.validate(); err != nil {
		return err
	}
	decision, err := source.journal.AcquireDecision()
	if err != nil {
		return err
	}
	defer func() {
		closeErr := decision.Close()
		life.recordCleanup(closeErr)
		returnErr = errors.Join(returnErr, closeErr)
	}()
	if err := source.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return action(decision)
}
