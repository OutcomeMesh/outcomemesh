package store

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type ManagedCustodyTerminalCaptureServiceConfig struct {
	AuthorityPath, AuthorityPinsPath string
	Scope                            CustodyCommandScope
	Admission                        custodyauthority.Entry
	AdmissionID                      types.Hash
	IntentPath, AdmissionPath        string
	JournalPath                      string
	JournalLimits                    workarchive.CustodyJournalLimits
}

// ManagedCustodyCaptureReview describes only the exact current local terminal.
// A captured historical value never authorizes either ticket's completion.
type ManagedCustodyCaptureReview struct {
	ScopeID, AdmissionID, TerminalID       types.Hash
	AuthorityPosition                      custodyauthority.Position
	JournalSequence                        uint64
	JournalHeadID, CurrentReceiptID        types.Hash
	AuthorityPath, AuthorityPinsPath       string
	IntentPath, AdmissionPath, JournalPath string
	JournalLimits                          workarchive.CustodyJournalLimits
}

func (review ManagedCustodyCaptureReview) ID() (types.Hash, error) {
	if review.ScopeID.IsZero() || review.AdmissionID.IsZero() || review.TerminalID.IsZero() ||
		review.AuthorityPosition.HeadID.IsZero() || review.JournalHeadID.IsZero() || review.JournalSequence == 0 ||
		review.CurrentReceiptID.IsZero() || review.JournalLimits.Validate() != nil {
		return types.Hash{}, ErrManagedCustodyReview
	}
	e := codec.NewEncoder(2048)
	for _, id := range []types.Hash{review.ScopeID, review.AdmissionID, review.TerminalID, review.AuthorityPosition.HeadID,
		review.JournalHeadID, review.CurrentReceiptID} {
		e.Fixed(id[:])
	}
	e.U64(review.AuthorityPosition.Sequence)
	e.U64(review.JournalSequence)
	e.U64(review.JournalLimits.MaximumBytes)
	e.U64(review.JournalLimits.MaximumPaths)
	for _, path := range []string{review.AuthorityPath, review.AuthorityPinsPath, review.IntentPath, review.AdmissionPath, review.JournalPath} {
		if path == "" || len(path) > 32<<10 {
			return types.Hash{}, ErrManagedCustodyReview
		}
		e.BytesField([]byte(path))
	}
	return types.DomainHash("OMESH/local/custody-terminal-capture-review/v0", e.Bytes()), nil
}

type ManagedCustodyTerminalCaptureService struct {
	life        *custodyRuntimeLifetime
	source      *managedCustodyCommandSource
	admission   custodyauthority.Entry
	admissionID types.Hash
	hooks       storeHooks
}

func OpenManagedCustodyTerminalCaptureService(ctx context.Context, config ManagedCustodyTerminalCaptureServiceConfig) (_ *ManagedCustodyTerminalCaptureService, returnErr error) {
	if ctx == nil {
		return nil, ErrManagedCustodyCommand
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scope, err := cloneCustodyCommandScope(config.Scope)
	if err != nil {
		return nil, err
	}
	id, err := config.Admission.ID()
	if err != nil || config.AdmissionID.IsZero() || id != config.AdmissionID || config.Admission.Command.Kind != custodyauthority.Admit ||
		config.Admission.Command.AssignmentID != scope.AssignmentID || config.Admission.AuthorityPublicKey != scope.Assignment.AuthorityPublicKey {
		return nil, errors.Join(ErrManagedCustodyCommand, err)
	}
	b, err := config.Admission.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, scope.Assignment, scope.AssignmentID)
	if err != nil {
		return nil, err
	}
	service := &ManagedCustodyTerminalCaptureService{life: newCustodyRuntimeLifetime(owner), admission: config.Admission, admissionID: id}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, service.Close())
		}
	}()
	service.source, err = openManagedCustodyCommandSource(ctx, owner, scope, config.IntentPath, config.JournalPath, config.JournalLimits,
		[]managedCustodyCommandArtifact{{path: config.AdmissionPath, bytes: b, maximum: custodyauthority.MaximumEntryBytes}})
	if err != nil {
		return nil, err
	}
	if _, err := service.Review(ctx); err != nil {
		return nil, err
	}
	return service, nil
}

func (service *ManagedCustodyTerminalCaptureService) Review(ctx context.Context) (review ManagedCustodyCaptureReview, returnErr error) {
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
		review, _, err = service.reviewLocked(run, decision)
		return err
	})
	if err != nil {
		return ManagedCustodyCaptureReview{}, err
	}
	return review, nil
}

func (service *ManagedCustodyTerminalCaptureService) reviewLocked(ctx context.Context, decision *workarchive.CustodyJournalDecision) (ManagedCustodyCaptureReview, CustodyTerminal, error) {
	owner := service.life.owner
	if err := owner.checkOperation(custodyAdmissionBinding(service.source.scope, service.admission)); err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	if err := retainedCustodyCommand(owner, service.admission, true); err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	terminal, err := captureCustodyTerminalLocked(ctx, service.source.scope, service.admission, decision)
	if err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	current, err := owner.snapshot()
	if err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	state, err := decision.State()
	if err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	receiptID, err := state.CurrentReceipt.ID()
	if err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	terminalID, err := terminal.ID()
	if err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	review := ManagedCustodyCaptureReview{ScopeID: service.source.scopeID, AdmissionID: service.admissionID, TerminalID: terminalID,
		AuthorityPosition: current.Confirmed, JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID, CurrentReceiptID: receiptID,
		AuthorityPath: owner.authority.path, AuthorityPinsPath: owner.journal.path, IntentPath: service.source.artifacts[0].path,
		AdmissionPath: service.source.artifacts[1].path, JournalPath: service.source.journal.Directory(), JournalLimits: service.source.limits}
	if err := ctx.Err(); err != nil {
		return ManagedCustodyCaptureReview{}, CustodyTerminal{}, err
	}
	return review, terminal, nil
}

// Capture returns a detached historical value at a checked point in time. For
// durable publication under both original guards, use CaptureToFile instead.
func (service *ManagedCustodyTerminalCaptureService) Capture(ctx context.Context, expectedReviewID types.Hash) (CustodyTerminal, error) {
	return service.capture(ctx, expectedReviewID, "")
}

// CaptureToFile publishes no-replace bytes and fsyncs them BEFORE releasing the
// original coordinator and active source decision. The output path is selected
// and reported by the caller's review flow; it cannot name a writer/source root.
func (service *ManagedCustodyTerminalCaptureService) CaptureToFile(ctx context.Context, expectedReviewID types.Hash, path string) (CustodyTerminal, error) {
	if path == "" {
		return CustodyTerminal{}, ErrManagedCustodyCommand
	}
	return service.capture(ctx, expectedReviewID, path)
}

func (service *ManagedCustodyTerminalCaptureService) capture(ctx context.Context, expectedReviewID types.Hash, path string) (terminal CustodyTerminal, returnErr error) {
	if service == nil || service.life == nil {
		return terminal, ErrClosed
	}
	if expectedReviewID.IsZero() {
		return terminal, ErrManagedCustodyReview
	}
	run, finish, err := service.life.begin(ctx)
	if err != nil {
		return terminal, err
	}
	defer finish()
	owner := service.life.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	err = service.source.withDecision(run, service.life, func(decision *workarchive.CustodyJournalDecision) error {
		review, captured, err := service.reviewLocked(run, decision)
		if err != nil {
			return err
		}
		id, err := review.ID()
		if err != nil || id != expectedReviewID {
			return errors.Join(ErrManagedCustodyReview, err)
		}
		if path != "" {
			output, err := storePath(path)
			if err != nil {
				return err
			}
			parent, err := filepath.EvalSymlinks(filepath.Dir(output))
			if err != nil {
				return err
			}
			output = filepath.Join(parent, filepath.Base(output))
			for _, root := range []string{owner.authority.path, owner.journal.path, service.source.journal.Directory()} {
				if workarchive.CustodyEvidencePathsOverlap(root, output) {
					return ErrManagedCustodyCommand
				}
			}
			if err := service.hooks.reach("capture-before-publish"); err != nil {
				return err
			}
			if err := PublishCustodyTerminalFile(run, output, captured); err != nil {
				return err
			}
			if err := service.hooks.reach("capture-after-publish"); err != nil {
				return err
			}
		} else if err := run.Err(); err != nil {
			return err
		}
		// The decoder detaches every slice from the private source snapshot.
		b, err := captured.CanonicalBytes()
		if err != nil {
			return err
		}
		terminal, err = DecodeCustodyTerminal(b)
		return err
	})
	if err != nil {
		return CustodyTerminal{}, err
	}
	return terminal, nil
}

func (service *ManagedCustodyTerminalCaptureService) Close() error {
	if service == nil || service.life == nil {
		return nil
	}
	return service.life.close()
}
