package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type RemoteCustodyChallengeConfig struct {
	Admission     ManagedCustodyCommandServiceConfig
	ArtifactsPath string
	SessionConfig workarchive.CustodySessionConfig
}

type RemoteCustodyChallengeReview struct {
	Admission                    ManagedCustodyCommandReview
	ArtifactsPath, ChallengePath string
}

func (r RemoteCustodyChallengeReview) ID() (types.Hash, error) {
	base, err := r.Admission.ID()
	if err != nil || r.ArtifactsPath == "" || r.ChallengePath == "" {
		return types.Hash{}, errors.Join(ErrManagedCustodyReview, err)
	}
	return types.DomainHash("OMESH/local/remote-custody-challenge-review/v0", base[:], []byte(r.ArtifactsPath), []byte{0}, []byte(r.ChallengePath)), nil
}

// RemoteCustodyChallengeService owns only the pre-Begin preparation boundary.
// Review loads no seed and creates no cycle files. Prepare requires an already
// confirmed pending Audit and retains original authority/artifact/source guards.
type RemoteCustodyChallengeService struct {
	admission *ManagedCustodyCommandService
	artifacts string
	config    workarchive.CustodySessionConfig
}

func OpenRemoteCustodyChallengeService(ctx context.Context, config RemoteCustodyChallengeConfig) (_ *RemoteCustodyChallengeService, returnErr error) {
	if config.Admission.Entry.Command.Purpose != custodyauthority.Audit || config.SessionConfig.Validate() != nil {
		return nil, ErrRemoteCustody
	}
	s, err := OpenRemoteCustodyAdmissionService(ctx, config.Admission)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, s.Close())
		}
	}()
	if err := managedCustodyAuditRoots(s.life.owner, s.source.artifacts[0].path, s.source.journal.Directory(), config.ArtifactsPath); err != nil {
		return nil, err
	}
	artifacts, err := filepath.EvalSymlinks(config.ArtifactsPath)
	if err != nil {
		return nil, err
	}
	artifacts, err = filepath.Abs(artifacts)
	if err != nil {
		return nil, err
	}
	if err := ValidateBootstrapPaths(artifacts, filepath.Dir(s.entryPath)); err != nil {
		return nil, err
	}
	lock, err := workarchive.OpenExistingCustodyArtifacts(ctx, artifacts)
	if err != nil {
		return nil, err
	}
	if err := lock.Close(); err != nil {
		return nil, err
	}
	for _, path := range []struct {
		path      string
		directory bool
	}{{artifacts, true}, {filepath.Join(artifacts, "custody.lock"), false}} {
		if err := s.source.retainIdentity(path.path, path.directory); err != nil {
			return nil, err
		}
	}
	runtime := &RemoteCustodyChallengeService{admission: s, artifacts: artifacts, config: config.SessionConfig}
	_, err = runtime.Review(ctx)
	return runtime, err
}

func (s *RemoteCustodyChallengeService) reviewLocked(ctx context.Context, decision *workarchive.CustodyJournalDecision) (RemoteCustodyChallengeReview, error) {
	base, err := s.admission.reviewLocked(ctx, decision)
	if err != nil {
		return RemoteCustodyChallengeReview{}, err
	}
	if base.Pending || !base.AlreadyApplied {
		return RemoteCustodyChallengeReview{}, ErrRemoteCustody
	}
	if err := s.admission.life.owner.checkOperation(custodyAdmissionBinding(s.admission.source.scope, s.admission.entry)); err != nil {
		return RemoteCustodyChallengeReview{}, err
	}
	return RemoteCustodyChallengeReview{Admission: base, ArtifactsPath: s.artifacts,
		ChallengePath: filepath.Join(s.artifacts, fmt.Sprintf("cycle-%020d", s.admission.source.scope.Intent.PriorSequence+1), "challenge.omcc")}, nil
}

func (s *RemoteCustodyChallengeService) Review(ctx context.Context) (review RemoteCustodyChallengeReview, err error) {
	if s == nil || s.admission == nil {
		return review, ErrClosed
	}
	a := s.admission
	run, finish, err := a.life.begin(ctx)
	if err != nil {
		return review, err
	}
	defer finish()
	a.life.owner.mu.Lock()
	defer a.life.owner.mu.Unlock()
	err = a.source.withDecision(run, a.life, func(d *workarchive.CustodyJournalDecision) error {
		var err error
		review, err = s.reviewLocked(run, d)
		return err
	})
	return review, err
}

func (s *RemoteCustodyChallengeService) Prepare(ctx context.Context, expected types.Hash, auditorKey ed25519.PrivateKey) (challenge workarchive.CustodyChallenge, err error) {
	if s == nil || s.admission == nil || expected.IsZero() {
		return challenge, ErrRemoteCustody
	}
	a := s.admission
	run, finish, err := a.life.begin(ctx)
	if err != nil {
		return challenge, err
	}
	defer finish()
	a.life.owner.mu.Lock()
	defer a.life.owner.mu.Unlock()
	if err := a.source.validate(); err != nil {
		return challenge, err
	}
	cycle, err := workarchive.NewCustodyAuditCycle(run, a.source.journal, s.artifacts, a.source.scope.Intent, auditorKey, s.config)
	if err != nil {
		return challenge, err
	}
	return cycle.PrepareChallengeChecked(run, func(d *workarchive.CustodyJournalDecision) error {
		if err := a.source.validate(); err != nil {
			return err
		}
		r, err := s.reviewLocked(run, d)
		if err != nil {
			return err
		}
		id, err := r.ID()
		if err != nil || id != expected {
			return errors.Join(ErrManagedCustodyReview, err)
		}
		return run.Err()
	})
}

func (s *RemoteCustodyChallengeService) Close() error {
	if s == nil || s.admission == nil {
		return nil
	}
	return s.admission.Close()
}
