package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func remoteInitialConfig(t testing.TB, f *remoteExecutionFixture, fresh bool) ManagedCustodyCommandServiceConfig {
	t.Helper()
	c := f.auditConfig(t)
	s := f.scope
	config := ManagedCustodyCommandServiceConfig{AuthorityPath: f.authorityPath, AuthorityPinsPath: f.pinsPath,
		Scope: CustodyCommandScope{Assignment: s.Worker.Assignment, AssignmentID: s.Worker.Plan.AssignmentID, Manifest: s.Manifest, InitialReceipt: s.InitialReceipt, PreviousReceipt: s.PreviousReceipt, CustodyPolicy: s.CustodyPolicy, Intent: f.intent},
		Entry: f.audit, JournalPath: c.Audit.JournalPath, JournalLimits: c.Audit.JournalLimits, IntentPath: c.Audit.IntentPath}
	config.EntryID, _ = f.audit.ID()
	b, err := f.audit.CanonicalBytes()
	config.EntryPath = managedCommandApplyTestFile(t, "audit", b, err)
	if fresh {
		config.AuthorityPath, config.AuthorityPinsPath = filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "pins")
		owner, err := CreateCoordinatedAuthority(config.AuthorityPath, config.AuthorityPinsPath, s.Worker.Assignment, s.Worker.Plan.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return config
}

func TestRemoteCustodyInitialAdmissionRequiresExplicitExactResume(t *testing.T) {
	for _, written := range []bool{false, true} {
		t.Run(map[bool]string{false: "intent", true: "unconfirmed-entry"}[written], func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := remoteInitialConfig(t, f, true)
			if s, err := OpenManagedCustodyCommandService(t.Context(), config); err == nil {
				_ = s.Close()
				t.Fatal("legacy V0 accepted V1")
			}
			s, err := OpenRemoteCustodyAdmissionService(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			_, stale := managedCommandApplyTestReview(t, s)
			owner := s.life.owner
			owner.mu.Lock()
			err = owner.journal.prepare(t.Context(), config.Entry)
			if err == nil && written {
				_, err = owner.authority.Append(t.Context(), config.Entry)
			}
			owner.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Apply(t.Context(), stale); !errors.Is(err, ErrManagedCustodyReview) {
				t.Fatal("stale review accepted", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenRemoteCustodyAdmissionService(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			review, id := managedCommandApplyTestReview(t, s)
			if !review.Pending || review.PendingEntryID != config.EntryID || review.AlreadyApplied {
				t.Fatal(review)
			}
			if _, err := s.Apply(t.Context(), id); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("Apply implicitly resumed", err)
			}
			if commit, err := s.Resume(t.Context(), id); err != nil || commit.EntryID != config.EntryID {
				t.Fatal(commit, err)
			}
			review, id = managedCommandApplyTestReview(t, s)
			if !review.AlreadyApplied || review.Pending || review.AuthorityPosition.Sequence != 1 {
				t.Fatal(review)
			}
			if commit, err := s.Apply(t.Context(), id); err != nil || commit.Appended {
				t.Fatal("exact retry appended", commit, err)
			}
		})
	}
}

func TestRemoteCustodyInitialChallengeNeedsPendingOriginalAudit(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	config := remoteInitialConfig(t, f, false)
	challengeConfig := RemoteCustodyChallengeConfig{Admission: config, ArtifactsPath: f.base.config.ArtifactsPath, SessionConfig: f.base.config.SessionConfig}
	s, err := OpenRemoteCustodyChallengeService(t.Context(), challengeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	entries, err := os.ReadDir(challengeConfig.ArtifactsPath)
	if err != nil || len(entries) != 1 {
		t.Fatal("Open/Review created a challenge", err, entries)
	}
	review, err := s.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	if _, err := s.Prepare(t.Context(), id, testKey(4)); err == nil {
		t.Fatal("consumer key signed evidence")
	}
	challenge, err := s.Prepare(t.Context(), id, testKey(3))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := f.scope.Challenge.CanonicalBytes()
	got, _ := challenge.CanonicalBytes()
	if !bytes.Equal(want, got) {
		t.Fatal("challenge refreshed selected intent")
	}
	retained, err := os.ReadFile(review.ChallengePath)
	if err != nil || !bytes.Equal(retained, got) {
		t.Fatal(err)
	}
	if again, err := s.Prepare(t.Context(), id, testKey(3)); err != nil {
		t.Fatal(err)
	} else {
		b, _ := again.CanonicalBytes()
		if !bytes.Equal(b, got) {
			t.Fatal("exact retry changed challenge")
		}
	}
	// Replacement is rejected before any publication under the new path.
	old := challengeConfig.ArtifactsPath + ".old"
	if err := os.Rename(challengeConfig.ArtifactsPath, old); err != nil {
		t.Fatal(err)
	}
	lock, err := workarchive.CreateCustodyArtifacts(t.Context(), challengeConfig.ArtifactsPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	if _, err := s.Prepare(t.Context(), id, testKey(3)); err == nil {
		t.Fatal("accepted replaced original artifacts")
	}
	if entries, err := os.ReadDir(challengeConfig.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("published under substituted root", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A signed Begin, confirmed by the same original owner, closes this generic
	// pre-Begin preparation surface even though the source is still at prior.
	owner := f.openOwner(t)
	if _, err := owner.Append(t.Context(), f.scope.Worker.Begin); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenRemoteCustodyAdmissionService(t.Context(), config); err == nil {
		_ = other.Close()
		t.Fatal("admission tooling crossed active remote hold")
	}
}

func TestRemoteCustodyInitialChallengeRejectsUnappliedAdmission(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	config := remoteInitialConfig(t, f, true)
	if s, err := OpenRemoteCustodyChallengeService(t.Context(), RemoteCustodyChallengeConfig{Admission: config, ArtifactsPath: f.base.config.ArtifactsPath, SessionConfig: f.base.config.SessionConfig}); err == nil {
		_ = s.Close()
		t.Fatal("signed proposal treated as confirmed Audit")
	}
	config.Entry = f.scope.Worker.Begin
	config.EntryID, _ = config.Entry.ID()
	if s, err := OpenRemoteCustodyAdmissionService(t.Context(), config); err == nil {
		_ = s.Close()
		t.Fatal("admission service accepted Begin")
	}
}
