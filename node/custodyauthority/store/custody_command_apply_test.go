package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func managedCommandApplyTestScope(f *managedAuditFixture) CustodyCommandScope {
	return CustodyCommandScope{Schedule: f.config.Schedule, Assignment: f.serve.archive.policy.Assignments[0], AssignmentID: f.config.AssignmentID,
		Manifest: f.config.Manifest, InitialReceipt: f.config.InitialReceipt, CustodyPolicy: f.config.CustodyPolicy,
		Intent: f.intent, PreviousReceipt: f.config.InitialReceipt}
}

func managedCommandApplyTestFile(t testing.TB, name string, b []byte, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func managedCommandApplyTestSign(t testing.TB, draft custodyauthority.Command) custodyauthority.Entry {
	t.Helper()
	command, err := draft.Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func managedCommandApplyTestConfig(t testing.TB, f *managedAuditFixture, purpose custodyauthority.Purpose) (ManagedCustodyCommandServiceConfig, *Coordinator) {
	t.Helper()
	scope := managedCommandApplyTestScope(f)
	authorityPath, pinsPath := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "pins")
	owner, err := CreateCoordinatedAuthority(authorityPath, pinsPath, scope.Assignment, scope.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	position := testCoordination(t, owner).Confirmed
	var challenge workarchive.CustodyChallenge
	journalPath := f.config.JournalPath
	if purpose == custodyauthority.Serve {
		challenge, journalPath = f.serve.challenge, f.serve.config.JournalPath
	}
	draft, err := BuildCustodyAdmitCommand(scope, purpose, testPublic(4), position, challenge)
	if err != nil {
		t.Fatal(err)
	}
	entry := managedCommandApplyTestSign(t, draft)
	entryID, _ := entry.ID()
	entryBytes, err := entry.CanonicalBytes()
	config := ManagedCustodyCommandServiceConfig{AuthorityPath: authorityPath, AuthorityPinsPath: pinsPath,
		Scope: scope, Entry: entry, EntryID: entryID, IntentPath: f.config.IntentPath,
		EntryPath: managedCommandApplyTestFile(t, "entry.omcae", entryBytes, err), JournalPath: journalPath,
		JournalLimits: f.config.JournalLimits, Challenge: challenge}
	if purpose == custodyauthority.Serve {
		b, err := challenge.CanonicalBytes()
		config.ChallengePath = managedCommandApplyTestFile(t, "challenge.omach", b, err)
	}
	return config, owner
}

func managedCommandApplyTestOpen(t testing.TB, config ManagedCustodyCommandServiceConfig) *ManagedCustodyCommandService {
	t.Helper()
	service, err := OpenManagedCustodyCommandService(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func managedCommandApplyTestReview(t testing.TB, service *ManagedCustodyCommandService) (ManagedCustodyCommandReview, types.Hash) {
	t.Helper()
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil {
		t.Fatal(err)
	}
	return review, id
}

func TestManagedCustodyCommandAdmitReviewApplyAndRetainedRetry(t *testing.T) {
	for _, purpose := range []custodyauthority.Purpose{custodyauthority.Audit, custodyauthority.Serve} {
		t.Run(string(rune('0'+purpose)), func(t *testing.T) {
			f := newManagedAuditFixture(t)
			config, bootstrap := managedCommandApplyTestConfig(t, f, purpose)
			before := testCoordination(t, bootstrap)
			if err := bootstrap.Close(); err != nil {
				t.Fatal(err)
			}
			service := managedCommandApplyTestOpen(t, config)
			review, id := managedCommandApplyTestReview(t, service)
			if review.AuthorityPosition != before.Confirmed || review.AlreadyApplied || review.Pending {
				t.Fatal("open/review changed owner", review)
			}
			if other, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Scope.Assignment, config.Scope.AssignmentID); !errors.Is(err, ErrBusy) {
				if other != nil {
					_ = other.Close()
				}
				t.Fatal("original owner was not retained", err)
			}
			result, err := service.Apply(t.Context(), id)
			if err != nil || !result.Appended || result.EntryID != config.EntryID || result.Snapshot.Sequence != before.Confirmed.Sequence+1 {
				t.Fatal(result, err)
			}
			if _, err := service.Apply(t.Context(), id); !errors.Is(err, ErrManagedCustodyReview) {
				t.Fatal("old review submitted", err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			service = managedCommandApplyTestOpen(t, config)
			review, id = managedCommandApplyTestReview(t, service)
			if !review.AlreadyApplied || review.Pending {
				t.Fatal("exact retained command was not identified", review)
			}
			retry, err := service.Apply(t.Context(), id)
			if err != nil || retry.Appended || retry.EntryID != result.EntryID || retry.Snapshot.Sequence != result.Snapshot.Sequence {
				t.Fatal("lost-output retry advanced or changed entry", retry, err)
			}
		})
	}
}

func TestManagedCustodyCommandRejectsPinsSourceAndPositionDisagreement(t *testing.T) {
	for _, mutation := range []string{"entry-id", "assignment-id", "head", "sequence", "entry-file", "intent-file", "missing-journal"} {
		t.Run(mutation, func(t *testing.T) {
			f := newManagedAuditFixture(t)
			config, owner := managedCommandApplyTestConfig(t, f, custodyauthority.Audit)
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "entry-id":
				config.EntryID = testHash(201)
			case "assignment-id":
				config.Scope.AssignmentID = testHash(201)
			case "head", "sequence":
				draft := config.Entry.Command
				if mutation == "head" {
					draft.ExpectedHead = testHash(201)
				} else {
					draft.ExpectedSequence++
				}
				config.Entry = managedCommandApplyTestSign(t, draft)
				config.EntryID, _ = config.Entry.ID()
				b, err := config.Entry.CanonicalBytes()
				config.EntryPath = managedCommandApplyTestFile(t, "wrong-position.omcae", b, err)
			case "entry-file":
				if err := os.WriteFile(config.EntryPath, []byte("wrong entry"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "intent-file":
				if err := os.WriteFile(config.IntentPath, []byte("wrong intent"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing-journal":
				config.JournalPath = filepath.Join(t.TempDir(), "never-created")
			}
			service, err := OpenManagedCustodyCommandService(t.Context(), config)
			if err == nil {
				_ = service.Close()
				t.Fatal("invalid pinned scope opened")
			}
			check, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, f.serve.archive.policy.Assignments[0], f.config.AssignmentID)
			if err != nil {
				t.Fatal("failed open leaked owner", err)
			}
			defer check.Close()
			if current := testCoordination(t, check); current.Confirmed.Sequence != 0 || current.Pending != nil {
				t.Fatal("failed open wrote owner", current)
			}
			if mutation == "missing-journal" {
				if _, err := os.Lstat(config.JournalPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing source was created", err)
				}
			}
		})
	}
}

func TestManagedCustodyCommandPendingRequiresExplicitResume(t *testing.T) {
	for _, alreadyWritten := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained-intent", true: "unconfirmed-entry"}[alreadyWritten], func(t *testing.T) {
			f := newManagedAuditFixture(t)
			config, owner := managedCommandApplyTestConfig(t, f, custodyauthority.Audit)
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			service := managedCommandApplyTestOpen(t, config)
			_, stale := managedCommandApplyTestReview(t, service)
			owner = service.life.owner
			owner.mu.Lock()
			err := owner.journal.prepare(t.Context(), config.Entry)
			if err == nil && alreadyWritten {
				_, err = owner.authority.Append(t.Context(), config.Entry)
			}
			owner.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Apply(t.Context(), stale); !errors.Is(err, ErrManagedCustodyReview) {
				t.Fatal("pending did not invalidate review", err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			service = managedCommandApplyTestOpen(t, config)
			review, id := managedCommandApplyTestReview(t, service)
			if !review.Pending || review.PendingEntryID != config.EntryID || review.AlreadyApplied {
				t.Fatal(review)
			}
			if alreadyWritten && review.ObservedAuthorityPosition.Sequence != review.AuthorityPosition.Sequence+1 {
				t.Fatal("pending observed position hidden", review)
			}
			if _, err := service.Apply(t.Context(), id); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("normal apply resumed retained attempt", err)
			}
			current := testCoordination(t, service.life.owner)
			if current.Pending == nil || current.Confirmed.Sequence != 0 {
				t.Fatal("review/apply confirmed pending", current)
			}
			result, err := service.Resume(t.Context(), id)
			if err != nil || result.EntryID != config.EntryID || result.Appended == alreadyWritten {
				t.Fatal("explicit exact resume failed", result, err)
			}
			if current := testCoordination(t, service.life.owner); current.Pending != nil || current.Confirmed.Sequence != 1 {
				t.Fatal("resume not independently confirmed", current)
			}
		})
	}
}

func TestManagedCustodyCommandStaleReviewAndReplacedSourceNeverAppend(t *testing.T) {
	for _, mutation := range []string{"authority", "journal", "retired", "replaced-root", "entry-file"} {
		t.Run(mutation, func(t *testing.T) {
			f := newManagedAuditFixture(t)
			config, owner := managedCommandApplyTestConfig(t, f, custodyauthority.Audit)
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			service := managedCommandApplyTestOpen(t, config)
			_, id := managedCommandApplyTestReview(t, service)
			switch mutation {
			case "authority":
				snapshot := testCoordination(t, service.life.owner).Authority
				appendCoordinated(t, service.life.owner, testEntry(t, snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(202)))
			case "journal":
				if _, _, err := f.journal.Append(f.answer(t)); err != nil {
					t.Fatal(err)
				}
			case "retired":
				if err := os.WriteFile(filepath.Join(config.JournalPath, "retirement.omcrt"), []byte("partial"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "replaced-root":
				old := config.JournalPath + "-old"
				if err := os.Rename(config.JournalPath, old); err != nil {
					t.Fatal(err)
				}
				if err := os.CopyFS(config.JournalPath, os.DirFS(old)); err != nil {
					t.Fatal(err)
				}
			case "entry-file":
				if err := os.WriteFile(config.EntryPath, []byte("changed"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := testCoordination(t, service.life.owner)
			if _, err := service.Apply(t.Context(), id); err == nil {
				t.Fatal("changed review applied")
			}
			after := testCoordination(t, service.life.owner)
			if after.Confirmed != before.Confirmed || after.Pending != nil {
				t.Fatal("rejected action changed owner", after)
			}
		})
	}
}

func managedCommandApplyTestCompleteConfig(t testing.TB, f *managedAuditFixture, owner *Coordinator, terminal CustodyTerminal, journalPath string) ManagedCustodyCommandServiceConfig {
	t.Helper()
	scope := managedCommandApplyTestScope(f)
	draft, err := BuildCustodyCompleteCommand(scope, terminal.Admission, terminal, testCoordination(t, owner).Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	entry := managedCommandApplyTestSign(t, draft)
	id, _ := entry.ID()
	b, err := entry.CanonicalBytes()
	entryPath := managedCommandApplyTestFile(t, "complete.omcae", b, err)
	b, err = terminal.CanonicalBytes()
	terminalPath := managedCommandApplyTestFile(t, "terminal.omcat", b, err)
	return ManagedCustodyCommandServiceConfig{AuthorityPath: owner.authority.path, AuthorityPinsPath: owner.journal.path,
		Scope: scope, Entry: entry, EntryID: id, EntryPath: entryPath, IntentPath: f.config.IntentPath,
		JournalPath: journalPath, JournalLimits: f.config.JournalLimits, Terminal: terminal, TerminalPath: terminalPath}
}

func TestManagedCustodyCommandCompleteAuditAndServeIndependently(t *testing.T) {
	f := newManagedAuditFixture(t)
	owner := f.serve.archive.f.coordinator
	record := f.answer(t)
	for _, journal := range []*workarchive.CustodyJournal{f.journal, f.serve.journal} {
		if _, _, err := journal.Append(record); err != nil {
			t.Fatal(err)
		}
	}
	scope := managedCommandApplyTestScope(f)
	terminalAudit, err := CaptureCustodyTerminal(t.Context(), owner, CustodyTerminalCaptureConfig{Scope: scope, Admission: f.config.Admission,
		JournalPath: f.config.JournalPath, JournalLimits: f.config.JournalLimits})
	if err != nil {
		t.Fatal(err)
	}
	terminalServe, err := CaptureCustodyTerminal(t.Context(), owner, CustodyTerminalCaptureConfig{Scope: scope, Admission: f.serve.config.Admission,
		JournalPath: f.serve.config.JournalPath, JournalLimits: f.config.JournalLimits})
	if err != nil {
		t.Fatal(err)
	}
	auditConfig := managedCommandApplyTestCompleteConfig(t, f, owner, terminalAudit, f.config.JournalPath)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	audit := managedCommandApplyTestOpen(t, auditConfig)
	_, auditID := managedCommandApplyTestReview(t, audit)
	auditResult, err := audit.Apply(t.Context(), auditID)
	if err != nil || !auditResult.Appended {
		t.Fatal(auditResult, err)
	}
	serveConfig := managedCommandApplyTestCompleteConfig(t, f, audit.life.owner, terminalServe, f.serve.config.JournalPath)
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	serve := managedCommandApplyTestOpen(t, serveConfig)
	_, serveID := managedCommandApplyTestReview(t, serve)
	serveResult, err := serve.Apply(t.Context(), serveID)
	if err != nil || !serveResult.Appended {
		t.Fatal("serve completion incorrectly required pending audit", serveResult, err)
	}
	if err := serve.Close(); err != nil {
		t.Fatal(err)
	}
	// The first completion remains exactly retryable after the other closes.
	audit = managedCommandApplyTestOpen(t, auditConfig)
	review, id := managedCommandApplyTestReview(t, audit)
	if !review.AlreadyApplied {
		t.Fatal(review)
	}
	retry, err := audit.Apply(t.Context(), id)
	if err != nil || retry.Appended || retry.EntryID != auditResult.EntryID || retry.Snapshot.Sequence != serveResult.Snapshot.Sequence {
		t.Fatal("completed exact retry was refreshed or ticket-guarded", retry, err)
	}
	auditTicket, _ := terminalAudit.Admission.ID()
	serveTicket, _ := terminalServe.Admission.ID()
	completed := 0
	for _, operation := range retry.Snapshot.Operations {
		if operation.TicketID == auditTicket || operation.TicketID == serveTicket {
			if operation.CompletionID.IsZero() {
				t.Fatal("completion did not drain its own ticket", operation)
			}
			completed++
		}
	}
	if completed != 2 {
		t.Fatal("both tickets were not retained", completed)
	}
}

func TestManagedCustodyCommandCloseCancelsDrainsAndRetainsCleanupFailure(t *testing.T) {
	f := newManagedAuditFixture(t)
	config, bootstrap := managedCommandApplyTestConfig(t, f, custodyauthority.Audit)
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	service := managedCommandApplyTestOpen(t, config)
	_, id := managedCommandApplyTestReview(t, service)
	entered, release := make(chan struct{}), make(chan struct{})
	service.hooks.at = func(stage string) error {
		if stage == "command-before-append" {
			close(entered)
			<-release
		}
		return nil
	}
	applied := make(chan error, 1)
	go func() { _, err := service.Apply(context.Background(), id); applied <- err }()
	<-entered
	if _, err := service.Review(t.Context()); !errors.Is(err, ErrManagedCustodyRuntimeBusy) {
		t.Fatal("concurrent action admitted", err)
	}
	cleanup := errors.New("retained cleanup failure")
	service.life.recordCleanup(cleanup)
	closed := make(chan error, 1)
	go func() { closed <- service.Close() }()
	select {
	case err := <-closed:
		t.Fatal("Close released owner before drain", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-applied; !errors.Is(err, context.Canceled) {
		t.Fatal("Close did not cancel pending action", err)
	}
	if err := <-closed; !errors.Is(err, cleanup) {
		t.Fatal("cleanup failure lost", err)
	}
	if err := service.Close(); !errors.Is(err, cleanup) {
		t.Fatal("repeated Close lost cleanup failure", err)
	}
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Scope.Assignment, config.Scope.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if state := testCoordination(t, owner); state.Pending != nil || state.Confirmed.Sequence != 0 {
		t.Fatal("cancelled command appended", state)
	}
}
