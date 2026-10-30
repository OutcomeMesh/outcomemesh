package store

import (
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// The second exchange must use the same authority and both original journals.
// Completing old work releases pending slots, never the spent-operation budget.
func TestCustodyScheduledNewAdmissionsContinueOriginalJournals(t *testing.T) {
	f, oldAudit, oldServe := scheduledCompleteFixture(t)
	owner := f.serve.archive.f.coordinator
	before := testCoordination(t, owner).Authority
	apply := func(scope CustodyCommandScope, draft custodyauthority.Command, journal string, challenge workarchive.CustodyChallenge, terminal *CustodyTerminal) custodyauthority.Entry {
		t.Helper()
		purpose := draft.Purpose
		if terminal != nil {
			purpose = terminal.Admission.Command.Purpose
		}
		reviewID, err := custodyauthority.ScheduledCustodyCommandReviewID(scope.Assignment, draft, purpose)
		if err != nil {
			t.Fatal(err)
		}
		command, err := custodyauthority.SignReviewedScheduledCustodyCommand(scope.Assignment, draft, purpose, reviewID, testKey(4))
		if err != nil {
			t.Fatal(err)
		}
		entryID, err := custodyauthority.ScheduledCustodyEntryReviewID(scope.Assignment, command, purpose)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.CosignReviewedScheduledCustodyCommand(scope.Assignment, command, purpose, entryID, testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := entry.ID()
		raw, err := entry.CanonicalBytes()
		cfg := ManagedCustodyCommandServiceConfig{AuthorityPath: owner.authority.path, AuthorityPinsPath: owner.journal.path, Scope: scope, Entry: entry, EntryID: id, EntryPath: managedCommandApplyTestFile(t, "entry", raw, err), IntentPath: f.config.IntentPath, JournalPath: journal, JournalLimits: f.config.JournalLimits, Challenge: challenge}
		if purpose == custodyauthority.Serve && terminal == nil {
			raw, err = challenge.CanonicalBytes()
			cfg.ChallengePath = managedCommandApplyTestFile(t, "challenge", raw, err)
		}
		if terminal != nil {
			cfg.Terminal = *terminal
			raw, err = terminal.CanonicalBytes()
			cfg.TerminalPath = managedCommandApplyTestFile(t, "terminal", raw, err)
		}
		owner.Close()
		service := managedCommandApplyTestOpen(t, cfg)
		_, reviewed := managedCommandApplyTestReview(t, service)
		if _, err := service.Apply(t.Context(), reviewed); err != nil {
			t.Fatal(err)
		}
		// An exact retry cannot consume another pending slot or operation.
		snapshot := testCoordination(t, service.life.owner)
		_, reviewed = managedCommandApplyTestReview(t, service)
		if result, err := service.Apply(t.Context(), reviewed); err != nil || result.Appended {
			t.Fatal("exact retry", err)
		}
		if !reflect.DeepEqual(snapshot, testCoordination(t, service.life.owner)) {
			t.Fatal("retry spent another operation")
		}
		owner = service.life.owner
		f.serve.archive.f.coordinator = owner
		return entry
	}
	scope := managedCommandApplyTestScope(f)
	for i, terminal := range []CustodyTerminal{oldAudit, oldServe} {
		draft, err := BuildCustodyCompleteCommand(scope, terminal.Admission, terminal, testCoordination(t, owner).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		apply(scope, draft, []string{f.config.JournalPath, f.serve.config.JournalPath}[i], workarchive.CustodyChallenge{}, &terminal)
	}
	prior, err := f.journal.State()
	if err != nil {
		t.Fatal(err)
	}
	priorID, _ := prior.CurrentReceipt.ID()
	f.intent.PriorReceiptID = priorID
	f.intent.PriorSequence = prior.Sequence
	f.intent.PriorHeadID = prior.HeadEntryID
	f.intent.Nonce = testHash(187)
	f.intent.IssuedAt = f.serve.now + 2
	f.intent.ExpiresAt = f.intent.IssuedAt + 60
	f.intent.RenewUntil = prior.CurrentReceipt.RetainUntil + 1
	f.config.IntentID, err = f.intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	f.config.IntentPath = filepath.Join(t.TempDir(), "next.intent")
	if err := workarchive.PublishCustodyAuditIntent(t.Context(), f.config.IntentPath, f.intent); err != nil {
		t.Fatal(err)
	}
	f.config.ArtifactsPath = filepath.Join(t.TempDir(), "next-artifacts")
	artifacts, err := workarchive.AcquireCustodyArtifacts(f.config.ArtifactsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifacts.Close(); err != nil {
		t.Fatal(err)
	}
	f.config.SessionConfig.Now = func() uint64 { return f.intent.IssuedAt + 1 }
	f.serve.config.SessionConfig.Now = f.config.SessionConfig.Now
	scope.Intent, scope.PreviousReceipt = f.intent, prior.CurrentReceipt
	draft, err := BuildCustodyAdmitCommand(scope, custodyauthority.Audit, testPublic(4), testCoordination(t, owner).Confirmed, workarchive.CustodyChallenge{})
	if err != nil {
		t.Fatal(err)
	}
	f.config.Admission = apply(scope, draft, f.config.JournalPath, workarchive.CustodyChallenge{}, nil)
	audit := f.open(t)
	f.serve.challenge, err = audit.PrepareChallenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.serve.config.ChallengeID, _ = f.serve.challenge.ID()
	draft, err = BuildCustodyAdmitCommand(scope, custodyauthority.Serve, testPublic(4), testCoordination(t, owner).Confirmed, f.serve.challenge)
	if err != nil {
		t.Fatal(err)
	}
	f.serve.config.Admission = apply(scope, draft, f.serve.config.JournalPath, f.serve.challenge, nil)
	pair := openManagedCustodyPair(t, f)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(5 * time.Second))
	right.SetDeadline(time.Now().Add(5 * time.Second))
	result, err := pair.Exchange(t.Context(), f.intent.ReplicaPeerID, f.serve.config.AuditorPeerID, left, right)
	if err != nil || result.Audit.JournalSequence != 2 || result.Serve.JournalSequence != 2 {
		t.Fatal("next original-journal exchange", err)
	}
	for i, admission := range []custodyauthority.Entry{f.config.Admission, f.serve.config.Admission} {
		path := []string{f.config.JournalPath, f.serve.config.JournalPath}[i]
		terminal, err := CaptureCustodyTerminal(t.Context(), owner, CustodyTerminalCaptureConfig{Scope: scope, Admission: admission, JournalPath: path, JournalLimits: f.config.JournalLimits})
		if err != nil {
			t.Fatal(err)
		}
		draft, err := BuildCustodyCompleteCommand(scope, admission, terminal, testCoordination(t, owner).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		apply(scope, draft, path, workarchive.CustodyChallenge{}, &terminal)
	}
	after := testCoordination(t, owner).Authority
	if after.Pending != before.Pending-2 || len(after.Operations) != len(before.Operations)+2 || after.ScheduleID != before.ScheduleID {
		t.Fatal("new cycle reset original accounting")
	}
	for _, old := range before.Operations {
		found := false
		for _, current := range after.Operations {
			if old.TicketID == current.TicketID {
				found = current.OperationID == old.OperationID && current.ConsumerPublicKey == old.ConsumerPublicKey
			}
		}
		if !found {
			t.Fatal("original operation disappeared")
		}
	}
	// Even a completed request remains spent under its original identity.
	draft, err = BuildCustodyAdmitCommand(scope, custodyauthority.Audit, testPublic(4), testCoordination(t, owner).Confirmed, workarchive.CustodyChallenge{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Append(t.Context(), managedCommandApplyTestSign(t, draft)); err == nil {
		t.Fatal("completed request was reissued")
	}
	if !reflect.DeepEqual(after, testCoordination(t, owner).Authority) {
		t.Fatal("rejection changed accounting")
	}
}
