package store

import (
	"errors"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func scheduledCompleteFixture(t testing.TB) (*managedAuditFixture, CustodyTerminal, CustodyTerminal) {
	t.Helper()
	f, _ := newManagedCustodyPair(t)
	s, e := managedScheduleFixture(t, f)
	migrateManagedSchedule(t, f, s, e)
	f.config.Schedule = &s
	f.serve.config.Schedule = &s
	exchangeManagedCustodyPair(t, f, openManagedCustodyPair(t, f))
	capture := func(admission custodyauthority.Entry, path string) CustodyTerminal {
		t.Helper()
		terminal, err := CaptureCustodyTerminal(t.Context(), f.serve.archive.f.coordinator, CustodyTerminalCaptureConfig{Scope: managedCommandApplyTestScope(f), Admission: admission, JournalPath: path, JournalLimits: f.config.JournalLimits})
		if err != nil {
			t.Fatal(err)
		}
		return terminal
	}
	return f, capture(f.config.Admission, f.config.JournalPath), capture(f.serve.config.Admission, f.serve.config.JournalPath)
}

func TestCustodyScheduleCompletionPreservesSpentTicketsAndRetries(t *testing.T) {
	f, auditTerminal, serveTerminal := scheduledCompleteFixture(t)
	owner := f.serve.archive.f.coordinator
	before := testCoordination(t, owner).Authority
	terminals := []CustodyTerminal{auditTerminal, serveTerminal}
	paths := []string{f.config.JournalPath, f.serve.config.JournalPath}
	var first ManagedCustodyCommandServiceConfig
	for i, terminal := range terminals {
		if terminal.Version != CustodyTerminalVersion1 || terminal.ScheduleID != f.config.Schedule.ExpectedID {
			t.Fatal("missing explicit terminal scope")
		}
		raw, err := terminal.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeCustodyTerminal(raw)
		if err != nil || decoded.Validate(managedCommandApplyTestScope(f)) != nil {
			t.Fatal("terminal roundtrip", err)
		}
		config := managedCommandApplyTestCompleteConfig(t, f, owner, terminal, paths[i])
		if i == 0 {
			first = config
		}
		ticket, _ := terminal.Admission.ID()
		if config.Entry.Command.Version != custodyauthority.ScheduleVersion2 || config.Entry.Command.TicketID != ticket {
			t.Fatal("reissued ticket")
		}
		owner.Close()
		service := managedCommandApplyTestOpen(t, config)
		_, review := managedCommandApplyTestReview(t, service)
		result, err := service.Apply(t.Context(), review)
		if err != nil || !result.Appended || result.Snapshot.Pending != before.Pending-uint16(i+1) {
			t.Fatal("completion failed", err, result.Snapshot.Pending)
		}
		owner = service.life.owner
		if i == 1 {
			service.Close()
		} else {
			t.Cleanup(func() { service.Close() })
		}
	}
	retry := managedCommandApplyTestOpen(t, first)
	review, id := managedCommandApplyTestReview(t, retry)
	if !review.AlreadyApplied {
		t.Fatal("lost retained completion")
	}
	result, err := retry.Apply(t.Context(), id)
	if err != nil || result.Appended || len(result.Snapshot.Operations) != len(before.Operations) || result.Snapshot.ScheduleID != before.ScheduleID {
		t.Fatal("retry reset accounting", err)
	}
	for i, operation := range before.Operations {
		got := result.Snapshot.Operations[i]
		if got.TicketID != operation.TicketID || got.OperationID != operation.OperationID || got.ConsumerPublicKey != operation.ConsumerPublicKey {
			t.Fatal("changed spent operation")
		}
	}
}

func TestCustodyScheduleCompletionRejectsWrongScopeAndLegacyTerminal(t *testing.T) {
	f, terminal, _ := scheduledCompleteFixture(t)
	scope := managedCommandApplyTestScope(f)
	owner := f.serve.archive.f.coordinator
	before := testCoordination(t, owner)
	for _, kind := range []string{"legacy", "scope", "ticket", "journal", "proof", "trust"} {
		t.Run(kind, func(t *testing.T) {
			bad := terminal
			s := scope
			switch kind {
			case "legacy":
				bad.Version = CustodyTerminalVersion0
				bad.ScheduleID = types.Hash{}
			case "scope":
				bad.ScheduleID = testHash(209)
			case "ticket":
				bad.Admission = f.serve.config.Admission
			case "journal":
				bad.Entry.PreviousEntryID = testHash(208)
			case "proof":
				copy := *s.Schedule
				copy.ExpectedID = testHash(207)
				s.Schedule = &copy
			case "trust":
				copy := *s.Schedule
				copy.Policy.TrustedAttestors = nil
				s.Schedule = &copy
			}
			if kind == "ticket" { // A different valid ticket cannot replace the explicitly selected admission.
				if _, err := BuildCustodyCompleteCommand(s, terminal.Admission, bad, before.Confirmed); err == nil {
					t.Fatal("substituted admission")
				}
			} else if _, err := BuildCustodyCompleteCommand(s, bad.Admission, bad, before.Confirmed); err == nil {
				t.Fatal("accepted substitution", kind)
			}
		})
	}
	legacy := scope
	legacy.Schedule = nil
	if _, err := CaptureCustodyTerminal(t.Context(), owner, CustodyTerminalCaptureConfig{Scope: legacy, Admission: terminal.Admission, JournalPath: f.config.JournalPath, JournalLimits: f.config.JournalLimits}); err == nil {
		t.Fatal("legacy capture used new authority")
	}
	draft, err := BuildCustodyAdmitCommand(scope, custodyauthority.Audit, scope.Intent.ConsumerPublicKey, before.Confirmed, workarchive.CustodyChallenge{})
	if err != nil || draft.Version != custodyauthority.ScheduleVersion2 || draft.ScheduleID != scope.scheduleID() {
		t.Fatal("admission draft lost explicit schedule", err)
	}
	entry := managedCommandApplyTestSign(t, draft)
	if _, err := owner.Append(t.Context(), entry); err == nil {
		t.Fatal("previously spent operation admitted again")
	}
	if !reflect.DeepEqual(before, testCoordination(t, owner)) {
		t.Fatal("rejection changed accounting")
	}
}

func TestCustodyScheduleCompletionRecoversExactPendingEntry(t *testing.T) {
	for _, stage := range []string{"intent-before-publish", "intent-after-publish", "intent-directory-synced", "authority-before-publish", "authority-after-publish", "authority-directory-synced", "confirm-before-publish", "confirm-after-publish", "confirm-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			f, terminal, _ := scheduledCompleteFixture(t)
			owner := f.serve.archive.f.coordinator
			before := testCoordination(t, owner).Authority
			config := managedCommandApplyTestCompleteConfig(t, f, owner, terminal, f.config.JournalPath)
			owner.Close()
			service := managedCommandApplyTestOpen(t, config)
			_, id := managedCommandApplyTestReview(t, service)
			injected := errors.New("scheduled completion interrupted")
			hit := false
			setCoordinatorHooks(service.life.owner, storeHooks{at: func(s string) error {
				if s == stage {
					hit = true
					return injected
				}
				return nil
			}})
			_, err := service.Apply(t.Context(), id)
			if !hit || err == nil {
				t.Fatal("fault not reached", stage, err)
			}
			service.Close()
			service = managedCommandApplyTestOpen(t, config)
			review, id := managedCommandApplyTestReview(t, service)
			if review.PendingEntryID.IsZero() {
				_, err = service.Apply(t.Context(), id)
			} else {
				_, err = service.Resume(t.Context(), id)
			}
			if err != nil {
				t.Fatal("cold exact recovery", err)
			}
			final := testCoordination(t, service.life.owner)
			if final.Pending != nil || final.Authority.Pending != before.Pending-1 || final.Authority.Sequence != before.Sequence+1 || len(final.Authority.Operations) != len(before.Operations) {
				t.Fatal("recovery changed accounting")
			}
		})
	}
}
