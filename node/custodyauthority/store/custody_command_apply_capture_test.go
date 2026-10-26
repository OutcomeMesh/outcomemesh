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
)

func managedCommandApplyCaptureConfig(t testing.TB, f *managedAuditFixture) ManagedCustodyTerminalCaptureServiceConfig {
	t.Helper()
	id, _ := f.config.Admission.ID()
	b, err := f.config.Admission.CanonicalBytes()
	return ManagedCustodyTerminalCaptureServiceConfig{AuthorityPath: f.serve.archive.f.authorityPath, AuthorityPinsPath: f.serve.archive.f.pinsPath,
		Scope: managedCommandApplyTestScope(f), Admission: f.config.Admission, AdmissionID: id,
		IntentPath: f.config.IntentPath, AdmissionPath: managedCommandApplyTestFile(t, "admission.omcae", b, err),
		JournalPath: f.config.JournalPath, JournalLimits: f.config.JournalLimits}
}

func managedCommandApplyCaptureOpen(t testing.TB, config ManagedCustodyTerminalCaptureServiceConfig) *ManagedCustodyTerminalCaptureService {
	t.Helper()
	service, err := OpenManagedCustodyTerminalCaptureService(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func TestManagedCustodyCaptureReviewPublicationAndDetachedValue(t *testing.T) {
	f := newManagedAuditFixture(t)
	if _, _, err := f.journal.Append(f.answer(t)); err != nil {
		t.Fatal(err)
	}
	config := managedCommandApplyCaptureConfig(t, f)
	before := testCoordination(t, f.serve.archive.f.coordinator)
	if err := f.serve.archive.f.coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	service := managedCommandApplyCaptureOpen(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil {
		t.Fatal(err)
	}
	if review.AuthorityPosition != before.Confirmed || review.JournalSequence != 1 || review.TerminalID.IsZero() {
		t.Fatal(review)
	}
	terminal, err := service.Capture(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(terminal.Entry.Record.Challenge.IDs) == 0 {
		t.Fatal("fixture has no mutable sample")
	}
	terminal.Entry.Record.Challenge.IDs[0] = testHash(230)
	output := filepath.Join(t.TempDir(), "terminal.omcat")
	terminal, err = service.CaptureToFile(t.Context(), id, output)
	if err != nil {
		t.Fatal("caller mutated private capture evidence", err)
	}
	terminalID, _ := terminal.ID()
	if terminalID != review.TerminalID {
		t.Fatal("capture changed selected current head", terminalID, review.TerminalID)
	}
	if _, err := LoadCustodyTerminalFile(output, review.TerminalID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CaptureToFile(t.Context(), id, output); err != nil {
		t.Fatal("exact durable retry rejected", err)
	}
	for _, root := range []string{config.AuthorityPath, config.AuthorityPinsPath, config.JournalPath} {
		if _, err := service.CaptureToFile(t.Context(), id, filepath.Join(root, "forbidden.omcat")); err == nil {
			t.Fatal("published inside protected root", root)
		}
	}
	if current := testCoordination(t, service.life.owner); current.Confirmed != before.Confirmed || current.Pending != nil {
		t.Fatal("capture completed authority ticket", current)
	}
	if err := os.WriteFile(output, []byte("different output"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CaptureToFile(t.Context(), id, output); err == nil {
		t.Fatal("capture replaced existing output")
	}
}

func TestManagedCustodyCaptureKeepsOwnerAndJournalThroughPublication(t *testing.T) {
	f := newManagedAuditFixture(t)
	record := f.answer(t)
	if _, _, err := f.journal.Append(record); err != nil {
		t.Fatal(err)
	}
	config := managedCommandApplyCaptureConfig(t, f)
	if err := f.serve.archive.f.coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	service := managedCommandApplyCaptureOpen(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	entered, release := make(chan struct{}), make(chan struct{})
	service.hooks.at = func(stage string) error {
		if stage == "capture-after-publish" {
			close(entered)
			<-release
		}
		return nil
	}
	output := filepath.Join(t.TempDir(), "terminal.omcat")
	captured := make(chan error, 1)
	go func() { _, err := service.CaptureToFile(context.Background(), id, output); captured <- err }()
	<-entered
	if _, err := LoadCustodyTerminalFile(output, review.TerminalID); err != nil {
		t.Fatal("publication hook preceded durable output", err)
	}
	journalDone := make(chan error, 1)
	go func() { _, _, err := f.journal.Append(record); journalDone <- err }()
	stop := testEntry(t, custodyauthority.Snapshot{AssignmentID: config.Scope.AssignmentID, Sequence: review.AuthorityPosition.Sequence,
		HeadID: review.AuthorityPosition.HeadID}, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(231))
	ownerDone := make(chan error, 1)
	go func() { _, err := service.life.owner.Append(context.Background(), stop); ownerDone <- err }()
	select {
	case err := <-journalDone:
		t.Fatal("source journal escaped publication guard", err)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case err := <-ownerDone:
		t.Fatal("authority escaped publication guard", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-captured; err != nil {
		t.Fatal(err)
	}
	if err := <-journalDone; err != nil {
		t.Fatal(err)
	}
	if err := <-ownerDone; err != nil {
		t.Fatal(err)
	}
	service.hooks = storeHooks{}
	if _, err := service.Capture(t.Context(), id); !errors.Is(err, ErrManagedCustodyReview) {
		t.Fatal("old owner review captured after stop", err)
	}
}

func TestManagedCustodyCommandSourceGuardIncludesConfirmation(t *testing.T) {
	f := newManagedAuditFixture(t)
	config, bootstrap := managedCommandApplyTestConfig(t, f, custodyauthority.Audit)
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	service := managedCommandApplyTestOpen(t, config)
	_, id := managedCommandApplyTestReview(t, service)
	entered, release := make(chan struct{}), make(chan struct{})
	service.life.owner.journal.hooks.at = func(stage string) error {
		if stage == "confirm-before-write" {
			close(entered)
			<-release
		}
		return nil
	}
	applied := make(chan error, 1)
	go func() { _, err := service.Apply(context.Background(), id); applied <- err }()
	<-entered
	advanced := make(chan error, 1)
	record := f.answer(t)
	go func() { _, _, err := f.journal.Append(record); advanced <- err }()
	select {
	case err := <-advanced:
		t.Fatal("journal advanced before authority confirmation", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if err := <-advanced; err != nil {
		t.Fatal(err)
	}
	if state := testCoordination(t, service.life.owner); state.Pending != nil || state.Confirmed.HeadID != config.EntryID {
		t.Fatal("command was not confirmed before guard release", state)
	}
}

func TestManagedCustodyCommandCompleteRejectsArbitraryReceiptEvidence(t *testing.T) {
	f := newManagedAuditFixture(t)
	if _, _, err := f.journal.Append(f.answer(t)); err != nil {
		t.Fatal(err)
	}
	owner := f.serve.archive.f.coordinator
	terminal, err := CaptureCustodyTerminal(t.Context(), owner, CustodyTerminalCaptureConfig{Scope: managedCommandApplyTestScope(f),
		Admission: f.config.Admission, JournalPath: f.config.JournalPath, JournalLimits: f.config.JournalLimits})
	if err != nil {
		t.Fatal(err)
	}
	config := managedCommandApplyTestCompleteConfig(t, f, owner, terminal, f.config.JournalPath)
	draft := config.Entry.Command
	draft.EvidenceID, _ = terminal.Entry.Record.RenewedReceipt.ID()
	config.Entry = managedCommandApplyTestSign(t, draft)
	config.EntryID, _ = config.Entry.ID()
	b, err := config.Entry.CanonicalBytes()
	config.EntryPath = managedCommandApplyTestFile(t, "receipt-is-not-terminal.omcae", b, err)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if service, err := OpenManagedCustodyCommandService(t.Context(), config); err == nil {
		_ = service.Close()
		t.Fatal("arbitrary receipt ID completed terminal ticket")
	}
}
