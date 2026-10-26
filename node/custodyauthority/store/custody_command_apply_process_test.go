//go:build integration

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// Real process death exercises the separately durable intent, authority and
// confirmation stores. It does not certify physical power-loss durability.
func TestManagedCustodyCommandProcessRecovery(t *testing.T) {
	for _, purpose := range []custodyauthority.Purpose{custodyauthority.Audit, custodyauthority.Serve} {
		purposeName := map[custodyauthority.Purpose]string{custodyauthority.Audit: "audit", custodyauthority.Serve: "serve"}[purpose]
		for _, kind := range []string{"admit", "complete"} {
			for _, stage := range []string{"intent-after-apply", "authority-after-apply"} {
				t.Run(purposeName+"/"+kind+"/"+stage, func(t *testing.T) {
					f := newManagedAuditFixture(t)
					config, source := managedCommandApplyProcessConfig(t, f, purpose, kind)
					service := managedCommandApplyTestOpen(t, config)
					initial, initialID := managedCommandApplyTestReview(t, service)
					before := testCoordination(t, service.life.owner)
					sourceBefore, err := source.State()
					if err != nil {
						t.Fatal(err)
					}
					if err := service.Close(); err != nil {
						t.Fatal(err)
					}
					managedCommandApplyKillChild(t, config, source, stage)
					decided := stage == "authority-after-apply"
					// Reopen is deliberately repeated: neither observation may append
					// or independently confirm the process's retained attempt.
					for attempt := 0; attempt < 2; attempt++ {
						service = managedCommandApplyTestOpen(t, config)
						review, pendingID := managedCommandApplyTestReview(t, service)
						if !review.Pending || review.PendingEntryID != config.EntryID || review.AlreadyApplied || review.AuthorityPosition != initial.AuthorityPosition {
							t.Fatal("open changed pending intent or confirmation", review)
						}
						if pendingID == initialID {
							t.Fatal("pending attempt reused predecessor review")
						}
						observed := initial.AuthorityPosition
						if decided {
							observed = custodyauthority.Position{Sequence: observed.Sequence + 1, HeadID: config.EntryID}
						}
						if review.ObservedAuthorityPosition != observed {
							t.Fatal("wrong process recovery boundary", review, observed)
						}
						if _, err := service.Apply(t.Context(), initialID); !errors.Is(err, ErrManagedCustodyReview) {
							t.Fatal("stale review applied recovered attempt", err)
						}
						if _, err := service.Resume(t.Context(), initialID); !errors.Is(err, ErrManagedCustodyReview) {
							t.Fatal("stale review resumed recovered attempt", err)
						}
						if _, err := service.Apply(t.Context(), pendingID); !errors.Is(err, ErrPendingAttempt) {
							t.Fatal("normal Apply resumed recovered intent", err)
						}
						current := testCoordination(t, service.life.owner)
						if current.Confirmed != before.Confirmed || current.Pending == nil || *current.Pending != config.Entry || current.Authority.Sequence != observed.Sequence || current.Authority.HeadID != observed.HeadID {
							t.Fatal("recovery observation changed authority", current)
						}
						managedCommandApplyCheckProcessOperations(t, before.Authority, current.Authority, config, decided)
						if sourceAfter, err := source.State(); err != nil || !reflect.DeepEqual(sourceBefore, sourceAfter) {
							t.Fatal("recovery changed selected source evidence", sourceAfter, err)
						}
						if attempt == 0 {
							if err := service.Close(); err != nil {
								t.Fatal(err)
							}
							continue
						}
						result, err := service.Resume(t.Context(), pendingID)
						if err != nil || result.EntryID != config.EntryID || result.Appended == decided || result.Snapshot.Sequence != before.Confirmed.Sequence+1 || result.Snapshot.HeadID != config.EntryID {
							t.Fatal("explicit recovery changed exact signed entry", result, err)
						}
						confirmed := testCoordination(t, service.life.owner)
						if confirmed.Pending != nil || confirmed.Confirmed != (custodyauthority.Position{Sequence: result.Snapshot.Sequence, HeadID: config.EntryID}) {
							t.Fatal("resume did not independently confirm", confirmed)
						}
						managedCommandApplyCheckProcessOperations(t, before.Authority, confirmed.Authority, config, true)
						if err := service.Close(); err != nil {
							t.Fatal(err)
						}
					}
					service = managedCommandApplyTestOpen(t, config)
					review, retryID := managedCommandApplyTestReview(t, service)
					if !review.AlreadyApplied || review.Pending {
						t.Fatal("confirmed recovered entry was not retained history", review)
					}
					retry, err := service.Apply(t.Context(), retryID)
					if err != nil || retry.Appended || retry.EntryID != config.EntryID || retry.Snapshot.Sequence != before.Confirmed.Sequence+1 {
						t.Fatal("recovered lost-output retry repeated transition", retry, err)
					}
				})
			}
		}
	}
}

func managedCommandApplyProcessConfig(t testing.TB, f *managedAuditFixture, purpose custodyauthority.Purpose, kind string) (ManagedCustodyCommandServiceConfig, *workarchive.CustodyJournal) {
	t.Helper()
	journal, journalPath, admission := f.journal, f.config.JournalPath, f.config.Admission
	if purpose == custodyauthority.Serve {
		journal, journalPath, admission = f.serve.journal, f.serve.config.JournalPath, f.serve.config.Admission
	}
	if kind == "admit" {
		config, owner := managedCommandApplyTestConfig(t, f, purpose)
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		return config, journal
	}
	if _, _, err := journal.Append(f.answer(t)); err != nil {
		t.Fatal(err)
	}
	owner := f.serve.archive.f.coordinator
	terminal, err := CaptureCustodyTerminal(t.Context(), owner, CustodyTerminalCaptureConfig{Scope: managedCommandApplyTestScope(f),
		Admission: admission, JournalPath: journalPath, JournalLimits: f.config.JournalLimits})
	if err != nil {
		t.Fatal(err)
	}
	config := managedCommandApplyTestCompleteConfig(t, f, owner, terminal, journalPath)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	return config, journal
}

func managedCommandApplyCheckProcessOperations(t testing.TB, before, current custodyauthority.Snapshot, config ManagedCustodyCommandServiceConfig, decided bool) {
	t.Helper()
	want := make(map[types.Hash]custodyauthority.Operation, len(before.Operations)+1)
	for _, operation := range before.Operations {
		want[operation.TicketID] = operation
	}
	entry := config.Entry.Command
	if decided {
		if entry.Kind == custodyauthority.Admit {
			want[config.EntryID] = custodyauthority.Operation{TicketID: config.EntryID, ConsumerPublicKey: entry.ActorPublicKey, OperationID: entry.OperationID, Purpose: entry.Purpose}
		} else {
			operation, ok := want[entry.TicketID]
			if !ok || !operation.CompletionID.IsZero() {
				t.Fatal("fixture completion did not select original pending ticket")
			}
			operation.CompletionID, operation.EvidenceID = config.EntryID, entry.EvidenceID
			want[entry.TicketID] = operation
		}
	}
	if len(current.Operations) != len(want) {
		t.Fatal("process recovery invented or removed operation", current.Operations, want)
	}
	for _, operation := range current.Operations {
		if expected, ok := want[operation.TicketID]; !ok || operation != expected {
			t.Fatal("process recovery changed ticket/actor/terminal", operation, expected)
		}
	}
}

func managedCommandApplyKillChild(t *testing.T, config ManagedCustodyCommandServiceConfig, source *workarchive.CustodyJournal, stage string) {
	t.Helper()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := managedCommandApplyTestFile(t, "process-config.json", encoded, nil)
	marker := filepath.Join(t.TempDir(), "command-boundary")
	command := exec.Command(os.Args[0], "-test.run=^TestManagedCustodyCommandProcessHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_OWNED_COMMAND_PROCESS_CONFIG="+configPath,
		"OUTCOMEMESH_OWNED_COMMAND_PROCESS_STAGE="+stage, "OUTCOMEMESH_OWNED_COMMAND_PROCESS_MARKER="+marker)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() { exitErr = command.Wait(); close(done) }()
	t.Cleanup(func() { _ = command.Process.Kill(); <-done })
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for reached := false; !reached; {
		select {
		case <-done:
			t.Fatalf("owned command process exited before %s: %v\n%s", stage, exitErr, output.String())
		case <-deadline.C:
			_ = command.Process.Kill()
			<-done
			t.Fatalf("owned command missed %s\n%s", stage, output.String())
		case <-ticker.C:
			_, err := os.Stat(marker)
			reached = err == nil
		}
	}
	if other, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Scope.Assignment, config.Scope.AssignmentID); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("live process lost original ownership", err)
	}
	identities := make(map[string]os.FileInfo)
	for _, path := range []string{filepath.Join(config.AuthorityPath, lockName), filepath.Join(config.AuthorityPinsPath, intentLockName), filepath.Join(config.JournalPath, "journal.lock")} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		identities[path] = info
	}
	// The process is stopped inside its authority transaction. Its selected
	// source decision must still block another local custody decision.
	sourceReleased := make(chan error, 1)
	go func() {
		decision, err := source.AcquireDecision()
		if err == nil {
			_, err = decision.State()
			err = errors.Join(err, decision.Close())
		}
		sourceReleased <- err
	}()
	select {
	case err := <-sourceReleased:
		t.Fatal("process released source before authority confirmation", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	if exitErr == nil {
		t.Fatal("process exited without being killed")
	}
	select {
	case err := <-sourceReleased:
		if err != nil {
			t.Fatal("process death did not release source decision", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("source decision remained locked after process death")
	}
	if _, err := os.Lstat(marker + ".ack"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("process returned command acknowledgement before kill", err)
	}
	for path, before := range identities {
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("process death replaced a permanent ownership inode", path, err)
		}
	}
}

func TestManagedCustodyCommandProcessHelper(t *testing.T) {
	configPath := os.Getenv("OUTCOMEMESH_OWNED_COMMAND_PROCESS_CONFIG")
	if configPath == "" {
		t.Skip("subprocess helper")
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var config ManagedCustodyCommandServiceConfig
	if err := json.Unmarshal(b, &config); err != nil {
		t.Fatal(err)
	}
	service, err := OpenManagedCustodyCommandService(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	stage, marker := os.Getenv("OUTCOMEMESH_OWNED_COMMAND_PROCESS_STAGE"), os.Getenv("OUTCOMEMESH_OWNED_COMMAND_PROCESS_MARKER")
	setCoordinatorHooks(service.life.owner, storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, marker, []byte(at))
			select {}
		}
		return nil
	}})
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Apply(t.Context(), id)
	writeTestFile(t, marker+".ack", nil)
	t.Fatalf("owned command returned before process kill: %v", err)
}
