package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestRemoteCustodyDrainRetainedAttemptNeedsExplicitReconciledResume(t *testing.T) {
	for _, fault := range []string{"intent-after-apply", "confirm-before-publish"} {
		t.Run(fault, func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := f.auditConfig(t)
			a, b, address := openRemoteTerminalPair(t, f, config)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if _, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err != nil {
				t.Fatal("remote result was not locally accepted before fault", err)
			}
			head, exists, err := a.journal.Head()
			if err != nil || !exists {
				t.Fatal("missing original A result", err)
			}
			acceptedID, _ := head.ID()
			injected := errors.New("injected A drain durability failure")
			a.life.owner.journal.hooks = storeHooks{at: func(stage string) error {
				if stage == fault {
					return injected
				}
				return nil
			}}
			if _, err := a.SealQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address); !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
				t.Fatal("drain fault did not retain uncertainty", err)
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			a, err = OpenRemoteCustodyAuditRuntime(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			before := testCoordination(t, a.life.owner)
			if before.Pending == nil || before.Pending.Command.Kind != custodyauthority.RemoteDrained ||
				before.Pending.Command.OperationID != f.scope.Worker.BeginID || before.Confirmed.Sequence != 3 ||
				before.Confirmed.HeadID != f.scope.Worker.BeginID || before.Authority.Pending != 2 {
				t.Fatal("Open confirmed/replaced the pending Drain", before)
			}
			pending := *before.Pending
			worker, err := b.worker.Snapshot(ctx)
			if err != nil || worker.Stage != remoteworker.Sealed || worker.Pending != 0 || worker.Seal == nil ||
				worker.Seal.Disposition != remoteworker.RetainedResult || worker.Seal.ResultID != acceptedID {
				t.Fatal("B did not retain its exact already sealed result", worker, err)
			}
			if _, err := a.SealQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("Seal silently resumed its retained Drain", err)
			}
			if _, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("pending Drain reopened Start", err)
			}
			if _, err := a.ResumeBegin(ctx); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("Begin recovery accepted a pending Drain", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, a.life.owner)) {
				t.Fatal("rejected actions mutated the retained attempt")
			}
			response, err := a.ResumeDrainQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address)
			if err != nil || response.Status != remotewire.StatusDrained || response.Drain != pending.Command ||
				response.Seal != *worker.Seal {
				t.Fatal("explicit reconciliation changed B's sealed Drain", response, err)
			}
			after := testCoordination(t, a.life.owner)
			drainID, _ := pending.ID()
			if after.Pending != nil || after.Authority.Remote != nil || after.Authority.Pending != 2 ||
				after.Confirmed.Sequence != 4 || after.Confirmed.HeadID != drainID {
				t.Fatal("reconciled Drain lost its exact independent confirmation", after)
			}
			if _, err := a.ResumeDrainQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address); !errors.Is(err, ErrNoAttempt) {
				t.Fatal("Drain resume invented another authority attempt", err)
			}
			terminal, err := a.CaptureTerminal(ctx, response)
			terminalEntryID, entryErr := terminal.Entry.ID()
			if err != nil || entryErr != nil || terminalEntryID != acceptedID {
				t.Fatal("drain recovery lost original local A acceptance", err, entryErr)
			}
			if !reflect.DeepEqual(after, testCoordination(t, a.life.owner)) {
				t.Fatal("capture/retry completed tickets or changed authority")
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRemoteCustodyCompleteRetainedConfirmationResumesOnlyExactResult(t *testing.T) {
	for _, selected := range []custodyauthority.Purpose{custodyauthority.Audit, custodyauthority.Serve} {
		name := "audit"
		if selected == custodyauthority.Serve {
			name = "serve"
		}
		t.Run(name, func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := f.auditConfig(t)
			a, b, address := openRemoteTerminalPair(t, f, config)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if _, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err != nil {
				t.Fatal(err)
			}
			response, err := a.SealQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address)
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := a.CaptureTerminal(ctx, response)
			if err != nil {
				t.Fatal(err)
			}
			auditID, _ := f.audit.ID()
			serveID, _ := f.scope.Worker.Plan.Admission.ID()
			ticket, other := auditID, serveID
			if selected == custodyauthority.Serve {
				ticket, other = serveID, auditID
			}
			position := testCoordination(t, a.life.owner).Confirmed
			draft, err := BuildRemoteCustodyCompleteCommand(f.scope, terminal, ticket, position)
			if err != nil {
				t.Fatal(err)
			}
			entry := remoteStoreSign(t, draft, 4)
			injected := errors.New("injected A Complete confirmation failure")
			a.life.owner.journal.hooks = storeHooks{at: func(stage string) error {
				if stage == "confirm-before-publish" {
					return injected
				}
				return nil
			}}
			if _, err := a.ApplyComplete(ctx, terminal, entry); !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
				t.Fatal("Complete confirmation fault lost uncertainty", err)
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			// Previously accepted evidence remains historical. Recovery must
			// neither refresh its proof time nor demand another network proof.
			config.Audit.SessionConfig.Now = func() uint64 { return f.base.serve.now + f.scope.CustodyPolicy.MaximumProofAge + 1000 }
			a, err = OpenRemoteCustodyAuditRuntime(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			before := testCoordination(t, a.life.owner)
			if before.Pending == nil || *before.Pending != entry || before.Confirmed != position ||
				before.Authority.Sequence != position.Sequence+1 || before.Authority.Pending != 1 {
				t.Fatal("Open silently confirmed/replaced Complete", before)
			}
			if _, err := a.ApplyComplete(ctx, terminal, entry); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("ordinary Apply implicitly resumed Complete", err)
			}
			wrongDraft, err := BuildRemoteCustodyCompleteCommand(f.scope, terminal, other, position)
			if err != nil {
				t.Fatal(err)
			}
			wrong := remoteStoreSign(t, wrongDraft, 4)
			if _, err := a.ResumeComplete(ctx, terminal, wrong); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("ResumeComplete changed the selected ticket", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, a.life.owner)) {
				t.Fatal("wrong completion changed retained attempt")
			}
			commit, err := a.ResumeComplete(ctx, terminal, entry)
			entryID, _ := entry.ID()
			if err != nil || commit.Appended || commit.EntryID != entryID {
				t.Fatal("exact Complete resume did not settle prior decision", commit, err)
			}
			after := testCoordination(t, a.life.owner)
			if after.Pending != nil || after.Authority.Pending != 1 || after.Authority.Remote != nil ||
				after.Confirmed.Sequence != position.Sequence+1 || after.Confirmed.HeadID != entryID {
				t.Fatal("completion resume changed unrelated pending ticket", after)
			}
			for _, operation := range after.Authority.Operations {
				if operation.TicketID == ticket && operation.CompletionID != entryID || operation.TicketID == other && !operation.CompletionID.IsZero() {
					t.Fatal("completion was not independent per ticket", operation)
				}
			}
			if _, err := a.ResumeComplete(ctx, terminal, entry); !errors.Is(err, ErrNoAttempt) {
				t.Fatal("repeated resume invented work", err)
			}
			retry, err := a.ApplyComplete(ctx, terminal, entry)
			if err != nil || retry.Appended || retry.EntryID != entryID || !reflect.DeepEqual(after.Authority, retry.Snapshot) ||
				!reflect.DeepEqual(after, testCoordination(t, a.life.owner)) {
				t.Fatal("exact historical retry changed completion", retry, err)
			}
			accepted, exists, err := a.journal.Head()
			originalID, _ := terminal.Entry.ID()
			acceptedID, idErr := accepted.ID()
			if err != nil || idErr != nil || !exists || acceptedID != originalID || accepted.Record.Proof.RespondedAt != terminal.Entry.Record.Proof.RespondedAt {
				t.Fatal("completion recovery refreshed/replaced accepted proof", err, idErr)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
