package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestRemoteNegativeAuditDispositionRetainsExecutionObligation(t *testing.T) {
	for _, branch := range []string{"unseen", "unknown", "unverified", "verified"} {
		t.Run(branch, func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := f.auditConfig(t)
			var now atomic.Uint64
			now.Store(f.base.serve.now)
			config.Audit.SessionConfig.Now = now.Load
			a, b, address := openRemoteTerminalPair(t, f, config)
			if branch == "unknown" {
				a.hooks.at = func(stage string) error {
					if stage == "remote-audit-start-confirmed" {
						return errors.New("lost execution outcome")
					}
					return nil
				}
			} else if branch != "unseen" {
				b.hooks.at = func(stage string) error {
					if stage == "remote-data-admitted" {
						now.Store(f.base.serve.now + f.scope.CustodyPolicy.MaximumProofAge + 1000)
					}
					return nil
				}
			}
			if branch != "unseen" {
				if _, err := a.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err == nil {
					t.Fatal("negative branch accepted a result")
				}
			}
			reply, err := a.SealQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), address)
			if err != nil {
				t.Fatal(err)
			}
			var remote *workarchive.CustodyJournalEntry
			if branch == "verified" {
				entry, exists, err := f.base.serve.journal.Head()
				if err != nil || !exists {
					t.Fatal(err)
				}
				remote = &entry
			}
			n, err := a.CaptureNegativeToFile(t.Context(), reply, remote, filepath.Join(t.TempDir(), "negative"))
			if err != nil {
				t.Fatal(err)
			}
			before := testCoordination(t, a.life.owner)
			source, _ := a.journal.State()
			draft, err := BuildRemoteCustodyNegativeAuditCompleteCommand(f.scope, n, before.Confirmed)
			if err != nil {
				t.Fatal(err)
			}
			entry := remoteStoreSign(t, draft, 4)
			// Even a properly signed Serve Complete is forbidden by this adapter.
			bad := draft
			bad.TicketID, _ = f.scope.Worker.Plan.Admission.ID()
			bad.ActorPublicKey = f.scope.Worker.Plan.Admission.Command.ActorPublicKey
			badEntry := remoteStoreSign(t, bad, 4)
			if _, err := a.ApplyNegativeAuditComplete(t.Context(), n, badEntry); err == nil {
				t.Fatal("negative disposition released Serve")
			}
			if !reflect.DeepEqual(before, testCoordination(t, a.life.owner)) {
				t.Fatal("rejection changed authority")
			}
			if branch == "unknown" {
				// A retained but unsubmitted attempt survives a cold restart. Open
				// and review must not submit it; only exact explicit Resume may.
				a.life.owner.mu.Lock()
				err := a.life.owner.journal.prepare(t.Context(), entry)
				a.life.owner.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				if err := a.Close(); err != nil {
					t.Fatal(err)
				}
				a, err = OpenRemoteCustodyAuditRuntime(t.Context(), config)
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				held := testCoordination(t, a.life.owner)
				if held.Confirmed != before.Confirmed || held.Pending == nil || *held.Pending != entry || held.Authority.Pending != 2 {
					t.Fatal("Open implicitly completed the attempt")
				}
				if _, err := a.ApplyNegativeAuditComplete(t.Context(), n, entry); !errors.Is(err, ErrPendingAttempt) {
					t.Fatal("Apply resumed implicitly", err)
				}
				if _, err := a.ResumeNegativeAuditComplete(t.Context(), n, badEntry); err == nil {
					t.Fatal("Resume selected another ticket")
				}
				if _, err := a.ResumeNegativeAuditComplete(t.Context(), n, entry); err != nil {
					t.Fatal(err)
				}
			} else if result, err := a.ApplyNegativeAuditComplete(t.Context(), n, entry); err != nil || !result.Appended {
				t.Fatal("explicit administrative completion", result, err)
			}
			if result, err := a.ApplyNegativeAuditComplete(t.Context(), n, entry); err != nil || result.Appended {
				t.Fatal("exact lost-output retry", result, err)
			}
			if err := a.VerifyNegative(t.Context(), n); err != nil {
				t.Fatal("exact retained observation lost", err)
			}
			after := testCoordination(t, a.life.owner)
			if after.Authority.Pending != 1 || after.Confirmed.Sequence != before.Confirmed.Sequence+1 || after.Pending != nil {
				t.Fatal("Serve obligation disappeared", after)
			}
			for _, op := range after.Authority.Operations {
				if op.Purpose == custodyauthority.Serve && (!op.CompletionID.IsZero() || op.RemoteDrainID.IsZero()) {
					t.Fatal("Serve was completed or its tombstone lost")
				}
			}
			if _, err := a.CaptureTerminal(t.Context(), reply); err == nil {
				t.Fatal("administrative observation became successful custody")
			}
			if _, err := a.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err == nil {
				t.Fatal("settlement re-enabled execution")
			}
			if got, _ := a.journal.State(); !reflect.DeepEqual(got, source) {
				t.Fatal("administrative outcome advanced source or refreshed receipt")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			a, err = OpenRemoteCustodyAuditRuntime(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if err := a.VerifyNegative(t.Context(), n); err != nil {
				t.Fatal("cold review lost remaining obligation", err)
			}
			if got := testCoordination(t, a.life.owner); !reflect.DeepEqual(got, after) {
				t.Fatal("cold review changed state")
			}
			stop := remoteStoreSign(t, custodyauthority.Command{Version: custodyauthority.Version1,
				AssignmentID: after.Authority.AssignmentID, ExpectedSequence: after.Confirmed.Sequence,
				ExpectedHead: after.Confirmed.HeadID, Kind: custodyauthority.Stop, EvidenceID: after.Confirmed.HeadID}, 1)
			stopped, err := a.life.owner.Append(t.Context(), stop)
			if err != nil {
				t.Fatal(err)
			}
			retire := remoteStoreSign(t, custodyauthority.Command{Version: custodyauthority.Version1,
				AssignmentID: after.Authority.AssignmentID, ExpectedSequence: stopped.Snapshot.Sequence,
				ExpectedHead: stopped.Snapshot.HeadID, Kind: custodyauthority.Retire, EvidenceID: stopped.EntryID}, 1)
			if _, err := a.life.owner.Append(t.Context(), retire); !errors.Is(err, custodyauthority.ErrOutstanding) {
				t.Fatal("negative Audit disposition permitted retirement across unresolved Serve", err)
			}
		})
	}
}
