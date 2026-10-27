package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// This joins the two record machines; it deliberately performs no remote work
// and creates no proof. There is one fresh original authority, and B owns only
// its plan/sealing journal. No authority root or key is copied to B.
func TestRemoteFoundationOriginalOwnerAndWorkerTombstone(t *testing.T) {
	for _, started := range []bool{false, true} {
		name := "unseen_delayed_start"
		if started {
			name = "started_unknown_result"
		}
		t.Run(name, func(t *testing.T) {
			f := newManagedAuditFixture(t)
			a, err := workarchive.CreateRemoteCustodyAuthorityAssignment(f.config.Manifest, f.config.InitialReceipt,
				f.config.CustodyPolicy, testHash(211), testPublic(1),
				[]custodyauthority.Consumer{{PublicKey: testPublic(4), Purposes: custodyauthority.AllPurposes}}, 4, 2,
				testPublic(14), testPublic(15))
			if err != nil {
				t.Fatal(err)
			}
			id, _ := a.ID()
			root := t.TempDir()
			authority, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
			owner, err := CreateCoordinatedAuthority(authority, pins, a, id)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owner.Close() })
			intent := f.intent
			intent.AssignmentID = id
			intentID, _ := intent.ID()
			appendAdmission := func(purpose custodyauthority.Purpose, operation types.Hash) custodyauthority.Entry {
				t.Helper()
				snapshot := testCoordination(t, owner).Authority
				entry := remoteStoreCommand(t, a, snapshot, custodyauthority.Admit, purpose, operation, types.Hash{}, types.Hash{}, 4)
				if result, err := owner.Append(t.Context(), entry); err != nil || !result.Appended {
					t.Fatal("admission", result, err)
				}
				return entry
			}
			audit := appendAdmission(custodyauthority.Audit, intentID)
			challengeID, _ := f.serve.challenge.ID()
			serve := appendAdmission(custodyauthority.Serve, challengeID)
			receiptID, _ := f.config.InitialReceipt.ID()
			plan := remoteworker.Plan{AssignmentID: id, Admission: serve,
				AuthorityTransportPublicKey: testPublic(16), AuditorTransportPublicKey: testPublic(46),
				PriorReceiptID: receiptID, Nonce: testHash(212)}
			if err := plan.Validate(a); err != nil {
				t.Fatal(err)
			}
			planID, _ := plan.ID()
			draft, err := custodyauthority.BuildRemoteBeginCommand(a, serve, planID, testCoordination(t, owner).Confirmed)
			if err != nil {
				t.Fatal(err)
			}
			begin := remoteFoundationCosign(t, a, draft)
			beginID, _ := begin.ID()
			config := remoteworker.Config{Assignment: a, Plan: plan, PlanID: planID, Begin: begin, BeginID: beginID}
			workerRoot := filepath.Join(t.TempDir(), "worker")
			worker, err := remoteworker.Create(t.Context(), workerRoot, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = worker.Close() })
			// A co-signed proposal is not an applied A hold or execution grant.
			if before := testCoordination(t, owner); before.Authority.Remote != nil || before.Confirmed.Sequence != 2 {
				t.Fatal("a proposal changed the original authority", before)
			}
			if started {
				if _, err := owner.Append(t.Context(), begin); err != nil {
					t.Fatal(err)
				}
				if _, err := worker.Start(t.Context(), beginID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := worker.BeginSeal(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := worker.Close(); err != nil {
				t.Fatal(err)
			}
			worker, err = remoteworker.Open(t.Context(), workerRoot, config)
			if err != nil {
				t.Fatal(err)
			}
			if state, err := worker.Snapshot(t.Context()); err != nil || state.Stage != remoteworker.Sealing || state.Started != started {
				t.Fatal("reopen changed the sealing branch", state, err)
			}
			if _, err := worker.Start(t.Context(), beginID); !errors.Is(err, remoteworker.ErrTransition) {
				t.Fatal("a delayed Start escaped the durable sealing record", err)
			}
			disposition := remoteworker.Unseen
			if started {
				disposition = remoteworker.NoResult
			}
			seal, err := worker.CommitSeal(t.Context(), disposition, types.Hash{})
			if err != nil {
				t.Fatal(err)
			}
			sealID, _ := seal.ID()
			if !started {
				// The unseen tombstone is retained BEFORE this delayed application
				// of A's Begin. It must win against a later local Start record too.
				if _, err := owner.Append(t.Context(), begin); err != nil {
					t.Fatal(err)
				}
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			owner, err = OpenCoordinator(authority, pins, a, id)
			if err != nil {
				t.Fatal(err)
			}
			current := testCoordination(t, owner)
			if current.Pending != nil || current.Authority.Remote == nil || current.Authority.Remote.BeginEntryID != beginID {
				t.Fatal("A restart forgot the unresolved original hold", current)
			}
			for _, admission := range []custodyauthority.Entry{audit, serve} {
				ticket, _ := admission.ID()
				called := false
				err := owner.WithOperation(t.Context(), OperationBinding{AssignmentID: id, TicketID: ticket,
					ConsumerPublicKey: testPublic(4), OperationID: admission.Command.OperationID, Purpose: admission.Command.Purpose}, func() error {
					called = true
					return nil
				})
				if !errors.Is(err, custodyauthority.ErrRemoteActive) || called {
					t.Fatal("local effects bypassed the reopened A hold", called, err)
				}
			}
			drainDraft, err := worker.DrainedDraft(t.Context(), sealID, current.Confirmed)
			if err != nil {
				t.Fatal(err)
			}
			if drainDraft.Signature != [64]byte{} || drainDraft.EvidenceID != sealID {
				t.Fatal("worker draft signed work or lost the exact retained tombstone")
			}
			drain := remoteFoundationCosign(t, a, drainDraft)
			drainID, _ := drain.ID()
			if _, err := owner.Append(t.Context(), drain); err != nil {
				t.Fatal(err)
			}
			final := testCoordination(t, owner)
			if final.Pending != nil || final.Authority.Remote != nil || final.Authority.Pending != 2 || final.Confirmed.Sequence != 4 {
				t.Fatal("drain implicitly completed an ordinary operation", final)
			}
			for _, operation := range final.Authority.Operations {
				if !operation.CompletionID.IsZero() || !operation.EvidenceID.IsZero() {
					t.Fatal("an unknown/unseen outcome became successful custody", operation)
				}
				if operation.Purpose == custodyauthority.Serve && (operation.RemoteBeginID != beginID || operation.RemoteDrainID != drainID ||
					operation.RemotePlanID != planID || operation.RemoteTombstoneID != sealID) {
					t.Fatal("A lost its remote history commitment", operation)
				}
			}
			serveID, _ := serve.ID()
			called := false
			err = owner.WithOperation(t.Context(), OperationBinding{AssignmentID: id, TicketID: serveID,
				ConsumerPublicKey: testPublic(4), OperationID: challengeID, Purpose: custodyauthority.Serve}, func() error {
				called = true
				return nil
			})
			if !errors.Is(err, custodyauthority.ErrOperation) || called {
				t.Fatal("a drained remote ticket fell back to a generic local Serve callback", called, err)
			}
			if err := worker.Close(); err != nil {
				t.Fatal(err)
			}
			worker, err = remoteworker.Open(t.Context(), workerRoot, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := worker.Start(t.Context(), beginID); !errors.Is(err, remoteworker.ErrTransition) {
				t.Fatal("a closed attempt restarted after A confirmed its drain", err)
			}
			for _, journal := range []*workarchive.CustodyJournal{f.journal, f.serve.journal} {
				if state, err := journal.State(); err != nil || state.Sequence != 0 {
					t.Fatal("record-only foundation manufactured a custody result", state, err)
				}
			}
		})
	}
}

func remoteFoundationCosign(t testing.TB, assignment custodyauthority.Assignment, draft custodyauthority.Command) custodyauthority.Entry {
	t.Helper()
	review, err := custodyauthority.RemoteCommandReviewID(assignment, draft)
	if err != nil {
		t.Fatal(err)
	}
	command, err := custodyauthority.SignReviewedRemoteCommand(assignment, draft, review, testKey(14))
	if err != nil {
		t.Fatal(err)
	}
	review, err = custodyauthority.RemoteEntryReviewID(assignment, command)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.CosignReviewedRemoteCommand(assignment, command, review, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}
