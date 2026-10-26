package store

import (
	"bytes"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func custodyCommandTestScope(f *managedAuditFixture) CustodyCommandScope {
	return CustodyCommandScope{Assignment: f.serve.archive.policy.Assignments[0], AssignmentID: f.config.AssignmentID,
		Manifest: f.config.Manifest, InitialReceipt: f.config.InitialReceipt, CustodyPolicy: f.config.CustodyPolicy,
		Intent: f.intent, PreviousReceipt: f.config.InitialReceipt}
}

func custodyCommandTestSign(t testing.TB, scope CustodyCommandScope, draft custodyauthority.Command, purpose custodyauthority.Purpose) custodyauthority.Entry {
	t.Helper()
	review, err := CustodyCommandReviewID(scope.Assignment, draft, purpose)
	if err != nil {
		t.Fatal(err)
	}
	command, err := SignReviewedCustodyCommand(scope.Assignment, draft, purpose, review, testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	review, err = CustodyEntryReviewID(scope.Assignment, command, purpose)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := CosignReviewedCustodyCommand(scope.Assignment, command, purpose, review, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestCustodyCommandScopeAndExactAdmissionBuilders(t *testing.T) {
	f := newManagedAuditFixture(t)
	scope := custodyCommandTestScope(f)
	before := testCoordination(t, f.serve.archive.f.coordinator)
	if err := ValidateCustodyCommandScope(scope); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []custodyauthority.Purpose{custodyauthority.Audit, custodyauthority.Serve} {
		admission := f.config.Admission
		var challenge workarchive.CustodyChallenge
		if purpose == custodyauthority.Serve {
			admission, challenge = f.serve.config.Admission, f.serve.challenge
		}
		command := admission.Command
		draft, err := BuildCustodyAdmitCommand(scope, purpose, command.ActorPublicKey,
			custodyauthority.Position{Sequence: command.ExpectedSequence, HeadID: command.ExpectedHead}, challenge)
		if err != nil {
			t.Fatal(err)
		}
		if got := custodyCommandTestSign(t, scope, draft, purpose); got != admission {
			t.Fatal("builder changed signed admission")
		}
	}
	if got := testCoordination(t, f.serve.archive.f.coordinator); got.Authority.HeadID != before.Authority.HeadID {
		t.Fatal("offline builder mutated owner")
	}
	for name, mutate := range map[string]func(*CustodyCommandScope){
		"assignment pin":    func(s *CustodyCommandScope) { s.AssignmentID = testHash(170) },
		"intent assignment": func(s *CustodyCommandScope) { s.Intent.AssignmentID = testHash(170) },
		"consumer":          func(s *CustodyCommandScope) { s.Intent.ConsumerPublicKey = testPublic(170) },
		"auditor":           func(s *CustodyCommandScope) { s.Intent.AuditorPublicKey = testPublic(170) },
		"peer role": func(s *CustodyCommandScope) {
			s.Intent.ReplicaPeerID, _ = transport.PeerIDFromPublicKey(s.Assignment.ReplicaPublicKey[:])
		},
		"predecessor pin":     func(s *CustodyCommandScope) { s.Intent.PriorReceiptID = testHash(170) },
		"initial predecessor": func(s *CustodyCommandScope) { s.Intent.PriorSequence, s.Intent.PriorHeadID = 1, testHash(170) },
		"receipt":             func(s *CustodyCommandScope) { s.PreviousReceipt.Signature[0] ^= 1 },
		"manifest":            func(s *CustodyCommandScope) { s.Manifest.Binding.NetworkID++ },
		"policy":              func(s *CustodyCommandScope) { s.CustodyPolicy.MaximumProofAge++ },
		"policy lifetime":     func(s *CustodyCommandScope) { s.Intent.ExpiresAt++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := scope
			mutate(&changed)
			if err := ValidateCustodyCommandScope(changed); err == nil {
				t.Fatal("accepted substituted scope")
			}
		})
	}
	position := custodyauthority.Position{HeadID: scope.AssignmentID}
	if _, err := BuildCustodyAdmitCommand(scope, custodyauthority.Audit, scope.Intent.ConsumerPublicKey, position, f.serve.challenge); err == nil {
		t.Fatal("audit accepted a signed challenge in place of unsigned intent preparation")
	}
	if _, err := BuildCustodyAdmitCommand(scope, custodyauthority.Serve, scope.Intent.ConsumerPublicKey, position, workarchive.CustodyChallenge{}); err == nil {
		t.Fatal("serve accepted an arbitrary challenge ID without signed challenge")
	}
	changed := scope
	changed.Intent.Nonce = testHash(171)
	if _, err := BuildCustodyAdmitCommand(changed, custodyauthority.Serve, scope.Intent.ConsumerPublicKey, position, f.serve.challenge); err == nil {
		t.Fatal("serve accepted another intent's challenge")
	}
}

func TestCustodyCompleteBuildersBindEachSelectedAdmission(t *testing.T) {
	f := newManagedAuditFixture(t)
	scope := custodyCommandTestScope(f)
	entry, _, err := f.journal.Append(f.answer(t))
	if err != nil {
		t.Fatal(err)
	}
	before := testCoordination(t, f.serve.archive.f.coordinator).Authority
	var ids []types.Hash
	for _, admission := range []custodyauthority.Entry{f.config.Admission, f.serve.config.Admission} {
		terminal := CustodyTerminal{AssignmentID: scope.AssignmentID, Admission: admission, Intent: scope.Intent, Entry: entry}
		if err := terminal.Validate(scope); err != nil {
			t.Fatal(err)
		}
		draft, err := BuildCustodyCompleteCommand(scope, admission, terminal, position(before))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := terminal.ID()
		receiptID, _ := entry.Record.RenewedReceipt.ID()
		ticketID, _ := admission.ID()
		if draft.EvidenceID != id || id == receiptID || draft.TicketID != ticketID || draft.ActorPublicKey != admission.Command.ActorPublicKey || draft.Purpose != 0 || !draft.OperationID.IsZero() {
			t.Fatal("complete did not bind exact envelope and actor")
		}
		ids = append(ids, id)
		_ = custodyCommandTestSign(t, scope, draft, admission.Command.Purpose)
		if _, err := BuildCustodyCompleteCommand(scope, admission, terminal, custodyauthority.Position{Sequence: admission.Command.ExpectedSequence, HeadID: admission.Command.ExpectedHead}); err == nil {
			t.Fatal("completed before selected admission")
		}
		other := f.config.Admission
		if admission == other {
			other = f.serve.config.Admission
		}
		if _, err := BuildCustodyCompleteCommand(scope, other, terminal, position(before)); err == nil {
			t.Fatal("substituted another admission")
		}
		encoded, _ := terminal.CanonicalBytes()
		decoded, err := DecodeCustodyTerminal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, _ := decoded.CanonicalBytes()
		if !bytes.Equal(encoded, roundtrip) || decoded.Entry.Record.Proof.RespondedAt != entry.Record.Proof.RespondedAt {
			t.Fatal("roundtrip refreshed historical evidence")
		}
	}
	if ids[0] == ids[1] {
		t.Fatal("audit/serve terminals collapsed to the same receipt-only commitment")
	}
}

func TestCustodyTerminalVerifiesFullHistoricalProofBeyondSignedShapes(t *testing.T) {
	f := newManagedAuditFixture(t)
	scope := custodyCommandTestScope(f)
	entry, _, err := f.journal.Append(f.answer(t))
	if err != nil {
		t.Fatal(err)
	}
	terminal := CustodyTerminal{AssignmentID: scope.AssignmentID, Admission: f.config.Admission, Intent: scope.Intent, Entry: entry}
	b, err := terminal.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := DecodeCustodyTerminal(b)
	if err != nil {
		t.Fatal(err)
	}
	changed.Entry.Record.Batch.Objects[0].Encoded[0] ^= 1
	// Every original signature still verifies and the bounded envelope remains
	// canonical. Full validation must also bind the exact batch to the proof.
	if _, err := changed.CanonicalBytes(); err != nil {
		t.Fatal("test failed to preserve signed shapes", err)
	}
	if err := changed.Validate(scope); err == nil {
		t.Fatal("accepted signed proof with another batch")
	}
	changed, _ = DecodeCustodyTerminal(b)
	changed.Admission, err = custodyauthority.SignEntry(changed.Admission.Command, testKey(170))
	if err != nil {
		t.Fatal(err)
	}
	if err := changed.Validate(scope); err == nil {
		t.Fatal("accepted another assignment authority")
	}
	changed, _ = DecodeCustodyTerminal(b)
	changed.Intent.ReplicaPeerID = testHash(171)
	if err := changed.Validate(scope); err == nil {
		t.Fatal("accepted another selected peer/intent")
	}
}
