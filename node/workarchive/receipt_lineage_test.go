package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func receiptLineageFixture(t testing.TB) (CustodyReceiptLineage, custodyauthority.Assignment, ReplicaReceipt) {
	t.Helper()
	f := newCustodyRecordFixture(t)
	public := func(seed byte) [32]byte { return [32]byte(custodyTestKey(seed).Public().(ed25519.PublicKey)) }
	a, err := CreateCustodyAuthorityAssignment(f.manifest, f.receipt, f.policy, types.DomainHash("test/lineage/incarnation"), public(124),
		[]custodyauthority.Consumer{{PublicKey: public(123), Purposes: custodyauthority.AllPurposes}}, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := a.ID()
	manifest, _ := f.manifest.CanonicalBytes()
	lineage := CustodyReceiptLineage{AssignmentID: id, Manifest: manifest, InitialReceipt: f.receipt, Policy: f.policy}
	first := CustodyJournalEntry{Version: CustodyJournalEntryVersion0, Sequence: 1, PreviousReceipt: f.receipt, Record: f.record}
	encoded, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	lineage.Entries = append(lineage.Entries, encoded)
	previousID, _ := first.ID()
	f.receipt = first.Record.RenewedReceipt
	challenge, err := createCustodyChallenge(f.manifest, f.receipt, f.auditorKey, 1_003, 60, 2, 30_000,
		bytes.NewReader(bytes.Repeat([]byte{132}, types.HashSize)))
	if err != nil {
		t.Fatal(err)
	}
	second := CustodyJournalEntry{Version: CustodyJournalEntryVersion0, Sequence: 2, PreviousEntryID: previousID, PreviousReceipt: f.receipt,
		Record: f.answerChallenge(t, challenge, 1_004)}
	encoded, err = second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	lineage.Entries = append(lineage.Entries, encoded)
	return lineage, a, second.Record.RenewedReceipt
}

func TestReceiptLineageCompletePrefixIsHistoricalOnly(t *testing.T) {
	l, a, selected := receiptLineageFixture(t)
	if err := VerifyCustodyReceiptLineage(t.Context(), l, a, l.AssignmentID, selected); err != nil {
		t.Fatal(err)
	}
	if err := selected.verifyAvailabilityTime(ReplicaPolicy{MaximumReceiptAge: 100, MinimumRemainingTerm: 1}, 30_001); err == nil {
		t.Fatal("historical verification became live freshness")
	}
	l.Entries = nil
	if err := VerifyCustodyReceiptLineage(t.Context(), l, a, l.AssignmentID, l.InitialReceipt); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyReceiptLineage(t.Context(), l, a, l.AssignmentID, selected); !errors.Is(err, ErrReceiptLineage) {
		t.Fatal("missing prefix accepted", err)
	}
}

func TestReceiptLineageRejectsGapsSubstitutionAndChangedPolicy(t *testing.T) {
	original, assignment, terminal := receiptLineageFixture(t)
	for _, mode := range []string{"first-missing", "last-missing", "reversed", "duplicate", "corrupt", "initial", "manifest", "policy", "auditors", "assignment", "consumer-budget", "pin", "selected", "entry-budget", "byte-budget"} {
		t.Run(mode, func(t *testing.T) {
			l, a, selected, pin := original, assignment, terminal, original.AssignmentID
			l.Entries = append([][]byte(nil), l.Entries...)
			switch mode {
			case "first-missing":
				l.Entries = l.Entries[1:]
			case "last-missing":
				l.Entries = l.Entries[:1]
			case "reversed":
				l.Entries[0], l.Entries[1] = l.Entries[1], l.Entries[0]
			case "duplicate":
				l.Entries[1] = l.Entries[0]
			case "corrupt":
				l.Entries[0] = bytes.Clone(l.Entries[0])
				l.Entries[0][len(l.Entries[0])-1] ^= 1
			case "initial":
				l.InitialReceipt = terminal
			case "manifest":
				l.Manifest = []byte{0}
			case "policy":
				l.Policy.MaximumProofAge++
			case "auditors":
				l.Policy.TrustedAuditors = nil
			case "assignment":
				a.IncarnationID[0] ^= 1
			case "consumer-budget":
				a.Consumers = make([]custodyauthority.Consumer, custodyauthority.MaximumMembers+1)
			case "pin":
				pin[0] ^= 1
			case "selected":
				selected = l.InitialReceipt
			case "entry-budget":
				l.Entries = make([][]byte, MaximumReceiptLineageEntries+1)
			case "byte-budget":
				chunk := make([]byte, 1<<20)
				l.Entries = make([][]byte, 257)
				for i := range l.Entries {
					l.Entries[i] = chunk
				}
			}
			if err := VerifyCustodyReceiptLineage(t.Context(), l, a, pin, selected); !errors.Is(err, ErrReceiptLineage) {
				t.Fatal(mode, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := VerifyCustodyReceiptLineage(ctx, original, assignment, original.AssignmentID, terminal); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := VerifyCustodyReceiptLineage(nil, original, assignment, original.AssignmentID, terminal); !errors.Is(err, ErrReceiptLineage) {
		t.Fatal(err)
	}
}
