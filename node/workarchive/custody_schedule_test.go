package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func scheduleProofFixture(t testing.TB) (CustodyScheduleProof, custodyauthority.Assignment, Policy, CustodyReceiptLineage, ReplicaReceipt) {
	t.Helper()
	l, a, selected := receiptLineageFixture(t)
	m, err := DecodeManifest(l.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	old, err := m.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	oldID, _ := old.ID()
	if oldID != a.StatementID {
		t.Fatal("fixture statement changed")
	}
	originalBinding := m.Binding
	m.Version = ManifestVersion2
	m.Binding.RadixActivationHeight = m.Anchor.Height + 10
	next, err := m.ArchiveStatement(2, oldID)
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PrivateKey{custodyTestKey(231), custodyTestKey(232)}
	cp := func(s Statement) Checkpoint { t.Helper(); return signedCheckpoint(t, s, keys) }
	target, _ := m.CanonicalBytes()
	pivot, _ := DecodeCustodyJournalEntry(l.Entries[0])
	head, _ := pivot.ID()
	p := CustodyScheduleProof{AssignmentID: l.AssignmentID, OriginalManifest: l.Manifest, TargetManifest: target, OriginalCheckpoint: cp(old), TargetCheckpoint: cp(next), InitialReceipt: l.InitialReceipt, SelectedReceipt: pivot.Record.RenewedReceipt, JournalSequence: 1, JournalHeadID: head}
	policy := Policy{Binding: originalBinding, TrustedAttestors: sortedPublicKeys(keys), RequiredAttestations: 2}
	return p, a, policy, l, selected
}
func TestCustodyScheduleProofPreservesLineageAndRejectsSubstitution(t *testing.T) {
	p, a, policy, l, selected := scheduleProofFixture(t)
	if err := p.VerifyLineage(t.Context(), a, policy, l, selected); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"assignment", "journal-head", "selected", "initial", "height", "trust", "lineage", "earlier"} {
		t.Run(kind, func(t *testing.T) {
			changed, assignment, trust, lineage, receipt := p, a, policy, l, selected
			switch kind {
			case "assignment":
				assignment.MaximumOperations++
			case "journal-head":
				changed.JournalHeadID = types.Hash{7}
			case "selected":
				changed.SelectedReceipt = selected
			case "initial":
				changed.InitialReceipt = selected
			case "height":
				m, _ := DecodeManifest(changed.TargetManifest)
				m.Binding.RadixActivationHeight++
				changed.TargetManifest, _ = m.CanonicalBytes()
			case "trust":
				trust.TrustedAttestors = [][32]byte{[32]byte(custodyTestKey(233).Public().(ed25519.PublicKey)), [32]byte(custodyTestKey(234).Public().(ed25519.PublicKey))}
			case "lineage":
				lineage.Entries = lineage.Entries[1:]
			case "earlier":
				lineage.Entries = nil
				receipt = lineage.InitialReceipt
			}
			if err := changed.VerifyLineage(t.Context(), assignment, trust, lineage, receipt); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	b, _ := p.CanonicalBytes()
	decoded, err := DecodeCustodyScheduleProof(b)
	if err != nil {
		t.Fatal(err)
	}
	round, _ := decoded.CanonicalBytes()
	if !bytes.Equal(b, round) {
		t.Fatal("proof changed")
	}
	id, _ := p.ID()
	if id.String() != "439e603f95f1d9ecff0372ef0a4150c3848e0a8a366901b85582c85451cdc290" {
		t.Fatal("schedule proof vector changed", id)
	}
}
func TestScheduledJournalRequiresOriginalPrefixOnEveryDecision(t *testing.T) {
	p, a, policy, l, selected := scheduleProofFixture(t)
	manifest, _ := DecodeManifest(l.Manifest)
	path := filepath.Join(t.TempDir(), "journal")
	journal, _, err := OpenOrCreateCustodyJournal(path, manifest, l.InitialReceipt, l.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenScheduledCustodyJournal(t.Context(), path, p, a, policy, l.Policy, DefaultCustodyJournalLimits()); err == nil {
		t.Fatal("empty prefix accepted")
	}
	for _, b := range l.Entries {
		entry, _ := DecodeCustodyJournalEntry(b)
		if _, _, err := journal.Append(entry.Record); err != nil {
			t.Fatal(err)
		}
	}
	scheduled, _, err := OpenScheduledCustodyJournal(t.Context(), path, p, a, policy, l.Policy, DefaultCustodyJournalLimits())
	if err != nil {
		t.Fatal(err)
	}
	d, err := scheduled.AcquireDecision()
	if err != nil {
		t.Fatal(err)
	}
	exported, receipt, err := d.ScheduleLineage(t.Context(), p, a, policy)
	if err != nil || receipt != selected || len(exported.Entries) != 2 {
		t.Fatal("lineage export", err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	// Remove the exact source prefix and replace it with an otherwise valid old
	// empty copy. An already-open scheduled handle must fail, not renew from zero.
	if err = os.Rename(path, path+"-retained"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = OpenOrCreateCustodyJournal(path, manifest, l.InitialReceipt, l.Policy); err != nil {
		t.Fatal(err)
	}
	if d, err := scheduled.AcquireDecision(); err == nil {
		d.Close()
		t.Fatal("existing handle accepted rolled-back journal")
	}
}
func FuzzDecodeCustodySchedule(f *testing.F) {
	p, _, _, _, _ := scheduleProofFixture(f)
	b, _ := p.CanonicalBytes()
	f.Add(b)
	f.Add([]byte{})
	f.Add([]byte("OMWSRCP0"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodeCustodyScheduleProof(b)
		if err != nil {
			return
		}
		out, err := p.CanonicalBytes()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatal("noncanonical proof")
		}
	})
}
func FuzzDecodeScheduledReceipt(f *testing.F) {
	p, _, _, _, selected := scheduleProofFixture(f)
	id, _ := p.ID()
	r := ScheduledReplicaReceipt{ScheduleID: id, Original: selected}
	k := custodyTestKey(61)
	unsigned, _ := r.unsignedBytes()
	message := types.DomainHash("OMESH/workgraph/archive/scheduled-receipt/signature/v0", unsigned)
	copy(r.Signature[:], ed25519.Sign(k, message[:]))
	b, err := r.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte{})
	f.Add([]byte("OMWSRCP0"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeScheduledReplicaReceipt(b)
		if err != nil {
			return
		}
		out, err := r.CanonicalBytes()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatal("noncanonical receipt")
		}
	})
}

func TestScheduledReceiptCanonicalVector(t *testing.T) {
	p, a, policy, l, selected := scheduleProofFixture(t)
	receipt, err := CreateScheduledReplicaReceipt(t.Context(), p, a, policy, l, selected, custodyTestKey(61))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := receipt.ID()
	if id.String() != "0e1a776acaf1e74056c05024bfbdcc04272ad003751237308523d7e0b76be31d" {
		t.Fatal("scheduled receipt vector changed", id)
	}
	b, _ := receipt.CanonicalBytes()
	for i := range b {
		changed := bytes.Clone(b)
		changed[i] ^= 1
		if _, err := DecodeScheduledReplicaReceipt(changed); err == nil {
			t.Fatalf("accepted mutation %d", i)
		}
	}
	if err := receipt.Verify(t.Context(), p, a, policy, l); err != nil {
		t.Fatal(err)
	}
}
