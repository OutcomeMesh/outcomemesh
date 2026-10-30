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

func scheduledAvailabilityFixture(t testing.TB) (ScheduledAvailabilityBundle, Checkpoint, Policy, ReplicaPolicy, []custodyauthority.Assignment, []ScheduledReplicaEvidence) {
	t.Helper()
	p, a, policy, l, selected := scheduleProofFixture(t)
	r, err := CreateScheduledReplicaReceipt(t.Context(), p, a, policy, l, selected, custodyTestKey(61))
	if err != nil {
		t.Fatal(err)
	}
	initial := p.InitialReceipt
	initial.ReplicaPublicKey = [32]byte(custodyTestKey(62).Public().(ed25519.PublicKey))
	initial.LocationID = types.Hash{62}
	initial.Signature = [64]byte{}
	message, err := initial.signatureMessage()
	if err != nil {
		t.Fatal(err)
	}
	copy(initial.Signature[:], ed25519.Sign(custodyTestKey(62), message))
	m, _ := DecodeManifest(l.Manifest)
	second, err := CreateCustodyAuthorityAssignment(m, initial, l.Policy, types.Hash{63}, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending)
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := second.ID()
	q := p
	q.AssignmentID = sid
	q.InitialReceipt = initial
	q.SelectedReceipt = initial
	q.JournalSequence = 0
	q.JournalHeadID = types.Hash{}
	ll := CustodyReceiptLineage{AssignmentID: sid, Manifest: l.Manifest, InitialReceipt: initial, Policy: l.Policy}
	rr, err := CreateScheduledReplicaReceipt(t.Context(), q, second, policy, ll, initial, custodyTestKey(62))
	if err != nil {
		t.Fatal(err)
	}
	rp := ReplicaPolicy{TrustedReplicas: sortedPublicKeys([]ed25519.PrivateKey{custodyTestKey(61), custodyTestKey(62)}), RequiredReplicas: 2, MaximumReceiptAge: 1000, MinimumRemainingTerm: 100}
	aa := []custodyauthority.Assignment{a, second}
	ee := []ScheduledReplicaEvidence{{p, l}, {q, ll}}
	b, err := CreateScheduledAvailabilityBundle(t.Context(), p.TargetCheckpoint, policy, rp, aa, ee, []ScheduledReplicaReceipt{r, rr}, 1005)
	if err != nil {
		t.Fatal(err)
	}
	return b, p.TargetCheckpoint, policy, rp, aa, ee
}

func TestScheduledAvailabilityBindsQuorumAndOriginalReceiptTimes(t *testing.T) {
	b, target, old, policy, a, e := scheduledAvailabilityFixture(t)
	raw, err := b.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeScheduledAvailabilityBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := decoded.CanonicalBytes()
	if !bytes.Equal(raw, again) {
		t.Fatal("noncanonical roundtrip")
	}
	id, _ := b.ID()
	if id.String() != "a6d73873151636c75628811875244828d0d523aa818797378d3ed7294135e33e" {
		t.Fatal("scheduled availability vector changed", id)
	}
	if err := decoded.Verify(t.Context(), target, old, policy, a, e, 1005); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"duplicate-key", "duplicate-location", "duplicate-scope", "duplicate-assignment", "untrusted", "missing-lineage", "old-selected", "target-height", "target-manifest", "wrong-proof", "attestors", "expired", "future", "remaining", "age"} {
		t.Run(mutation, func(t *testing.T) {
			changed := b
			changed.Receipts = append([]ScheduledReplicaReceipt(nil), b.Receipts...)
			aa := append([]custodyauthority.Assignment(nil), a...)
			ee := append([]ScheduledReplicaEvidence(nil), e...)
			trust := old
			rp := policy
			cp := target
			now := uint64(1005)
			switch mutation {
			case "duplicate-key":
				changed.Receipts[1] = changed.Receipts[0]
			case "duplicate-location":
				changed.Receipts[1].Original.LocationID = changed.Receipts[0].Original.LocationID
			case "duplicate-scope":
				changed.Receipts[1].ScheduleID = changed.Receipts[0].ScheduleID
			case "duplicate-assignment":
				aa[1] = aa[0]
			case "untrusted":
				rp.TrustedReplicas = sortedPublicKeys([]ed25519.PrivateKey{custodyTestKey(63), custodyTestKey(64)})
			case "missing-lineage":
				ee[0].Lineage.Entries = nil
			case "old-selected":
				ee[0].Proof.SelectedReceipt = ee[0].Proof.InitialReceipt
			case "target-height":
				changed.RadixActivationHeight++
			case "target-manifest":
				changed.ManifestID = types.Hash{99}
			case "wrong-proof":
				ee[1] = ee[0]
			case "attestors":
				trust.TrustedAttestors = nil
			case "expired":
				now = 30001
			case "future":
				now = 1
			case "remaining":
				rp.MinimumRemainingTerm = MaximumReplicaTermSeconds
			case "age":
				rp.MaximumReceiptAge = 1
			}
			if err := changed.Verify(t.Context(), cp, trust, rp, aa, ee, now); err == nil {
				t.Fatal("accepted", mutation)
			}
		})
	}
	for i := range raw {
		if _, err := DecodeScheduledAvailabilityBundle(raw[:i]); err == nil {
			t.Fatalf("truncation %d", i)
		}
	}
	if _, err := DecodeScheduledAvailabilityBundle(append(raw, 0)); err == nil {
		t.Fatal("trailing data")
	}
}

func FuzzDecodeScheduledAvailabilityBundle(f *testing.F) {
	b, _, _, _, _, _ := scheduledAvailabilityFixture(f)
	raw, _ := b.CanonicalBytes()
	f.Add(raw)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := DecodeScheduledAvailabilityBundle(raw)
		if err == nil {
			encoded, err := b.CanonicalBytes()
			if err != nil || !bytes.Equal(raw, encoded) {
				t.Fatal("accepted noncanonical bundle")
			}
		}
	})
}

func TestScheduledAvailabilityRejectsValidDuplicateLocationAndAggregateOverflow(t *testing.T) {
	b, target, old, policy, a, e := scheduledAvailabilityFixture(t)
	// Re-sign a complete valid second vote at the first replica's location. A
	// signature-only check would accept it; distinct-location quorum must not.
	q := e[1].Proof
	r := q.InitialReceipt
	r.LocationID = e[0].Proof.InitialReceipt.LocationID
	r.Signature = [64]byte{}
	message, err := r.signatureMessage()
	if err != nil {
		t.Fatal(err)
	}
	copy(r.Signature[:], ed25519.Sign(custodyTestKey(62), message))
	m, _ := DecodeManifest(e[1].Lineage.Manifest)
	second := a[1]
	second, err = CreateCustodyAuthorityAssignment(m, r, e[1].Lineage.Policy, second.IncarnationID, second.AuthorityPublicKey, second.Consumers, second.MaximumOperations, second.MaximumPending)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := second.ID()
	q.AssignmentID = id
	q.InitialReceipt = r
	q.SelectedReceipt = r
	l := e[1].Lineage
	l.AssignmentID = id
	l.InitialReceipt = r
	wrapped, err := CreateScheduledReplicaReceipt(t.Context(), q, second, old, l, r, custodyTestKey(62))
	if err != nil {
		t.Fatal(err)
	}
	for i := range b.Receipts {
		if b.Receipts[i].Original.ReplicaPublicKey == r.ReplicaPublicKey {
			b.Receipts[i] = wrapped
		}
	}
	if _, err := b.CanonicalBytes(); err == nil {
		t.Fatal("two valid votes for the same location counted twice")
	}
	b, target, old, policy, a, e = scheduledAvailabilityFixture(t)
	block := make([]byte, 1<<20)
	e[0].Lineage.Entries = make([][]byte, 257)
	for i := range e[0].Lineage.Entries {
		e[0].Lineage.Entries[i] = block
	}
	if err := b.Verify(t.Context(), target, old, policy, a, e, 1005); err == nil {
		t.Fatal("aggregate evidence bound ignored")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.Verify(ctx, target, old, policy, a, e, 1005); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
