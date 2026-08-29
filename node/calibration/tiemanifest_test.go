package calibration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestTieReceiptManifestPrefixCompleteAndFileRoundTrip(t *testing.T) {
	plan, binding := testTiePlan(t)
	receipts := testTieReceipts(t, plan)
	prefix, err := ValidateTieReceiptManifest(plan, receipts[:2], binding)
	if err != nil {
		t.Fatal(err)
	}
	if prefix.Complete || prefix.ReceiptCount != 2 || prefix.CompletedTrials != 1 ||
		prefix.NoPairSlots != 1 || prefix.TestedAdoptions != 1 || prefix.ConservativeAdoptions != 2 {
		t.Fatalf("prefix aggregate = %+v", prefix)
	}
	if _, _, err := prefix.EvidenceCounters(); !errors.Is(err, ErrManifest) {
		t.Fatalf("prefix evidence error = %v, want ErrManifest", err)
	}
	encoded, aggregate, err := EncodeTieReceiptManifest(plan, receipts, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !aggregate.Complete || aggregate.PlannedSlots != 3 || aggregate.ReceiptCount != 3 ||
		aggregate.CompletedTrials != 2 || aggregate.NoPairSlots != 1 || aggregate.TestedAdoptions != 1 ||
		aggregate.ConservativeAdoptions != 2 || aggregate.FirstReceiptID.IsZero() || aggregate.LastReceiptID.IsZero() {
		t.Fatalf("complete aggregate = %+v", aggregate)
	}
	adoptions, trials, err := aggregate.EvidenceCounters()
	if err != nil || adoptions != 2 || trials != 3 {
		t.Fatalf("evidence counters = %d/%d, %v", adoptions, trials, err)
	}
	decodedPlan, decodedReceipts, decodedAggregate, err := DecodeTieReceiptManifest(encoded, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedPlan.CanonicalBytes(), plan.CanonicalBytes()) ||
		len(decodedReceipts) != len(receipts) || decodedAggregate != aggregate {
		t.Fatalf("decoded aggregate = %+v, want %+v", decodedAggregate, aggregate)
	}

	path := filepath.Join(t.TempDir(), "nested", "tie-receipts.omtr")
	if _, err := SaveTieReceiptFile(path, plan, receipts, binding); err != nil {
		t.Fatal(err)
	}
	_, loaded, loadedAggregate, err := LoadTieReceiptFile(path, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(receipts) || loadedAggregate != aggregate {
		t.Fatalf("loaded aggregate = %+v, want %+v", loadedAggregate, aggregate)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("tie manifest permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestTieReceiptManifestRejectsOmissionReorderingAndWrongLink(t *testing.T) {
	plan, binding := testTiePlan(t)
	receipts := testTieReceipts(t, plan)
	if _, err := ValidateTieReceiptManifest(plan, nil, binding); !errors.Is(err, ErrManifest) {
		t.Fatalf("empty manifest error = %v, want ErrManifest", err)
	}
	omitted := []TieTrialReceipt{receipts[0], receipts[2]}
	if _, err := ValidateTieReceiptManifest(plan, omitted, binding); !errors.Is(err, ErrSequence) {
		t.Fatalf("omitted slot error = %v, want ErrSequence", err)
	}
	reordered := append([]TieTrialReceipt(nil), receipts...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := ValidateTieReceiptManifest(plan, reordered, binding); !errors.Is(err, ErrSequence) {
		t.Fatalf("reordered slot error = %v, want ErrSequence", err)
	}
	broken := append([]TieTrialReceipt(nil), receipts...)
	broken[2].PreviousID = types.DomainHash("test/calibration/tie/wrong-previous")
	var err error
	broken[2], err = SignTieTrialReceipt(testTieObserverKey(), broken[2], plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateTieReceiptManifest(plan, broken, binding); !errors.Is(err, ErrPrevious) {
		t.Fatalf("broken link error = %v, want ErrPrevious", err)
	}
}

func TestTieReceiptManifestDecoderBoundsAndBinding(t *testing.T) {
	plan, binding := testTiePlan(t)
	receipts := testTieReceipts(t, plan)
	encoded, _, err := EncodeTieReceiptManifest(plan, receipts, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeTieReceiptManifest(encoded[:len(encoded)-1], binding); err == nil {
		t.Fatal("truncated tie manifest was accepted")
	}
	if _, _, _, err := DecodeTieReceiptManifest(append(encoded, 0), binding); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing tie manifest error = %v", err)
	}
	foreign := binding
	foreign.ObserverPublicKey[0] ^= 1
	if _, _, _, err := DecodeTieReceiptManifest(encoded, foreign); !errors.Is(err, ErrBinding) {
		t.Fatalf("foreign binding error = %v, want ErrBinding", err)
	}
	if _, _, _, err := DecodeTieReceiptManifest(make([]byte, MaximumTieManifestBytes+1), binding); !errors.Is(err, ErrManifestLimit) {
		t.Fatalf("oversize tie manifest error = %v", err)
	}
}

func TestMaximumTieReceiptManifestFitsPublishedBound(t *testing.T) {
	unsigned := unsignedTiePlan()
	unsigned.Slots = make([]TiePlanSlot, MaximumTiePlanSlots)
	for index := range unsigned.Slots {
		startedAt := testStartedAt + uint64(index)*60
		unsigned.Slots[index] = TiePlanSlot{StartedAt: startedAt, EndedAt: startedAt + 60}
	}
	plan, err := SignTiePlan(testTieCoordinatorKey(), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	observer := testTieObserverKey()
	receipts := make([]TieTrialReceipt, MaximumTiePlanSlots)
	var previousID types.Hash
	for index := range receipts {
		receipt := TieTrialReceipt{
			Version: TieReceiptVersion0, PlanID: planID, Sequence: uint64(index) + 1,
			Status: TieTrialNoPair, PreviousID: previousID,
		}
		copy(receipt.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
		if err := receipt.validateShape(plan, planID); err != nil {
			t.Fatal(err)
		}
		copy(receipt.Signature[:], ed25519.Sign(observer, receipt.signatureMessage()))
		receipts[index] = receipt
		previousID = types.DomainHash(tieReceiptIDDomain, receipt.CanonicalBytes())
	}
	encoded, aggregate, err := EncodeTieReceiptManifest(plan, receipts, plan.Binding())
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaximumTieManifestBytes || !aggregate.Complete ||
		aggregate.ConservativeAdoptions != MaximumTiePlanSlots {
		t.Fatalf("maximum manifest bytes = %d, aggregate = %+v", len(encoded), aggregate)
	}
}

func FuzzDecodeTieReceiptManifestNeverPanics(f *testing.F) {
	plan, binding := testTiePlan(f)
	receipts := testTieReceipts(f, plan)
	encoded, _, err := EncodeTieReceiptManifest(plan, receipts, binding)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _, _ = DecodeTieReceiptManifest(input, binding)
	})
}
