package calibration

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestEvidenceBundleDerivesTiesOnlyFromCompleteRawChain(t *testing.T) {
	records, plan, receipts, binding := testEvidenceBundle(t)
	aggregate, err := ValidateEvidenceBundle(records, plan, receipts, binding)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.ControlledTieAdoptions != 2 || aggregate.ControlledTieTrials != 3 ||
		aggregate.Tie.CompletedTrials != 2 || aggregate.Tie.NoPairSlots != 1 ||
		aggregate.Telemetry.ControlledTieTrials != 0 {
		t.Fatalf("evidence aggregate = %+v", aggregate)
	}

	manual := append([]Record(nil), records...)
	manual[0].ControlledTieAdoptions = 1
	manual[0].ControlledTieTrials = 1
	manual = resignTestRecords(t, manual, testKey())
	manualBinding := binding
	manualBinding.TelemetryTailID, err = manual[len(manual)-1].ID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateEvidenceBundle(manual, plan, receipts, manualBinding); !errors.Is(err, ErrEvidence) {
		t.Fatalf("manual tie counters error = %v, want ErrEvidence", err)
	}

	if _, err := ValidateEvidenceBundle(records, plan, receipts[:2], binding); !errors.Is(err, ErrEvidence) {
		t.Fatalf("incomplete raw chain error = %v, want ErrEvidence", err)
	}
}

func TestEvidenceBundleRequiresPublishedIDsMatchingOneDeployment(t *testing.T) {
	records, plan, receipts, binding := testEvidenceBundle(t)
	wrongTail := binding
	wrongTail.PublishedTieReceiptID[0] ^= 1
	if _, err := ValidateEvidenceBundle(records, plan, receipts, wrongTail); !errors.Is(err, ErrEvidence) {
		t.Fatalf("wrong receipt tail error = %v, want ErrEvidence", err)
	}
	wrongPlan := binding
	wrongPlan.PublishedTiePlanID[0] ^= 1
	if _, err := ValidateEvidenceBundle(records, plan, receipts, wrongPlan); !errors.Is(err, ErrEvidence) {
		t.Fatalf("wrong published plan error = %v, want ErrEvidence", err)
	}
	foreignDeployment := binding
	foreignDeployment.TiePlan.NetworkID++
	if _, err := ValidateEvidenceBundle(records, plan, receipts, foreignDeployment); !errors.Is(err, ErrBinding) {
		t.Fatalf("foreign deployment error = %v, want ErrBinding", err)
	}
}

func TestEvidenceBundleFileRoundTrip(t *testing.T) {
	records, plan, receipts, binding := testEvidenceBundle(t)
	root := t.TempDir()
	telemetryPath := filepath.Join(root, "telemetry.omtm")
	tiePath := filepath.Join(root, "ties.omtr")
	if _, err := SaveFile(telemetryPath, records, binding.Telemetry); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveTieReceiptFile(tiePath, plan, receipts, binding.TiePlan); err != nil {
		t.Fatal(err)
	}
	aggregate, err := LoadEvidenceFiles(telemetryPath, tiePath, binding)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.ControlledTieAdoptions != 2 || aggregate.ControlledTieTrials != 3 {
		t.Fatalf("loaded evidence = %+v", aggregate)
	}
}

func testEvidenceBundle(t testing.TB) ([]Record, TiePlan, []TieTrialReceipt, EvidenceBinding) {
	t.Helper()
	observer := testKey()
	records, telemetryBinding := testChain(t)
	for index := range records {
		records[index].ControlledTieAdoptions = 0
		records[index].ControlledTieTrials = 0
	}
	records = resignTestRecords(t, records, observer)

	unsigned := unsignedTiePlan()
	unsigned.NetworkID = telemetryBinding.NetworkID
	unsigned.GenesisID = telemetryBinding.GenesisID
	unsigned.ActivationHeight = telemetryBinding.ActivationHeight
	copy(unsigned.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	plan, err := SignTiePlan(testTieCoordinatorKey(), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	receipts := testTieReceiptsWithKey(t, plan, observer)
	telemetryTail, err := records[len(records)-1].ID()
	if err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	receiptTail, err := receipts[len(receipts)-1].ID(plan)
	if err != nil {
		t.Fatal(err)
	}
	return records, plan, receipts, EvidenceBinding{
		Telemetry: telemetryBinding, TiePlan: plan.Binding(), TelemetryTailID: telemetryTail,
		PublishedTiePlanID: planID, PublishedTieReceiptID: receiptTail,
	}
}

func resignTestRecords(t testing.TB, records []Record, key ed25519.PrivateKey) []Record {
	t.Helper()
	result := append([]Record(nil), records...)
	var previousID types.Hash
	for index := range result {
		result[index].PreviousID = previousID
		signed, err := Sign(key, result[index])
		if err != nil {
			t.Fatal(err)
		}
		result[index] = signed
		previousID, err = signed.ID()
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}
