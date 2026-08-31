package calibration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sort"
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
	foreignObserver := binding
	foreignObserver.TiePlan.ObserverPublicKey[0] ^= 1
	if _, err := ValidateEvidenceBundle(records, plan, receipts, foreignObserver); !errors.Is(err, ErrBinding) {
		t.Fatalf("pooled observer view error = %v, want ErrBinding", err)
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

func TestLegacyUnorderedTieEvidenceRemainsDecodableButCannotPassER5(t *testing.T) {
	records, _, _, currentBinding := testEvidenceBundle(t)
	observer := testKey()
	unsigned := unsignedTiePlan()
	unsigned.Version = TiePlanVersion0
	unsigned.NetworkID = currentBinding.Telemetry.NetworkID
	unsigned.GenesisID = currentBinding.Telemetry.GenesisID
	unsigned.ActivationHeight = currentBinding.Telemetry.ActivationHeight
	unsigned.Slots = unsigned.Slots[:1]
	unsigned.Slots[0].FirstRole = TieRoleUnspecified
	copy(unsigned.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	plan, err := SignTiePlan(testTieCoordinatorKey(), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTiePlan(plan.CanonicalBytes())
	if err != nil || decoded.Version != TiePlanVersion0 {
		t.Fatalf("legacy plan decode=%+v err=%v", decoded, err)
	}
	receiptUnsigned := unsignedCompletedTieReceipt(1, types.Hash{})
	receiptUnsigned.Version = TieReceiptVersion0
	receiptUnsigned.FirstObservedAnchorID = types.Hash{}
	receipt, err := SignTieTrialReceipt(observer, receiptUnsigned, plan)
	if err != nil {
		t.Fatal(err)
	}
	planID, _ := plan.ID()
	receiptTail, _ := receipt.ID(plan)
	legacyBinding := EvidenceBinding{
		Telemetry: currentBinding.Telemetry, TiePlan: plan.Binding(),
		TelemetryTailID:    currentBinding.TelemetryTailID,
		PublishedTiePlanID: planID, PublishedTieReceiptID: receiptTail,
	}
	if _, err := ValidateEvidenceBundle(records, plan, []TieTrialReceipt{receipt}, legacyBinding); !errors.Is(err, ErrEvidence) {
		t.Fatalf("legacy unordered evidence error=%v, want ErrEvidence", err)
	}
}

func TestEvidenceBundleRejectsOneViewFromSharedMultiObserverPlan(t *testing.T) {
	records, _, _, current := testEvidenceBundle(t)
	observer := testKey()
	secondSeed := types.DomainHash("test/calibration/evidence/multi-observer/second")
	second := ed25519.NewKeyFromSeed(secondSeed[:])
	unsigned := unsignedTiePlan()
	unsigned.Version = TiePlanVersion2
	unsigned.NetworkID = current.Telemetry.NetworkID
	unsigned.GenesisID = current.Telemetry.GenesisID
	unsigned.ActivationHeight = current.Telemetry.ActivationHeight
	unsigned.ObserverPublicKey = [ed25519.PublicKeySize]byte{}
	unsigned.ObserverPublicKeys = [][ed25519.PublicKeySize]byte{
		[ed25519.PublicKeySize]byte(observer.Public().(ed25519.PublicKey)),
		[ed25519.PublicKeySize]byte(second.Public().(ed25519.PublicKey)),
	}
	if bytes.Compare(unsigned.ObserverPublicKeys[0][:], unsigned.ObserverPublicKeys[1][:]) > 0 {
		unsigned.ObserverPublicKeys[0], unsigned.ObserverPublicKeys[1] =
			unsigned.ObserverPublicKeys[1], unsigned.ObserverPublicKeys[0]
	}
	plan, err := SignTiePlan(testTieCoordinatorKey(), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	receipts := testTieReceiptsWithKey(t, plan, observer)
	planID, _ := plan.ID()
	receiptTail, _ := receipts[len(receipts)-1].ID(plan)
	binding := current
	binding.TiePlan = plan.Binding()
	copy(binding.TiePlan.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	binding.PublishedTiePlanID = planID
	binding.PublishedTieReceiptID = receiptTail
	if _, err := ValidateEvidenceBundle(records, plan, receipts, binding); !errors.Is(err, ErrEvidence) {
		t.Fatalf("single-view version-2 evidence error=%v", err)
	}
}

func TestMultiObserverEvidenceRequiresAllViewsAndDowngradesDisagreement(t *testing.T) {
	records, plan, keys, receiptViews, expected := multiObserverEvidenceFixture(t)
	aggregate, err := ValidateMultiObserverEvidenceBundle(records, plan, receiptViews, expected)
	if err != nil || aggregate.ControlledTieAdoptions != 2 || aggregate.ControlledTieTrials != 3 ||
		aggregate.Tie.ObserverCount != 2 || aggregate.Tie.DisagreementSlots != 0 ||
		aggregate.Tie.ValidatedReceipts != 6 {
		t.Fatalf("multi-observer evidence=%+v err=%v", aggregate, err)
	}
	if _, err := ValidateMultiObserverEvidenceBundle(records, plan, receiptViews[:1], expected); !errors.Is(err, ErrEvidence) {
		t.Fatalf("selective observer subset error=%v", err)
	}

	receiptViews[1] = resignTieConsensusReceipts(t, plan, keys[1], receiptViews[1], func(receipts []TieTrialReceipt) {
		receipts[2].SelectedAnchorID = receipts[2].TestedAnchorID
	})
	expected.ObserverCheckpoints[1].PublishedReceiptID, _ = receiptViews[1][len(receiptViews[1])-1].ID(plan)
	aggregate, err = ValidateMultiObserverEvidenceBundle(records, plan, receiptViews, expected)
	if err != nil || aggregate.Tie.DisagreementSlots != 1 || aggregate.Tie.CompletedTrials != 1 ||
		aggregate.Tie.NoPairSlots != 2 || aggregate.ControlledTieAdoptions != 3 ||
		aggregate.ControlledTieTrials != 3 {
		t.Fatalf("disagreement evidence=%+v err=%v", aggregate, err)
	}
}

func TestMultiObserverEvidenceFileRoundTrip(t *testing.T) {
	records, plan, _, receiptViews, expected := multiObserverEvidenceFixture(t)
	root := t.TempDir()
	telemetryPath := filepath.Join(root, "telemetry.omtm")
	if _, err := SaveFile(telemetryPath, records, expected.Telemetry); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, len(receiptViews))
	for index, receipts := range receiptViews {
		paths[index] = filepath.Join(root, "ties-"+string(rune('a'+index))+".omtr")
		binding := expected.TiePlan
		binding.ObserverPublicKey = expected.ObserverCheckpoints[index].ObserverPublicKey
		if _, err := SaveTieReceiptFile(paths[index], plan, receipts, binding); err != nil {
			t.Fatal(err)
		}
	}
	aggregate, err := LoadMultiObserverEvidenceFiles(telemetryPath, paths, expected)
	if err != nil || aggregate.Tie.ObserverCount != 2 || aggregate.ControlledTieTrials != 3 {
		t.Fatalf("loaded multi-observer evidence=%+v err=%v", aggregate, err)
	}
	if _, err := LoadMultiObserverEvidenceFiles(telemetryPath, []string{paths[0], paths[0]}, expected); !errors.Is(err, ErrEvidence) {
		t.Fatalf("duplicate manifest path error=%v", err)
	}
}

func multiObserverEvidenceFixture(
	t testing.TB,
) ([]Record, TiePlan, []ed25519.PrivateKey, [][]TieTrialReceipt, MultiEvidenceBinding) {
	t.Helper()
	records, _, _, current := testEvidenceBundle(t)
	type keyedObserver struct {
		public [ed25519.PublicKeySize]byte
		key    ed25519.PrivateKey
	}
	telemetryObserver := testKey()
	secondSeed := types.DomainHash("test/calibration/evidence/multi-consensus/second")
	observers := []keyedObserver{{key: telemetryObserver}, {key: ed25519.NewKeyFromSeed(secondSeed[:])}}
	for index := range observers {
		copy(observers[index].public[:], observers[index].key.Public().(ed25519.PublicKey))
	}
	sort.Slice(observers, func(left, right int) bool {
		return bytes.Compare(observers[left].public[:], observers[right].public[:]) < 0
	})
	unsigned := unsignedTiePlan()
	unsigned.Version = TiePlanVersion2
	unsigned.NetworkID = current.Telemetry.NetworkID
	unsigned.GenesisID = current.Telemetry.GenesisID
	unsigned.ActivationHeight = current.Telemetry.ActivationHeight
	unsigned.ObserverPublicKey = [ed25519.PublicKeySize]byte{}
	unsigned.ObserverPublicKeys = [][ed25519.PublicKeySize]byte{observers[0].public, observers[1].public}
	plan, err := SignTiePlan(testTieCoordinatorKey(), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	planID, _ := plan.ID()
	receiptViews := make([][]TieTrialReceipt, len(observers))
	keys := make([]ed25519.PrivateKey, len(observers))
	checkpoints := make([]TieObserverCheckpoint, len(observers))
	for index, observer := range observers {
		keys[index] = observer.key
		receiptViews[index] = testTieReceiptsWithKey(t, plan, observer.key)
		tail, _ := receiptViews[index][len(receiptViews[index])-1].ID(plan)
		checkpoints[index] = TieObserverCheckpoint{
			ObserverPublicKey: observer.public, PublishedReceiptID: tail,
		}
	}
	tieBinding := plan.Binding()
	tieBinding.ObserverPublicKey = current.Telemetry.ObserverPublicKey
	return records, plan, keys, receiptViews, MultiEvidenceBinding{
		Telemetry: current.Telemetry, TiePlan: tieBinding,
		TelemetryTailID: current.TelemetryTailID, PublishedTiePlanID: planID,
		ObserverCheckpoints: checkpoints,
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
