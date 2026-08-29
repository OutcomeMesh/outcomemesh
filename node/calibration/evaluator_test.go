package calibration

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/sim/workgraphmodel"
)

func TestThirtyDayManifestFeedsPublicTestnetGate(t *testing.T) {
	records, binding := testThirtyDayChain(t)
	plan, receipts := testThirtyDayTieEvidence(t, binding)
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
	evidence, err := ValidateEvidenceBundle(records, plan, receipts, EvidenceBinding{
		Telemetry: binding, TiePlan: plan.Binding(), TelemetryTailID: telemetryTail,
		PublishedTiePlanID: planID, PublishedTieReceiptID: receiptTail,
	})
	if err != nil {
		t.Fatal(err)
	}
	aggregate := evidence.Telemetry
	config := workgraphmodel.PublicTestnetCalibrationConfig{
		ObservationWindowSeconds: aggregate.EndedAt - aggregate.StartedAt,
		ControlledTieAdoptions:   evidence.ControlledTieAdoptions,
		ControlledTieTrials:      evidence.ControlledTieTrials,
		TieCompletedTrials:       evidence.Tie.CompletedTrials,
		TieNoPairSlots:           evidence.Tie.NoPairSlots,
		LargestCoordinatedWork:   aggregate.LargestCoordinatedWork,
		ObservedWork:             aggregate.ObservedWork,
		CoordinatedClusters:      uint64(aggregate.Binding.ClusterComparisonBudget),
		EvidenceRecords:          aggregate.RecordCount,
		EvidenceTailID:           aggregate.LastRecordID.String(),
		EvidenceVerified:         true,
		TiePlanID:                evidence.Tie.PlanID.String(),
		TieEvidenceReceipts:      evidence.Tie.ReceiptCount,
		TieEvidenceTailID:        evidence.Tie.LastReceiptID.String(),
		TieEvidenceVerified:      true,
		MaximumUpperPPM:          workgraphmodel.PublicTestnetMaximumUpperPPM,
	}
	document, err := workgraphmodel.EvaluatePublicTestnetCalibration(config)
	if err != nil {
		t.Fatal(err)
	}
	if !document.Result.Pass {
		t.Fatalf("thirty-day manifest result = %+v", document.Result)
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const wantTelemetryTail = "8498100edacc5868a99f555f523280e4039aa8bf2be9f1c972e6bf7f687b616c"
	const wantTiePlan = "11e7ebfa5abad07ded642273af2cc19eb9571049a31a2b0b5eea12a1e9014eb7"
	const wantTieTail = "6b3eb05e94add29cf870abeea5464ae28c5c20c206392cc7fae99103aea4044a"
	const wantDigest = "0c74b8a0b46cf4d1f49bfa18e2f57f0cd43a48d7ff08b7c1aae0bd14a7441d80"
	if aggregate.LastRecordID.String() != wantTelemetryTail || planID.String() != wantTiePlan ||
		receiptTail.String() != wantTieTail || hex.EncodeToString(digest[:]) != wantDigest {
		t.Fatalf("telemetry=%s plan=%s tie=%s digest=%s", aggregate.LastRecordID, planID,
			receiptTail, hex.EncodeToString(digest[:]))
	}
}

func testThirtyDayChain(t testing.TB) ([]Record, Binding) {
	t.Helper()
	key := testKey()
	binding := testBinding(key)
	binding.ClusterComparisonBudget = 64
	clusters := make([]ClusterWork, 64)
	for index := range clusters {
		clusters[index] = ClusterWork{
			ID:   types.DomainHash("test/calibration/thirty-day-cluster", []byte{byte(index)}),
			Work: 619,
		}
	}
	clusters[0].Work = 11_000
	clusters[1].Work++
	clusters[2].Work++
	clusters[3].Work++
	slices.SortFunc(clusters, func(left, right ClusterWork) int { return types.CompareHash(left.ID, right.ID) })
	remainingWork := make([]uint64, len(clusters))
	for index := range clusters {
		remainingWork[index] = clusters[index].Work
	}

	records := make([]Record, 0, 30*24)
	var previous types.Hash
	for index := range 30 * 24 {
		record := Record{
			Version: Version0, NetworkID: binding.NetworkID, GenesisID: binding.GenesisID,
			ActivationHeight: binding.ActivationHeight, ClusterPolicyID: binding.ClusterPolicyID,
			ClusterComparisonBudget: binding.ClusterComparisonBudget,
			Sequence:                uint64(index + 1), StartedAt: testStartedAt + uint64(index)*MaximumIntervalSeconds,
			EndedAt: testStartedAt + uint64(index+1)*MaximumIntervalSeconds, PreviousID: previous,
		}
		record.ObservedWork = 69
		if index < 320 {
			record.ObservedWork++
		}
		needed := record.ObservedWork
		for clusterIndex := range clusters {
			if needed == 0 {
				break
			}
			work := min(needed, remainingWork[clusterIndex])
			if work == 0 {
				continue
			}
			record.Clusters = append(record.Clusters, ClusterWork{ID: clusters[clusterIndex].ID, Work: work})
			remainingWork[clusterIndex] -= work
			needed -= work
		}
		if needed != 0 {
			t.Fatalf("interval %d has %d unallocated work observations", index, needed)
		}
		var err error
		record, err = Sign(key, record)
		if err != nil {
			t.Fatal(err)
		}
		previous, err = record.ID()
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	for index, remaining := range remainingWork {
		if remaining != 0 {
			t.Fatalf("cluster %d has %d unallocated work observations", index, remaining)
		}
	}
	return records, binding
}

func testThirtyDayTieEvidence(t testing.TB, binding Binding) (TiePlan, []TieTrialReceipt) {
	t.Helper()
	observer := testKey()
	unsigned := TiePlan{
		Version: TiePlanVersion0, NetworkID: binding.NetworkID, GenesisID: binding.GenesisID,
		ActivationHeight:        binding.ActivationHeight,
		TestedMiner:             types.Address(types.DomainHash("test/calibration/thirty-day-tested-miner")),
		ControlMiner:            types.Address(types.DomainHash("test/calibration/thirty-day-control-miner")),
		MaximumPairDelaySeconds: 1,
		Slots:                   make([]TiePlanSlot, 10_000),
	}
	copy(unsigned.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	for index := range unsigned.Slots {
		startedAt := testStartedAt + uint64(index)*259
		unsigned.Slots[index] = TiePlanSlot{StartedAt: startedAt, EndedAt: startedAt + 2}
	}
	plan, err := SignTiePlan(testTieCoordinatorKey(), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]TieTrialReceipt, len(plan.Slots))
	var previousID types.Hash
	for index, slot := range plan.Slots {
		var sequence [8]byte
		binary.BigEndian.PutUint64(sequence[:], uint64(index)+1)
		tested := types.DomainHash("test/calibration/thirty-day-tested-anchor", sequence[:])
		control := types.DomainHash("test/calibration/thirty-day-control-anchor", sequence[:])
		selected := control
		if index < 2_000 {
			selected = tested
		}
		receipt := TieTrialReceipt{
			Version: TieReceiptVersion0, PlanID: planID, Sequence: uint64(index) + 1,
			Status: TieTrialCompleted, PreviousID: previousID,
			ParentID: types.DomainHash("test/calibration/thirty-day-parent", sequence[:]),
			Height:   binding.ActivationHeight + uint64(index), TestedAnchorID: tested,
			ControlAnchorID: control, TestedObservedAt: slot.StartedAt,
			ControlObservedAt: slot.StartedAt, SelectedAnchorID: selected,
		}
		copy(receipt.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
		if err := receipt.validateShape(plan, planID); err != nil {
			t.Fatal(err)
		}
		copy(receipt.Signature[:], ed25519.Sign(observer, receipt.signatureMessage()))
		receipts[index] = receipt
		previousID = types.DomainHash(tieReceiptIDDomain, receipt.CanonicalBytes())
	}
	return plan, receipts
}
