package calibration

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/sim/workgraphmodel"
)

func TestThirtyDayManifestFeedsPublicTestnetGate(t *testing.T) {
	records, binding := testThirtyDayChain(t)
	aggregate, err := ValidateManifest(records, binding)
	if err != nil {
		t.Fatal(err)
	}
	config := workgraphmodel.PublicTestnetCalibrationConfig{
		ObservationWindowSeconds: aggregate.EndedAt - aggregate.StartedAt,
		ControlledTieAdoptions:   aggregate.ControlledTieAdoptions,
		ControlledTieTrials:      aggregate.ControlledTieTrials,
		LargestCoordinatedWork:   aggregate.LargestCoordinatedWork,
		ObservedWork:             aggregate.ObservedWork,
		CoordinatedClusters:      uint64(aggregate.Binding.ClusterComparisonBudget),
		EvidenceRecords:          aggregate.RecordCount,
		EvidenceTailID:           aggregate.LastRecordID.String(),
		EvidenceVerified:         true,
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
	const wantTail = "c539440ac6d71c9178b2ab3d7815ed40c9ba502da5b00f33e2282dba7c7113ed"
	const wantDigest = "a31031b36ad9d570cdd0882d419badd8893f091e668192831721e96ac21176a4"
	if aggregate.LastRecordID.String() != wantTail || hex.EncodeToString(digest[:]) != wantDigest {
		t.Fatalf("tail=%s digest=%s", aggregate.LastRecordID, hex.EncodeToString(digest[:]))
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
		record.ControlledTieTrials = 13
		if index < 640 {
			record.ControlledTieTrials++
		}
		record.ControlledTieAdoptions = 2
		if index < 560 {
			record.ControlledTieAdoptions++
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
