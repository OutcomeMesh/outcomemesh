package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	telemetry "github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestRunEvidenceModeUsesRawTieReceiptsAndPublishedCheckpoints(t *testing.T) {
	const startedAt uint64 = 1_800_000_000
	observerSeed := types.DomainHash("test/omcalibrate/observer")
	observer := ed25519.NewKeyFromSeed(observerSeed[:])
	coordinatorSeed := types.DomainHash("test/omcalibrate/coordinator")
	coordinator := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	binding := telemetry.Binding{
		NetworkID: 91, GenesisID: types.DomainHash("test/omcalibrate/genesis"),
		ActivationHeight: 25, ClusterPolicyID: types.DomainHash("test/omcalibrate/policy"),
		ClusterComparisonBudget: 1,
	}
	copy(binding.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	clusterID := types.DomainHash("test/omcalibrate/cluster")
	record, err := telemetry.Sign(observer, telemetry.Record{
		Version: telemetry.Version0, NetworkID: binding.NetworkID, GenesisID: binding.GenesisID,
		ActivationHeight: binding.ActivationHeight, ClusterPolicyID: binding.ClusterPolicyID,
		ClusterComparisonBudget: binding.ClusterComparisonBudget,
		Sequence:                1, StartedAt: startedAt, EndedAt: startedAt + telemetry.MaximumIntervalSeconds,
		ObservedWork: 1, Clusters: []telemetry.ClusterWork{{ID: clusterID, Work: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	telemetryTail, err := record.ID()
	if err != nil {
		t.Fatal(err)
	}
	planUnsigned := telemetry.TiePlan{
		Version: telemetry.TiePlanVersion0, NetworkID: binding.NetworkID, GenesisID: binding.GenesisID,
		ActivationHeight:        binding.ActivationHeight,
		TestedMiner:             types.Address(types.DomainHash("test/omcalibrate/tested-miner")),
		ControlMiner:            types.Address(types.DomainHash("test/omcalibrate/control-miner")),
		MaximumPairDelaySeconds: 5,
		Slots:                   []telemetry.TiePlanSlot{{StartedAt: startedAt + 10, EndedAt: startedAt + 20}},
	}
	copy(planUnsigned.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	plan, err := telemetry.SignTiePlan(coordinator, planUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	tested := types.DomainHash("test/omcalibrate/tested-anchor")
	control := types.DomainHash("test/omcalibrate/control-anchor")
	receipt, err := telemetry.SignTieTrialReceipt(observer, telemetry.TieTrialReceipt{
		Version: telemetry.TieReceiptVersion0, Sequence: 1, Status: telemetry.TieTrialCompleted,
		ParentID: types.DomainHash("test/omcalibrate/parent"), Height: binding.ActivationHeight,
		TestedAnchorID: tested, ControlAnchorID: control,
		TestedObservedAt: startedAt + 12, ControlObservedAt: startedAt + 14,
		SelectedAnchorID: control,
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	receiptTail, err := receipt.ID(plan)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	manifestPath := filepath.Join(root, "telemetry.omtm")
	tiePath := filepath.Join(root, "ties.omtr")
	if _, err := telemetry.SaveFile(manifestPath, []telemetry.Record{record}, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetry.SaveTieReceiptFile(tiePath, plan, []telemetry.TieTrialReceipt{receipt}, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"--manifest", manifestPath, "--tie-manifest", tiePath,
		"--network-id", strconv.FormatUint(uint64(binding.NetworkID), 10),
		"--genesis-id", binding.GenesisID.String(),
		"--activation-height", strconv.FormatUint(binding.ActivationHeight, 10),
		"--cluster-policy-id", binding.ClusterPolicyID.String(),
		"--coordinated-clusters", "1",
		"--observer-public-key", bytesToHex(binding.ObserverPublicKey[:]),
		"--coordinator-public-key", bytesToHex(plan.CoordinatorPublicKey[:]),
		"--evidence-tail-id", telemetryTail.String(),
		"--tie-plan-id", planID.String(), "--tie-tail-id", receiptTail.String(),
		"--tie-adoptions", "1", "--tie-trials", "999",
	}
	var encoded bytes.Buffer
	if err := run(arguments, &encoded); err != nil {
		t.Fatal(err)
	}
	var result output
	if err := json.Unmarshal(encoded.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	config := result.Document.Config
	if config.ControlledTieAdoptions != 0 || config.ControlledTieTrials != 1 ||
		!config.EvidenceVerified || !config.TieEvidenceVerified || !result.Document.Result.EvidencePass ||
		result.TieManifest == nil || result.TieManifest.ReceiptCount != 1 ||
		result.TieManifest.LastReceiptID != receiptTail.String() {
		t.Fatalf("verified output = %+v", result)
	}
}

func bytesToHex(input []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(input)*2)
	for index, value := range input {
		result[index*2] = digits[value>>4]
		result[index*2+1] = digits[value&0x0f]
	}
	return string(result)
}
