package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestLiveWorkTelemetryClassifiesAdmissionAndSealsHour(t *testing.T) {
	const now uint64 = 1_800_000_000
	root := t.TempDir()
	seed := types.DomainHash("test/omd/live-telemetry-key")
	keyPath := filepath.Join(root, "observer.key")
	if err := os.WriteFile(keyPath, seed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	knownMiner := types.Address(types.DomainHash("test/omd/live-telemetry-miner"))
	knownCluster := types.DomainHash("test/omd/live-telemetry-known-cluster")
	unknownCluster := types.DomainHash("test/omd/live-telemetry-unknown-cluster")
	policyPath := filepath.Join(root, "clusters.txt")
	policyText := "# published before the window\nunknown," + unknownCluster.String() +
		"\nminer," + knownMiner.String() + "," + knownCluster.String() + "\n"
	if err := os.WriteFile(policyPath, []byte(policyText), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := loadClusterPolicyText(policyPath, 8)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := policy.ID()
	document := genesis.Document{
		Version: genesis.Version0, NetworkID: 91, Timestamp: 1_700_000_000,
		Target: types.DomainHash("test/omd/live-telemetry-target"), BlockSubsidy: 10_220,
	}
	profile := workActivationProfile{NetworkID: 91, ActivationHeight: 25}
	manifestPath := filepath.Join(root, "telemetry.omtm")
	pendingPath := filepath.Join(root, "telemetry.pending")
	telemetry, err := openLiveWorkTelemetry(
		document, profile, keyPath, policyPath, policyID, 8, manifestPath, pendingPath, now,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	knownID := types.DomainHash("test/omd/live-telemetry-known-work")
	telemetry.Observe(activation.WorkAdmission{ID: knownID, ObservedAt: now + 1, Miner: knownMiner})
	telemetry.Observe(activation.WorkAdmission{ID: knownID, ObservedAt: now + 2, Miner: knownMiner})
	unknownMiner := types.Address(types.DomainHash("test/omd/live-telemetry-unknown-miner"))
	telemetry.Observe(activation.WorkAdmission{
		ID: types.DomainHash("test/omd/live-telemetry-unknown-work"), ObservedAt: now + 3, Miner: unknownMiner,
	})
	if err := telemetry.collector.Advance(now + calibration.MaximumIntervalSeconds); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	genesisID, _ := document.ID()
	binding := calibration.Binding{
		NetworkID: document.NetworkID, GenesisID: genesisID, ActivationHeight: profile.ActivationHeight,
		ClusterPolicyID: policyID, ClusterComparisonBudget: 8,
	}
	copy(binding.ObserverPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	records, aggregate, err := calibration.LoadFile(manifestPath, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ObservedWork != 2 || records[0].ControlledTieTrials != 0 ||
		records[0].ControlledTieAdoptions != 0 || len(records[0].Clusters) != 2 ||
		aggregate.LargestCoordinatedWork != 1 {
		t.Fatalf("records=%+v aggregate=%+v", records, aggregate)
	}
	if err := telemetry.Close(now + calibration.MaximumIntervalSeconds + 1); err != nil {
		t.Fatal(err)
	}
}

func TestClusterPolicyTextRejectsMissingUnknownAndExpectedIDMismatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bad-policy.txt")
	miner := types.Address(types.DomainHash("test/omd/policy-text-miner"))
	cluster := types.DomainHash("test/omd/policy-text-cluster")
	if err := os.WriteFile(path, []byte("miner,"+miner.String()+","+cluster.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClusterPolicyText(path, 8); err == nil {
		t.Fatal("policy without unknown cluster was accepted")
	}

	unknown := types.DomainHash("test/omd/policy-text-unknown")
	if err := os.WriteFile(path, []byte("unknown,"+unknown.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := types.DomainHash("test/omd/policy-text-key")
	keyPath := filepath.Join(root, "observer.key")
	if err := os.WriteFile(keyPath, seed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	document := genesis.Document{
		Version: genesis.Version0, NetworkID: 91, Timestamp: 1,
		Target: types.DomainHash("test/omd/policy-text-target"), BlockSubsidy: 10_220,
	}
	_, err := openLiveWorkTelemetry(
		document, workActivationProfile{NetworkID: 91, ActivationHeight: 2}, keyPath, path,
		types.DomainHash("test/omd/wrong-policy-id"), 8,
		filepath.Join(root, "manifest"), filepath.Join(root, "pending"), 1_800_000_000,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "policy ID") {
		t.Fatalf("policy ID mismatch error=%v", err)
	}
}

func TestLiveWorkTelemetryWritesControlledTieReceiptFromOrderedAdmissions(t *testing.T) {
	const now uint64 = 1_800_000_000
	root := t.TempDir()
	observerSeed := types.DomainHash("test/omd/live-tie-observer")
	observer := ed25519.NewKeyFromSeed(observerSeed[:])
	observerPath := filepath.Join(root, "observer.key")
	if err := os.WriteFile(observerPath, observerSeed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	unknownCluster := types.DomainHash("test/omd/live-tie-cluster")
	policyPath := filepath.Join(root, "clusters.txt")
	if err := os.WriteFile(policyPath, []byte("unknown,"+unknownCluster.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := loadClusterPolicyText(policyPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := policy.ID()
	document := genesis.Document{
		Version: genesis.Version0, NetworkID: 91, Timestamp: 1_700_000_000,
		Target: types.DomainHash("test/omd/live-tie-target"), BlockSubsidy: 10_220,
	}
	genesisID, _ := document.ID()
	profile := workActivationProfile{NetworkID: 91, ActivationHeight: 25}
	coordinatorSeed := types.DomainHash("test/omd/live-tie-coordinator")
	coordinator := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	planUnsigned := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        profile.ActivationHeight,
		TestedMiner:             types.Address(types.DomainHash("test/omd/live-tie-tested-miner")),
		ControlMiner:            types.Address(types.DomainHash("test/omd/live-tie-control-miner")),
		MaximumPairDelaySeconds: 5,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: now, EndedAt: now + 60, FirstRole: calibration.TieRoleTested,
		}},
	}
	copy(planUnsigned.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	plan, err := calibration.SignTiePlan(coordinator, planUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	planID, _ := plan.ID()
	planPath := filepath.Join(root, "tie-plan.omtp")
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	tieConfig := &liveTieTelemetryConfig{
		PlanPath: planPath, ExpectedPlanID: planID,
		ReceiptPath: filepath.Join(root, "ties.omtr"), PendingPath: filepath.Join(root, "ties.pending"),
	}
	copy(tieConfig.CoordinatorPublicKey[:], coordinator.Public().(ed25519.PublicKey))
	telemetry, err := openLiveWorkTelemetry(
		document, profile, observerPath, policyPath, policyID, 1,
		filepath.Join(root, "telemetry.omtm"), filepath.Join(root, "telemetry.pending"), now, tieConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	parentID := types.DomainHash("test/omd/live-tie-parent")
	testedID := types.DomainHash("test/omd/live-tie-tested-anchor")
	controlID := types.DomainHash("test/omd/live-tie-control-anchor")
	telemetry.Observe(activation.WorkAdmission{
		Sequence: 1, ID: testedID, ParentID: parentID, Height: profile.ActivationHeight,
		ObservedAt: now + 1, Miner: plan.TestedMiner, SelectedID: testedID, Selected: true,
	})
	telemetry.Observe(activation.WorkAdmission{
		Sequence: 2, ID: controlID, ParentID: parentID, Height: profile.ActivationHeight,
		ObservedAt: now + 2, Miner: plan.ControlMiner, SelectedID: testedID,
	})
	status, err := telemetry.TieStatus()
	if err != nil || !status.Complete || status.CompletedTrials != 1 || status.NoPairSlots != 0 {
		t.Fatalf("tie status=%+v err=%v", status, err)
	}
	_, receipts, aggregate, err := calibration.LoadTieReceiptFile(tieConfig.ReceiptPath, plan.Binding())
	if err != nil || len(receipts) != 1 || receipts[0].SelectedAnchorID != testedID ||
		aggregate.TestedAdoptions != 1 {
		t.Fatalf("receipts=%+v aggregate=%+v err=%v", receipts, aggregate, err)
	}
	if err := telemetry.Close(now + 3); err != nil {
		t.Fatal(err)
	}
}

func TestWorkTelemetryTiePlanCommandBuildsBoundedSignedSchedule(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "node")
	if err := runInit([]string{
		"--data", data, "--network", "1002", "--timestamp", "1700000000",
		"--difficulty-bits", "12", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	}); err != nil {
		t.Fatal(err)
	}
	document, err := loadGenesis(data)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, _ := document.ID()
	if err := runWorkEnable([]string{
		"--data", data, "--activation-height", "2", "--confirm-genesis", genesisID.String(),
		"--max-trees", "4", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	}); err != nil {
		t.Fatal(err)
	}
	coordinatorSeed := types.DomainHash("test/omd/tie-plan-command-coordinator")
	coordinatorPath := filepath.Join(root, "coordinator.key")
	if err := os.WriteFile(coordinatorPath, coordinatorSeed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	observerSeed := types.DomainHash("test/omd/tie-plan-command-observer")
	observer := ed25519.NewKeyFromSeed(observerSeed[:])
	tested := types.Address(types.DomainHash("test/omd/tie-plan-command-tested"))
	control := types.Address(types.DomainHash("test/omd/tie-plan-command-control"))
	planPath := filepath.Join(root, "plan.omtp")
	firstStart := unixNow() + 10_000
	arguments := []string{
		"--data", data, "--coordinator-key", coordinatorPath,
		"--observer-public-key", bytesToLowerHex(observer.Public().(ed25519.PublicKey)),
		"--tested-miner", tested.String(), "--control-miner", control.String(),
		"--start", strconv.FormatUint(firstStart, 10), "--slots", "3", "--slot-seconds", "30",
		"--spacing-seconds", "60", "--pair-delay-seconds", "5", "--first-role", "control",
		"--output", planPath,
	}
	if err := runWorkTelemetryTiePlan(arguments); err != nil {
		t.Fatal(err)
	}
	if err := runWorkTelemetryTiePlan(arguments); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("published plan overwrite error=%v", err)
	}
	binding := calibration.TiePlanBinding{
		NetworkID: document.NetworkID, GenesisID: genesisID, ActivationHeight: 2,
	}
	copy(binding.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	coordinator := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	copy(binding.CoordinatorPublicKey[:], coordinator.Public().(ed25519.PublicKey))
	plan, err := calibration.LoadTiePlanFile(planPath, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Slots) != 3 || plan.Slots[0].StartedAt != firstStart ||
		plan.Slots[2].EndedAt != firstStart+150 || plan.MaximumPairDelaySeconds != 5 ||
		plan.TestedMiner != tested || plan.ControlMiner != control || plan.Slots[1].FirstRole != calibration.TieRoleControl {
		t.Fatalf("generated plan=%+v", plan)
	}
	secondSeed := types.DomainHash("test/omd/tie-plan-command-observer-second")
	secondObserver := ed25519.NewKeyFromSeed(secondSeed[:])
	multiPath := filepath.Join(root, "plan-v2.omtp")
	if err := runWorkTelemetryTiePlan([]string{
		"--data", data, "--coordinator-key", coordinatorPath,
		"--observer-public-keys", bytesToLowerHex(observer.Public().(ed25519.PublicKey)) + "," +
			bytesToLowerHex(secondObserver.Public().(ed25519.PublicKey)),
		"--tested-miner", tested.String(), "--control-miner", control.String(),
		"--start", strconv.FormatUint(firstStart, 10), "--slots", "3", "--slot-seconds", "30",
		"--spacing-seconds", "60", "--pair-delay-seconds", "5", "--first-role", "control",
		"--output", multiPath,
	}); err != nil {
		t.Fatal(err)
	}
	multi, err := calibration.LoadTiePlanFile(multiPath, binding)
	if err != nil || multi.Version != calibration.TiePlanVersion2 || len(multi.ObserverPublicKeys) != 2 {
		t.Fatalf("multi-observer plan=%+v err=%v", multi, err)
	}
	secondBinding := binding
	copy(secondBinding.ObserverPublicKey[:], secondObserver.Public().(ed25519.PublicKey))
	if err := multi.Verify(secondBinding); err != nil {
		t.Fatalf("second observer binding: %v", err)
	}
}

func bytesToLowerHex(input []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(input)*2)
	for index, value := range input {
		encoded[index*2] = alphabet[value>>4]
		encoded[index*2+1] = alphabet[value&15]
	}
	return string(encoded)
}
