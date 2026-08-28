package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
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
	if _, err := telemetry.collector.ObserveTie(
		now+4, types.DomainHash("test/omd/live-telemetry-tie"), true,
	); err != nil {
		t.Fatal(err)
	}
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
	if len(records) != 1 || records[0].ObservedWork != 2 || records[0].ControlledTieTrials != 1 ||
		records[0].ControlledTieAdoptions != 1 || len(records[0].Clusters) != 2 ||
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
	)
	if err == nil || !strings.Contains(err.Error(), "policy ID") {
		t.Fatalf("policy ID mismatch error=%v", err)
	}
}
