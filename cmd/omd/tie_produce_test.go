package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestWorkTelemetryTieProduceRunsThroughPersistentRouterAndReceiptWriter(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "node")
	if err := runInit([]string{
		"--data", data, "--network", "1003", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	}); err != nil {
		t.Fatal(err)
	}
	document, err := loadGenesis(data)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := runWorkEnable([]string{
		"--data", data, "--activation-height", "2", "--confirm-genesis", genesisID.String(),
		"--max-trees", "4", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	}); err != nil {
		t.Fatal(err)
	}
	if err := runWorkMine([]string{"--data", data, "--count", "1"}); err != nil {
		t.Fatal(err)
	}

	coordinatorSeed := types.DomainHash("test/omd/tie-produce-coordinator")
	coordinator := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	observerSeed := types.DomainHash("test/omd/tie-produce-observer")
	observer := ed25519.NewKeyFromSeed(observerSeed[:])
	observerPath := filepath.Join(root, "observer.key")
	if err := os.WriteFile(observerPath, observerSeed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	now := unixNow()
	if now == 0 {
		t.Fatal("zero wall clock")
	}
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/omd/tie-produce-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/omd/tie-produce-control")),
		MaximumPairDelaySeconds: 10,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: now - 1, EndedAt: now + 59, FirstRole: calibration.TieRoleControl,
		}},
	}
	copy(plan.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	plan, err = calibration.SignTiePlan(coordinator, plan)
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(root, "tie-plan.omtp")
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "tie-receipts.omtr")
	pendingPath := filepath.Join(root, "tie-receipts.pending")
	arguments := []string{
		"--data", data, "--observer-key", observerPath, "--plan", planPath,
		"--plan-id", planID.String(),
		"--coordinator-public-key", bytesToLowerHex(coordinator.Public().(ed25519.PublicKey)),
		"--sequence", "1", "--receipt-manifest", receiptPath, "--pending", pendingPath,
		"--tested-start-nonce", "11", "--control-start-nonce", "29", "--wait=false",
	}
	if err := runWorkTelemetryTieProduce(arguments); err != nil {
		t.Fatal(err)
	}
	loadedPlan, receipts, aggregate, err := calibration.LoadTieReceiptFile(receiptPath, plan.Binding())
	if err != nil {
		t.Fatal(err)
	}
	loadedPlanID, _ := loadedPlan.ID()
	if loadedPlanID != planID || len(receipts) != 1 || receipts[0].Status != calibration.TieTrialCompleted ||
		receipts[0].FirstObservedAnchorID != receipts[0].ControlAnchorID ||
		aggregate.CompletedTrials != 1 || !aggregate.Complete {
		t.Fatalf("plan=%s receipts=%+v aggregate=%+v", loadedPlanID, receipts, aggregate)
	}
	if err := runWorkTelemetryTieProduce(arguments); err == nil {
		t.Fatal("completed sequence was produced twice")
	}
}
