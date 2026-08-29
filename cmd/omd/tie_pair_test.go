package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
)

func TestPortableTiePairSeparatesMiningFromObserverAdmission(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "node")
	if err := runInit([]string{
		"--data", data, "--network", "1004", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
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
	if err := runWorkMine([]string{"--data", data, "--count", "1"}); err != nil {
		t.Fatal(err)
	}
	baseTip := workTip(t, data)

	observerSeed := types.DomainHash("test/omd/portable-pair-observer")
	observer := ed25519.NewKeyFromSeed(observerSeed[:])
	observerPath := filepath.Join(root, "observer.key")
	if err := os.WriteFile(observerPath, observerSeed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	coordinatorSeed := types.DomainHash("test/omd/portable-pair-coordinator")
	coordinator := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	now := unixNow()
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/omd/portable-pair-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/omd/portable-pair-control")),
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
	planID, _ := plan.ID()
	pairPath := filepath.Join(root, "tie-pair.omtpair")
	common := []string{
		"--data", data, "--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", bytesToLowerHex(coordinator.Public().(ed25519.PublicKey)),
		"--sequence", "1",
	}
	create := append(append([]string(nil), common...),
		"--observer-public-key", bytesToLowerHex(observer.Public().(ed25519.PublicKey)),
		"--output", pairPath, "--wait=false",
	)
	if err := runWorkTelemetryTiePairCreate(create); err != nil {
		t.Fatal(err)
	}
	if tip := workTip(t, data); tip != baseTip {
		t.Fatalf("pair creation mutated coordinator tip=%s want=%s", tip, baseTip)
	}
	encoded, err := readTiePairFile(pairPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := tieproducer.DecodePair(encoded, plan, plan.Binding(), planID)
	if err != nil || decoded.Sequence != 1 {
		t.Fatalf("decoded portable pair=%+v err=%v", decoded, err)
	}
	pairID, err := decoded.ID(plan, plan.Binding(), planID)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "tie-receipts.omtr")
	pendingPath := filepath.Join(root, "tie-receipts.pending")
	admit := append(append([]string(nil), common...),
		"--observer-key", observerPath, "--input", pairPath, "--pair-id", pairID.String(),
		"--receipt-manifest", receiptPath, "--pending", pendingPath,
	)
	if err := runWorkTelemetryTiePairAdmit(admit); err != nil {
		t.Fatal(err)
	}
	_, receipts, aggregate, err := calibration.LoadTieReceiptFile(receiptPath, plan.Binding())
	if err != nil || len(receipts) != 1 || receipts[0].Status != calibration.TieTrialCompleted ||
		receipts[0].FirstObservedAnchorID != receipts[0].ControlAnchorID || !aggregate.Complete {
		t.Fatalf("portable receipts=%+v aggregate=%+v err=%v", receipts, aggregate, err)
	}
	if tip := workTip(t, data); tip == baseTip {
		t.Fatal("observer admission did not advance the persistent WorkGraph tip")
	}
}

func workTip(t testing.TB, data string) types.Hash {
	t.Helper()
	_, store, router, _, err := openWorkNode(data)
	if err != nil {
		t.Fatal(err)
	}
	tip, tipErr := router.Tip()
	closeErr := router.Close()
	storeErr := store.Close()
	if tipErr != nil || closeErr != nil || storeErr != nil {
		t.Fatalf("tip error=%v router_close=%v store_close=%v", tipErr, closeErr, storeErr)
	}
	return tip.ID
}
