//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieexchange"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

const (
	helperProcessEnvironment          = "OUTCOMEMESH_TEST_HELPER_PROCESS"
	tieCampaignCrashModeEnvironment   = "OUTCOMEMESH_TEST_TIE_CAMPAIGN_CRASH_MODE"
	tieCampaignCrashMarkerEnvironment = "OUTCOMEMESH_TEST_TIE_CAMPAIGN_CRASH_MARKER"
)

// TestProcessQUICRestartSoak is intentionally behind the integration build tag.
// OUTCOMEMESH_SOAK_CYCLES may raise the default three restart/sync cycles to 100.
func TestProcessQUICRestartSoak(t *testing.T) {
	cycles := 3
	if text := os.Getenv("OUTCOMEMESH_SOAK_CYCLES"); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 1 || parsed > 100 {
			t.Fatalf("OUTCOMEMESH_SOAK_CYCLES must be 1..100, got %q", text)
		}
		cycles = parsed
	}
	root := t.TempDir()
	dataA := root + "/node-a"
	dataB := root + "/node-b"
	keyA := root + "/node-a.key"
	keyB := root + "/node-b.key"
	writeProcessKey(t, keyA, "a")
	writeProcessKey(t, keyB, "b")
	for _, data := range []string{dataA, dataB} {
		runProcessCommand(t, 20*time.Second,
			"init", "--data", data, "--network", "20260827", "--timestamp", "1700000000",
			"--difficulty-bits", "0", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
		)
	}

	for cycle := 0; cycle < cycles; cycle++ {
		runProcessCommand(t, 20*time.Second, "mine", "--data", dataA, "--count", "2")
		server, peerID, address := startQUICServerProcess(t, dataA, keyA)
		runProcessCommand(t, 30*time.Second,
			"sync-quic", "--data", dataB, "--key", keyB, "--peer", address, "--peer-id", peerID,
		)
		runProcessCommand(t, 20*time.Second, "verify", "--data", dataB)
		stopQUICServerProcess(t, server)
	}

	statusA := runProcessCommand(t, 20*time.Second, "status", "--data", dataA)
	statusB := runProcessCommand(t, 20*time.Second, "status", "--data", dataB)
	wantHeight := fmt.Sprintf("height=%d", cycles*2)
	if !strings.Contains(statusA, wantHeight) || !strings.Contains(statusB, wantHeight) {
		t.Fatalf("process nodes did not converge to %s\nnode-a: %s\nnode-b: %s", wantHeight, statusA, statusB)
	}
}

func TestProcessWorkGraphActivationQUICRestart(t *testing.T) {
	root := t.TempDir()
	dataA := root + "/work-node-a"
	dataB := root + "/work-node-b"
	dataC := root + "/work-node-c"
	dataD := root + "/legacy-incompatible-node"
	keyA := root + "/work-node-a.key"
	keyB := root + "/work-node-b.key"
	keyC := root + "/work-node-c.key"
	keyD := root + "/legacy-incompatible-node.key"
	writeProcessKey(t, keyA, "work-a")
	writeProcessKey(t, keyB, "work-b")
	writeProcessKey(t, keyC, "work-c")
	writeProcessKey(t, keyD, "work-incompatible")
	for _, data := range []string{dataA, dataB, dataC, dataD} {
		runProcessCommand(t, 20*time.Second,
			"init", "--data", data, "--network", "20260828", "--timestamp", "1700000000",
			"--difficulty-bits", "12", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
		)
	}
	document, err := loadGenesis(dataA)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{dataA, dataB, dataC} {
		runProcessCommand(t, 20*time.Second,
			"work-enable", "--data", data, "--activation-height", "2",
			"--confirm-genesis", genesisID.String(), "--max-trees", "4",
			"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
		)
	}
	runProcessCommand(t, 30*time.Second, "work-mine", "--data", dataA, "--count", "5")
	server, peerID, address := startWorkQUICServerProcess(t, dataA, keyA)
	runProcessCommand(t, 30*time.Second,
		"work-sync-quic", "--data", dataB, "--key", keyB, "--peer", address, "--peer-id", peerID,
	)
	runProcessCommand(t, 30*time.Second,
		"work-sync-quic", "--data", dataC, "--key", keyC, "--peer", address, "--peer-id", peerID,
	)
	serverC, peerIDC, addressC := startWorkQUICServerProcess(t, dataC, keyC)
	incompatible, peerIDD, addressD := startQUICServerProcess(t, dataD, keyD)
	relayProcessWorkShares(t, dataB, keyB, address, peerID, 2)
	relayProcessWorkShares(t, dataB, keyB, addressC, peerIDC, 2)
	minedQUIC := runProcessCommand(t, 40*time.Second,
		"work-mine-quic", "--data", dataB, "--key", keyB, "--peer", address,
		"--peer-id", peerID, "--peer", addressC, "--peer-id", peerIDC,
		"--peer", addressD, "--peer-id", peerIDD,
		"--count", "1", "--relay-every", "128",
	)
	if fields := outputFields(minedQUIC, "work_mined_quic"); fields["height"] != "6" || fields["relayed_shares"] == "" ||
		fields["pending_relay"] == "" || fields["gossip_shares"] == "" || fields["gossip_copies"] == "" ||
		fields["anchor_notify_queued"] != "3" ||
		!strings.HasSuffix(fields["relay_peers"], "/3") {
		t.Fatalf("cooperative miner output is incomplete: %s", minedQUIC)
	}
	if strings.Count(minedQUIC, "work_peerbook_refresh") != 3 ||
		strings.Count(minedQUIC, "work_peerbook_refresh peer_id=") != 3 ||
		strings.Count(minedQUIC, "result=ok") < 2 {
		t.Fatalf("activation peerbook refresh did not cover compatible and legacy peers: %s", minedQUIC)
	}
	if fields := outputFields(minedQUIC, "work_mining_quic_done"); fields["peers"] != "3" ||
		fields["notifications"] != "2/3" || fields["notification_failures"] != "1" {
		t.Fatalf("multi-peer notification summary is incomplete: %s", minedQUIC)
	}
	stopQUICServerProcess(t, server)
	stopQUICServerProcess(t, serverC)
	stopQUICServerProcess(t, incompatible)
	if output := server.stderr.String(); !strings.Contains(output, "work_relay") || !strings.Contains(output, "accepted=2") ||
		!strings.Contains(output, "chain_notification") || !strings.Contains(output, "height=6") {
		t.Fatalf("versioned server did not admit shares and the notified anchor: %s", output)
	}
	if output := serverC.stderr.String(); !strings.Contains(output, "work_relay") || !strings.Contains(output, "accepted=2") ||
		!strings.Contains(output, "chain_notification") || !strings.Contains(output, "height=6") {
		t.Fatalf("second versioned server did not admit shares and the notified anchor: %s", output)
	}
	runProcessCommand(t, 20*time.Second, "work-verify", "--data", dataB)
	runProcessCommand(t, 20*time.Second, "work-verify", "--data", dataA)
	runProcessCommand(t, 20*time.Second, "work-verify", "--data", dataC)

	statusA := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataA)
	statusB := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataB)
	statusC := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataC)
	fieldsA := outputFields(statusA, "work_status")
	fieldsB := outputFields(statusB, "work_status")
	fieldsC := outputFields(statusC, "work_status")
	if fieldsA["height"] != "6" || fieldsB["height"] != "6" || fieldsA["tip"] == "" ||
		fieldsA["tip"] != fieldsB["tip"] || fieldsA["state"] != fieldsB["state"] ||
		fieldsA["cumulative_work"] != fieldsB["cumulative_work"] || fieldsC["height"] != "6" ||
		fieldsA["tip"] != fieldsC["tip"] || fieldsA["state"] != fieldsC["state"] ||
		fieldsA["cumulative_work"] != fieldsC["cumulative_work"] {
		t.Fatalf("versioned process nodes did not converge\nnode-a: %s\nnode-b: %s\nnode-c: %s", statusA, statusB, statusC)
	}
	if output, err := runProcessCommandError(20*time.Second, "mine", "--data", dataB, "--count", "1"); err == nil || !strings.Contains(output, "use the explicit work-* command") {
		t.Fatalf("legacy mutation guard err=%v output=%s", err, output)
	}
	statusAfterRestart := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataB)
	if fields := outputFields(statusAfterRestart, "work_status"); fields["tip"] != fieldsA["tip"] || fields["trees"] == "0/4" {
		t.Fatalf("versioned restart lost forest state: %s", statusAfterRestart)
	}
	statusCAfterRestart := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataC)
	if fields := outputFields(statusCAfterRestart, "work_status"); fields["tip"] != fieldsA["tip"] || fields["trees"] == "0/4" {
		t.Fatalf("second versioned restart lost forest state: %s", statusCAfterRestart)
	}
}

func relayProcessWorkShares(
	t testing.TB,
	data string,
	key string,
	peerAddress string,
	peerIDText string,
	count int,
) {
	t.Helper()
	_, store, router, _, err := openWorkNode(data)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	defer router.Close()
	manager, err := workround.NewManager(router, unixNow, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	round, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	miner := types.Address(types.DomainHash("test/omd/process-work-relay-miner"))
	for index := 0; index < count; index++ {
		template, err := round.Template(miner, inclusion)
		if err != nil {
			t.Fatal(err)
		}
		for nonce := uint64(0); ; {
			share, _, err := workgraph.Mine(context.Background(), template, nonce)
			if err != nil {
				t.Fatal(err)
			}
			hard, err := workgraph.MeetsAnchor(share)
			if err != nil {
				t.Fatal(err)
			}
			if !hard {
				if _, err := round.Add(share); err != nil {
					t.Fatal(err)
				}
				break
			}
			nonce = share.Nonce + 1
		}
	}
	privateKey, err := loadPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	host, err := libp2ptransport.New(ctx, privateKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	expected, err := parseHash(peerIDText)
	if err != nil {
		t.Fatal(err)
	}
	stream, remote, err := host.OpenWorkGraphStream(ctx, peerAddress, &expected)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := round.Relay(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	if remote != expected || stats.Accepted != count || stats.Rejected != 0 {
		t.Fatalf("WorkGraph process relay remote=%s stats=%+v", remote, stats)
	}
}

func TestProcessControlledTieProducerRecoversWaitingState(t *testing.T) {
	root := t.TempDir()
	data := root + "/tie-node"
	observerPath := root + "/observer.key"
	planPath := root + "/tie-plan.omtp"
	receiptPath := root + "/tie-receipts.omtr"
	pendingPath := root + "/tie-receipts.pending"
	runProcessCommand(t, 20*time.Second,
		"init", "--data", data, "--network", "20260830", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(data)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", data, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", data, "--count", "1")

	observerSeed := types.DomainHash("test/process/tie-producer/observer")
	observer := ed25519.NewKeyFromSeed(observerSeed[:])
	if err := os.WriteFile(observerPath, observerSeed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	coordinatorSeed := types.DomainHash("test/process/tie-producer/coordinator")
	coordinator := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	startedAt := unixNow() + 2
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-producer/tested")),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-producer/control")),
		MaximumPairDelaySeconds: 10,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: startedAt, EndedAt: startedAt + 60, FirstRole: calibration.TieRoleControl,
		}},
	}
	copy(plan.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	plan, err = calibration.SignTiePlan(coordinator, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"work-telemetry-tie-produce", "--data", data, "--observer-key", observerPath,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", bytesToLowerHex(coordinator.Public().(ed25519.PublicKey)),
		"--sequence", "1", "--receipt-manifest", receiptPath, "--pending", pendingPath,
	}
	if output, err := runProcessCommandError(500*time.Millisecond, arguments...); err == nil {
		t.Fatalf("waiting producer unexpectedly completed: %s", output)
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("waiting producer did not persist restart state: %v", err)
	}
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatalf("waiting producer created a premature receipt: %v", err)
	}
	output := runProcessCommand(t, 30*time.Second, arguments...)
	fields := outputFields(output, "work_tie_produced")
	if fields["plan"] != planID.String() || fields["sequence"] != "1" ||
		fields["first_role"] != "control" || fields["receipt_tail"] == "" {
		t.Fatalf("incomplete controlled-tie process output: %s", output)
	}
	_, receipts, aggregate, err := calibration.LoadTieReceiptFile(receiptPath, plan.Binding())
	if err != nil || len(receipts) != 1 || receipts[0].Status != calibration.TieTrialCompleted ||
		receipts[0].FirstObservedAnchorID != receipts[0].ControlAnchorID || !aggregate.Complete {
		t.Fatalf("process receipts=%+v aggregate=%+v err=%v", receipts, aggregate, err)
	}
	if output, err := runProcessCommandError(10*time.Second, arguments...); err == nil {
		t.Fatalf("duplicate process run succeeded: %s", output)
	}
}

func TestProcessTiePairQUICReachesIndependentV2ObserversAndRecoversAck(t *testing.T) {
	root := t.TempDir()
	coordinatorData := root + "/coordinator"
	observerDataA := root + "/observer-a"
	observerDataB := root + "/observer-b"
	planPath := root + "/tie-plan-v2.omtp"
	pairPath := root + "/tie-pair.omtpair"
	coordinatorTransportKey := root + "/coordinator-transport.key"
	rogueTransportKey := root + "/rogue-transport.key"
	observerTransportKeyA := root + "/observer-a-transport.key"
	observerTransportKeyB := root + "/observer-b-transport.key"
	observerReceiptKeyA := root + "/observer-a-receipt.key"
	observerReceiptKeyB := root + "/observer-b-receipt.key"
	writeProcessKey(t, coordinatorTransportKey, "tie-pair-coordinator-transport")
	writeProcessKey(t, rogueTransportKey, "tie-pair-rogue-transport")
	writeProcessKey(t, observerTransportKeyA, "tie-pair-observer-a-transport")
	writeProcessKey(t, observerTransportKeyB, "tie-pair-observer-b-transport")
	writeProcessKey(t, observerReceiptKeyA, "tie-pair-observer-a-receipt")
	writeProcessKey(t, observerReceiptKeyB, "tie-pair-observer-b-receipt")

	runProcessCommand(t, 20*time.Second,
		"init", "--data", coordinatorData, "--network", "20260831", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(coordinatorData)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", coordinatorData, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", coordinatorData, "--count", "1")
	parentID := workTip(t, coordinatorData)
	if err := os.CopyFS(observerDataA, os.DirFS(coordinatorData)); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(observerDataB, os.DirFS(coordinatorData)); err != nil {
		t.Fatal(err)
	}

	observerKeyA, err := loadPrivateKey(observerReceiptKeyA)
	if err != nil {
		t.Fatal(err)
	}
	observerKeyB, err := loadPrivateKey(observerReceiptKeyB)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPlanSeed := types.DomainHash("test/process/tie-pair-v2-plan-coordinator")
	coordinatorPlanKey := ed25519.NewKeyFromSeed(coordinatorPlanSeed[:])
	var observerA, observerB [ed25519.PublicKeySize]byte
	copy(observerA[:], observerKeyA.Public().(ed25519.PublicKey))
	copy(observerB[:], observerKeyB.Public().(ed25519.PublicKey))
	observers := [][ed25519.PublicKeySize]byte{observerA, observerB}
	if bytes.Compare(observers[0][:], observers[1][:]) > 0 {
		observers[0], observers[1] = observers[1], observers[0]
	}
	startedAt := unixNow() + 1
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion2, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-pair-v2-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-pair-v2-control")),
		MaximumPairDelaySeconds: 10,
		ObserverPublicKeys:      observers,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: startedAt, EndedAt: startedAt + 180, FirstRole: calibration.TieRoleTested,
		}},
	}
	plan, err = calibration.SignTiePlan(coordinatorPlanKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPublicKey := bytesToLowerHex(coordinatorPlanKey.Public().(ed25519.PublicKey))
	observerPublicKeyA := bytesToLowerHex(observerKeyA.Public().(ed25519.PublicKey))
	observerPublicKeyB := bytesToLowerHex(observerKeyB.Public().(ed25519.PublicKey))
	created := runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-pair-create", "--data", coordinatorData,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observerPublicKeyA,
		"--sequence", "1", "--output", pairPath,
	)
	pairID := outputFields(created, "work_tie_pair_created")["pair"]
	if pairID == "" || workTip(t, coordinatorData) != parentID {
		t.Fatalf("pair creation output=%s", created)
	}
	coordinatorTransportID := processTransportPeerID(t, coordinatorTransportKey)
	receiverA, observerTransportIDA, addressA := startTieReceiverProcess(t,
		observerDataA, observerTransportKeyA, observerReceiptKeyA, coordinatorTransportID.String(),
		planPath, planID.String(), coordinatorPublicKey, pairID,
	)
	receiverB, observerTransportIDB, addressB := startTieReceiverProcess(t,
		observerDataB, observerTransportKeyB, observerReceiptKeyB, coordinatorTransportID.String(),
		planPath, planID.String(), coordinatorPublicKey, pairID,
	)

	if output, err := runProcessCommandError(10*time.Second,
		"work-telemetry-tie-pair-send-quic", "--key", rogueTransportKey,
		"--peer", addressA, "--observer-peer-id", observerTransportIDA,
		"--observer-public-key", observerPublicKeyA, "--plan-id", planID.String(),
		"--sequence", "1", "--pair-id", pairID, "--input", pairPath, "--timeout", "5s",
	); err == nil {
		t.Fatalf("unlisted coordinator transport was accepted: %s", output)
	}
	sentA, sendErrA := runProcessCommandError(30*time.Second,
		"work-telemetry-tie-pair-send-quic", "--key", coordinatorTransportKey,
		"--peer", addressA, "--observer-peer-id", observerTransportIDA,
		"--observer-public-key", observerPublicKeyA, "--plan-id", planID.String(),
		"--sequence", "1", "--pair-id", pairID, "--input", pairPath,
	)
	if sendErrA != nil {
		_ = waitTieReceiverProcess(t, receiverA)
		t.Fatalf("send observer A: %v output=%s", sendErrA, sentA)
	}
	sentB, sendErrB := runProcessCommandError(30*time.Second,
		"work-telemetry-tie-pair-send-quic", "--key", coordinatorTransportKey,
		"--peer", addressB, "--observer-peer-id", observerTransportIDB,
		"--observer-public-key", observerPublicKeyB, "--plan-id", planID.String(),
		"--sequence", "1", "--pair-id", pairID, "--input", pairPath,
	)
	if sendErrB != nil {
		_ = waitTieReceiverProcess(t, receiverB)
		t.Fatalf("send observer B: %v output=%s", sendErrB, sentB)
	}
	receivedA := waitTieReceiverProcess(t, receiverA)
	receivedB := waitTieReceiverProcess(t, receiverB)
	sentFieldsA := outputFields(sentA, "work_tie_pair_sent")
	sentFieldsB := outputFields(sentB, "work_tie_pair_sent")
	receivedFieldsA := outputFields(receivedA, "work_tie_pair_received")
	receivedFieldsB := outputFields(receivedB, "work_tie_pair_received")
	if sentFieldsA["receipt_tail"] == "" || sentFieldsB["receipt_tail"] == "" ||
		sentFieldsA["receipt_tail"] != receivedFieldsA["receipt_tail"] ||
		sentFieldsB["receipt_tail"] != receivedFieldsB["receipt_tail"] ||
		receivedFieldsA["recovered"] != "false" || receivedFieldsB["recovered"] != "false" {
		t.Fatalf("incomplete multi-observer exchange\nsent-a: %s\nreceived-a: %s\nsent-b: %s\nreceived-b: %s",
			sentA, receivedA, sentB, receivedB)
	}
	if sentFieldsA["receipt_tail"] == sentFieldsB["receipt_tail"] {
		t.Fatal("independent observer signatures unexpectedly produced one receipt ID")
	}

	recovery, recoveryTransportID, recoveryAddress := startTieReceiverProcess(t,
		observerDataA, observerTransportKeyA, observerReceiptKeyA, coordinatorTransportID.String(),
		planPath, planID.String(), coordinatorPublicKey, pairID,
	)
	if recoveryTransportID != observerTransportIDA {
		t.Fatalf("observer transport identity changed across restart: %s != %s", recoveryTransportID, observerTransportIDA)
	}
	recoveredSend := runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-pair-send-quic", "--key", coordinatorTransportKey,
		"--peer", recoveryAddress, "--observer-peer-id", recoveryTransportID,
		"--observer-public-key", observerPublicKeyA, "--plan-id", planID.String(),
		"--sequence", "1", "--pair-id", pairID, "--input", pairPath,
	)
	recoveredReceive := waitTieReceiverProcess(t, recovery)
	if fields := outputFields(recoveredReceive, "work_tie_pair_received"); fields["recovered"] != "true" ||
		fields["receipt_tail"] != sentFieldsA["receipt_tail"] ||
		outputFields(recoveredSend, "work_tie_pair_sent")["receipt_tail"] != sentFieldsA["receipt_tail"] {
		t.Fatalf("lost-ack recovery changed receipt\nsend: %s\nreceive: %s", recoveredSend, recoveredReceive)
	}

	bindingA := plan.Binding()
	bindingA.ObserverPublicKey = observerA
	bindingB := plan.Binding()
	bindingB.ObserverPublicKey = observerB
	_, receiptsA, aggregateA, errA := calibration.LoadTieReceiptFile(defaultTieReceiptPath(observerDataA), bindingA)
	_, receiptsB, aggregateB, errB := calibration.LoadTieReceiptFile(defaultTieReceiptPath(observerDataB), bindingB)
	if errA != nil || errB != nil || len(receiptsA) != 1 || len(receiptsB) != 1 ||
		!aggregateA.Complete || !aggregateB.Complete ||
		receiptsA[0].TestedAnchorID != receiptsB[0].TestedAnchorID ||
		receiptsA[0].ControlAnchorID != receiptsB[0].ControlAnchorID ||
		receiptsA[0].ObserverPublicKey == receiptsB[0].ObserverPublicKey ||
		workTip(t, observerDataA) != workTip(t, observerDataB) {
		t.Fatalf("independent receipts diverged receipts-a=%+v aggregate-a=%+v err-a=%v receipts-b=%+v aggregate-b=%+v err-b=%v",
			receiptsA, aggregateA, errA, receiptsB, aggregateB, errB)
	}
}

func TestProcessTieCampaignReceiverRecoversAckAfterKillBeforeConfirmation(t *testing.T) {
	root := t.TempDir()
	coordinatorData := root + "/coordinator"
	observerData := root + "/observer"
	planPath := root + "/tie-plan.omtp"
	pairPath := root + "/tie-pair.omtpair"
	publicationDirectory := root + "/published"
	confirmationDirectory := root + "/confirmed"
	coordinatorTransportKeyPath := root + "/coordinator-transport.key"
	observerTransportKeyPath := root + "/observer-transport.key"
	observerReceiptKeyPath := root + "/observer-receipt.key"
	writeProcessKey(t, coordinatorTransportKeyPath, "tie-campaign-coordinator-transport")
	writeProcessKey(t, observerTransportKeyPath, "tie-campaign-observer-transport")
	writeProcessKey(t, observerReceiptKeyPath, "tie-campaign-observer-receipt")
	runProcessCommand(t, 20*time.Second,
		"init", "--data", coordinatorData, "--network", "20260832", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(coordinatorData)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", coordinatorData, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", coordinatorData, "--count", "1")
	if err := os.CopyFS(observerData, os.DirFS(coordinatorData)); err != nil {
		t.Fatal(err)
	}
	observerReceiptKey, err := loadPrivateKey(observerReceiptKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPlanSeed := types.DomainHash("test/process/tie-campaign-plan-coordinator")
	coordinatorPlanKey := ed25519.NewKeyFromSeed(coordinatorPlanSeed[:])
	startedAt := unixNow() + 1
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-campaign-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-campaign-control")),
		MaximumPairDelaySeconds: 10,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: startedAt, EndedAt: startedAt + 180, FirstRole: calibration.TieRoleTested,
		}},
	}
	copy(plan.ObserverPublicKey[:], observerReceiptKey.Public().(ed25519.PublicKey))
	plan, err = calibration.SignTiePlan(coordinatorPlanKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPublicKey := bytesToLowerHex(coordinatorPlanKey.Public().(ed25519.PublicKey))
	observerPublicKey := bytesToLowerHex(observerReceiptKey.Public().(ed25519.PublicKey))
	created := runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-pair-create", "--data", coordinatorData,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observerPublicKey,
		"--sequence", "1", "--output", pairPath,
	)
	pairID, err := parseHash(outputFields(created, "work_tie_pair_created")["pair"])
	if err != nil {
		t.Fatalf("pair creation output=%s err=%v", created, err)
	}
	checkpoint, err := calibration.SignTiePairCheckpoint(
		coordinatorPlanKey, plan, plan.Binding(), planID, 1, pairID,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointID, err := checkpoint.ID(plan, plan.Binding(), planID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(publicationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationDirectory+"/0000000001.omtcp", checkpoint.CanonicalBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationDirectory+"/0000000001.published", []byte(checkpointID.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	coordinatorTransportID := processTransportPeerID(t, coordinatorTransportKeyPath)
	receiver, observerTransportIDText, observerAddress := startTieCampaignReceiverProcess(
		t, observerData, observerTransportKeyPath, observerReceiptKeyPath,
		coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
		publicationDirectory, confirmationDirectory,
	)
	observerTransportID, err := parseHash(observerTransportIDText)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := readTiePairFile(pairPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorTransportKey, err := loadPrivateKey(coordinatorTransportKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClient := context.WithTimeout(context.Background(), 30*time.Second)
	client, err := libp2ptransport.New(
		clientContext, coordinatorTransportKey, libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		cancelClient()
		t.Fatal(err)
	}
	stream, _, err := client.OpenTiePairStream(clientContext, observerAddress, &observerTransportID)
	if err != nil {
		_ = client.Close()
		cancelClient()
		t.Fatal(err)
	}
	exchangeBinding := tieexchange.Binding{PlanID: planID, PairID: pairID, Sequence: 1}
	if err := tieexchange.WriteRequest(stream, tieexchange.Request{
		Binding: exchangeBinding, Artifact: artifact,
	}); err != nil {
		t.Fatal(err)
	}
	acknowledgement, err := tieexchange.ReadAcknowledgement(
		stream, exchangeBinding, hashFromPublicKey(observerReceiptKey.Public().(ed25519.PublicKey)),
	)
	if err != nil || acknowledgement.ReceiptTail.IsZero() {
		t.Fatalf("pre-kill acknowledgement=%+v err=%v", acknowledgement, err)
	}
	_ = stream.Reset()
	_ = client.Close()
	cancelClient()
	killTieReceiverProcess(t, receiver)
	if _, err := os.Stat(confirmationDirectory + "/0000000001.confirmed"); !os.IsNotExist(err) {
		t.Fatalf("confirmation marker exists before coordinator confirmation: %v", err)
	}

	restarted, restartedTransportID, restartedAddress := startTieCampaignReceiverProcess(
		t, observerData, observerTransportKeyPath, observerReceiptKeyPath,
		coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
		publicationDirectory, confirmationDirectory,
	)
	if restartedTransportID != observerTransportIDText {
		t.Fatalf("observer transport identity changed: %s != %s", restartedTransportID, observerTransportIDText)
	}
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelRecovery()
	recoveryClient, err := libp2ptransport.New(
		recoveryContext, coordinatorTransportKey, libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	recoveredAck, _, err := exchangeTiePairQUIC(
		recoveryContext, recoveryClient, restartedAddress, observerTransportID,
		hashFromPublicKey(observerReceiptKey.Public().(ed25519.PublicKey)),
		exchangeBinding, artifact, 30*time.Second,
	)
	_ = recoveryClient.Close()
	if err != nil {
		t.Fatal(err)
	}
	if recoveredAck.ReceiptTail != acknowledgement.ReceiptTail {
		t.Fatalf("receipt changed across restart: %s != %s", recoveredAck.ReceiptTail, acknowledgement.ReceiptTail)
	}
	output := waitTieReceiverProcess(t, restarted)
	fields := outputFields(output, "work_tie_campaign_pair_received")
	if fields["recovered"] != "true" || fields["receipt_tail"] != acknowledgement.ReceiptTail.String() ||
		!strings.Contains(output, "work_tie_campaign_observer_complete") {
		t.Fatalf("incomplete recovery output: %s", output)
	}
	if _, err := os.Stat(confirmationDirectory + "/0000000001.confirmed"); err != nil {
		t.Fatalf("confirmation marker missing after recovery: %v", err)
	}
	_, receipts, aggregate, err := calibration.LoadTieReceiptFile(
		defaultTieReceiptPath(observerData), plan.Binding(),
	)
	if err != nil || len(receipts) != 1 || receipts[0].Status != calibration.TieTrialCompleted ||
		!aggregate.Complete || aggregate.LastReceiptID != acknowledgement.ReceiptTail {
		t.Fatalf("recovered receipts=%+v aggregate=%+v err=%v", receipts, aggregate, err)
	}
}

func TestProcessTieCampaignSkipsExpiredZeroDeliveryAndContinuesNextSlot(t *testing.T) {
	root := t.TempDir()
	coordinatorData := root + "/coordinator"
	observerData := root + "/observer"
	planPath := root + "/tie-plan.omtp"
	artifactDirectory := root + "/artifacts"
	publicationDirectory := root + "/published"
	confirmationDirectory := root + "/confirmed"
	routesPath := root + "/observer-routes.txt"
	coordinatorTransportKeyPath := root + "/coordinator-transport.key"
	coordinatorPlanKeyPath := root + "/coordinator-plan.key"
	observerTransportKeyPath := root + "/observer-transport.key"
	observerReceiptKeyPath := root + "/observer-receipt.key"
	writeProcessKey(t, coordinatorTransportKeyPath, "tie-skip-coordinator-transport")
	writeProcessKey(t, observerTransportKeyPath, "tie-skip-observer-transport")
	writeProcessKey(t, observerReceiptKeyPath, "tie-skip-observer-receipt")
	runProcessCommand(t, 20*time.Second,
		"init", "--data", coordinatorData, "--network", "20260833", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(coordinatorData)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", coordinatorData, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", coordinatorData, "--count", "1")
	if err := os.CopyFS(observerData, os.DirFS(coordinatorData)); err != nil {
		t.Fatal(err)
	}
	observerReceiptKey, err := loadPrivateKey(observerReceiptKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPlanSeed := types.DomainHash("test/process/tie-campaign-skip-plan-coordinator")
	coordinatorPlanKey := ed25519.NewKeyFromSeed(coordinatorPlanSeed[:])
	if err := os.WriteFile(coordinatorPlanKeyPath, coordinatorPlanKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	now := unixNow()
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-campaign-skip-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-campaign-skip-control")),
		MaximumPairDelaySeconds: 10,
		Slots: []calibration.TiePlanSlot{
			{StartedAt: now - 121, EndedAt: now - 61, FirstRole: calibration.TieRoleTested},
			{StartedAt: now + 2, EndedAt: now + 122, FirstRole: calibration.TieRoleControl},
		},
	}
	copy(plan.ObserverPublicKey[:], observerReceiptKey.Public().(ed25519.PublicKey))
	plan, err = calibration.SignTiePlan(coordinatorPlanKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPublicKey := bytesToLowerHex(coordinatorPlanKey.Public().(ed25519.PublicKey))
	observerPublicKey := bytesToLowerHex(observerReceiptKey.Public().(ed25519.PublicKey))
	if err := os.MkdirAll(publicationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	coordinatorTransportID := processTransportPeerID(t, coordinatorTransportKeyPath)
	receiver, observerTransportID, observerAddress := startTieCampaignReceiverProcess(
		t, observerData, observerTransportKeyPath, observerReceiptKeyPath,
		coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
		publicationDirectory, confirmationDirectory,
	)
	if err := os.WriteFile(
		routesPath,
		[]byte(observerPublicKey+" "+observerTransportID+" "+observerAddress+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	coordinator := startTieCampaignCoordinatorProcess(
		t, coordinatorData, coordinatorTransportKeyPath, coordinatorPlanKeyPath,
		planPath, planID.String(), coordinatorPublicKey, observerPublicKey,
		routesPath, artifactDirectory, publicationDirectory, 2,
	)
	checkpointBytes, err := os.ReadFile(artifactDirectory + "/0000000002.omtcp")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := calibration.DecodeTiePairCheckpoint(checkpointBytes)
	if err != nil {
		t.Fatal(err)
	}
	checkpointID, err := checkpoint.ID(plan, plan.Binding(), planID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationDirectory+"/0000000002.omtcp", checkpointBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		publicationDirectory+"/0000000002.published", []byte(checkpointID.String()+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	coordinatorOutput := waitTieReceiverProcess(t, coordinator)
	receiverOutput := waitTieReceiverProcess(t, receiver)
	completeFields := outputFields(coordinatorOutput, "work_tie_campaign_complete")
	observerFields := outputFields(receiverOutput, "work_tie_campaign_observer_complete")
	if completeFields["skipped"] != "1" || completeFields["skipped_sequences"] != "1" ||
		observerFields["slots"] != "2" || observerFields["completed"] != "1" ||
		observerFields["no_pair"] != "1" {
		t.Fatalf("unexpected campaign completion\ncoordinator: %s\nobserver: %s", coordinatorOutput, receiverOutput)
	}
	_, receipts, aggregate, err := calibration.LoadTieReceiptFile(
		defaultTieReceiptPath(observerData), plan.Binding(),
	)
	if err != nil || len(receipts) != 2 || receipts[0].Status != calibration.TieTrialNoPair ||
		receipts[1].Status != calibration.TieTrialCompleted || !aggregate.Complete ||
		aggregate.NoPairSlots != 1 || aggregate.CompletedTrials != 1 {
		t.Fatalf("observer receipts=%+v aggregate=%+v err=%v", receipts, aggregate, err)
	}
	coordinatorTip := workTip(t, coordinatorData)
	observerTip := workTip(t, observerData)
	if coordinatorTip != observerTip {
		t.Fatalf("campaign tips diverged coordinator=%s observer=%s", coordinatorTip, observerTip)
	}
	auditObserversPath := root + "/audit-observers.txt"
	if err := os.WriteFile(
		auditObserversPath,
		[]byte(observerPublicKey+" "+defaultTieReceiptPath(observerData)+" "+confirmationDirectory+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	statePath := coordinatorData + "/work-tie-campaign.state"
	stateBeforeAudit, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	auditOutput := runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-campaign-audit", "--data", coordinatorData,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observerPublicKey,
		"--state", statePath, "--artifacts", artifactDirectory,
		"--published", publicationDirectory, "--observers", auditObserversPath,
	)
	auditFields := outputFields(auditOutput, "work_tie_campaign_audit")
	if auditFields["disposition"] != "healthy" || auditFields["complete"] != "true" ||
		auditFields["verified_success"] != "1" || auditFields["verified_skipped"] != "1" ||
		auditFields["issues"] != "0" {
		t.Fatalf("unexpected campaign audit: %s", auditOutput)
	}
	stateAfterAudit, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(stateBeforeAudit, stateAfterAudit) {
		t.Fatalf("campaign audit mutated coordinator state err=%v", err)
	}
	if err := os.Remove(artifactDirectory + "/0000000002.omtpair"); err != nil {
		t.Fatal(err)
	}
	blockedOutput, blockedErr := runProcessCommandError(30*time.Second,
		"work-telemetry-tie-campaign-audit", "--data", coordinatorData,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observerPublicKey,
		"--state", statePath, "--artifacts", artifactDirectory,
		"--published", publicationDirectory, "--observers", auditObserversPath,
	)
	if blockedErr == nil || outputFields(blockedOutput, "work_tie_campaign_audit")["disposition"] != "blocked" ||
		!strings.Contains(blockedOutput, "code=missing_or_invalid_artifact") {
		t.Fatalf("missing artifact did not block audit err=%v output=%s", blockedErr, blockedOutput)
	}
}

func TestProcessTieCampaignV2ObserversSurviveBetweenSlotRestartAndAudit(t *testing.T) {
	root := t.TempDir()
	coordinatorData := root + "/coordinator"
	planPath := root + "/tie-plan-v2.omtp"
	artifactDirectory := root + "/artifacts"
	publicationDirectory := root + "/published"
	routesPath := root + "/observer-routes.txt"
	auditObserversPath := root + "/audit-observers.txt"
	coordinatorTransportKeyPath := root + "/coordinator-transport.key"
	coordinatorPlanKeyPath := root + "/coordinator-plan.key"
	writeProcessKey(t, coordinatorTransportKeyPath, "tie-v2-campaign-coordinator-transport")

	type processObserver struct {
		data                  string
		transportKey          string
		receiptKey            string
		confirmationDirectory string
		publicKey             [ed25519.PublicKeySize]byte
		publicKeyText         string
		receiver              *tieReceiverProcess
		transportID           string
		address               string
	}
	observers := []processObserver{
		{
			data: root + "/observer-a", transportKey: root + "/observer-a-transport.key",
			receiptKey:            root + "/observer-a-receipt.key",
			confirmationDirectory: root + "/observer-a-confirmed",
		},
		{
			data: root + "/observer-b", transportKey: root + "/observer-b-transport.key",
			receiptKey:            root + "/observer-b-receipt.key",
			confirmationDirectory: root + "/observer-b-confirmed",
		},
	}
	writeProcessKey(t, observers[0].transportKey, "tie-v2-campaign-observer-a-transport")
	writeProcessKey(t, observers[0].receiptKey, "tie-v2-campaign-observer-a-receipt")
	writeProcessKey(t, observers[1].transportKey, "tie-v2-campaign-observer-b-transport")
	writeProcessKey(t, observers[1].receiptKey, "tie-v2-campaign-observer-b-receipt")

	runProcessCommand(t, 20*time.Second,
		"init", "--data", coordinatorData, "--network", "20260835", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(coordinatorData)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", coordinatorData, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", coordinatorData, "--count", "1")
	for index := range observers {
		if err := os.CopyFS(observers[index].data, os.DirFS(coordinatorData)); err != nil {
			t.Fatal(err)
		}
		privateKey, err := loadPrivateKey(observers[index].receiptKey)
		if err != nil {
			t.Fatal(err)
		}
		copy(observers[index].publicKey[:], privateKey.Public().(ed25519.PublicKey))
		observers[index].publicKeyText = bytesToLowerHex(observers[index].publicKey[:])
	}
	if bytes.Compare(observers[0].publicKey[:], observers[1].publicKey[:]) > 0 {
		observers[0], observers[1] = observers[1], observers[0]
	}

	coordinatorPlanSeed := types.DomainHash("test/process/tie-v2-campaign-plan-coordinator")
	coordinatorPlanKey := ed25519.NewKeyFromSeed(coordinatorPlanSeed[:])
	if err := os.WriteFile(coordinatorPlanKeyPath, coordinatorPlanKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	startedAt := unixNow() + 4
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion2, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-v2-campaign-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-v2-campaign-control")),
		MaximumPairDelaySeconds: 2,
		ObserverPublicKeys:      [][ed25519.PublicKeySize]byte{observers[0].publicKey, observers[1].publicKey},
		Slots: []calibration.TiePlanSlot{
			{StartedAt: startedAt, EndedAt: startedAt + 6, FirstRole: calibration.TieRoleTested},
			{StartedAt: startedAt + 8, EndedAt: startedAt + 20, FirstRole: calibration.TieRoleControl},
		},
	}
	plan, err = calibration.SignTiePlan(coordinatorPlanKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPublicKey := bytesToLowerHex(coordinatorPlanKey.Public().(ed25519.PublicKey))
	if err := os.MkdirAll(publicationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	coordinatorTransportID := processTransportPeerID(t, coordinatorTransportKeyPath)
	for index := range observers {
		observers[index].receiver, observers[index].transportID, observers[index].address =
			startTieCampaignReceiverProcess(
				t, observers[index].data, observers[index].transportKey, observers[index].receiptKey,
				coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
				publicationDirectory, observers[index].confirmationDirectory,
			)
	}
	var routes strings.Builder
	for _, observer := range observers {
		fmt.Fprintf(&routes, "%s %s %s\n", observer.publicKeyText, observer.transportID, observer.address)
	}
	if err := os.WriteFile(routesPath, []byte(routes.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	coordinator := startTieCampaignCoordinatorProcess(
		t, coordinatorData, coordinatorTransportKeyPath, coordinatorPlanKeyPath,
		planPath, planID.String(), coordinatorPublicKey, observers[0].publicKeyText,
		routesPath, artifactDirectory, publicationDirectory, 1,
	)
	publishProcessCampaignCheckpoint(
		t, artifactDirectory, publicationDirectory, plan, plan.Binding(), planID, 1,
	)
	for _, observer := range observers {
		waitForProcessFile(t, observer.confirmationDirectory+"/0000000001.confirmed", 30*time.Second)
	}
	waitForProcessCampaignStatus(
		t,
		tieproducer.CampaignConfig{
			Plan: plan, Binding: plan.Binding(), ExpectedPlanID: planID,
			StatePath: coordinatorData + "/work-tie-campaign.state",
		},
		30*time.Second,
		func(status tieproducer.CampaignStatus) bool {
			return status.NextSequence == 2 && status.Phase == tieproducer.CampaignAwaitingPair
		},
	)

	restarted := &observers[1]
	originalTransportID := restarted.transportID
	originalAddress := restarted.address
	listenAddress := processListenAddress(originalAddress)
	killTieReceiverProcess(t, restarted.receiver)
	restarted.receiver, restarted.transportID, restarted.address = startTieCampaignReceiverProcessWithOptions(
		t, restarted.data, restarted.transportKey, restarted.receiptKey,
		coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
		publicationDirectory, restarted.confirmationDirectory, listenAddress, nil,
	)
	if restarted.transportID != originalTransportID || restarted.address != originalAddress {
		t.Fatalf(
			"observer route changed across restart transport=%s/%s address=%s/%s",
			restarted.transportID, originalTransportID, restarted.address, originalAddress,
		)
	}

	publishProcessCampaignCheckpoint(
		t, artifactDirectory, publicationDirectory, plan, plan.Binding(), planID, 2,
	)
	coordinatorOutput := waitTieReceiverProcess(t, coordinator)
	completeFields := outputFields(coordinatorOutput, "work_tie_campaign_complete")
	if completeFields["slots"] != "2" || completeFields["next_sequence"] != "3" ||
		completeFields["skipped"] != "0" || completeFields["skipped_sequences"] != "-" {
		t.Fatalf("unexpected v2 campaign completion: %s", coordinatorOutput)
	}
	for index := range observers {
		observerOutput := waitTieReceiverProcess(t, observers[index].receiver)
		fields := outputFields(observerOutput, "work_tie_campaign_observer_complete")
		if fields["slots"] != "2" || fields["completed"] != "2" || fields["no_pair"] != "0" {
			t.Fatalf("observer %d did not complete both slots: %s", index, observerOutput)
		}
	}

	receiptSets := make([][]calibration.TieTrialReceipt, len(observers))
	receiptTails := make([]types.Hash, len(observers))
	for index, observer := range observers {
		binding := plan.Binding()
		binding.ObserverPublicKey = observer.publicKey
		_, receipts, aggregate, err := calibration.LoadTieReceiptFile(
			defaultTieReceiptPath(observer.data), binding,
		)
		if err != nil || len(receipts) != 2 || !aggregate.Complete ||
			aggregate.CompletedTrials != 2 || aggregate.NoPairSlots != 0 ||
			receipts[0].Status != calibration.TieTrialCompleted ||
			receipts[1].Status != calibration.TieTrialCompleted ||
			receipts[0].FirstObservedAnchorID != receipts[0].TestedAnchorID ||
			receipts[1].FirstObservedAnchorID != receipts[1].ControlAnchorID {
			t.Fatalf("observer %d receipts=%+v aggregate=%+v err=%v", index, receipts, aggregate, err)
		}
		receiptSets[index] = receipts
		receiptTails[index] = aggregate.LastReceiptID
	}
	if receiptTails[0] == receiptTails[1] {
		t.Fatal("independent observers produced one receipt-chain tail")
	}
	for sequence := range receiptSets[0] {
		left, right := receiptSets[0][sequence], receiptSets[1][sequence]
		if left.ParentID != right.ParentID || left.Height != right.Height ||
			left.TestedAnchorID != right.TestedAnchorID || left.ControlAnchorID != right.ControlAnchorID ||
			left.SelectedAnchorID != right.SelectedAnchorID ||
			left.FirstObservedAnchorID != right.FirstObservedAnchorID {
			t.Fatalf("observer views diverged at sequence %d: %+v %+v", sequence+1, left, right)
		}
	}
	coordinatorTip := workTip(t, coordinatorData)
	for index, observer := range observers {
		if observerTip := workTip(t, observer.data); observerTip != coordinatorTip {
			t.Fatalf("observer %d tip diverged coordinator=%s observer=%s", index, coordinatorTip, observerTip)
		}
	}

	var auditObservers strings.Builder
	for _, observer := range observers {
		fmt.Fprintf(
			&auditObservers, "%s %s %s\n", observer.publicKeyText,
			defaultTieReceiptPath(observer.data), observer.confirmationDirectory,
		)
	}
	if err := os.WriteFile(auditObserversPath, []byte(auditObservers.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := coordinatorData + "/work-tie-campaign.state"
	stateBeforeAudit, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	auditOutput := runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-campaign-audit", "--data", coordinatorData,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observers[0].publicKeyText,
		"--state", statePath, "--artifacts", artifactDirectory,
		"--published", publicationDirectory, "--observers", auditObserversPath,
	)
	auditFields := outputFields(auditOutput, "work_tie_campaign_audit")
	if auditFields["disposition"] != "healthy" || auditFields["state_version"] != "1" ||
		auditFields["complete"] != "true" || auditFields["verified_success"] != "2" ||
		auditFields["verified_skipped"] != "0" || auditFields["pending_observers"] != "0" ||
		auditFields["recoverable_acks"] != "0" || auditFields["issues"] != "0" ||
		strings.Count(auditOutput, "work_tie_campaign_audit_observer ") != 2 {
		t.Fatalf("unexpected multi-observer campaign audit: %s", auditOutput)
	}
	stateAfterAudit, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(stateBeforeAudit, stateAfterAudit) {
		t.Fatalf("multi-observer campaign audit mutated coordinator state err=%v", err)
	}
}

func TestProcessTieCampaignCoordinatorResumesOnlyMissingObserver(t *testing.T) {
	root := t.TempDir()
	coordinatorData := root + "/coordinator"
	planPath := root + "/tie-plan-v2.omtp"
	artifactDirectory := root + "/artifacts"
	publicationDirectory := root + "/published"
	routesPath := root + "/observer-routes.txt"
	auditObserversPath := root + "/audit-observers.txt"
	blockedRequestMarker := root + "/observer-request-blocked"
	coordinatorTransportKeyPath := root + "/coordinator-transport.key"
	coordinatorPlanKeyPath := root + "/coordinator-plan.key"
	writeProcessKey(t, coordinatorTransportKeyPath, "tie-coordinator-restart-transport")

	type processObserver struct {
		data                  string
		transportKey          string
		receiptKey            string
		confirmationDirectory string
		publicKey             [ed25519.PublicKeySize]byte
		publicKeyText         string
		receiver              *tieReceiverProcess
		transportID           string
		address               string
	}
	observers := []processObserver{
		{
			data: root + "/observer-a", transportKey: root + "/observer-a-transport.key",
			receiptKey:            root + "/observer-a-receipt.key",
			confirmationDirectory: root + "/observer-a-confirmed",
		},
		{
			data: root + "/observer-b", transportKey: root + "/observer-b-transport.key",
			receiptKey:            root + "/observer-b-receipt.key",
			confirmationDirectory: root + "/observer-b-confirmed",
		},
	}
	writeProcessKey(t, observers[0].transportKey, "tie-coordinator-restart-observer-a-transport")
	writeProcessKey(t, observers[0].receiptKey, "tie-coordinator-restart-observer-a-receipt")
	writeProcessKey(t, observers[1].transportKey, "tie-coordinator-restart-observer-b-transport")
	writeProcessKey(t, observers[1].receiptKey, "tie-coordinator-restart-observer-b-receipt")

	runProcessCommand(t, 20*time.Second,
		"init", "--data", coordinatorData, "--network", "20260836", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(coordinatorData)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", coordinatorData, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", coordinatorData, "--count", "1")
	parentID := workTip(t, coordinatorData)
	for index := range observers {
		if err := os.CopyFS(observers[index].data, os.DirFS(coordinatorData)); err != nil {
			t.Fatal(err)
		}
		privateKey, err := loadPrivateKey(observers[index].receiptKey)
		if err != nil {
			t.Fatal(err)
		}
		copy(observers[index].publicKey[:], privateKey.Public().(ed25519.PublicKey))
		observers[index].publicKeyText = bytesToLowerHex(observers[index].publicKey[:])
	}
	if bytes.Compare(observers[0].publicKey[:], observers[1].publicKey[:]) > 0 {
		observers[0], observers[1] = observers[1], observers[0]
	}

	coordinatorPlanSeed := types.DomainHash("test/process/tie-coordinator-restart-plan")
	coordinatorPlanKey := ed25519.NewKeyFromSeed(coordinatorPlanSeed[:])
	if err := os.WriteFile(coordinatorPlanKeyPath, coordinatorPlanKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	startedAt := unixNow() + 4
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion2, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-coordinator-restart-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-coordinator-restart-control")),
		MaximumPairDelaySeconds: 10,
		ObserverPublicKeys:      [][ed25519.PublicKeySize]byte{observers[0].publicKey, observers[1].publicKey},
		Slots: []calibration.TiePlanSlot{{
			StartedAt: startedAt, EndedAt: startedAt + 120, FirstRole: calibration.TieRoleControl,
		}},
	}
	plan, err = calibration.SignTiePlan(coordinatorPlanKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPublicKey := bytesToLowerHex(coordinatorPlanKey.Public().(ed25519.PublicKey))
	if err := os.MkdirAll(publicationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	coordinatorTransportID := processTransportPeerID(t, coordinatorTransportKeyPath)
	observers[0].receiver, observers[0].transportID, observers[0].address =
		startTieCampaignReceiverProcess(
			t, observers[0].data, observers[0].transportKey, observers[0].receiptKey,
			coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
			publicationDirectory, observers[0].confirmationDirectory,
		)
	observers[1].receiver, observers[1].transportID, observers[1].address =
		startTieCampaignReceiverProcessWithEnvironment(
			t, observers[1].data, observers[1].transportKey, observers[1].receiptKey,
			coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
			publicationDirectory, observers[1].confirmationDirectory,
			[]string{
				tieCampaignCrashModeEnvironment + "=before-request",
				tieCampaignCrashMarkerEnvironment + "=" + blockedRequestMarker,
			},
		)
	var routes strings.Builder
	for _, observer := range observers {
		fmt.Fprintf(&routes, "%s %s %s\n", observer.publicKeyText, observer.transportID, observer.address)
	}
	if err := os.WriteFile(routesPath, []byte(routes.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	coordinator := startTieCampaignCoordinatorProcess(
		t, coordinatorData, coordinatorTransportKeyPath, coordinatorPlanKeyPath,
		planPath, planID.String(), coordinatorPublicKey, observers[0].publicKeyText,
		routesPath, artifactDirectory, publicationDirectory, 1,
	)
	publishProcessCampaignCheckpoint(
		t, artifactDirectory, publicationDirectory, plan, plan.Binding(), planID, 1,
	)
	waitForProcessFile(t, blockedRequestMarker, 30*time.Second)
	waitForProcessFile(t, observers[0].confirmationDirectory+"/0000000001.confirmed", 30*time.Second)
	statePath := coordinatorData + "/work-tie-campaign.state"
	partialStatus := waitForProcessCampaignStatus(
		t,
		tieproducer.CampaignConfig{
			Plan: plan, Binding: plan.Binding(), ExpectedPlanID: planID, StatePath: statePath,
		},
		30*time.Second,
		func(status tieproducer.CampaignStatus) bool {
			return status.NextSequence == 1 && status.Phase == tieproducer.CampaignDelivering &&
				status.AcknowledgedCount == 1
		},
	)
	if len(partialStatus.ObserverReceiptTails) != 2 || partialStatus.ObserverReceiptTails[0].IsZero() ||
		!partialStatus.ObserverReceiptTails[1].IsZero() {
		t.Fatalf("unexpected partial coordinator state: %+v", partialStatus)
	}
	killTieReceiverProcess(t, coordinator)
	if tip := workTip(t, coordinatorData); tip != parentID {
		t.Fatalf("coordinator advanced before every observer ACK parent=%s tip=%s", parentID, tip)
	}
	firstObserverOutput := waitTieReceiverProcess(t, observers[0].receiver)
	if fields := outputFields(firstObserverOutput, "work_tie_campaign_observer_complete"); fields["completed"] != "1" || fields["no_pair"] != "0" {
		t.Fatalf("first observer did not durably complete before coordinator crash: %s", firstObserverOutput)
	}

	blockedAddress := observers[1].address
	blockedTransportID := observers[1].transportID
	killTieReceiverProcess(t, observers[1].receiver)
	observers[1].receiver, observers[1].transportID, observers[1].address =
		startTieCampaignReceiverProcessWithOptions(
			t, observers[1].data, observers[1].transportKey, observers[1].receiptKey,
			coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
			publicationDirectory, observers[1].confirmationDirectory,
			processListenAddress(blockedAddress), nil,
		)
	if observers[1].transportID != blockedTransportID || observers[1].address != blockedAddress {
		t.Fatalf(
			"blocked observer route changed transport=%s/%s address=%s/%s",
			observers[1].transportID, blockedTransportID, observers[1].address, blockedAddress,
		)
	}
	coordinator = startTieCampaignCoordinatorResumeProcess(
		t, coordinatorData, coordinatorTransportKeyPath, coordinatorPlanKeyPath,
		planPath, planID.String(), coordinatorPublicKey, observers[0].publicKeyText,
		routesPath, artifactDirectory, publicationDirectory, 1, tieproducer.CampaignDelivering,
	)
	coordinatorOutput := waitTieReceiverProcess(t, coordinator)
	startedFields := outputFields(coordinatorOutput, "work_tie_campaign_started")
	if startedFields["phase"] != strconv.FormatUint(uint64(tieproducer.CampaignDelivering), 10) ||
		startedFields["acknowledged"] != "1" {
		t.Fatalf("resumed coordinator did not report its durable boundary: %s", coordinatorOutput)
	}
	ackFields := outputFields(coordinatorOutput, "work_tie_campaign_observer_ack")
	if strings.Count(coordinatorOutput, "work_tie_campaign_observer_ack ") != 1 ||
		ackFields["observer"] != observers[1].publicKeyText {
		t.Fatalf("resumed coordinator did not contact only the missing observer: %s", coordinatorOutput)
	}
	if fields := outputFields(coordinatorOutput, "work_tie_campaign_complete"); fields["slots"] != "1" || fields["next_sequence"] != "2" || fields["skipped"] != "0" {
		t.Fatalf("resumed coordinator did not complete: %s", coordinatorOutput)
	}
	secondObserverOutput := waitTieReceiverProcess(t, observers[1].receiver)
	if fields := outputFields(secondObserverOutput, "work_tie_campaign_observer_complete"); fields["completed"] != "1" || fields["no_pair"] != "0" {
		t.Fatalf("missing observer did not complete after coordinator restart: %s", secondObserverOutput)
	}

	receiptSets := make([][]calibration.TieTrialReceipt, len(observers))
	for index, observer := range observers {
		binding := plan.Binding()
		binding.ObserverPublicKey = observer.publicKey
		_, receipts, aggregate, err := calibration.LoadTieReceiptFile(
			defaultTieReceiptPath(observer.data), binding,
		)
		if err != nil || len(receipts) != 1 || !aggregate.Complete ||
			aggregate.CompletedTrials != 1 || receipts[0].Status != calibration.TieTrialCompleted ||
			receipts[0].FirstObservedAnchorID != receipts[0].ControlAnchorID {
			t.Fatalf("observer %d receipts=%+v aggregate=%+v err=%v", index, receipts, aggregate, err)
		}
		receiptSets[index] = receipts
	}
	if receiptSets[0][0].ParentID != receiptSets[1][0].ParentID ||
		receiptSets[0][0].TestedAnchorID != receiptSets[1][0].TestedAnchorID ||
		receiptSets[0][0].ControlAnchorID != receiptSets[1][0].ControlAnchorID ||
		receiptSets[0][0].SelectedAnchorID != receiptSets[1][0].SelectedAnchorID {
		t.Fatalf("observer views diverged after coordinator restart: %+v %+v", receiptSets[0][0], receiptSets[1][0])
	}
	coordinatorTip := workTip(t, coordinatorData)
	for index, observer := range observers {
		if observerTip := workTip(t, observer.data); observerTip != coordinatorTip {
			t.Fatalf("observer %d tip diverged coordinator=%s observer=%s", index, coordinatorTip, observerTip)
		}
	}

	var auditObservers strings.Builder
	for _, observer := range observers {
		fmt.Fprintf(
			&auditObservers, "%s %s %s\n", observer.publicKeyText,
			defaultTieReceiptPath(observer.data), observer.confirmationDirectory,
		)
	}
	if err := os.WriteFile(auditObserversPath, []byte(auditObservers.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	stateBeforeAudit, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	auditOutput := runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-campaign-audit", "--data", coordinatorData,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observers[0].publicKeyText,
		"--state", statePath, "--artifacts", artifactDirectory,
		"--published", publicationDirectory, "--observers", auditObserversPath,
	)
	auditFields := outputFields(auditOutput, "work_tie_campaign_audit")
	if auditFields["disposition"] != "healthy" || auditFields["complete"] != "true" ||
		auditFields["verified_success"] != "1" || auditFields["pending_observers"] != "0" ||
		auditFields["issues"] != "0" {
		t.Fatalf("unexpected coordinator-restart audit: %s", auditOutput)
	}
	stateAfterAudit, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(stateBeforeAudit, stateAfterAudit) {
		t.Fatalf("coordinator-restart audit mutated state err=%v", err)
	}
}

type campaignStorageProcessFixture struct {
	root                    string
	coordinatorData         string
	observerData            string
	planPath                string
	artifactDirectory       string
	publicationDirectory    string
	confirmationDirectory   string
	stateDirectory          string
	statePath               string
	routesPath              string
	auditObserversPath      string
	coordinatorTransportKey string
	coordinatorPlanKey      string
	observerTransportKey    string
	observerReceiptKey      string
	coordinatorTransportID  string
	coordinatorPublicKey    string
	observerPublicKey       string
	plan                    calibration.TiePlan
	binding                 calibration.TiePlanBinding
	planID                  types.Hash
	parentID                types.Hash
}

func newCampaignStorageProcessFixture(
	t testing.TB,
	label string,
	networkID string,
) campaignStorageProcessFixture {
	t.Helper()
	root := t.TempDir()
	fixture := campaignStorageProcessFixture{
		root: root, coordinatorData: root + "/coordinator", observerData: root + "/observer",
		planPath: root + "/tie-plan.omtp", artifactDirectory: root + "/artifacts",
		publicationDirectory:  root + "/published",
		confirmationDirectory: root + "/confirmed", stateDirectory: root + "/state",
		statePath:  root + "/state/work-tie-campaign.state",
		routesPath: root + "/observer-routes.txt", auditObserversPath: root + "/audit-observers.txt",
		coordinatorTransportKey: root + "/coordinator-transport.key",
		coordinatorPlanKey:      root + "/coordinator-plan.key",
		observerTransportKey:    root + "/observer-transport.key",
		observerReceiptKey:      root + "/observer-receipt.key",
	}
	writeProcessKey(t, fixture.coordinatorTransportKey, "tie-storage-coordinator-transport-"+label)
	writeProcessKey(t, fixture.observerTransportKey, "tie-storage-observer-transport-"+label)
	writeProcessKey(t, fixture.observerReceiptKey, "tie-storage-observer-receipt-"+label)
	runProcessCommand(t, 20*time.Second,
		"init", "--data", fixture.coordinatorData, "--network", networkID,
		"--timestamp", "1700000000", "--difficulty-bits", "9",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(fixture.coordinatorData)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", fixture.coordinatorData, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", fixture.coordinatorData, "--count", "1")
	fixture.parentID = workTip(t, fixture.coordinatorData)
	if err := os.CopyFS(fixture.observerData, os.DirFS(fixture.coordinatorData)); err != nil {
		t.Fatal(err)
	}
	observerKey, err := loadPrivateKey(fixture.observerReceiptKey)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorSeed := types.DomainHash("test/process/tie-storage-plan/" + label)
	coordinatorKey := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	if err := os.WriteFile(fixture.coordinatorPlanKey, coordinatorKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	startedAt := unixNow() + 2
	fixture.plan = calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-storage-tested/" + label)),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-storage-control/" + label)),
		MaximumPairDelaySeconds: 10,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: startedAt, EndedAt: startedAt + 180, FirstRole: calibration.TieRoleTested,
		}},
	}
	copy(fixture.plan.ObserverPublicKey[:], observerKey.Public().(ed25519.PublicKey))
	fixture.plan, err = calibration.SignTiePlan(coordinatorKey, fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	fixture.binding = fixture.plan.Binding()
	fixture.planID, err = fixture.plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(fixture.planPath, fixture.plan, fixture.binding); err != nil {
		t.Fatal(err)
	}
	fixture.coordinatorPublicKey = bytesToLowerHex(coordinatorKey.Public().(ed25519.PublicKey))
	fixture.observerPublicKey = bytesToLowerHex(observerKey.Public().(ed25519.PublicKey))
	fixture.coordinatorTransportID = processTransportPeerID(t, fixture.coordinatorTransportKey).String()
	for _, directory := range []string{
		fixture.artifactDirectory, fixture.publicationDirectory, fixture.stateDirectory,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func startCampaignStorageObserver(
	t testing.TB,
	fixture campaignStorageProcessFixture,
	listenAddress string,
) (*tieReceiverProcess, string, string) {
	t.Helper()
	if listenAddress == "" {
		listenAddress = "/ip4/127.0.0.1/udp/0/quic-v1"
	}
	return startTieCampaignReceiverProcessWithOptions(
		t, fixture.observerData, fixture.observerTransportKey, fixture.observerReceiptKey,
		fixture.coordinatorTransportID, fixture.planPath, fixture.planID.String(),
		fixture.coordinatorPublicKey, fixture.publicationDirectory,
		fixture.confirmationDirectory, listenAddress, nil,
	)
}

func writeCampaignStorageEvidenceLists(
	t testing.TB,
	fixture campaignStorageProcessFixture,
	observerTransportID string,
	observerAddress string,
) {
	t.Helper()
	if err := os.WriteFile(
		fixture.routesPath,
		[]byte(fixture.observerPublicKey+" "+observerTransportID+" "+observerAddress+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		fixture.auditObserversPath,
		[]byte(fixture.observerPublicKey+" "+defaultTieReceiptPath(fixture.observerData)+" "+fixture.confirmationDirectory+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func startCampaignStorageCoordinator(
	t testing.TB,
	fixture campaignStorageProcessFixture,
	readyLine func(string) bool,
) *tieReceiverProcess {
	t.Helper()
	return startTieCampaignCoordinatorProcessWhenWithState(
		t, fixture.coordinatorData, fixture.coordinatorTransportKey,
		fixture.coordinatorPlanKey, fixture.planPath, fixture.planID.String(),
		fixture.coordinatorPublicKey, fixture.observerPublicKey, fixture.routesPath,
		fixture.artifactDirectory, fixture.publicationDirectory, fixture.statePath, readyLine,
	)
}

func campaignStorageConfig(fixture campaignStorageProcessFixture) tieproducer.CampaignConfig {
	return tieproducer.CampaignConfig{
		Plan: fixture.plan, Binding: fixture.binding, ExpectedPlanID: fixture.planID,
		StatePath: fixture.statePath,
	}
}

func restrictCampaignDirectory(
	t *testing.T,
	directory string,
	mode os.FileMode,
) {
	t.Helper()
	if err := os.Chmod(directory, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	switch mode {
	case 0o500:
		probe, err := os.CreateTemp(directory, ".permission-probe-*")
		if err == nil {
			name := probe.Name()
			_ = probe.Close()
			_ = os.Remove(name)
			_ = os.Chmod(directory, 0o700)
			t.Skip("filesystem does not enforce owner write removal")
		}
	case 0o300:
		handle, err := os.Open(directory)
		if err == nil {
			_ = handle.Close()
			_ = os.Chmod(directory, 0o700)
			t.Skip("filesystem does not enforce owner read removal on directories")
		}
	}
}

func restoreCampaignDirectory(t testing.TB, directory string) {
	t.Helper()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
}

func runCampaignStorageAudit(
	t testing.TB,
	fixture campaignStorageProcessFixture,
) string {
	t.Helper()
	return runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-campaign-audit", "--data", fixture.coordinatorData,
		"--plan", fixture.planPath, "--plan-id", fixture.planID.String(),
		"--coordinator-public-key", fixture.coordinatorPublicKey,
		"--observer-public-key", fixture.observerPublicKey,
		"--state", fixture.statePath, "--artifacts", fixture.artifactDirectory,
		"--published", fixture.publicationDirectory, "--observers", fixture.auditObserversPath,
	)
}

func assertCampaignStorageComplete(
	t testing.TB,
	fixture campaignStorageProcessFixture,
	coordinatorOutput string,
	observerOutput string,
) {
	t.Helper()
	if fields := outputFields(coordinatorOutput, "work_tie_campaign_complete"); fields["slots"] != "1" || fields["next_sequence"] != "2" {
		t.Fatalf("campaign did not complete: %s", coordinatorOutput)
	}
	if observerOutput != "" && !strings.Contains(observerOutput, "work_tie_campaign_observer_complete") {
		t.Fatalf("observer did not complete: %s", observerOutput)
	}
	if coordinatorTip, observerTip := workTip(t, fixture.coordinatorData), workTip(t, fixture.observerData); coordinatorTip == fixture.parentID || coordinatorTip != observerTip {
		t.Fatalf("recovered tips coordinator=%s observer=%s parent=%s", coordinatorTip, observerTip, fixture.parentID)
	}
	audit := runCampaignStorageAudit(t, fixture)
	if fields := outputFields(audit, "work_tie_campaign_audit"); fields["disposition"] != "healthy" || fields["complete"] != "true" ||
		fields["verified_success"] != "1" || fields["issues"] != "0" {
		t.Fatalf("recovered campaign audit: %s", audit)
	}
}

func TestProcessTieCampaignStorageFailuresRecoverWithoutFalseAdvance(t *testing.T) {
	for _, test := range []struct {
		name          string
		mode          os.FileMode
		expectedPhase tieproducer.CampaignPhase
	}{
		{name: "coordinator journal before rename", mode: 0o500, expectedPhase: tieproducer.CampaignAwaitingPublication},
		{name: "coordinator journal after rename", mode: 0o300, expectedPhase: tieproducer.CampaignDelivering},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCampaignStorageProcessFixture(t, strings.ReplaceAll(test.name, " ", "-"), "20260837")
			observer, observerTransportID, observerAddress := startCampaignStorageObserver(t, fixture, "")
			writeCampaignStorageEvidenceLists(t, fixture, observerTransportID, observerAddress)
			coordinator := startCampaignStorageCoordinator(t, fixture, func(line string) bool {
				return outputFields(line, "work_tie_campaign_pair_ready")["sequence"] == "1"
			})
			waitForProcessCampaignStatus(
				t, campaignStorageConfig(fixture), 30*time.Second,
				func(status tieproducer.CampaignStatus) bool {
					return status.Phase == tieproducer.CampaignAwaitingPublication
				},
			)
			restrictCampaignDirectory(t, fixture.stateDirectory, test.mode)
			publishProcessCampaignCheckpoint(
				t, fixture.artifactDirectory, fixture.publicationDirectory,
				fixture.plan, fixture.binding, fixture.planID, 1,
			)
			coordinatorOutput, coordinatorErr := waitTieReceiverProcessError(coordinator, 30*time.Second)
			if coordinatorErr == nil {
				t.Fatalf("coordinator ignored journal failure: %s", coordinatorOutput)
			}
			restoreCampaignDirectory(t, fixture.stateDirectory)
			status, err := tieproducer.LoadCampaignStatus(campaignStorageConfig(fixture))
			if err != nil || status.Phase != test.expectedPhase || status.AcknowledgedCount != 0 {
				t.Fatalf("journal boundary status=%+v err=%v stderr=%s", status, err, coordinator.stderr.String())
			}
			if tip := workTip(t, fixture.coordinatorData); tip != fixture.parentID {
				t.Fatalf("journal error advanced local tip: %s != %s", tip, fixture.parentID)
			}
			if _, err := os.Stat(defaultTieReceiptPath(fixture.observerData)); !os.IsNotExist(err) {
				t.Fatalf("observer received pair before durable delivery phase: %v", err)
			}
			restarted := startCampaignStorageCoordinator(t, fixture, func(line string) bool {
				fields := outputFields(line, "work_tie_campaign_started")
				return fields["next_sequence"] == "1" &&
					fields["phase"] == strconv.FormatUint(uint64(test.expectedPhase), 10)
			})
			coordinatorOutput = waitTieReceiverProcess(t, restarted)
			observerOutput := waitTieReceiverProcess(t, observer)
			assertCampaignStorageComplete(t, fixture, coordinatorOutput, observerOutput)
		})
	}

	for _, test := range []struct {
		name             string
		mode             os.FileMode
		markerCommitted  bool
		requiresObserver bool
	}{
		{name: "observer confirmation before link", mode: 0o500, requiresObserver: true},
		{name: "observer confirmation after link", mode: 0o300, markerCommitted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCampaignStorageProcessFixture(t, strings.ReplaceAll(test.name, " ", "-"), "20260838")
			observer, observerTransportID, observerAddress := startCampaignStorageObserver(t, fixture, "")
			writeCampaignStorageEvidenceLists(t, fixture, observerTransportID, observerAddress)
			restrictCampaignDirectory(t, fixture.confirmationDirectory, test.mode)
			coordinator := startCampaignStorageCoordinator(t, fixture, func(line string) bool {
				return outputFields(line, "work_tie_campaign_pair_ready")["sequence"] == "1"
			})
			publishProcessCampaignCheckpoint(
				t, fixture.artifactDirectory, fixture.publicationDirectory,
				fixture.plan, fixture.binding, fixture.planID, 1,
			)
			coordinatorOutput, coordinatorErr := waitTieReceiverProcessError(coordinator, 30*time.Second)
			observerOutput, observerErr := waitTieReceiverProcessError(observer, 30*time.Second)
			if coordinatorErr == nil || observerErr == nil {
				t.Fatalf("confirmation failure was ignored coordinator_err=%v observer_err=%v\ncoordinator=%s\nobserver=%s",
					coordinatorErr, observerErr, coordinatorOutput, observerOutput)
			}
			status, err := tieproducer.LoadCampaignStatus(campaignStorageConfig(fixture))
			if err != nil || status.Phase != tieproducer.CampaignDelivering || status.AcknowledgedCount != 0 {
				t.Fatalf("confirmation boundary status=%+v err=%v", status, err)
			}
			if tip := workTip(t, fixture.coordinatorData); tip != fixture.parentID {
				t.Fatalf("missing final ACK advanced local tip: %s != %s", tip, fixture.parentID)
			}
			markerPath := fixture.confirmationDirectory + "/0000000001.confirmed"
			_, markerErr := os.Stat(markerPath)
			if test.markerCommitted && markerErr != nil {
				t.Fatalf("post-link failure lost confirmation marker: %v", markerErr)
			}
			if !test.markerCommitted && !os.IsNotExist(markerErr) {
				t.Fatalf("pre-link failure created confirmation marker: %v", markerErr)
			}
			restoreCampaignDirectory(t, fixture.confirmationDirectory)

			var restartedObserver *tieReceiverProcess
			if test.requiresObserver {
				var restartedTransportID string
				restartedObserver, restartedTransportID, _ = startCampaignStorageObserver(
					t, fixture, processListenAddress(observerAddress),
				)
				if restartedTransportID != observerTransportID {
					t.Fatalf("observer identity changed: %s != %s", restartedTransportID, observerTransportID)
				}
			} else {
				stateBeforeAudit, readErr := os.ReadFile(fixture.statePath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				audit := runCampaignStorageAudit(t, fixture)
				if fields := outputFields(audit, "work_tie_campaign_audit"); fields["disposition"] != "recoverable" || fields["recoverable_acks"] != "1" ||
					!strings.Contains(audit, "code=unrecorded_observer_ack") {
					t.Fatalf("ambiguous marker was not recoverable: %s", audit)
				}
				stateAfterAudit, readErr := os.ReadFile(fixture.statePath)
				if readErr != nil || !bytes.Equal(stateBeforeAudit, stateAfterAudit) {
					t.Fatalf("read-only audit mutated state err=%v", readErr)
				}
				recovery := runProcessCommand(t, 30*time.Second,
					"work-telemetry-tie-campaign-recover", "--data", fixture.coordinatorData,
					"--plan", fixture.planPath, "--plan-id", fixture.planID.String(),
					"--coordinator-public-key", fixture.coordinatorPublicKey,
					"--observer-public-key", fixture.observerPublicKey,
					"--state", fixture.statePath, "--artifacts", fixture.artifactDirectory,
					"--published", fixture.publicationDirectory,
					"--observers", fixture.auditObserversPath,
				)
				if fields := outputFields(recovery, "work_tie_campaign_recovered"); fields["recovered_acks"] != "1" || fields["after"] != "healthy" ||
					fields["phase"] != strconv.FormatUint(uint64(tieproducer.CampaignAwaitingAdvance), 10) {
					t.Fatalf("ambiguous ACK recovery failed: %s", recovery)
				}
			}

			expectedPhase := tieproducer.CampaignDelivering
			if !test.requiresObserver {
				expectedPhase = tieproducer.CampaignAwaitingAdvance
			}
			restarted := startCampaignStorageCoordinator(t, fixture, func(line string) bool {
				fields := outputFields(line, "work_tie_campaign_started")
				return fields["next_sequence"] == "1" &&
					fields["phase"] == strconv.FormatUint(uint64(expectedPhase), 10)
			})
			coordinatorOutput = waitTieReceiverProcess(t, restarted)
			observerOutput = ""
			if restartedObserver != nil {
				observerOutput = waitTieReceiverProcess(t, restartedObserver)
			}
			assertCampaignStorageComplete(t, fixture, coordinatorOutput, observerOutput)
		})
	}
}

func TestProcessTieCampaignPartialSiblingCrashRemainsFailClosed(t *testing.T) {
	root := t.TempDir()
	coordinatorData := root + "/coordinator"
	observerData := root + "/observer"
	planPath := root + "/tie-plan.omtp"
	pairPath := root + "/tie-pair.omtpair"
	publicationDirectory := root + "/published"
	confirmationDirectory := root + "/confirmed"
	crashMarker := root + "/first-sibling-durable"
	coordinatorTransportKeyPath := root + "/coordinator-transport.key"
	observerTransportKeyPath := root + "/observer-transport.key"
	observerReceiptKeyPath := root + "/observer-receipt.key"
	writeProcessKey(t, coordinatorTransportKeyPath, "tie-partial-coordinator-transport")
	writeProcessKey(t, observerTransportKeyPath, "tie-partial-observer-transport")
	writeProcessKey(t, observerReceiptKeyPath, "tie-partial-observer-receipt")
	runProcessCommand(t, 20*time.Second,
		"init", "--data", coordinatorData, "--network", "20260834", "--timestamp", "1700000000",
		"--difficulty-bits", "9", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	document, err := loadGenesis(coordinatorData)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	runProcessCommand(t, 20*time.Second,
		"work-enable", "--data", coordinatorData, "--activation-height", "2",
		"--confirm-genesis", genesisID.String(), "--max-trees", "4",
		"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
	)
	runProcessCommand(t, 20*time.Second, "work-mine", "--data", coordinatorData, "--count", "1")
	parentID := workTip(t, coordinatorData)
	if err := os.CopyFS(observerData, os.DirFS(coordinatorData)); err != nil {
		t.Fatal(err)
	}
	observerReceiptKey, err := loadPrivateKey(observerReceiptKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPlanSeed := types.DomainHash("test/process/tie-campaign-partial-plan-coordinator")
	coordinatorPlanKey := ed25519.NewKeyFromSeed(coordinatorPlanSeed[:])
	startedAt := unixNow() + 1
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/process/tie-campaign-partial-tested")),
		ControlMiner:            types.Address(types.DomainHash("test/process/tie-campaign-partial-control")),
		MaximumPairDelaySeconds: 10,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: startedAt, EndedAt: startedAt + 180, FirstRole: calibration.TieRoleTested,
		}},
	}
	copy(plan.ObserverPublicKey[:], observerReceiptKey.Public().(ed25519.PublicKey))
	plan, err = calibration.SignTiePlan(coordinatorPlanKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := calibration.SaveTiePlanFile(planPath, plan, plan.Binding()); err != nil {
		t.Fatal(err)
	}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	coordinatorPublicKey := bytesToLowerHex(coordinatorPlanKey.Public().(ed25519.PublicKey))
	observerPublicKey := bytesToLowerHex(observerReceiptKey.Public().(ed25519.PublicKey))
	created := runProcessCommand(t, 30*time.Second,
		"work-telemetry-tie-pair-create", "--data", coordinatorData,
		"--plan", planPath, "--plan-id", planID.String(),
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observerPublicKey,
		"--sequence", "1", "--output", pairPath,
	)
	pairID, err := parseHash(outputFields(created, "work_tie_pair_created")["pair"])
	if err != nil {
		t.Fatalf("pair creation output=%s err=%v", created, err)
	}
	checkpoint, err := calibration.SignTiePairCheckpoint(
		coordinatorPlanKey, plan, plan.Binding(), planID, 1, pairID,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointID, _ := checkpoint.ID(plan, plan.Binding(), planID)
	if err := os.MkdirAll(publicationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationDirectory+"/0000000001.omtcp", checkpoint.CanonicalBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationDirectory+"/0000000001.published", []byte(checkpointID.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	coordinatorTransportID := processTransportPeerID(t, coordinatorTransportKeyPath)
	receiver, observerTransportIDText, observerAddress := startTieCampaignReceiverProcessWithEnvironment(
		t, observerData, observerTransportKeyPath, observerReceiptKeyPath,
		coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
		publicationDirectory, confirmationDirectory,
		[]string{
			tieCampaignCrashModeEnvironment + "=after-first-observation",
			tieCampaignCrashMarkerEnvironment + "=" + crashMarker,
		},
	)
	observerTransportID, err := parseHash(observerTransportIDText)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := readTiePairFile(pairPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorTransportKey, err := loadPrivateKey(coordinatorTransportKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClient := context.WithTimeout(context.Background(), 30*time.Second)
	client, err := libp2ptransport.New(
		clientContext, coordinatorTransportKey, libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		cancelClient()
		t.Fatal(err)
	}
	stream, _, err := client.OpenTiePairStream(clientContext, observerAddress, &observerTransportID)
	if err != nil {
		t.Fatal(err)
	}
	if err := tieexchange.WriteRequest(stream, tieexchange.Request{
		Binding:  tieexchange.Binding{PlanID: planID, PairID: pairID, Sequence: 1},
		Artifact: artifact,
	}); err != nil {
		t.Fatal(err)
	}
	waitForProcessFile(t, crashMarker, 30*time.Second)
	killTieReceiverProcess(t, receiver)
	_ = stream.Reset()
	_ = client.Close()
	cancelClient()
	if workTip(t, observerData) == parentID {
		t.Fatal("first sibling was not durably committed before the injected crash")
	}
	if _, err := os.Stat(defaultTieReceiptPath(observerData)); !os.IsNotExist(err) {
		t.Fatalf("partial pair created a completed receipt: %v", err)
	}
	if _, err := os.Stat(confirmationDirectory + "/0000000001.confirmed"); !os.IsNotExist(err) {
		t.Fatalf("partial pair created a confirmation marker: %v", err)
	}

	restarted, restartedTransportID, _ := startTieCampaignReceiverProcess(
		t, observerData, observerTransportKeyPath, observerReceiptKeyPath,
		coordinatorTransportID.String(), planPath, planID.String(), coordinatorPublicKey,
		publicationDirectory, confirmationDirectory,
	)
	if restartedTransportID != observerTransportIDText {
		t.Fatalf("observer identity changed: %s != %s", restartedTransportID, observerTransportIDText)
	}
	restartOutput, restartErr := waitTieReceiverProcessError(restarted, 30*time.Second)
	if restartErr == nil || !strings.Contains(restarted.stderr.String(), calibration.ErrPartialTiePair.Error()) {
		t.Fatalf("partial restart did not fail closed err=%v stdout=%s stderr=%s",
			restartErr, restartOutput, restarted.stderr.String())
	}
	collector, err := calibration.OpenTieCollector(calibration.TieCollectorConfig{
		Plan: plan, Binding: plan.Binding(), PrivateKey: observerReceiptKey,
		ReceiptPath: defaultTieReceiptPath(observerData), PendingPath: defaultTiePendingPath(observerData),
		FailOnPartialExpiry: true,
	}, unixNow())
	if err != nil {
		t.Fatal(err)
	}
	status, err := collector.Status()
	if err != nil || status.NextSequence != 1 || status.ClosedSlots != 0 ||
		status.CurrentCandidates != 1 {
		t.Fatalf("partial collector status=%+v err=%v", status, err)
	}
	if err := collector.Close(unixNow()); err != nil {
		t.Fatal(err)
	}
}

// TestOMDHelperProcess executes exactly one CLI command in a separate process.
func TestOMDHelperProcess(t *testing.T) {
	if os.Getenv(helperProcessEnvironment) != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "missing helper command")
		os.Exit(2)
	}
	switch os.Getenv(tieCampaignCrashModeEnvironment) {
	case "before-request":
		marker := os.Getenv(tieCampaignCrashMarkerEnvironment)
		tieCampaignBeforeRequest = func() {
			if marker != "" {
				_ = os.WriteFile(marker, []byte("connected\n"), 0o600)
			}
			select {}
		}
	case "after-first-observation":
		marker := os.Getenv(tieCampaignCrashMarkerEnvironment)
		tieCampaignAfterFirstObservation = func() {
			if marker == "" {
				select {}
			}
			_ = os.WriteFile(marker, []byte("durable\n"), 0o600)
			select {}
		}
	}
	if err := run(os.Args[separator+1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	os.Exit(0)
}

type serverProcess struct {
	command *exec.Cmd
	stderr  *bytes.Buffer
}

type tieReceiverProcess struct {
	command    *exec.Cmd
	stderr     *bytes.Buffer
	stdout     *bytes.Buffer
	stdoutDone chan struct{}
}

func startTieReceiverProcess(
	t testing.TB,
	data string,
	transportKey string,
	receiptKey string,
	coordinatorTransportID string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	pairID string,
) (*tieReceiverProcess, string, string) {
	t.Helper()
	command := helperCommand(nil,
		"work-telemetry-tie-pair-receive-quic", "--data", data,
		"--key", transportKey, "--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--coordinator-peer-id", coordinatorTransportID, "--observer-key", receiptKey,
		"--plan", planPath, "--plan-id", planID, "--coordinator-public-key", coordinatorPublicKey,
		"--sequence", "1", "--pair-id", pairID,
	)
	pipe, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(pipe)
	lineResult := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		lineResult <- line
	}()
	var line string
	select {
	case line = <-lineResult:
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("tie-pair receiver startup timeout stderr=%s", stderr.String())
	}
	values := outputFields(line, "work_tie_pair_receiving")
	peerID := values["transport_peer_id"]
	address := strings.Split(values["listen"], ",")[0]
	if peerID == "" || address == "" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid tie-pair receiver line %q stderr=%s", line, stderr.String())
	}
	stdout := new(bytes.Buffer)
	stdout.WriteString(line)
	stdoutDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(stdout, reader)
		close(stdoutDone)
	}()
	result := &tieReceiverProcess{command: command, stderr: stderr, stdout: stdout, stdoutDone: stdoutDone}
	t.Cleanup(func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return result, peerID, address
}

func startTieCampaignReceiverProcess(
	t testing.TB,
	data string,
	transportKey string,
	receiptKey string,
	coordinatorTransportID string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	publicationDirectory string,
	confirmationDirectory string,
) (*tieReceiverProcess, string, string) {
	return startTieCampaignReceiverProcessWithEnvironment(
		t, data, transportKey, receiptKey, coordinatorTransportID, planPath, planID,
		coordinatorPublicKey, publicationDirectory, confirmationDirectory, nil,
	)
}

func startTieCampaignReceiverProcessWithEnvironment(
	t testing.TB,
	data string,
	transportKey string,
	receiptKey string,
	coordinatorTransportID string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	publicationDirectory string,
	confirmationDirectory string,
	environment []string,
) (*tieReceiverProcess, string, string) {
	return startTieCampaignReceiverProcessWithOptions(
		t, data, transportKey, receiptKey, coordinatorTransportID, planPath, planID,
		coordinatorPublicKey, publicationDirectory, confirmationDirectory,
		"/ip4/127.0.0.1/udp/0/quic-v1", environment,
	)
}

func startTieCampaignReceiverProcessWithOptions(
	t testing.TB,
	data string,
	transportKey string,
	receiptKey string,
	coordinatorTransportID string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	publicationDirectory string,
	confirmationDirectory string,
	listenAddress string,
	environment []string,
) (*tieReceiverProcess, string, string) {
	t.Helper()
	command := helperCommand(nil,
		"work-telemetry-tie-campaign-receive-quic", "--data", data,
		"--key", transportKey, "--listen", listenAddress,
		"--coordinator-peer-id", coordinatorTransportID, "--observer-key", receiptKey,
		"--plan", planPath, "--plan-id", planID, "--coordinator-public-key", coordinatorPublicKey,
		"--published", publicationDirectory, "--confirmed", confirmationDirectory, "--poll", "20ms",
	)
	command.Env = append(command.Env, environment...)
	pipe, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(pipe)
	lineResult := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		lineResult <- line
	}()
	var line string
	select {
	case line = <-lineResult:
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("tie-campaign receiver startup timeout stderr=%s", stderr.String())
	}
	values := outputFields(line, "work_tie_campaign_receiving")
	peerID := values["transport_peer_id"]
	address := strings.Split(values["listen"], ",")[0]
	if peerID == "" || address == "" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid tie-campaign receiver line %q stderr=%s", line, stderr.String())
	}
	stdout := new(bytes.Buffer)
	stdout.WriteString(line)
	stdoutDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(stdout, reader)
		close(stdoutDone)
	}()
	result := &tieReceiverProcess{command: command, stderr: stderr, stdout: stdout, stdoutDone: stdoutDone}
	t.Cleanup(func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return result, peerID, address
}

func startTieCampaignCoordinatorProcess(
	t testing.TB,
	data string,
	transportKey string,
	coordinatorKey string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	observerPublicKey string,
	routesPath string,
	artifactDirectory string,
	publicationDirectory string,
	wantSequence uint64,
) *tieReceiverProcess {
	return startTieCampaignCoordinatorProcessWhen(
		t, data, transportKey, coordinatorKey, planPath, planID, coordinatorPublicKey,
		observerPublicKey, routesPath, artifactDirectory, publicationDirectory,
		func(line string) bool {
			fields := outputFields(line, "work_tie_campaign_pair_ready")
			return fields["sequence"] == strconv.FormatUint(wantSequence, 10)
		},
	)
}

func startTieCampaignCoordinatorResumeProcess(
	t testing.TB,
	data string,
	transportKey string,
	coordinatorKey string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	observerPublicKey string,
	routesPath string,
	artifactDirectory string,
	publicationDirectory string,
	wantSequence uint64,
	wantPhase tieproducer.CampaignPhase,
) *tieReceiverProcess {
	return startTieCampaignCoordinatorProcessWhen(
		t, data, transportKey, coordinatorKey, planPath, planID, coordinatorPublicKey,
		observerPublicKey, routesPath, artifactDirectory, publicationDirectory,
		func(line string) bool {
			fields := outputFields(line, "work_tie_campaign_started")
			return fields["next_sequence"] == strconv.FormatUint(wantSequence, 10) &&
				fields["phase"] == strconv.FormatUint(uint64(wantPhase), 10)
		},
	)
}

func startTieCampaignCoordinatorProcessWhen(
	t testing.TB,
	data string,
	transportKey string,
	coordinatorKey string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	observerPublicKey string,
	routesPath string,
	artifactDirectory string,
	publicationDirectory string,
	readyLine func(string) bool,
) *tieReceiverProcess {
	return startTieCampaignCoordinatorProcessWhenWithState(
		t, data, transportKey, coordinatorKey, planPath, planID, coordinatorPublicKey,
		observerPublicKey, routesPath, artifactDirectory, publicationDirectory, "", readyLine,
	)
}

func startTieCampaignCoordinatorProcessWhenWithState(
	t testing.TB,
	data string,
	transportKey string,
	coordinatorKey string,
	planPath string,
	planID string,
	coordinatorPublicKey string,
	observerPublicKey string,
	routesPath string,
	artifactDirectory string,
	publicationDirectory string,
	statePath string,
	readyLine func(string) bool,
) *tieReceiverProcess {
	t.Helper()
	arguments := []string{
		"work-telemetry-tie-campaign", "--data", data,
		"--key", transportKey, "--coordinator-key", coordinatorKey,
		"--plan", planPath, "--plan-id", planID,
		"--coordinator-public-key", coordinatorPublicKey,
		"--observer-public-key", observerPublicKey,
		"--observers", routesPath, "--artifacts", artifactDirectory,
		"--published", publicationDirectory, "--publication-poll", "20ms",
		"--delivery-timeout", "30s",
	}
	if statePath != "" {
		arguments = append(arguments, "--state", statePath)
	}
	command := helperCommand(nil, arguments...)
	pipe, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(pipe)
	stdout := new(bytes.Buffer)
	ready := make(chan error, 1)
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		for {
			line, readErr := reader.ReadString('\n')
			if line != "" {
				stdout.WriteString(line)
				if readyLine(line) {
					ready <- nil
					_, _ = io.Copy(stdout, reader)
					return
				}
			}
			if readErr != nil {
				ready <- readErr
				return
			}
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = command.Wait()
			t.Fatalf("tie-campaign coordinator stopped before ready state: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("tie-campaign coordinator ready timeout stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	result := &tieReceiverProcess{command: command, stderr: stderr, stdout: stdout, stdoutDone: stdoutDone}
	t.Cleanup(func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return result
}

func killTieReceiverProcess(t testing.TB, receiver *tieReceiverProcess) {
	t.Helper()
	if err := receiver.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := receiver.command.Wait(); err == nil {
		t.Fatal("killed tie receiver exited successfully")
	}
	<-receiver.stdoutDone
}

func waitTieReceiverProcess(t testing.TB, receiver *tieReceiverProcess) string {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- receiver.command.Wait() }()
	select {
	case err := <-done:
		<-receiver.stdoutDone
		if err != nil {
			t.Fatalf("tie-pair receiver: %v\nstdout=%s\nstderr=%s", err, receiver.stdout.String(), receiver.stderr.String())
		}
		return receiver.stdout.String()
	case <-time.After(30 * time.Second):
		_ = receiver.command.Process.Kill()
		t.Fatalf("tie-pair receiver completion timeout stderr=%s", receiver.stderr.String())
		return ""
	}
}

func waitTieReceiverProcessError(
	receiver *tieReceiverProcess,
	timeout time.Duration,
) (string, error) {
	done := make(chan error, 1)
	go func() { done <- receiver.command.Wait() }()
	select {
	case err := <-done:
		<-receiver.stdoutDone
		return receiver.stdout.String(), err
	case <-time.After(timeout):
		_ = receiver.command.Process.Kill()
		return receiver.stdout.String(), context.DeadlineExceeded
	}
}

func waitForProcessFile(t testing.TB, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process marker %s was not created", path)
}

func waitForProcessCampaignStatus(
	t testing.TB,
	config tieproducer.CampaignConfig,
	timeout time.Duration,
	ready func(tieproducer.CampaignStatus) bool,
) tieproducer.CampaignStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last tieproducer.CampaignStatus
	var lastErr error
	for time.Now().Before(deadline) {
		last, lastErr = tieproducer.LoadCampaignStatus(config)
		if lastErr == nil && ready(last) {
			return last
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("campaign status did not reach crash boundary last=%+v err=%v", last, lastErr)
	return tieproducer.CampaignStatus{}
}

func publishProcessCampaignCheckpoint(
	t testing.TB,
	artifactDirectory string,
	publicationDirectory string,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	planID types.Hash,
	sequence uint64,
) {
	t.Helper()
	name := fmt.Sprintf("%010d", sequence)
	checkpointPath := artifactDirectory + "/" + name + ".omtcp"
	waitForProcessFile(t, checkpointPath, 30*time.Second)
	checkpointBytes, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := calibration.DecodeTiePairCheckpoint(checkpointBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkpoint.Verify(plan, binding, planID); err != nil {
		t.Fatal(err)
	}
	checkpointID, err := checkpoint.ID(plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationDirectory+"/"+name+".omtcp", checkpointBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		publicationDirectory+"/"+name+".published", []byte(checkpointID.String()+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func processListenAddress(advertisedAddress string) string {
	if index := strings.LastIndex(advertisedAddress, "/p2p/"); index >= 0 {
		return advertisedAddress[:index]
	}
	return advertisedAddress
}

func processTransportPeerID(t testing.TB, path string) types.Hash {
	t.Helper()
	privateKey, err := loadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return types.DomainHash("OMESH/p2p/ed25519/v0", privateKey.Public().(ed25519.PublicKey))
}

func startQUICServerProcess(t testing.TB, data, key string) (*serverProcess, string, string) {
	t.Helper()
	command := helperCommand(nil,
		"serve-quic", "--data", data, "--key", key,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--max-connections", "8", "--max-streams-per-peer", "2",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	lineResult := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lineResult <- line
	}()
	var line string
	select {
	case line = <-lineResult:
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("detached QUIC server startup timeout stderr=%s", stderr.String())
	}
	values := make(map[string]string)
	fields := strings.Fields(strings.TrimSpace(line))
	for _, field := range fields {
		keyValue := strings.SplitN(field, "=", 2)
		if len(keyValue) == 2 {
			values[keyValue[0]] = keyValue[1]
		}
	}
	peerID := values["peer_id"]
	address := strings.Split(values["listen"], ",")[0]
	if len(fields) == 0 || fields[0] != "serving_quic" || peerID == "" || address == "" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid detached QUIC server line %q stderr=%s", line, stderr.String())
	}
	return &serverProcess{command: command, stderr: stderr}, peerID, address
}

func startWorkQUICServerProcess(t testing.TB, data, key string) (*serverProcess, string, string) {
	t.Helper()
	command := helperCommand(nil,
		"work-serve-quic", "--data", data, "--key", key,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--max-connections", "8",
		"--max-chain-streams", "2", "--max-chain-streams-per-peer", "1",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	lineResult := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lineResult <- line
	}()
	var line string
	select {
	case line = <-lineResult:
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("detached versioned QUIC server startup timeout stderr=%s", stderr.String())
	}
	values := outputFields(line, "serving_work_quic")
	peerID := values["peer_id"]
	address := strings.Split(values["listen"], ",")[0]
	if peerID == "" || address == "" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid detached versioned server line %q stderr=%s", line, stderr.String())
	}
	return &serverProcess{command: command, stderr: stderr}, peerID, address
}

func stopQUICServerProcess(t testing.TB, server *serverProcess) {
	t.Helper()
	if err := server.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal QUIC server: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("QUIC server shutdown: %v stderr=%s", err, server.stderr.String())
		}
	case <-time.After(20 * time.Second):
		_ = server.command.Process.Kill()
		t.Fatalf("QUIC server shutdown timeout stderr=%s", server.stderr.String())
	}
}

func runProcessCommand(t testing.TB, timeout time.Duration, arguments ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := helperCommand(ctx, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("command %q: %v\n%s", arguments, err, output)
	}
	return string(output)
}

func runProcessCommandError(timeout time.Duration, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := helperCommand(ctx, arguments...).CombinedOutput()
	return string(output), err
}

func outputFields(output, prefix string) map[string]string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || fields[0] != prefix {
			continue
		}
		result := make(map[string]string, len(fields)-1)
		for _, field := range fields[1:] {
			keyValue := strings.SplitN(field, "=", 2)
			if len(keyValue) == 2 {
				result[keyValue[0]] = keyValue[1]
			}
		}
		return result
	}
	return nil
}

func helperCommand(ctx context.Context, arguments ...string) *exec.Cmd {
	commandArguments := append([]string{"-test.run=^TestOMDHelperProcess$", "--"}, arguments...)
	var command *exec.Cmd
	if ctx == nil {
		command = exec.Command(os.Args[0], commandArguments...)
	} else {
		command = exec.CommandContext(ctx, os.Args[0], commandArguments...)
	}
	command.Env = append(os.Environ(), helperProcessEnvironment+"=1")
	return command
}

func writeProcessKey(t testing.TB, path, label string) {
	t.Helper()
	seed := types.DomainHash("test/cmd/process/key", []byte(label))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	if err := os.WriteFile(path, privateKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
}
