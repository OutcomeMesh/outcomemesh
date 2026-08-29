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
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

const helperProcessEnvironment = "OUTCOMEMESH_TEST_HELPER_PROCESS"

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
