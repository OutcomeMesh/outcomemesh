//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestProcessArchiveCustodyQUICSurvivesReplicaRestart(t *testing.T) {
	fixture := newProcessCustodyFixture(t)
	firstServer, replicaPeerID, address := startProcessCustodyServer(t, fixture)
	firstRecord := filepath.Join(fixture.root, "auditor-first.omcr")
	firstRenewal := filepath.Join(fixture.root, "auditor-first.omrr")
	firstOutput, err := runProcessCustodyChallenge(
		t, fixture, address, replicaPeerID, firstRecord, firstRenewal,
	)
	if err != nil {
		t.Fatalf("first custody audit: %v\nclient=%s\nserver=%s", err, firstOutput, firstServer.stderr.String())
	}
	if fields := outputFields(firstOutput, "work_archive_custody_verified"); fields["recovered"] != "false" || fields["peer_id"] != replicaPeerID ||
		fields["challenge"] == "" || fields["proof"] == "" || fields["renewal"] == "" {
		t.Fatalf("first custody audit output is incomplete: %s", firstOutput)
	}
	waitProcessCustodyServer(t, firstServer)

	firstBytes, err := os.ReadFile(firstRecord)
	if err != nil {
		t.Fatal(err)
	}
	serverBytes, err := os.ReadFile(fixture.serverRecord)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, serverBytes) {
		t.Fatal("replica and auditor did not durably commit the same custody record")
	}

	secondServer, restartedPeerID, restartedAddress := startProcessCustodyServer(t, fixture)
	if restartedPeerID != replicaPeerID {
		t.Fatalf("replica transport identity changed after restart: %s != %s", restartedPeerID, replicaPeerID)
	}
	secondRecord := filepath.Join(fixture.root, "auditor-second.omcr")
	secondRenewal := filepath.Join(fixture.root, "auditor-second.omrr")
	secondOutput, err := runProcessCustodyChallenge(
		t, fixture, restartedAddress, restartedPeerID, secondRecord, secondRenewal,
	)
	if err != nil {
		t.Fatalf("restarted custody audit: %v\nclient=%s\nserver=%s", err, secondOutput, secondServer.stderr.String())
	}
	if fields := outputFields(secondOutput, "work_archive_custody_verified"); fields["recovered"] != "false" || fields["peer_id"] != replicaPeerID {
		t.Fatalf("restarted custody audit output is incomplete: %s", secondOutput)
	}
	waitProcessCustodyServer(t, secondServer)
	secondBytes, err := os.ReadFile(secondRecord)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("restarted replica did not replay its exact durable response")
	}

	// The verified record is self-contained: it can restore a lost challenge and
	// finish without a live replica.
	if err := os.Remove(fixture.challengePath); err != nil {
		t.Fatal(err)
	}
	recoveredOutput, err := runProcessCustodyChallenge(
		t, fixture, restartedAddress, restartedPeerID, secondRecord, secondRenewal,
	)
	if err != nil {
		t.Fatalf("auditor local recovery: %v\n%s", err, recoveredOutput)
	}
	if fields := outputFields(recoveredOutput, "work_archive_custody_verified"); fields["recovered"] != "true" || fields["renewal"] == "" {
		t.Fatalf("auditor did not recover its committed result: %s", recoveredOutput)
	}
	if _, err := os.Stat(fixture.challengePath); err != nil {
		t.Fatalf("auditor did not restore its durable challenge: %v", err)
	}

	loaded, err := workarchive.LoadCustodyRecordFile(
		secondRecord, fixture.manifest, fixture.receipt, fixture.custodyPolicy,
	)
	if err != nil {
		t.Fatal(err)
	}
	renewedBytes, err := loaded.RenewedReceipt.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	committedRenewal, err := os.ReadFile(secondRenewal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renewedBytes, committedRenewal) {
		t.Fatal("auditor receipt output differs from the verified custody record")
	}
}

type processCustodyFixture struct {
	root             string
	manifestPath     string
	receiptPath      string
	objectStorePath  string
	serverRecord     string
	replicaTransport string
	auditorTransport string
	replicaEvidence  string
	auditorEvidence  string
	challengePath    string
	auditorPublicKey string
	renewUntil       uint64
	manifest         workarchive.Manifest
	receipt          workarchive.ReplicaReceipt
	custodyPolicy    workarchive.CustodyPolicy
}

func newProcessCustodyFixture(t testing.TB) processCustodyFixture {
	t.Helper()
	root := t.TempDir()
	parameters := processCustodyParameters()
	base := processCustodyBase()
	chain, err := workchain.New(base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := chain.Prepare(
		base.Tip.ID, base.Tip.Timestamp+parameters.TargetSpacing, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	template, err := payload.SealTemplate(
		types.Address(types.DomainHash("test/cmd/process-custody/miner")), inclusion, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	block, _, err := payload.Finalize(anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := chain.Commit(block, block.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	tip, err := chain.Tip()
	if err != nil {
		t.Fatal(err)
	}
	binding := workarchive.Binding{
		NetworkID:        parameters.NetworkID,
		GenesisID:        types.DomainHash("test/cmd/process-custody/genesis"),
		ActivationHeight: parameters.ActivationHeight,
		BaseID:           base.Tip.ID,
	}
	archivePath := filepath.Join(root, "archive")
	manifest, _, err := workarchive.ExportDirectory(
		archivePath, binding, chain, tip.ID, workarchive.DefaultExportOptions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	attestorKeys := []ed25519.PrivateKey{
		processCustodyKey("attestor-a"), processCustodyKey("attestor-b"),
	}
	attestations := make([]workarchive.Attestation, len(attestorKeys))
	trustedAttestors := make([][ed25519.PublicKeySize]byte, len(attestorKeys))
	for index, key := range attestorKeys {
		attestations[index], err = workarchive.Attest(key, statement)
		if err != nil {
			t.Fatal(err)
		}
		copy(trustedAttestors[index][:], key.Public().(ed25519.PublicKey))
	}
	sort.Slice(trustedAttestors, func(left, right int) bool {
		return bytes.Compare(trustedAttestors[left][:], trustedAttestors[right][:]) < 0
	})
	checkpoint, err := workarchive.NewCheckpoint(statement, attestations)
	if err != nil {
		t.Fatal(err)
	}
	checkpointPolicy := workarchive.Policy{
		Binding: binding, TrustedAttestors: trustedAttestors, RequiredAttestations: 2,
	}

	replicaKey := processCustodyKey("replica-evidence")
	now := uint64(time.Now().Unix())
	receipt, err := workarchive.CreateReplicaReceipt(
		archivePath, checkpoint, checkpointPolicy, base, parameters,
		workarchive.DefaultLimits(), replicaKey,
		types.DomainHash("test/cmd/process-custody/location"),
		now-60, now+3_600,
	)
	if err != nil {
		t.Fatal(err)
	}
	objectStorePath := filepath.Join(root, "objects")
	objectStore, err := workarchive.OpenObjectStore(
		objectStorePath, workarchive.DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objectStore.ImportArchiveDirectory(
		archivePath, checkpoint, checkpointPolicy, base, parameters,
		workarchive.DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(root, "manifest.omwm")
	receiptPath := filepath.Join(root, "receipt.omrr")
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := receipt.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writeProcessCustodyCanonical(t, manifestPath, manifestBytes)
	writeProcessCustodyCanonical(t, receiptPath, receiptBytes)
	replicaTransport := filepath.Join(root, "replica-transport.key")
	auditorTransport := filepath.Join(root, "auditor-transport.key")
	replicaEvidence := filepath.Join(root, "replica-evidence.key")
	auditorEvidence := filepath.Join(root, "auditor-evidence.key")
	writeProcessCustodyKey(t, replicaTransport, processCustodyKey("replica-transport"))
	writeProcessCustodyKey(t, auditorTransport, processCustodyKey("auditor-transport"))
	writeProcessCustodyKey(t, replicaEvidence, replicaKey)
	auditorKey := processCustodyKey("auditor-evidence")
	writeProcessCustodyKey(t, auditorEvidence, auditorKey)
	var auditorPublicKey [ed25519.PublicKeySize]byte
	copy(auditorPublicKey[:], auditorKey.Public().(ed25519.PublicKey))
	return processCustodyFixture{
		root: root, manifestPath: manifestPath, receiptPath: receiptPath,
		objectStorePath:  objectStorePath,
		serverRecord:     filepath.Join(root, "replica-response.omcr"),
		replicaTransport: replicaTransport, auditorTransport: auditorTransport,
		replicaEvidence: replicaEvidence, auditorEvidence: auditorEvidence,
		challengePath:    filepath.Join(root, "auditor-challenge.omcc"),
		auditorPublicKey: types.Hash(auditorPublicKey).String(), renewUntil: now + 7_200,
		manifest: manifest, receipt: receipt,
		custodyPolicy: workarchive.CustodyPolicy{
			TrustedAuditors:          [][ed25519.PublicKeySize]byte{auditorPublicKey},
			MaximumChallengeLifetime: 120, MaximumProofAge: 120,
			MaximumRenewalTerm: defaultCustodyRenewalTerm,
		},
	}
}

func startProcessCustodyServer(
	t testing.TB,
	fixture processCustodyFixture,
) (*serverProcess, string, string) {
	t.Helper()
	auditorPeerID := processTransportPeerID(t, fixture.auditorTransport).String()
	command := helperCommand(nil,
		"work-archive-custody-serve-quic",
		"--key", fixture.replicaTransport,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--auditor-peer-id", auditorPeerID,
		"--replica-key", fixture.replicaEvidence,
		"--auditor-public-key", fixture.auditorPublicKey,
		"--manifest", fixture.manifestPath,
		"--receipt", fixture.receiptPath,
		"--object-store", fixture.objectStorePath,
		"--record", fixture.serverRecord,
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
	server := &serverProcess{command: command, stderr: stderr}
	t.Cleanup(func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
		}
	})
	type readyResult struct {
		line string
		err  error
	}
	ready := make(chan readyResult, 1)
	reader := bufio.NewReader(stdout)
	go func() {
		line, readErr := reader.ReadString('\n')
		ready <- readyResult{line: line, err: readErr}
		_, _ = io.Copy(io.Discard, reader)
	}()
	select {
	case result := <-ready:
		if result.err != nil {
			_ = command.Process.Kill()
			t.Fatalf("custody server readiness: %v stderr=%s", result.err, stderr.String())
		}
		fields := outputFields(result.line, "work_archive_custody_receiving")
		if fields["transport_peer_id"] == "" || fields["listen"] == "" {
			_ = command.Process.Kill()
			t.Fatalf("custody server readiness output is incomplete: %s", result.line)
		}
		return server, fields["transport_peer_id"], strings.Split(fields["listen"], ",")[0]
	case <-time.After(20 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("custody server readiness timeout stderr=%s", stderr.String())
	}
	return nil, "", ""
}

func runProcessCustodyChallenge(
	t testing.TB,
	fixture processCustodyFixture,
	address string,
	replicaPeerID string,
	recordPath string,
	receiptPath string,
) (string, error) {
	t.Helper()
	return runProcessCommandError(30*time.Second,
		"work-archive-custody-challenge-quic",
		"--key", fixture.auditorTransport,
		"--peer", address,
		"--peer-id", replicaPeerID,
		"--auditor-key", fixture.auditorEvidence,
		"--manifest", fixture.manifestPath,
		"--receipt", fixture.receiptPath,
		"--challenge", fixture.challengePath,
		"--record", recordPath,
		"--out-receipt", receiptPath,
		"--renew-until", strconv.FormatUint(fixture.renewUntil, 10),
		"--samples", "1",
	)
}

func waitProcessCustodyServer(t testing.TB, server *serverProcess) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- server.command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("custody server exit: %v stderr=%s", err, server.stderr.String())
		}
	case <-time.After(20 * time.Second):
		_ = server.command.Process.Kill()
		t.Fatalf("custody server exit timeout stderr=%s", server.stderr.String())
	}
}

func processCustodyParameters() workblock.Parameters {
	return workblock.Parameters{
		NetworkID: 910, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: 1_699_999_940, DifficultyAnchorTarget: processCustodyTarget(),
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
}

func processCustodyBase() workchain.Base {
	initial := state.Empty()
	return workchain.Base{
		Tip: storage.Tip{
			ID: types.DomainHash("test/cmd/process-custody/base"), Height: 0,
			Timestamp: 1_699_999_940, Target: processCustodyTarget(), StateRoot: initial.Root(),
		},
		State: initial, RecentTimestamps: []uint64{1_699_999_940},
	}
}

func processCustodyTarget() types.Hash {
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return target
}

func processCustodyKey(label string) ed25519.PrivateKey {
	seed := types.DomainHash("test/cmd/process-custody/key", []byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func writeProcessCustodyKey(t testing.TB, path string, key ed25519.PrivateKey) {
	t.Helper()
	if err := os.WriteFile(path, key.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeProcessCustodyCanonical(t testing.TB, path string, encoded []byte) {
	t.Helper()
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
