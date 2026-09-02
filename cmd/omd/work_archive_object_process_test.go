//go:build integration

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestProcessArchiveObjectQUICMaterializesAndRecoversAcrossRestart(t *testing.T) {
	fixture := newProcessArchiveObjectFixture(t)
	firstServer, serverPeerID, address := startProcessArchiveObjectServer(t, fixture)
	firstStore := filepath.Join(fixture.root, "destination-objects-a")
	firstOutputPath := filepath.Join(fixture.root, "materialized-a")
	firstOutput := runProcessArchiveObjectFetch(
		t, fixture, address, serverPeerID, firstStore, firstOutputPath,
	)
	if fields := outputFields(firstOutput, "work_archive_objects_fetched"); fields["complete"] != "true" || fields["network"] != "true" ||
		fields["recovered"] != "false" || fields["objects"] == "0" ||
		fields["manifest"] != fixture.manifestID.String() {
		t.Fatalf("first archive fetch output is incomplete: %s", firstOutput)
	}
	firstServed := waitProcessArchiveObjectServer(t, firstServer)
	if fields := outputFields(firstServed, "work_archive_objects_served"); fields["peer_id"] != fixture.clientPeerID.String() ||
		fields["manifest"] != fixture.manifestID.String() || fields["objects"] == "0" {
		t.Fatalf("first archive server output is incomplete: %s", firstServed)
	}
	assertProcessArchiveObjectOutput(t, fixture, firstOutputPath)

	// A complete local store/output must recover without contacting the stopped server.
	recovered := runProcessArchiveObjectFetch(
		t, fixture, address, serverPeerID, firstStore, firstOutputPath,
	)
	if fields := outputFields(recovered, "work_archive_objects_fetched"); fields["complete"] != "true" || fields["network"] != "false" ||
		fields["recovered"] != "true" || fields["requests"] != "0" {
		t.Fatalf("archive client local recovery is incomplete: %s", recovered)
	}

	// Restart the source on the same transport identity and persistent object
	// store, then materialize an independent receiver from scratch.
	secondServer, restartedPeerID, restartedAddress := startProcessArchiveObjectServer(t, fixture)
	if restartedPeerID != serverPeerID {
		t.Fatalf("archive source identity changed on restart: %s != %s", restartedPeerID, serverPeerID)
	}
	secondStore := filepath.Join(fixture.root, "destination-objects-b")
	secondOutputPath := filepath.Join(fixture.root, "materialized-b")
	secondOutput := runProcessArchiveObjectFetch(
		t, fixture, restartedAddress, restartedPeerID, secondStore, secondOutputPath,
	)
	if fields := outputFields(secondOutput, "work_archive_objects_fetched"); fields["complete"] != "true" || fields["network"] != "true" ||
		fields["recovered"] != "false" || fields["manifest"] != fixture.manifestID.String() {
		t.Fatalf("restarted archive fetch output is incomplete: %s", secondOutput)
	}
	waitProcessArchiveObjectServer(t, secondServer)
	assertProcessArchiveObjectOutput(t, fixture, secondOutputPath)

	firstManifest, err := os.ReadFile(filepath.Join(firstOutputPath, "manifest.omwm"))
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, err := os.ReadFile(filepath.Join(secondOutputPath, "manifest.omwm"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstManifest, secondManifest) {
		t.Fatal("source restart produced different materialized manifest bytes")
	}
}

type processArchiveObjectFixture struct {
	root              string
	data              string
	archive           string
	manifestPath      string
	checkpointPath    string
	attestorPublicKey []string
	sourceStore       string
	serverKey         string
	clientKey         string
	clientPeerID      types.Hash
	manifest          workarchive.Manifest
	checkpoint        workarchive.Checkpoint
	policy            workarchive.Policy
	base              workchain.Base
	parameters        workblock.Parameters
	manifestID        types.Hash
}

func newProcessArchiveObjectFixture(t testing.TB) processArchiveObjectFixture {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "node")
	runProcessCommand(t, 20*time.Second,
		"init", "--data", data, "--network", "20260902", "--timestamp", "1700000000",
		"--difficulty-bits", "12", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
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
	runProcessCommand(t, 40*time.Second, "work-mine", "--data", data, "--count", "3")

	_, ledger, router, profile, err := openWorkNode(data)
	if err != nil {
		t.Fatal(err)
	}
	tip, err := router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := router.BlockByID(tip.ID)
	if err != nil {
		t.Fatal(err)
	}
	for candidate.Height() > profile.ActivationHeight {
		candidate, err = router.BlockByID(candidate.ParentID())
		if err != nil {
			t.Fatal(err)
		}
	}
	activationBlock, ok := candidate.WorkBlock()
	if !ok || candidate.Height() != profile.ActivationHeight {
		t.Fatalf("activation candidate=%+v", candidate)
	}
	baseID := activationBlock.Header.Seal.AnchorParent
	base, err := archiveBaseFromLedger(ledger, baseID, profile.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	_, parameters, err := router.Parameters()
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	tree, err := workchain.Open(
		filepath.Join(data, workForestDirectory, baseID.String()), base, parameters,
	)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "source-archive")
	binding := workarchive.Binding{
		NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight: profile.ActivationHeight, BaseID: baseID,
	}
	manifest, manifestID, err := workarchive.ExportDirectory(
		archive, binding, tree, tip.ID, workarchive.DefaultExportOptions(),
	)
	closeErr := tree.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	statement, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	attestorKeys := []ed25519.PrivateKey{
		archiveObjectProcessKey("attestor-a"), archiveObjectProcessKey("attestor-b"),
	}
	attestations := make([]workarchive.Attestation, len(attestorKeys))
	trusted := make([][ed25519.PublicKeySize]byte, len(attestorKeys))
	publicKeyText := make([]string, len(attestorKeys))
	for index, key := range attestorKeys {
		attestations[index], err = workarchive.Attest(key, statement)
		if err != nil {
			t.Fatal(err)
		}
		copy(trusted[index][:], key.Public().(ed25519.PublicKey))
		publicKeyText[index] = types.Hash(trusted[index]).String()
	}
	sort.Slice(trusted, func(left, right int) bool {
		return types.CompareHash(types.Hash(trusted[left]), types.Hash(trusted[right])) < 0
	})
	checkpoint, err := workarchive.NewCheckpoint(statement, attestations)
	if err != nil {
		t.Fatal(err)
	}
	policy := workarchive.Policy{
		Binding: binding, TrustedAttestors: trusted, RequiredAttestations: 2,
	}
	manifestPath := filepath.Join(root, "manifest.omwm")
	checkpointPath := filepath.Join(root, "checkpoint.omwc")
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	checkpointBytes, err := checkpoint.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writeProcessCustodyCanonical(t, manifestPath, manifestBytes)
	writeProcessCustodyCanonical(t, checkpointPath, checkpointBytes)
	serverKey := filepath.Join(root, "archive-server.key")
	clientKey := filepath.Join(root, "archive-client.key")
	writeProcessCustodyKey(t, serverKey, archiveObjectProcessKey("server-transport"))
	clientPrivateKey := archiveObjectProcessKey("client-transport")
	writeProcessCustodyKey(t, clientKey, clientPrivateKey)
	clientPeerID := types.DomainHash(
		"OMESH/p2p/ed25519/v0", clientPrivateKey.Public().(ed25519.PublicKey),
	)
	return processArchiveObjectFixture{
		root: root, data: data, archive: archive,
		manifestPath: manifestPath, checkpointPath: checkpointPath,
		attestorPublicKey: publicKeyText,
		sourceStore:       filepath.Join(root, "source-objects"),
		serverKey:         serverKey, clientKey: clientKey, clientPeerID: clientPeerID,
		manifest: manifest, checkpoint: checkpoint, policy: policy,
		base: base, parameters: parameters, manifestID: manifestID,
	}
}

func startProcessArchiveObjectServer(
	t testing.TB,
	fixture processArchiveObjectFixture,
) (*archiveObjectServerProcess, string, string) {
	t.Helper()
	arguments := []string{
		"work-archive-object-serve-quic",
		"--data", fixture.data,
		"--key", fixture.serverKey,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--client-peer-id", fixture.clientPeerID.String(),
		"--archive", fixture.archive,
		"--manifest", fixture.manifestPath,
		"--checkpoint", fixture.checkpointPath,
		"--required-attestations", "2",
		"--object-store", fixture.sourceStore,
	}
	for _, publicKey := range fixture.attestorPublicKey {
		arguments = append(arguments, "--attestor-public-key", publicKey)
	}
	command := helperCommand(nil, arguments...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	server := &archiveObjectServerProcess{
		command: command, stderr: stderr, output: new(bytes.Buffer),
	}
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
		_, _ = io.Copy(server.output, reader)
	}()
	select {
	case result := <-ready:
		server.output.WriteString(result.line)
		if result.err != nil {
			_ = command.Process.Kill()
			t.Fatalf("archive server readiness: %v stderr=%s", result.err, stderr.String())
		}
		fields := outputFields(result.line, "work_archive_objects_receiving")
		if fields["transport_peer_id"] == "" || fields["listen"] == "" ||
			fields["manifest"] != fixture.manifestID.String() {
			_ = command.Process.Kill()
			t.Fatalf("archive server readiness output is incomplete: %s", result.line)
		}
		return server, fields["transport_peer_id"], strings.Split(fields["listen"], ",")[0]
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("archive server readiness timeout stderr=%s", stderr.String())
	}
	return nil, "", ""
}

type archiveObjectServerProcess struct {
	command *exec.Cmd
	stderr  *bytes.Buffer
	output  *bytes.Buffer
}

func waitProcessArchiveObjectServer(
	t testing.TB,
	server *archiveObjectServerProcess,
) string {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- server.command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("archive server exit: %v stderr=%s output=%s", err, server.stderr.String(), server.output.String())
		}
		return server.output.String()
	case <-time.After(30 * time.Second):
		_ = server.command.Process.Kill()
		t.Fatalf("archive server exit timeout stderr=%s", server.stderr.String())
	}
	return ""
}

func runProcessArchiveObjectFetch(
	t testing.TB,
	fixture processArchiveObjectFixture,
	address string,
	serverPeerID string,
	store string,
	output string,
) string {
	t.Helper()
	arguments := []string{
		"work-archive-object-fetch-quic",
		"--data", fixture.data,
		"--key", fixture.clientKey,
		"--peer", address,
		"--peer-id", serverPeerID,
		"--object-store", store,
		"--out", output,
		"--manifest", fixture.manifestPath,
		"--checkpoint", fixture.checkpointPath,
		"--required-attestations", "2",
	}
	for _, publicKey := range fixture.attestorPublicKey {
		arguments = append(arguments, "--attestor-public-key", publicKey)
	}
	return runProcessCommand(t, 45*time.Second, arguments...)
}

func assertProcessArchiveObjectOutput(
	t testing.TB,
	fixture processArchiveObjectFixture,
	path string,
) {
	t.Helper()
	verified, err := workarchive.VerifyArchiveDirectory(
		path, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, workarchive.DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedID, err := verified.ID()
	if err != nil || verifiedID != fixture.manifestID {
		t.Fatalf("materialized archive ID=%s want=%s error=%v", verifiedID, fixture.manifestID, err)
	}
}

func archiveObjectProcessKey(label string) ed25519.PrivateKey {
	seed := types.DomainHash("test/cmd/process-archive-object/key", []byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}
