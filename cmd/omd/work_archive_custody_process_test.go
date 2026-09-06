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

func TestProcessArchiveCustodyJournalRunsTwoRestartedCycles(t *testing.T) {
	fixture := newProcessCustodyFixture(t)
	replicaJournal := filepath.Join(fixture.root, "replica-journal")
	auditorJournal := filepath.Join(fixture.root, "auditor-journal")
	auditorArtifacts := filepath.Join(fixture.root, "auditor-cycles")

	firstServer, replicaPeerID, address := startProcessCustodyJournalServer(
		t, fixture, replicaJournal,
	)
	firstOutput, err := runProcessCustodyJournalChallenge(
		t, fixture, address, replicaPeerID, auditorJournal, auditorArtifacts, 7_200, 0,
	)
	if err != nil {
		t.Fatalf("first journal custody audit: %v\nclient=%s\nserver=%s", err, firstOutput, firstServer.stderr.String())
	}
	if fields := outputFields(firstOutput, "work_archive_custody_verified"); fields["sequence"] != "1" || fields["journal"] != auditorJournal || fields["recovered"] != "false" {
		t.Fatalf("first journal custody output is incomplete: %s", firstOutput)
	}
	waitProcessCustodyServer(t, firstServer)
	assertProcessCustodyJournalState(t, fixture, replicaJournal, 1)
	assertProcessCustodyJournalState(t, fixture, auditorJournal, 1)
	// A record committed just before the auditor's journal append can finish
	// locally on restart, including restoration of the missing output files.
	pendingArtifacts := filepath.Join(fixture.root, "pending-cycles")
	pendingJournal := filepath.Join(fixture.root, "pending-journal")
	_, completedRecord, _ := custodyCycleArtifactPaths(auditorArtifacts, 1)
	_, pendingRecord, _ := custodyCycleArtifactPaths(pendingArtifacts, 1)
	recordBytes, err := os.ReadFile(completedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishImmutableArtifact(pendingRecord, recordBytes); err != nil {
		t.Fatal(err)
	}
	// Refusing journal growth must preserve the verified record so an operator
	// can raise the cap and finish the same cycle without contacting the replica.
	limitedOutput, err := runProcessCustodyJournalChallenge(t, fixture, address, replicaPeerID,
		pendingJournal, pendingArtifacts, 7_200, 0, "--journal-max-paths", "9")
	if err == nil || !strings.Contains(limitedOutput, workarchive.ErrCustodyJournalBudget.Error()) {
		t.Fatalf("undersized journal budget was accepted: %v\n%s", err, limitedOutput)
	}
	_, limitedState, err := workarchive.OpenOrCreateCustodyJournal(pendingJournal, fixture.manifest, fixture.receipt, fixture.custodyPolicy)
	if err != nil || limitedState.Sequence != 0 {
		t.Fatalf("refused append changed custody head: %+v %v", limitedState, err)
	}
	if preserved, err := os.ReadFile(pendingRecord); err != nil || !bytes.Equal(preserved, recordBytes) {
		t.Fatalf("budget refusal changed pending evidence: %v", err)
	}
	pendingOutput, err := runProcessCustodyJournalChallenge(t, fixture, address, replicaPeerID, pendingJournal, pendingArtifacts, 7_200, 0)
	if err != nil {
		t.Fatalf("pending record journal recovery: %v\n%s", err, pendingOutput)
	}
	if fields := outputFields(pendingOutput, "work_archive_custody_verified"); fields["sequence"] != "1" || fields["recovered"] != "true" {
		t.Fatalf("pending record was not journaled locally: %s", pendingOutput)
	}
	assertProcessCustodyJournalState(t, fixture, pendingJournal, 1)

	// Model a client that persisted its challenge but lost the response before
	// committing it. The restarted replica must redeliver its first decision.
	retryArtifacts := filepath.Join(fixture.root, "retry-cycles")
	retryJournal := filepath.Join(fixture.root, "retry-journal")
	firstChallenge, _, _ := custodyCycleArtifactPaths(auditorArtifacts, 1)
	retryChallenge, _, _ := custodyCycleArtifactPaths(retryArtifacts, 1)
	challengeBytes, err := os.ReadFile(firstChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishImmutableArtifact(retryChallenge, challengeBytes); err != nil {
		t.Fatal(err)
	}
	// Lowering the replica's cap below existing usage must still allow exact
	// network redelivery of the durable response. Its active segment is empty.
	retryServer, retryPeer, retryAddress := startProcessCustodyJournalServer(t, fixture, replicaJournal, "--journal-max-paths", "9")
	retryOutput, err := runProcessCustodyJournalChallenge(t, fixture, retryAddress, retryPeer, retryJournal, retryArtifacts, 7_200, 0)
	if err != nil {
		t.Fatalf("journal response redelivery: %v\n%s", err, retryOutput)
	}
	waitProcessCustodyServer(t, retryServer)
	assertProcessCustodyJournalState(t, fixture, replicaJournal, 1)
	_, originalState, err := workarchive.OpenOrCreateCustodyJournal(auditorJournal, fixture.manifest, fixture.receipt, fixture.custodyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	_, retryState, err := workarchive.OpenOrCreateCustodyJournal(retryJournal, fixture.manifest, fixture.receipt, fixture.custodyPolicy)
	if err != nil || originalState != retryState {
		t.Fatalf("redelivery changed journal decision: %v", err)
	}

	secondServer, restartedPeerID, restartedAddress := startProcessCustodyJournalServer(
		t, fixture, replicaJournal,
	)
	if restartedPeerID != replicaPeerID {
		t.Fatalf("journal replica identity changed after restart: %s != %s", restartedPeerID, replicaPeerID)
	}
	secondOutput, err := runProcessCustodyJournalChallenge(
		t, fixture, restartedAddress, restartedPeerID, auditorJournal, auditorArtifacts, 10_800, 0,
	)
	if err != nil {
		t.Fatalf("second journal custody audit: %v\nclient=%s\nserver=%s", err, secondOutput, secondServer.stderr.String())
	}
	if fields := outputFields(secondOutput, "work_archive_custody_verified"); fields["sequence"] != "2" || fields["recovered"] != "false" {
		t.Fatalf("second journal custody output is incomplete: %s", secondOutput)
	}
	waitProcessCustodyServer(t, secondServer)
	assertProcessCustodyJournalState(t, fixture, replicaJournal, 2)
	assertProcessCustodyJournalState(t, fixture, auditorJournal, 2)
	recoveryChallenge, recoveryRecord, recoveryReceipt := custodyCycleArtifactPaths(auditorArtifacts, 2)
	for _, path := range []string{recoveryChallenge, recoveryRecord, recoveryReceipt} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	recoveredOutput, err := runProcessCustodyJournalChallenge(
		t, fixture, restartedAddress, restartedPeerID, auditorJournal, auditorArtifacts, 10_800, 0,
		"--journal-max-paths", "9",
	)
	if err != nil {
		t.Fatalf("journal head artifact recovery: %v\n%s", err, recoveredOutput)
	}
	if fields := outputFields(recoveredOutput, "work_archive_custody_verified"); fields["sequence"] != "2" || fields["recovered"] != "true" {
		t.Fatalf("journal did not restore completed artifacts locally: %s", recoveredOutput)
	}
	if fields := outputFields(recoveredOutput, "work_archive_custody_journal_usage"); fields["over_budget"] != "true" || fields["max_paths"] != "9" {
		t.Fatalf("over-budget journal usage was not reported: %s", recoveredOutput)
	}
	auditor, _, err := workarchive.OpenOrCreateCustodyJournal(auditorJournal, fixture.manifest, fixture.receipt, fixture.custodyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	head, _, err := auditor.Head()
	if err != nil {
		t.Fatal(err)
	}
	expectedReceipt, _ := head.Record.RenewedReceipt.CanonicalBytes()
	actualReceipt, err := os.ReadFile(recoveryReceipt)
	if err != nil || !bytes.Equal(expectedReceipt, actualReceipt) {
		t.Fatalf("recovered receipt differs: %v", err)
	}

	// An external timer may call the auditor command as often as it wants. With
	// no unfinished cycle artifacts it exits before dialing until the interval
	// derived from the replayed receipt is due.
	notDueOutput, err := runProcessCustodyJournalChallenge(
		t, fixture, restartedAddress, restartedPeerID, auditorJournal, auditorArtifacts,
		10_800, 3_600,
	)
	if err != nil {
		t.Fatalf("journal not-due check: %v\n%s", err, notDueOutput)
	}
	if fields := outputFields(notDueOutput, "work_archive_custody_not_due"); fields["sequence"] != "3" || fields["journal"] != auditorJournal || fields["due_at"] == "" {
		t.Fatalf("journal not-due output is incomplete: %s", notDueOutput)
	}

	for _, journalPath := range []string{replicaJournal, auditorJournal} {
		segments, err := os.ReadDir(filepath.Join(journalPath, "objects", "segments"))
		if err != nil || len(segments) != 2 {
			t.Fatalf("journal %s sealed segments=%d error=%v", journalPath, len(segments), err)
		}
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

func startProcessCustodyJournalServer(
	t testing.TB,
	fixture processCustodyFixture,
	journalPath string,
	extraFlags ...string,
) (*serverProcess, string, string) {
	t.Helper()
	auditorPeerID := processTransportPeerID(t, fixture.auditorTransport).String()
	arguments := []string{
		"work-archive-custody-serve-quic",
		"--key", fixture.replicaTransport,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--auditor-peer-id", auditorPeerID,
		"--replica-key", fixture.replicaEvidence,
		"--auditor-public-key", fixture.auditorPublicKey,
		"--manifest", fixture.manifestPath,
		"--receipt", fixture.receiptPath,
		"--object-store", fixture.objectStorePath,
		"--journal", journalPath,
		"--rotate-every", "1",
	}
	command := helperCommand(nil, append(arguments, extraFlags...)...)
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
			t.Fatalf("journal custody server readiness: %v stderr=%s", result.err, stderr.String())
		}
		fields := outputFields(result.line, "work_archive_custody_receiving")
		if fields["transport_peer_id"] == "" || fields["listen"] == "" {
			_ = command.Process.Kill()
			t.Fatalf("journal custody readiness output is incomplete: %s", result.line)
		}
		return server, fields["transport_peer_id"], strings.Split(fields["listen"], ",")[0]
	case <-time.After(20 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("journal custody readiness timeout stderr=%s", stderr.String())
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

func runProcessCustodyJournalChallenge(
	t testing.TB,
	fixture processCustodyFixture,
	address string,
	replicaPeerID string,
	journalPath string,
	artifactPath string,
	renewalSeconds uint64,
	minimumInterval uint64,
	extraFlags ...string,
) (string, error) {
	t.Helper()
	arguments := []string{
		"work-archive-custody-challenge-quic",
		"--key", fixture.auditorTransport,
		"--peer", address,
		"--peer-id", replicaPeerID,
		"--auditor-key", fixture.auditorEvidence,
		"--manifest", fixture.manifestPath,
		"--receipt", fixture.receiptPath,
		"--journal", journalPath,
		"--artifacts", artifactPath,
		"--renewal-seconds", strconv.FormatUint(renewalSeconds, 10),
		"--minimum-interval-seconds", strconv.FormatUint(minimumInterval, 10),
		"--rotate-every", "1",
		"--samples", "1",
	}
	return runProcessCommandError(30*time.Second, append(arguments, extraFlags...)...)
}

func assertProcessCustodyJournalState(
	t testing.TB,
	fixture processCustodyFixture,
	path string,
	wantSequence uint64,
) {
	t.Helper()
	_, state, err := workarchive.OpenOrCreateCustodyJournal(
		path, fixture.manifest, fixture.receipt, fixture.custodyPolicy,
	)
	if err != nil || state.Sequence != wantSequence ||
		state.CurrentReceipt.RetainUntil <= fixture.receipt.RetainUntil {
		t.Fatalf("custody journal %s state=%+v error=%v", path, state, err)
	}
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
