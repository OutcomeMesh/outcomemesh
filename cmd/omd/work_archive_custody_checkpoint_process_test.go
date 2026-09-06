//go:build integration

package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestProcessArchiveCustodyCheckpointRestoresPendingCycle(t *testing.T) {
	testProcessCustodyCopyRestoresPendingCycle(t, false)
}

func TestProcessArchiveCustodyBackupRestoresPendingCycle(t *testing.T) {
	testProcessCustodyCopyRestoresPendingCycle(t, true)
}

func testProcessCustodyCopyRestoresPendingCycle(t *testing.T, managed bool) {
	fixture := newProcessCustodyFixture(t)
	journalPath := filepath.Join(fixture.root, "journal")
	artifactsPath := filepath.Join(fixture.root, "cycles")
	if _, _, err := workarchive.OpenOrCreateCustodyJournal(journalPath, fixture.manifest, fixture.receipt, fixture.custodyPolicy); err != nil {
		t.Fatal(err)
	}
	lock, err := workarchive.AcquireCustodyArtifacts(artifactsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(fixture.root, "before.omccp")
	runCheckpoint := func(verify bool, j, a, path string, extra ...string) (string, error) {
		name := "work-archive-custody-checkpoint"
		if verify {
			name = "work-archive-custody-verify-checkpoint"
		}
		args := []string{name, "--journal", j, "--checkpoint", path,
			"--manifest", fixture.manifestPath, "--receipt", fixture.receiptPath,
			"--auditor-public-key", fixture.auditorPublicKey}
		if a == "" {
			args = append(args, "--replica-only")
		} else {
			args = append(args, "--artifacts", a)
		}
		return runProcessCommandError(20*time.Second, append(args, extra...)...)
	}
	output, err := runCheckpoint(false, journalPath, artifactsPath, checkpointPath)
	if err != nil {
		t.Fatalf("initial checkpoint: %v\n%s", err, output)
	}
	oldID := outputFields(output, "work_archive_custody_checkpoint")["id"]
	if oldID == "" {
		t.Fatal("checkpoint did not print an independent pin")
	}
	replicaCheckpoint := filepath.Join(fixture.root, "replica-only.omccp")
	if output, err := runCheckpoint(false, journalPath, "", replicaCheckpoint); err != nil || outputFields(output, "work_archive_custody_checkpoint")["replica_only"] != "true" {
		t.Fatalf("explicit replica checkpoint failed: %v\n%s", err, output)
	}
	if output, err := runCheckpoint(false, journalPath, artifactsPath, filepath.Join(artifactsPath, "inside.omccp")); err == nil {
		t.Fatalf("checkpoint inside artifacts accepted: %s", output)
	}
	if output, err := runCheckpoint(false, journalPath, artifactsPath, replicaCheckpoint, "--replica-only"); err == nil {
		t.Fatalf("ambiguous artifact scope accepted: %s", output)
	}
	oldBytes, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}

	// Model a stopped auditor with a fully verified response, but no journal
	// slot yet. These exact artifacts must survive its cold backup and restore.
	now := unixNow()
	auditorKey := processCustodyKey("auditor-evidence")
	replicaKey := processCustodyKey("replica-evidence")
	challenge, err := workarchive.CreateCustodyChallenge(fixture.manifest, fixture.receipt, auditorKey, now, 60, 1, now+7_200)
	if err != nil {
		t.Fatal(err)
	}
	store, err := workarchive.OpenObjectStore(fixture.objectStorePath, workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := workarchive.AnswerCustodyChallenge(store, fixture.manifest, fixture.receipt, challenge, fixture.custodyPolicy, replicaKey, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := workarchive.RenewReplicaReceipt(fixture.manifest, fixture.receipt, challenge, batch, proof, fixture.custodyPolicy, replicaKey, now)
	if err != nil {
		t.Fatal(err)
	}
	record := workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: receipt}
	challengePath, recordPath, _ := custodyCycleArtifactPaths(artifactsPath, 1)
	challengeBytes, _ := challenge.CanonicalBytes()
	recordBytes, _ := record.CanonicalBytes()
	if err := publishImmutableArtifact(challengePath, challengeBytes); err != nil {
		t.Fatal(err)
	}
	if err := publishImmutableArtifact(recordPath, recordBytes); err != nil {
		t.Fatal(err)
	}
	if output, err := runCheckpoint(false, journalPath, artifactsPath, checkpointPath); err == nil || !strings.Contains(output, "immutable artifact conflict") {
		t.Fatalf("changed inventory replaced checkpoint: %v\n%s", err, output)
	}
	if current, err := os.ReadFile(checkpointPath); err != nil || !bytes.Equal(current, oldBytes) {
		t.Fatal("old checkpoint was overwritten")
	}
	checkpointPath = filepath.Join(fixture.root, "pending.omccp")
	output, err = runCheckpoint(false, journalPath, artifactsPath, checkpointPath)
	if err != nil {
		t.Fatalf("pending checkpoint: %v\n%s", err, output)
	}
	fields := outputFields(output, "work_archive_custody_checkpoint")
	newID := fields["id"]
	if newID == oldID || newID == "" || fields["sequence"] != "0" || fields["replica_only"] != "false" {
		t.Fatalf("pending challenge missing from checkpoint: %s", output)
	}
	copyRoot := t.TempDir()
	copyJournal, copyArtifacts := filepath.Join(copyRoot, "journal"), filepath.Join(copyRoot, "cycles")
	var verifyBackup func() (string, error)
	if managed {
		backupPath := filepath.Join(t.TempDir(), "managed-backup")
		args := []string{"work-archive-custody-backup", "--backup", backupPath, "--journal", journalPath,
			"--artifacts", artifactsPath, "--manifest", fixture.manifestPath, "--receipt", fixture.receiptPath,
			"--auditor-public-key", fixture.auditorPublicKey}
		for _, wantCreated := range []string{"true", "false"} {
			output, err := runProcessCommandError(20*time.Second, args...)
			fields := outputFields(output, "work_archive_custody_backup")
			if err != nil || fields["id"] != newID || fields["created"] != wantCreated {
				t.Fatalf("managed backup create/retry: %v\n%s", err, output)
			}
		}
		verifyArgs := []string{"work-archive-custody-verify-backup", "--backup", backupPath,
			"--manifest", fixture.manifestPath, "--receipt", fixture.receiptPath,
			"--auditor-public-key", fixture.auditorPublicKey}
		if output, err := runProcessCommandError(20*time.Second, verifyArgs...); err == nil {
			t.Fatalf("backup accepted missing independent pin: %s", output)
		}
		verifyBackup = func() (string, error) {
			return runProcessCommandError(20*time.Second, append(verifyArgs, "--expected-id", newID)...)
		}
		if output, err := verifyBackup(); err != nil || outputFields(output, "work_archive_custody_backup")["verified"] != "true" {
			t.Fatalf("managed backup verification: %v\n%s", err, output)
		}
		// Restore into a separate non-serving location; never turn the retained
		// backup bundle itself into a mutable journal.
		copyProcessCustodyEvidence(t, filepath.Join(backupPath, "journal"), copyJournal)
		copyProcessCustodyEvidence(t, filepath.Join(backupPath, "artifacts"), copyArtifacts)
	} else {
		copyProcessCustodyEvidence(t, journalPath, copyJournal)
		copyProcessCustodyEvidence(t, artifactsPath, copyArtifacts)
	}
	output, err = runCheckpoint(true, copyJournal, copyArtifacts, checkpointPath, "--expected-id", newID)
	if err != nil || outputFields(output, "work_archive_custody_checkpoint")["verified"] != "true" {
		t.Fatalf("cold copy verification: %v\n%s", err, output)
	}
	if output, err := runCheckpoint(true, copyJournal, copyArtifacts, checkpointPath); err == nil {
		t.Fatalf("missing independent pin accepted: %s", output)
	}
	if output, err := runCheckpoint(true, copyJournal, copyArtifacts, checkpointPath, "--expected-id", oldID); err == nil {
		t.Fatalf("wrong pin accepted: %s", output)
	}
	copyChallenge, copyRecord, copyReceipt := custodyCycleArtifactPaths(copyArtifacts, 1)
	if err := os.Remove(copyChallenge); err != nil {
		t.Fatal(err)
	}
	if output, err := runCheckpoint(true, copyJournal, copyArtifacts, checkpointPath, "--expected-id", newID); err == nil {
		t.Fatalf("lost pending challenge accepted: %s", output)
	}
	if _, err := os.Lstat(copyChallenge); !os.IsNotExist(err) {
		t.Fatal("verification repaired the copy")
	}
	if err := publishImmutableArtifact(copyChallenge, challengeBytes); err != nil {
		t.Fatal(err)
	}
	if output, err := runCheckpoint(true, copyJournal, copyArtifacts, checkpointPath, "--expected-id", newID); err != nil {
		t.Fatalf("exact restored challenge rejected: %v\n%s", err, output)
	}

	// No replica is running. Only the restored instance is invoked: starting two
	// copies as authorities is intentionally not a supported recovery path.
	peerID := processTransportPeerID(t, fixture.replicaTransport).String()
	output, err = runProcessCustodyJournalChallenge(t, fixture, "/ip4/127.0.0.1/udp/1/quic-v1", peerID, copyJournal, copyArtifacts, 7_200, 0)
	if err != nil || outputFields(output, "work_archive_custody_verified")["recovered"] != "true" {
		t.Fatalf("restored pending record did not complete offline: %v\n%s", err, output)
	}
	assertProcessCustodyJournalState(t, fixture, copyJournal, 1)
	for path, want := range map[string][]byte{copyChallenge: challengeBytes, copyRecord: recordBytes} {
		if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(actual, want) {
			t.Fatalf("recovery changed %s: %v", path, err)
		}
	}
	wantReceipt, _ := receipt.CanonicalBytes()
	if actual, err := os.ReadFile(copyReceipt); err != nil || !bytes.Equal(actual, wantReceipt) {
		t.Fatalf("recovery changed receipt: %v", err)
	}
	if output, err := runCheckpoint(true, copyJournal, copyArtifacts, checkpointPath, "--expected-id", newID); err == nil {
		t.Fatalf("advanced copy still matched old inventory: %s", output)
	}
	if verifyBackup != nil {
		if output, err := verifyBackup(); err != nil {
			t.Fatalf("restore modified retained backup: %v\n%s", err, output)
		}
	}
}

func copyProcessCustodyEvidence(t testing.TB, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
}
