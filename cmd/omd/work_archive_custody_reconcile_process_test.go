//go:build integration

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestProcessArchiveCustodyReconciliationKeepsStaleEvidenceReadOnly(t *testing.T) {
	fixture := newProcessCustodyFixture(t)
	auditorPath, replicaPath, artifacts := filepath.Join(fixture.root, "auditor"), filepath.Join(fixture.root, "replica"), filepath.Join(fixture.root, "artifacts")
	auditor, _, err := workarchive.OpenOrCreateCustodyJournal(auditorPath, fixture.manifest, fixture.receipt, fixture.custodyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	replica, _, err := workarchive.OpenOrCreateCustodyJournal(replicaPath, fixture.manifest, fixture.receipt, fixture.custodyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := workarchive.AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	now := unixNow()
	challenge, err := workarchive.CreateCustodyChallenge(fixture.manifest, fixture.receipt, processCustodyKey("auditor-evidence"), now, 60, 1, now+7_200)
	if err != nil {
		t.Fatal(err)
	}
	challengePath, recordPath, _ := custodyCycleArtifactPaths(artifacts, 1)
	challengeBytes, _ := challenge.CanonicalBytes()
	if err := publishImmutableArtifact(challengePath, challengeBytes); err != nil {
		t.Fatal(err)
	}
	store, err := workarchive.OpenObjectStore(fixture.objectStorePath, workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := workarchive.AnswerCustodyChallenge(store, fixture.manifest, fixture.receipt, challenge, fixture.custodyPolicy, processCustodyKey("replica-evidence"), now)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := workarchive.RenewReplicaReceipt(fixture.manifest, fixture.receipt, challenge, batch, proof, fixture.custodyPolicy, processCustodyKey("replica-evidence"), now)
	if err != nil {
		t.Fatal(err)
	}
	record := workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}
	trust := []string{"--manifest", fixture.manifestPath, "--receipt", fixture.receiptPath, "--auditor-public-key", fixture.auditorPublicKey}
	backup := func(journal, cycles string) (string, string) {
		path := filepath.Join(t.TempDir(), "backup")
		args := append([]string{"work-archive-custody-backup", "--journal", journal, "--backup", path}, trust...)
		if cycles == "" {
			args = append(args, "--replica-only")
		} else {
			args = append(args, "--artifacts", cycles)
		}
		output, err := runProcessCommandError(20*time.Second, args...)
		id := outputFields(output, "work_archive_custody_backup")["id"]
		if err != nil || id == "" {
			t.Fatalf("create backup: %v\n%s", err, output)
		}
		return path, id
	}
	aBackup, aID := backup(auditorPath, artifacts)
	rEmptyBackup, rEmptyID := backup(replicaPath, "")
	if _, _, err := replica.Append(record); err != nil {
		t.Fatal(err)
	}
	rBackup, rID := backup(replicaPath, "")
	args := append([]string{"work-archive-custody-reconcile", "--auditor-backup", aBackup, "--replica-backup", rBackup}, trust...)
	if output, err := runProcessCommandError(20*time.Second, args...); err == nil {
		t.Fatalf("missing independent IDs accepted: %s", output)
	}
	args = append(args, "--auditor-checkpoint-id", aID, "--replica-checkpoint-id", rID, "--at", strconv.FormatUint(now+9_000, 10))
	var firstOutput string
	for range 2 {
		output, err := runProcessCommandError(20*time.Second, args...)
		summary := outputFields(output, "work_archive_custody_reconciliation")
		pending := outputFields(output, "work_archive_custody_reconciliation_pending")
		review := outputFields(output, "work_archive_custody_reconciliation_review")
		if err != nil || summary["automatic_resume"] != "false" || summary["availability_attested"] != "false" || summary["relation"] != "replica-ahead" || pending["state"] != "historical-response" || pending["source"] != "replica-slot" || pending["proof_within_age"] != "false" || pending["receipt_unexpired"] != "false" || review["next_step"] != "review-historical-response" {
			t.Fatalf("long-outage assessment: %v\n%s", err, output)
		}
		if firstOutput != "" && output != firstOutput {
			t.Fatal("same snapshots and time produced different reports")
		}
		firstOutput = output
	}
	output, err := runProcessCommandError(20*time.Second, append(args, "--replica-backup", rEmptyBackup, "--replica-checkpoint-id", rEmptyID)...)
	if err != nil || outputFields(output, "work_archive_custody_reconciliation_pending")["state"] != "unanswered-expired" || outputFields(output, "work_archive_custody_reconciliation_review")["next_step"] != "review-rebaseline" {
		t.Fatalf("expired unanswered assessment: %v\n%s", err, output)
	}
	for _, extra := range [][]string{{"--at", "0"}, {"--replica-checkpoint-id", aID}, {"--apply"}} {
		if output, err := runProcessCommandError(20*time.Second, append(args, extra...)...); err == nil {
			t.Fatalf("invalid assessment flags accepted: %s", output)
		}
	}
	t.Run("reviewed-historical-handoff", func(t *testing.T) {
		checkProcessCustodyHistoricalTransfer(t, trust, aBackup, rBackup, aID, rID, record)
	})
	if state, err := auditor.State(); err != nil || state.Sequence != 0 {
		t.Fatalf("read-only assessment advanced auditor: %v", err)
	}
	if _, err := os.Lstat(recordPath); !os.IsNotExist(err) {
		t.Fatal("assessment imported the old response")
	}
	if encoded, err := os.ReadFile(challengePath); err != nil || !bytes.Equal(encoded, challengeBytes) {
		t.Fatal("assessment replaced the signed request")
	}
	if err := workarchive.VerifyReplicaRenewal(fixture.manifest, fixture.receipt, renewed, challenge, batch, proof, fixture.custodyPolicy, now+9_000); err == nil {
		t.Fatal("inspection relaxed live proof freshness")
	}
	for path, id := range map[string]string{aBackup: aID, rBackup: rID, rEmptyBackup: rEmptyID} {
		verify := append([]string{"work-archive-custody-verify-backup", "--backup", path, "--expected-id", id}, trust...)
		if output, err := runProcessCommandError(20*time.Second, verify...); err != nil {
			t.Fatalf("assessment changed backup: %v\n%s", err, output)
		}
	}
}
