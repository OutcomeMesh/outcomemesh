//go:build integration

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func checkProcessCustodyHistoricalApplication(t *testing.T, fixture processCustodyFixture, trust []string,
	aBackup, rBackup, aID, rID, packagePath, transferID string, record workarchive.CustodyRecord,
) {
	t.Helper()
	recovery := filepath.Join(t.TempDir(), "recovery")
	args := append([]string{"work-archive-custody-apply-history", "--recovery", recovery, "--package", packagePath, "--transfer-id", transferID,
		"--auditor-backup", aBackup, "--replica-backup", rBackup, "--auditor-checkpoint-id", aID, "--replica-checkpoint-id", rID}, trust...)
	for _, extra := range [][]string{{"--mode", "verify"}, {"--mode", "activate"}, {"--resume"}, {"--transfer-id", aID}, {"--expected-id", transferID}} {
		invalid := append(append([]string(nil), args...), extra...)
		if output, err := runProcessCommandError(20*time.Second, invalid...); err == nil {
			t.Fatalf("invalid application flags accepted: %s", output)
		}
		if _, err := os.Lstat(recovery); !os.IsNotExist(err) {
			t.Fatal("invalid application flags created destination")
		}
	}
	var applicationID string
	for index := range 2 {
		output, err := runProcessCommandError(20*time.Second, args...)
		fields := outputFields(output, "work_archive_custody_application")
		if err != nil || fields["id"] == "" || fields["transfer"] != transferID || fields["sequence"] != "1" ||
			fields["historical_only"] != "true" || fields["participant_fenced"] != "false" || fields["automatic_resume"] != "false" ||
			fields["created"] != strconv.FormatBool(index == 0) {
			t.Fatalf("create/retry: %v\n%s", err, output)
		}
		if applicationID != "" && applicationID != fields["id"] {
			t.Fatal("retry changed application ID")
		}
		applicationID = fields["id"]
	}
	verify := append(append([]string(nil), args...), "--mode", "verify", "--expected-id", applicationID)
	if output, err := runProcessCommandError(20*time.Second, verify...); err != nil {
		t.Fatalf("verify: %v\n%s", err, output)
	}
	journal, artifacts := filepath.Join(recovery, "journal"), filepath.Join(recovery, "artifacts")
	before, err := workarchive.CaptureCustodyCheckpoint(journal, artifacts, fixture.manifest, fixture.receipt, fixture.custodyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(artifacts, "cycle-00000000000000000001", "record.omcr")
	want, _ := record.CanonicalBytes()
	if actual, err := os.ReadFile(recordPath); err != nil || !bytes.Equal(actual, want) {
		t.Fatal("CLI application changed signed response")
	}
	// Correctly configured live CLI participants must stop on the quarantine
	// header before opening a transport session or issuing another challenge.
	output, err := runProcessCustodyJournalChallenge(t, fixture, "/ip4/127.0.0.1/udp/1/quic-v1",
		processTransportPeerID(t, fixture.replicaTransport).String(), journal, artifacts, 7_200, 0)
	if err == nil || !strings.Contains(output, workarchive.ErrCustodyJournalHistoricalOnly.Error()) {
		t.Fatalf("live auditor did not reject quarantine: %v\n%s", err, output)
	}
	output, err = runProcessCommandError(15*time.Second,
		"work-archive-custody-serve-quic", "--key", fixture.replicaTransport,
		"--auditor-peer-id", processTransportPeerID(t, fixture.auditorTransport).String(),
		"--replica-key", fixture.replicaEvidence, "--auditor-public-key", fixture.auditorPublicKey,
		"--manifest", fixture.manifestPath, "--receipt", fixture.receiptPath, "--object-store", fixture.objectStorePath, "--journal", journal)
	if err == nil || !strings.Contains(output, workarchive.ErrCustodyJournalHistoricalOnly.Error()) || strings.Contains(output, "work_archive_custody_receiving") {
		t.Fatalf("live replica did not reject quarantine: %v\n%s", err, output)
	}
	checkpointID, _ := before.ID()
	if err := workarchive.VerifyCustodyCheckpoint(before, checkpointID, journal, artifacts, fixture.manifest, fixture.receipt, fixture.custodyPolicy); err != nil {
		t.Fatalf("rejected live CLI changed recovery evidence: %v", err)
	}
	// Independently verified reconstruction stays exact after those failed starts.
	if output, err := runProcessCommandError(20*time.Second, verify...); err != nil {
		t.Fatalf("post-rejection verification: %v\n%s", err, output)
	}
}
