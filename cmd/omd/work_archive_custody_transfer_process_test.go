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

// Run within the outage fixture so the assertions after this handoff also prove
// that neither the live auditor nor the retained source bundles were modified.
func checkProcessCustodyHistoricalTransfer(t *testing.T, trust []string, aBackup, rBackup, aID, rID string, record workarchive.CustodyRecord) {
	t.Helper()
	args := append([]string{"work-archive-custody-transfer", "--auditor-backup", aBackup, "--replica-backup", rBackup,
		"--auditor-checkpoint-id", aID, "--replica-checkpoint-id", rID}, trust...)
	output, err := runProcessCommandError(20*time.Second, args...)
	fields := outputFields(output, "work_archive_custody_transfer")
	id := fields["id"]
	if err != nil || id == "" || fields["mode"] != "plan" || fields["historical_only"] != "true" || fields["automatic_resume"] != "false" || fields["availability_attested"] != "false" || fields["responded_at"] != strconv.FormatUint(record.Proof.RespondedAt, 10) {
		t.Fatalf("transfer plan: %v\n%s", err, output)
	}
	if repeated, err := runProcessCommandError(20*time.Second, args...); err != nil || repeated != output {
		t.Fatalf("nondeterministic transfer plan: %v\n%s", err, repeated)
	}
	destination := filepath.Join(t.TempDir(), "handoff")
	for _, extra := range [][]string{
		{"--package", destination},
		{"--mode", "export", "--package", destination},
		{"--mode", "export", "--package", destination, "--expected-id", aID},
		{"--mode", "apply"}, {"--apply"}, {"--auditor-checkpoint-id", rID},
	} {
		testArgs := append(append([]string(nil), args...), extra...)
		if output, err := runProcessCommandError(20*time.Second, testArgs...); err == nil {
			t.Fatalf("invalid transfer accepted: %s", output)
		}
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Fatal("invalid transfer created package")
		}
	}
	export := append(append([]string(nil), args...), "--mode", "export", "--package", destination, "--expected-id", id)
	for index := range 2 {
		output, err := runProcessCommandError(20*time.Second, export...)
		fields := outputFields(output, "work_archive_custody_transfer")
		if err != nil || fields["id"] != id || fields["created"] != strconv.FormatBool(index == 0) || fields["automatic_resume"] != "false" {
			t.Fatalf("export/retry: %v\n%s", err, output)
		}
	}
	verify := append(append([]string(nil), args...), "--mode", "verify", "--package", destination, "--expected-id", id)
	if output, err := runProcessCommandError(20*time.Second, verify...); err != nil || outputFields(output, "work_archive_custody_transfer")["mode"] != "verify" {
		t.Fatalf("verify transfer: %v\n%s", err, output)
	}
	encoded, err := os.ReadFile(filepath.Join(destination, "historical.omcht"))
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := workarchive.DecodeCustodyHistoricalTransfer(encoded)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := record.CanonicalBytes()
	got, _ := transfer.Entry.Record.CanonicalBytes()
	if !bytes.Equal(want, got) {
		t.Fatal("handoff changed the original signed response")
	}
	encoded[len(encoded)-1] ^= 1
	if err := os.WriteFile(filepath.Join(destination, "historical.omcht"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runProcessCommandError(20*time.Second, verify...); err == nil {
		t.Fatalf("changed handoff verified: %s", output)
	}
	if output, err := runProcessCommandError(20*time.Second, export...); err == nil {
		t.Fatalf("retry replaced changed handoff: %s", output)
	}
}
