//go:build integration

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestProcessArchiveCustodyPinsTrackLatestBackup(t *testing.T) {
	fixture := newProcessCustodyFixture(t)
	journal, artifacts := filepath.Join(fixture.root, "journal"), filepath.Join(fixture.root, "artifacts")
	if _, _, err := workarchive.OpenOrCreateCustodyJournal(journal, fixture.manifest, fixture.receipt, fixture.custodyPolicy); err != nil {
		t.Fatal(err)
	}
	lock, err := workarchive.AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	trust := []string{"--manifest", fixture.manifestPath, "--receipt", fixture.receiptPath, "--auditor-public-key", fixture.auditorPublicKey}
	backup := func(path string) string {
		args := append([]string{"work-archive-custody-backup", "--backup", path, "--journal", journal, "--artifacts", artifacts}, trust...)
		output, err := runProcessCommandError(20*time.Second, args...)
		id := outputFields(output, "work_archive_custody_backup")["id"]
		if err != nil || id == "" {
			t.Fatalf("create backup: %v\n%s", err, output)
		}
		return id
	}
	pins := filepath.Join(t.TempDir(), "pins")
	runPin := func(action, path string, extra ...string) (string, error) {
		args := append([]string{"work-archive-custody-" + action, "--pins", pins, "--backup", path}, trust...)
		return runProcessCommandError(20*time.Second, append(args, extra...)...)
	}
	oldPath := filepath.Join(t.TempDir(), "old-backup")
	oldID := backup(oldPath)
	if output, err := runPin("pin-backup", oldPath, "--checkpoint-id", oldID); err == nil {
		t.Fatalf("implicit initialization accepted: %s", output)
	}
	if output, err := runPin("verify-pinned-backup", oldPath); err == nil {
		t.Fatalf("missing pin authority accepted: %s", output)
	}
	if _, err := os.Lstat(pins); !os.IsNotExist(err) {
		t.Fatal("verification initialized the pin authority")
	}
	if output, err := runPin("pin-backup", oldPath, "--initial"); err == nil {
		t.Fatalf("missing independent checkpoint ID accepted: %s", output)
	}
	output, err := runPin("pin-backup", oldPath, "--initial", "--checkpoint-id", oldID)
	first := outputFields(output, "work_archive_custody_pin")
	firstID := first["pin_id"]
	if err != nil || firstID == "" || first["pin_sequence"] != "1" || first["created"] != "true" || first["verified"] != "true" {
		t.Fatalf("initial pin: %v\n%s", err, output)
	}
	if output, err := runPin("pin-backup", oldPath, "--initial", "--checkpoint-id", oldID); err != nil || outputFields(output, "work_archive_custody_pin")["created"] != "false" {
		t.Fatalf("initial pin retry: %v\n%s", err, output)
	}

	// A real signed request changes the exact backup inventory even though no
	// receipt has committed. It must not disappear behind the same custody head.
	now := unixNow()
	challenge, err := workarchive.CreateCustodyChallenge(fixture.manifest, fixture.receipt, processCustodyKey("auditor-evidence"), now, 60, 1, now+7_200)
	if err != nil {
		t.Fatal(err)
	}
	challengePath, _, _ := custodyCycleArtifactPaths(artifacts, 1)
	encoded, _ := challenge.CanonicalBytes()
	if err := publishImmutableArtifact(challengePath, encoded); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(t.TempDir(), "new-backup")
	newID := backup(newPath)
	if oldID == newID {
		t.Fatal("pending request did not change backup ID")
	}
	if output, err := runPin("pin-backup", newPath, "--expected-pin", firstID, "--checkpoint-id", newID); err == nil {
		t.Fatalf("missing prior backup accepted: %s", output)
	}
	output, err = runPin("pin-backup", newPath, "--expected-pin", firstID, "--checkpoint-id", newID, "--previous-backup", oldPath)
	second := outputFields(output, "work_archive_custody_pin")
	secondID := second["pin_id"]
	if err != nil || secondID == "" || secondID == firstID || second["pin_sequence"] != "2" || second["custody_sequence"] != "0" || second["previous_pin"] != firstID {
		t.Fatalf("advance pin: %v\n%s", err, output)
	}
	if output, err := runPin("pin-backup", newPath, "--expected-pin", firstID, "--checkpoint-id", newID); err != nil || outputFields(output, "work_archive_custody_pin")["created"] != "false" {
		t.Fatalf("lost-response retry: %v\n%s", err, output)
	}
	if output, err := runProcessCommandError(20*time.Second, "work-archive-custody-pin-head", "--pins", pins); err != nil || outputFields(output, "work_archive_custody_pin")["pin_id"] != secondID || outputFields(output, "work_archive_custody_pin")["verified"] != "false" {
		t.Fatalf("head inspection: %v\n%s", err, output)
	}
	if output, err := runPin("verify-pinned-backup", oldPath); err == nil {
		t.Fatalf("old backup accepted as current: %s", output)
	}
	if output, err := runPin("verify-pinned-backup", newPath, "--expected-pin", firstID); err == nil {
		t.Fatalf("stale external head accepted: %s", output)
	}
	for _, extra := range [][]string{nil, {"--expected-pin", secondID}} {
		if output, err := runPin("verify-pinned-backup", newPath, extra...); err != nil || outputFields(output, "work_archive_custody_pin")["verified"] != "true" {
			t.Fatalf("latest backup verification: %v\n%s", err, output)
		}
	}
	if output, err := runPin("pin-backup", oldPath, "--expected-pin", secondID, "--checkpoint-id", oldID, "--previous-backup", newPath); err == nil {
		t.Fatalf("lost signed request promoted: %s", output)
	}
	// Historical verification remains useful, but never means 'latest'.
	args := append([]string{"work-archive-custody-verify-backup", "--backup", oldPath, "--expected-id", oldID}, trust...)
	if output, err := runProcessCommandError(20*time.Second, args...); err != nil {
		t.Fatalf("historical backup changed: %v\n%s", err, output)
	}
}
