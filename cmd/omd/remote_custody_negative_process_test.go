//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func enrollRemoteProcessPlacement(t testing.TB, f *remoteCLIFixture, role string) []string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "external-control")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "placement")
	text := runProcessCommand(t, 15*time.Second, append(f.args(role, "placement-review"), "--placement", path)...)
	fields := outputFields(strings.TrimSpace(text), "remote_custody_placement")
	if fields == nil || fields["keys_loaded"] != "false" {
		t.Fatal(text)
	}
	runProcessCommand(t, 15*time.Second, append(f.args(role, "placement-create"), "--placement", path, "--placement-id", fields["placement_id"])...)
	return []string{"--placement", path, "--placement-id", fields["placement_id"], "--require-placement=true"}
}

func TestProcessRemoteCustodyNegativeAuditLostCompletionOutput(t *testing.T) {
	f := newRemoteCLIFixture(t)
	b := startRemoteCLIProcess(t, f.args("serve", "control"))
	ready := remoteProcessAction(t, b, "serve", "remote_custody_serving")
	path := filepath.Join(t.TempDir(), "negative")
	args := append(f.args("audit", "control"), "--peer", ready["listen"], "--negative", path)
	a := startRemoteCLIProcess(t, args)
	remoteProcessAction(t, a, "prepare", "remote_custody_prepared")
	remoteProcessAction(t, a, "begin", "remote_custody_begun")
	metadata := remoteProcessAction(t, a, "seal", "remote_custody_metadata")
	negative := remoteProcessAction(t, a, "capture-negative", "remote_custody_negative")
	a.send(t, "close\n")
	if err := a.wait(t); err != nil {
		t.Fatal(err)
	}
	b.send(t, "close\n")
	if err := b.wait(t); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := store.DecodeRemoteCustodyNegative(body)
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := f.audit.ID()
	extra := []string{"--kind", "negative-audit-complete", "--purpose", "audit", "--expected-sequence", "4", "--expected-head", metadata["drain_id"],
		"--begin", filepath.Join(f.public, "begin"), "--begin-id", f.scope.Worker.BeginID.String(), "--admission", filepath.Join(f.public, "audit"), "--admission-id", ticket.String(), "--negative", path, "--negative-id", negative["negative_id"]}
	// The drain artifact ID is a distinct domain from its authority entry ID.
	drained, _ := n.Drained.ID()
	extra = replaceRemoteCLIFlag(extra, "--expected-head", drained.String())
	extra = append(extra, remoteOfflinePlanArgs(f)...)
	extra = append(extra, remoteOfflineChallengeArgs(f)...)
	entry, entryPath := remoteOfflineSignEntry(t, f, extra, 4)
	eid, _ := entry.ID()
	var selected []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--terminal" {
			i++
			continue
		}
		selected = append(selected, args[i])
	}
	args = append(selected, "--drain-id", metadata["drain_id"], "--negative-id", negative["negative_id"], "--complete-entry", entryPath, "--complete-entry-id", eid.String())
	a = startRemoteCLIProcess(t, args)
	token := remoteProcessReview(t, a)
	_ = a.output.Close()
	a.send(t, "apply-negative-audit-complete "+token+"\n")
	if err := a.wait(t); err == nil {
		t.Fatal("lost completion output succeeded")
	}
	a = startRemoteCLIProcess(t, args)
	result := remoteProcessAction(t, a, "apply-negative-audit-complete", "remote_custody_audit_disposed")
	if result["appended"] != strconv.FormatBool(false) || result["serve_ticket_retained"] != "true" {
		t.Fatal("lost output duplicated completion or lost Serve", result)
	}
	if err := a.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := a.wait(t); err == nil {
		t.Fatal("operator was not killed")
	}
	view := runProcessCommand(t, 15*time.Second, replaceRemoteCLIFlag(args, "--mode", "review")...)
	if !strings.Contains(view, `"ConfirmedSequence": 5`) || !strings.Contains(view, `"Pending": 1`) {
		t.Fatal("cold review lost the unresolved Serve obligation", view)
	}
}

func TestProcessRemoteCustodyNegativeLostOutputAndCopyRefusal(t *testing.T) {
	f := newRemoteCLIFixture(t)
	af := enrollRemoteProcessPlacement(t, f, "audit")
	bf := enrollRemoteProcessPlacement(t, f, "serve")
	b := startRemoteCLIProcess(t, append(f.args("serve", "control"), bf...))
	ready := remoteProcessAction(t, b, "serve", "remote_custody_serving")
	path := filepath.Join(t.TempDir(), "negative")
	args := append(f.args("audit", "control"), af...)
	args = append(args, "--peer", ready["listen"], "--negative", path)
	a := startRemoteCLIProcess(t, args)
	remoteProcessAction(t, a, "prepare", "remote_custody_prepared")
	remoteProcessAction(t, a, "begin", "remote_custody_begun")
	metadata := remoteProcessAction(t, a, "seal", "remote_custody_metadata")
	token := remoteProcessReview(t, a)
	_ = a.output.Close()
	a.send(t, "capture-negative "+token+"\n")
	if err := a.wait(t); err == nil {
		t.Fatal("broken negative output succeeded")
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("negative observation not retained", err)
	}
	n, err := store.DecodeRemoteCustodyNegative(bytes)
	if err != nil {
		t.Fatal(err)
	}
	id, err := n.ID()
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "--drain-id", metadata["drain_id"], "--negative-id", id.String())
	a = startRemoteCLIProcess(t, args)
	retry := remoteProcessAction(t, a, "capture-negative", "remote_custody_negative")
	if retry["negative_id"] != id.String() {
		t.Fatal("recovered another observation")
	}
	if err := a.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := a.wait(t); err == nil {
		t.Fatal("operator was not killed")
	}
	review := runProcessCommand(t, 15*time.Second, replaceRemoteCLIFlag(args, "--mode", "review")...)
	if !strings.Contains(review, `"ConfirmedSequence": 4`) || !strings.Contains(review, `"Pending": 2`) || !strings.Contains(review, id.String()) {
		t.Fatal("restart lost obligations", review)
	}
	key := f.keyPaths[16]
	original, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "copy.seed")
	if err := os.WriteFile(copyPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := replaceRemoteCLIFlag(replaceRemoteCLIFlag(args, "--mode", "review"), "--control-key", copyPath)
	command := helperCommand(nil, bad...)
	out, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "placement") || strings.Contains(string(out), "remote_custody_ready") {
		t.Fatal("copied seed reached operator startup", err, string(out))
	}
	b.send(t, "close\n")
	if err := b.wait(t); err != nil {
		t.Fatal(err)
	}
}
