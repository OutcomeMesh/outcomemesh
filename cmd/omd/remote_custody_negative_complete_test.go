package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func remoteNegativeAuditCLIFlow(t testing.TB) {
	t.Helper()
	f := newRemoteCLIFixture(t)
	b := startRemoteCLIControl(t, f.args("serve", "control"))
	b.send(t, "serve "+b.review(t))
	ready := b.next(t, "remote_custody_serving")
	negativePath := filepath.Join(f.public, "negative")
	args := append(f.args("audit", "control"), "--peer", ready["listen"], "--negative", negativePath)
	a := startRemoteCLIControl(t, args)
	for _, step := range []struct{ action, prefix string }{{"prepare", "remote_custody_prepared"}, {"begin", "remote_custody_begun"}, {"seal", "remote_custody_metadata"}, {"capture-negative", "remote_custody_negative"}} {
		a.send(t, step.action+" "+a.review(t))
		a.next(t, step.prefix)
	}
	a.close(t)
	b.close(t)
	body, err := os.ReadFile(negativePath)
	if err != nil {
		t.Fatal(err)
	}
	n, err := store.DecodeRemoteCustodyNegative(body)
	if err != nil {
		t.Fatal(err)
	}
	nid, _ := n.ID()
	drainBody, err := os.ReadFile(f.drain)
	if err != nil {
		t.Fatal(err)
	}
	drainID, err := decodeRemoteDrainForCLI(f, drainBody)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.OpenCoordinator(f.authority, f.pins, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	current, err := owner.Snapshot()
	_ = owner.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Review/sign/co-sign all use the regular offline CLI with an explicit kind.
	signing := []string{"--kind", "negative-audit-complete", "--purpose", "audit", "--expected-sequence", strconv.FormatUint(current.Confirmed.Sequence, 10), "--expected-head", current.Confirmed.HeadID.String(),
		"--begin", filepath.Join(f.public, "begin"), "--begin-id", f.scope.Worker.BeginID.String(), "--admission", filepath.Join(f.public, "audit"), "--negative", negativePath, "--negative-id", nid.String()}
	auditID, _ := f.audit.ID()
	signing = append(signing, "--admission-id", auditID.String())
	signing = append(signing, remoteOfflinePlanArgs(f)...)
	signing = append(signing, remoteOfflineChallengeArgs(f)...)
	entry, path := remoteOfflineSignEntry(t, f, signing, 4)
	eid, _ := entry.ID()
	for _, purpose := range []string{"serve", "prune"} {
		bad := append([]string{remoteCustodySignCommand}, remoteOfflineCommonArgs(f)...)
		bad = append(bad, replaceRemoteCLIFlag(signing, "--purpose", purpose)...)
		if err := runCustodyCommand(t.Context(), bad, nil, &bytes.Buffer{}); err == nil {
			t.Fatal("negative offline signing accepted", purpose)
		}
	}
	// No successful-terminal file may be selected for the negative path.
	var filtered []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--terminal" {
			i++
			continue
		}
		filtered = append(filtered, args[i])
	}
	args = append(filtered, "--drain-id", drainID.String(), "--negative-id", nid.String(), "--complete-entry", path, "--complete-entry-id", eid.String())
	for i := 0; i < 2; i++ {
		a = startRemoteCLIControl(t, args)
		a.send(t, "apply-negative-audit-complete "+a.review(t))
		result := a.next(t, "remote_custody_audit_disposed")
		if result["serve_ticket_retained"] != "true" || result["execution_outcome_resolved"] != "false" || result["source_advanced"] != "false" || result["appended"] != strconv.FormatBool(i == 0) {
			t.Fatal("negative settlement lost its boundary", result)
		}
		a.close(t)
	}
	var review bytes.Buffer
	if err := runRemoteCustody(t.Context(), replaceRemoteCLIFlag(args, "--mode", "review"), nil, &review); err != nil {
		t.Fatal("cold review", err)
	}
	if !strings.Contains(review.String(), `"Pending": 1`) {
		t.Fatal("review lost Serve hold", review.String())
	}
}

func TestRemoteCustodyNegativeAuditCLI(t *testing.T) {
	remoteNegativeAuditCLIFlow(t)
}
