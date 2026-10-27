//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func TestProcessRemoteCustodyFromZeroAndLostFirstAdmissionOutput(t *testing.T) {
	firstAdmission := true
	d := remoteZeroDriver{run: func(args []string) string { return runProcessCommand(t, 15*time.Second, args...) }}
	d.owned = func(args []string, action string) map[string]string {
		t.Helper()
		const prefix = "work_archive_custody_command"
		args = append(append([]string{}, args...), "--mode", "control")
		p := startManagedCustodyOperatorProcess(t, args, prefix)
		id := reviewManagedCustodyOperatorProcess(t, p, prefix)
		if firstAdmission && action == "apply" {
			firstAdmission = false
			// The native output pipe is lost after review. The signed admission
			// must remain durable even though its confirmation report is unseen.
			_ = p.output.Close()
			p.send(t, action+" "+id)
			if err := p.wait(t); err == nil {
				t.Fatal("lost admission output succeeded")
			}
			p = startManagedCustodyOperatorProcess(t, args, prefix)
			id = reviewManagedCustodyOperatorProcess(t, p, prefix)
		}
		p.send(t, action+" "+id)
		result := outputFields(p.line(t), prefix+"_result")
		if result == nil || result["expected_review_id"] != id {
			t.Fatal("missing explicit preparation result", result)
		}
		p.send(t, "close")
		if err := p.wait(t); err != nil {
			t.Fatal(err, p.stderr.String())
		}
		return result
	}
	f := bootstrapRemoteZero(t, d)
	b := startRemoteCLIProcess(t, f.args("serve", "control"))
	ready := remoteProcessAction(t, b, "serve", "remote_custody_serving")
	a := startRemoteCLIProcess(t, append(f.args("audit", "control"), "--peer", ready["listen"]))
	for _, action := range []struct{ command, prefix string }{{"prepare", "remote_custody_prepared"}, {"begin", "remote_custody_begun"}, {"execute", "remote_custody_executed"}, {"seal", "remote_custody_metadata"}, {"capture", "remote_custody_captured"}} {
		remoteProcessAction(t, a, action.command, action.prefix)
	}
	a.send(t, "close\n")
	if err := a.wait(t); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(f.terminal)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := store.DecodeRemoteCustodyTerminal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := terminal.ID()
	head, _ := terminal.Drained.ID()
	sequence := terminal.Drained.Command.ExpectedSequence + 1
	for i, ticket := range []custodyauthority.Entry{f.audit, f.scope.Worker.Plan.Admission} {
		purpose, name := "audit", "audit"
		if i == 1 {
			purpose, name = "serve", "serve"
		}
		ticketID, _ := ticket.ID()
		args := []string{"--kind", "complete", "--purpose", purpose, "--expected-sequence", strconv.FormatUint(sequence, 10), "--expected-head", head.String(), "--begin", filepath.Join(f.public, "begin"), "--begin-id", f.scope.Worker.BeginID.String(), "--admission", filepath.Join(f.public, name), "--admission-id", ticketID.String(), "--terminal", f.terminal, "--terminal-id", tid.String()}
		args = append(args, remoteOfflineChallengeArgs(f)...)
		args = append(args, remoteOfflinePlanArgs(f)...)
		entry := remoteZeroSign(t, d, f, "complete-"+purpose, 4, args)
		eid, _ := entry.ID()
		args = append(f.args("audit", "control"), "--terminal-id", tid.String(), "--complete-entry", filepath.Join(f.public, "complete-"+purpose), "--complete-entry-id", eid.String())
		args = pruneCLISet(args, "drain", "")
		a = startRemoteCLIProcess(t, args)
		remoteProcessAction(t, a, "apply-complete", "remote_custody_completed")
		a.send(t, "close\n")
		if err := a.wait(t); err != nil {
			t.Fatal(err)
		}
		head, sequence = eid, sequence+1
	}
	b.send(t, "close\n")
	if err := b.wait(t); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(strings.SplitN(d.run([]string{remoteCustodyAuthorityBootstrapCommand, "--mode", "verify", "--assignment", filepath.Join(f.public, "assignment"), "--assignment-id", f.scope.Worker.Plan.AssignmentID.String(), "--authority", f.authority, "--authority-pins", f.pins}), "\n", 2)[0])
	if fields["confirmed_sequence"] != "6" || fields["confirmed_head"] != head.String() || fields["pending_operations"] != "0" || fields["active_remote"] != "false" || fields["retained_attempt"] != "false" {
		t.Fatal("process lifecycle did not close exactly", fields)
	}
}
