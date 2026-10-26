//go:build integration

package main

import (
	"bufio"
	"context"
	"io"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func startManagedCustodyOperatorProcess(t testing.TB, arguments []string, prefix string) *pruneEffectProcess {
	t.Helper()
	requirePruneEffectControlPlatform(t)
	p := &pruneEffectProcess{command: helperCommand(nil, arguments...), lines: make(chan string),
		done: make(chan struct{}), readerDone: make(chan struct{}), stopReader: make(chan struct{})}
	var err error
	p.input, err = p.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.output, err = p.command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.command.Stderr = &p.stderr
	if err := p.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.readerDone)
		defer close(p.lines)
		reader := bufio.NewReader(p.output)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			select {
			case p.lines <- line:
			case <-p.stopReader:
				return
			}
		}
	}()
	go func() { p.err = p.command.Wait(); close(p.done) }()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = p.command.Process.Kill()
			<-p.done
		}
		p.stopOnce.Do(func() { close(p.stopReader); _ = p.output.Close() })
		_ = p.input.Close()
		<-p.readerDone
	})
	ready := outputFields(p.line(t), prefix+"_ready")
	if ready["owners_retained"] != "true" || ready["automatic_completion"] != "false" {
		t.Fatal("invalid operator readiness", ready)
	}
	return p
}

func reviewManagedCustodyOperatorProcess(t testing.TB, p *pruneEffectProcess, prefix string) string {
	t.Helper()
	p.send(t, "review")
	header := outputFields(p.line(t), prefix+"_review")
	if header["review_id"] == "" || header["owners_retained"] != "true" ||
		(header["execution_authorized"] != "false" && header["exchange_authorized"] != "false") {
		t.Fatal("invalid retained operator review", header)
	}
	for line := p.line(t); line != prefix+"_scope_end\n"; line = p.line(t) {
	}
	return header["review_id"]
}

func TestProcessManagedCustodyAuditOperator(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	s := f.serve.config.Session
	objects, err := workarchive.OpenExistingObjectStore(f.serve.config.ObjectPath, f.serve.config.ObjectPolicy)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := workarchive.NewJournalCustodyReplicaSession(f.serve.journal, objects, s.ReplicaPrivateKey, s.SessionConfig)
	if err != nil {
		t.Fatal(err)
	}
	tcg := libp2ptransport.DefaultConfig()
	tcg.MaxArchiveCustodyStreamsPerMinute = 2
	server, err := libp2ptransport.New(ctx, pruneCLIKey(45), tcg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	served := make(chan error, 2)
	if err := server.SetArchiveCustodyHandler([]types.Hash{pruneCLIPeer(46)}, func(ctx context.Context, peer types.Hash, stream network.Stream) {
		_, err := replica.Serve(ctx, stream)
		served <- err
	}); err != nil {
		t.Fatal(err)
	}
	args := append(f.args("control"), "--peer", server.Addresses()[0], "--transport-key", f.transportKey)
	const prefix = "work_archive_custody_managed_audit"
	p := startManagedCustodyOperatorProcess(t, args, prefix)
	f.assertBusy(t)
	if out, err := runProcessCommandError(15*time.Second, f.args("")...); err == nil || strings.Contains(out, prefix+"_review ") {
		t.Fatal("duplicate auditor stole original owner", err, out)
	}
	id := reviewManagedCustodyOperatorProcess(t, p, prefix)
	p.send(t, "prepare "+id)
	prepared := outputFields(p.line(t), prefix+"_prepared")
	if prepared["challenge_id"] != s.ChallengeID.String() || prepared["completion_submitted"] != "false" {
		t.Fatal("prepare did not retain the original challenge", prepared)
	}
	id = reviewManagedCustodyOperatorProcess(t, p, prefix)
	p.send(t, "audit "+id)
	accepted := outputFields(p.line(t), prefix+"_result")
	if accepted["sequence"] != "1" || accepted["action"] != "audit" || accepted["challenge_id"] != s.ChallengeID.String() || accepted["completion_submitted"] != "false" {
		t.Fatal("invalid accepted audit", accepted)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("remote replica did not drain")
	}
	if err := p.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := p.wait(t); err == nil {
		t.Fatal("auditor did not die")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("audit implicitly completed an operation")
	}
	p = startManagedCustodyOperatorProcess(t, args, prefix)
	id = reviewManagedCustodyOperatorProcess(t, p, prefix)
	p.send(t, "recover "+id)
	recovered := outputFields(p.line(t), prefix+"_result")
	if recovered["recovered"] != "true" || recovered["sequence"] != "1" || recovered["proof_id"] != accepted["proof_id"] || recovered["receipt_id"] != accepted["receipt_id"] {
		t.Fatal("restart refreshed or lost accepted evidence", recovered)
	}
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	select {
	case err := <-served:
		t.Fatal("offline recovery contacted the replica", err)
	default:
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("recovery changed authority")
	}
}

func exchangeManagedCustodyPairProcess(t testing.TB, p *pruneEffectProcess) map[string]string {
	t.Helper()
	const prefix = "work_archive_custody_managed_pair"
	id := reviewManagedCustodyOperatorProcess(t, p, prefix)
	p.send(t, "exchange "+id)
	result := outputFields(p.line(t), prefix+"_exchanged")
	if result["audit_sequence"] != "1" || result["replica_sequence"] != "1" || result["automatic_completion"] != "false" || result["expected_review_id"] != id {
		t.Fatal("invalid paired result", result)
	}
	return result
}

func TestProcessManagedCustodyPairOperator(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newManagedCustodyPairCLIFixture(t)
	before := f.snapshot(t)
	const prefix = "work_archive_custody_managed_pair"
	p := startManagedCustodyOperatorProcess(t, f.args("control"), prefix)
	f.assertBusy(t)
	first := exchangeManagedCustodyPairProcess(t, p)
	second := exchangeManagedCustodyPairProcess(t, p)
	if first["proof_id"] != second["proof_id"] || first["renewal_id"] != second["renewal_id"] || second["recovered"] != "true" {
		t.Fatal("reviewed retry minted another response", second)
	}
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	committed := f.heads(t)
	if committed.Audit.Sequence != 1 || committed.Replica.Sequence != 1 || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("paired exchange changed authority or missed a journal")
	}
	p = startManagedCustodyOperatorProcess(t, f.args("control"), prefix)
	third := exchangeManagedCustodyPairProcess(t, p)
	if third["proof_id"] != first["proof_id"] || third["renewal_id"] != first["renewal_id"] || third["recovered"] != "true" {
		t.Fatal("reopened pair changed signed evidence", third)
	}
	if err := p.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := p.wait(t); err == nil {
		t.Fatal("paired process was not killed")
	}
	for _, stop := range []string{"eof", "signal"} {
		p = startManagedCustodyOperatorProcess(t, f.args("control"), prefix)
		f.assertBusy(t)
		if stop == "eof" {
			_ = p.input.Close()
		} else if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := p.wait(t); err != nil && !strings.Contains(p.stderr.String(), "context canceled") {
			t.Fatal("shutdown failed to drain", err, p.stderr.String())
		}
		if !reflect.DeepEqual(before, f.snapshot(t)) || !reflect.DeepEqual(committed, f.heads(t)) {
			t.Fatal("shutdown/reopen changed evidence or authority", stop)
		}
	}
}

func TestProcessManagedCustodyPairLostResult(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newManagedCustodyPairCLIFixture(t)
	before := f.snapshot(t)
	const prefix = "work_archive_custody_managed_pair"
	p := startManagedCustodyOperatorProcess(t, f.args("control"), prefix)
	id := reviewManagedCustodyOperatorProcess(t, p, prefix)
	// The input remains live, so the reviewed operation may commit before its
	// result write discovers that the supervisor no longer has stdout open.
	_ = p.output.Close()
	p.send(t, "exchange "+id)
	if err := p.wait(t); err == nil || !strings.Contains(p.stderr.String(), "not reported") {
		t.Fatal("lost result was reported as success or another failure", err, p.stderr.String())
	}
	head := f.heads(t)
	if head.Audit.Sequence != 1 || head.Replica.Sequence != 1 || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("lost stdout discarded a committed result or completed authority")
	}
	p = startManagedCustodyOperatorProcess(t, f.args("control"), prefix)
	result := exchangeManagedCustodyPairProcess(t, p)
	if result["recovered"] != "true" {
		t.Fatal("lost result became a new operation")
	}
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	if !reflect.DeepEqual(head, f.heads(t)) || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("reviewed retry changed the original evidence")
	}
}

func TestProcessManagedCustodyOperatorRequiresReportedReview(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	for _, mode := range []string{"audit", "pair"} {
		t.Run(mode, func(t *testing.T) {
			var args func(string) []string
			var check func()
			prefix, action := "work_archive_custody_managed_audit", "prepare"
			if mode == "audit" {
				f := newManagedCustodyAuditCLIFixture(t)
				before := f.snapshot(t)
				args = f.args
				check = func() {
					if !reflect.DeepEqual(before, f.snapshot(t)) {
						t.Fatal("unreported review advanced authority")
					}
				}
			} else {
				f := newManagedCustodyPairCLIFixture(t)
				before, heads := f.snapshot(t), f.heads(t)
				args = f.args
				prefix, action = "work_archive_custody_managed_pair", "exchange"
				check = func() {
					if !reflect.DeepEqual(before, f.snapshot(t)) || !reflect.DeepEqual(heads, f.heads(t)) {
						t.Fatal("unreported review performed an effect")
					}
				}
			}
			external := outputFields(runProcessCommand(t, 15*time.Second, args("")...), prefix+"_review")
			if external["review_id"] == "" {
				t.Fatal("one-shot review was not returned")
			}
			p := startManagedCustodyOperatorProcess(t, args("control"), prefix)
			p.send(t, action+" "+external["review_id"])
			if err := p.wait(t); err == nil || !strings.Contains(p.stderr.String(), "reported") {
				t.Fatal("another session's review bypassed control", err, p.stderr.String())
			}
			check()
		})
	}
}

func TestProcessManagedCustodyOperatorRejectsPartialControl(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	p := startManagedCustodyOperatorProcess(t, f.args("control"), "work_archive_custody_managed_audit")
	if _, err := io.WriteString(p.input, "prepare "); err != nil {
		t.Fatal(err)
	}
	_ = p.input.Close()
	if err := p.wait(t); err == nil || !strings.Contains(p.stderr.String(), "LF") {
		t.Fatal("partial EOF was accepted", err, p.stderr.String())
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("partial command changed authority")
	}
}
