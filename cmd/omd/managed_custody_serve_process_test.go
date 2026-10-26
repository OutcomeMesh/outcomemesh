//go:build integration

package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func startManagedCustodyServeProcess(t testing.TB, f *managedCustodyServeCLIFixture) (*pruneEffectProcess, string) {
	t.Helper()
	requirePruneEffectControlPlatform(t)
	p := &pruneEffectProcess{command: helperCommand(nil, f.args("serve")...), lines: make(chan string),
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
	ready := outputFields(p.line(t), "work_archive_custody_managed_serve_ready")
	if ready["owners_retained"] != "true" || ready["automatic_completion"] != "false" ||
		ready["assignment_id"] != f.config.Session.AssignmentID.String() || ready["challenge_id"] != f.config.Session.ChallengeID.String() ||
		ready["server_peer_id"] != f.config.ServerPeerID.String() || ready["auditor_peer_id"] != f.config.Session.AuditorPeerID.String() || ready["listen"] == "" {
		t.Fatal("wrong managed server readiness", ready)
	}
	return p, ready["listen"]
}

func auditManagedCustodyServeProcess(t testing.TB, f *managedCustodyServeCLIFixture, address string) workarchive.CustodyResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	client, err := libp2ptransport.New(ctx, pruneCLIKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, peer, err := client.OpenArchiveCustodyStream(ctx, address, f.config.ServerPeerID)
	if err != nil || peer != f.config.ServerPeerID {
		t.Fatal("open pinned managed server", err)
	}
	s := f.config.Session
	auditor, err := workarchive.NewCustodyAuditorSession(s.Manifest, s.InitialReceipt, s.CustodyPolicy, s.SessionConfig)
	if err != nil {
		t.Fatal(err)
	}
	response, report, err := auditor.Audit(ctx, stream, f.challenge)
	if err != nil || report.ChallengeID != s.ChallengeID {
		t.Fatal("managed process audit", err)
	}
	state, err := f.journal.State()
	if err != nil || state.Sequence != 1 || state.CurrentReceipt != response.RenewedReceipt {
		t.Fatal("response differs from the durable journal", state.Sequence, err)
	}
	return response
}

func TestProcessManagedCustodyServeRestart(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	review := outputFields(runProcessCommand(t, 15*time.Second, f.args("")...), "work_archive_custody_managed_serve_review")
	if review["owners_retained"] != "false" || review["listener_started"] != "false" {
		t.Fatal("review retained owners or listened", review)
	}
	p, address := startManagedCustodyServeProcess(t, f)
	f.assertBusy(t)
	if out, err := runProcessCommandError(15*time.Second, f.args("review")...); err == nil || strings.Contains(out, "managed_serve_review") {
		t.Fatal("duplicate process stole the original authority", err, out)
	}
	first := auditManagedCustodyServeProcess(t, f, address)
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal(err, p.stderr.String())
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("successful delivery completed authority")
	}
	p, address = startManagedCustodyServeProcess(t, f)
	if second := auditManagedCustodyServeProcess(t, f, address); !reflect.DeepEqual(first, second) {
		t.Fatal("restarted server refreshed its signed response")
	}
	if err := p.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := p.wait(t); err == nil {
		t.Fatal("server did not die")
	}
	for _, stop := range []string{"eof", "sigterm"} {
		p, _ := startManagedCustodyServeProcess(t, f)
		f.assertBusy(t)
		if stop == "eof" {
			_ = p.input.Close()
		} else if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := p.wait(t); err != nil {
			t.Fatal("managed server did not drain", stop, err, p.stderr.String())
		}
		if !reflect.DeepEqual(before, f.snapshot(t)) {
			t.Fatal("reopen or shutdown advanced authority")
		}
	}
	state, err := f.journal.State()
	if err != nil || state.Sequence != 1 {
		t.Fatal("restart changed committed response", state.Sequence, err)
	}
}

func TestProcessManagedCustodyServeBrokenReadiness(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	command := helperCommand(nil, f.args("serve")...)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	defer writer.Close()
	command.Stdout = writer
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("broken readiness reported success")
		}
	case <-time.After(15 * time.Second):
		_ = command.Process.Kill()
		<-done
		t.Fatal("broken readiness retained owners", stderr.String())
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("broken readiness changed authority")
	}
	state, err := f.journal.State()
	if err != nil || state.Sequence != 0 {
		t.Fatal("failed startup signed a response", state.Sequence, err)
	}
}

func TestProcessManagedCustodyServePartialInput(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	p, _ := startManagedCustodyServeProcess(t, f)
	if _, err := io.WriteString(p.input, "close"); err != nil {
		t.Fatal(err)
	}
	_ = p.input.Close()
	if err := p.wait(t); err == nil || !strings.Contains(p.stderr.String(), "LF") {
		t.Fatal("partial command was accepted or failed for another reason", err, p.stderr.String())
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("invalid supervision command changed authority")
	}
}
