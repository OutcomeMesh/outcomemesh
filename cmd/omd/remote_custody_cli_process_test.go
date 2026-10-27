//go:build integration

package main

import (
	"bufio"
	"io"
	"os"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func startRemoteCLIProcess(t testing.TB, args []string) *pruneControlProcess {
	t.Helper()
	p := &pruneControlProcess{command: helperCommand(nil, args...), lines: make(chan string, 2048), done: make(chan struct{})}
	var err error
	p.input, err = p.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p.output = reader
	p.command.Stdout, p.command.Stderr = writer, &p.stderr
	if err := p.command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 65536)
		for scanner.Scan() {
			p.lines <- scanner.Text()
		}
	}()
	go func() { p.err = p.command.Wait(); <-readDone; close(p.done) }()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = p.command.Process.Kill()
		}
		_ = p.input.Close()
		_ = p.output.Close()
		p.wait(t)
	})
	remoteProcessNext(t, p, "remote_custody_ready")
	return p
}

func remoteProcessNext(t testing.TB, p *pruneControlProcess, prefix string) map[string]string {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case line := <-p.lines:
			if fields := outputFields(line, prefix); fields != nil {
				return fields
			}
		case <-p.done:
			t.Fatalf("missing %s: %v %s", prefix, p.err, p.stderr.String())
		case <-deadline.C:
			_ = p.command.Process.Kill()
			_ = p.wait(t)
			t.Fatalf("timeout %s: %s", prefix, p.stderr.String())
		}
	}
}
func remoteProcessReview(t testing.TB, p *pruneControlProcess) string {
	t.Helper()
	p.send(t, "review\n")
	fields := remoteProcessNext(t, p, "remote_custody_review")
	remoteProcessNext(t, p, "remote_custody_scope_end")
	return fields["review_id"]
}
func remoteProcessAction(t testing.TB, p *pruneControlProcess, action, prefix string) map[string]string {
	t.Helper()
	token := remoteProcessReview(t, p)
	p.send(t, action+" "+token+"\n")
	return remoteProcessNext(t, p, prefix)
}

func TestProcessRemoteCustodyCLIRecoversBrokenMetadataOutput(t *testing.T) {
	f := newRemoteCLIFixture(t)
	b := startRemoteCLIProcess(t, f.args("serve", "control"))
	ready := remoteProcessAction(t, b, "serve", "remote_custody_serving")
	args := append(f.args("audit", "control"), "--peer", ready["listen"])
	a := startRemoteCLIProcess(t, args)
	remoteProcessAction(t, a, "prepare", "remote_custody_prepared")
	remoteProcessAction(t, a, "begin", "remote_custody_begun")
	remoteProcessAction(t, a, "execute", "remote_custody_executed")
	token := remoteProcessReview(t, a)
	// The pipe is broken before the reply. A must still retain sealed metadata
	// after its already confirmed authority append, without fabricating an ACK.
	_ = a.output.Close()
	a.send(t, "seal "+token+"\n")
	if err := a.wait(t); err == nil {
		t.Fatal("broken metadata output succeeded")
	}
	bytes, err := os.ReadFile(f.drain)
	if err != nil {
		t.Fatal("lost output lost sealed artifact", err)
	}
	reply, err := remotewire.DecodeResponse(bytes)
	if err != nil {
		t.Fatal(err)
	}
	_, id, err := store.RemoteCustodyDrainArtifact(f.scope, reply)
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "--drain-id", id.String())
	a = startRemoteCLIProcess(t, args)
	recovered := remoteProcessAction(t, a, "reconcile", "remote_custody_metadata")
	if recovered["drain_id"] != id.String() {
		t.Fatal("reconciliation changed retained metadata", recovered)
	}
	remoteProcessAction(t, a, "capture", "remote_custody_captured")
	a.send(t, "close\n")
	if err := a.wait(t); err != nil {
		t.Fatal(err)
	}
	b.send(t, "close\n")
	if err := b.wait(t); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRemoteCustodyCLIStopsOnEOFAndRejectsUnreviewedStart(t *testing.T) {
	for _, mode := range []string{"eof", "unreviewed"} {
		t.Run(mode, func(t *testing.T) {
			f := newRemoteCLIFixture(t)
			b := startRemoteCLIProcess(t, f.args("serve", "control"))
			if mode == "eof" {
				_ = b.input.Close()
				if err := b.wait(t); err != nil {
					t.Fatal(err)
				}
			} else {
				_, err := io.WriteString(b.input, "serve "+pruneCLIHash(252).String()+"\n")
				if err != nil {
					t.Fatal(err)
				}
				if err := b.wait(t); err == nil {
					t.Fatal("unreviewed start succeeded")
				}
			}
			if _, err := loadRemoteCustodyOptions(t.Context(), f.args("serve", "")); err != nil {
				t.Fatal("shutdown lost original state", err)
			}
		})
	}
}
