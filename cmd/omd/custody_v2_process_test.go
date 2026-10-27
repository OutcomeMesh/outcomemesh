//go:build integration && (darwin || linux)

package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func startV2Native(t testing.TB, args []string, prefix string) (*pruneControlProcess, map[string]string) {
	t.Helper()
	p := &pruneControlProcess{command: helperCommand(nil, args...), lines: make(chan string, 2048), done: make(chan struct{})}
	var e error
	p.input, e = p.command.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	p.output = reader
	p.command.Stdout, p.command.Stderr = writer, &p.stderr
	if e := p.command.Start(); e != nil {
		t.Fatal(e)
	}
	_ = writer.Close()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scan := bufio.NewScanner(reader)
		scan.Buffer(make([]byte, 4096), 65536)
		for scan.Scan() {
			p.lines <- scan.Text()
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
		_ = p.wait(t)
	})
	return p, remoteProcessNext(t, p, prefix)
}
func TestProcessCustodyV2EntireJobThroughCLI(t *testing.T) {
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		return runProcessCommand(t, 15*time.Second, args...)
	}
	start := func(t testing.TB, args []string, prefix string) (string, func()) {
		t.Helper()
		p, fields := startV2Native(t, args, prefix)
		return fields["address"], func() {
			p.send(t, "close\n")
			if e := p.wait(t); e != nil {
				t.Fatal(e, p.stderr.String())
			}
			_ = p.input.Close()
			_ = p.output.Close()
		}
	}
	runV2CLICampaign(t, driver, start)
}
func TestProcessCustodyV2LostClientOutputThenKilledTarget(t *testing.T) {
	x := newCustodyV2Fixture(t)
	dir := t.TempDir()
	contextFile := filepath.Join(dir, "context")
	raw, _ := x.context.CanonicalBytes()
	writePruneCLIFile(t, contextFile, raw)
	cid, _ := x.context.ID()
	common := []string{"--context", contextFile, "--context-id", cid.String(), "--scope-id", x.pin.String()}
	keys := map[byte]string{}
	for _, seed := range []byte{14, 15, 46, 61} {
		keys[seed] = filepath.Join(dir, "key-"+strconv.Itoa(int(seed)))
		writePruneCLIFile(t, keys[seed], f.Key(seed).Seed())
	}
	args := func(action string, extra ...string) []string {
		a := append([]string{custodyV2Command, "--action", action}, common...)
		return append(a, extra...)
	}
	reviewed := func(a []string) []string {
		t.Helper()
		fields := pruneCLIFields(strings.SplitN(runProcessCommand(t, 10*time.Second, a...), "\n", 2)[0])
		return append(a, "--mode", "run", "--expected-review-id", fields["review_id"])
	}
	serve := args("serve-target", "--root", x.target, "--journal", x.sources.Journal, "--objects", x.sources.Objects, "--sign-key", keys[14], "--transport-key", keys[15], "--replica-key", keys[61])
	server, ready := startV2Native(t, reviewed(serve), "custody_v2_serving")
	prepare := v2.Request{Version: 2, Operation: v2.Prepare, ScopeID: x.pin, Nonce: f.Hash("process-prepare")}
	prepareFile := filepath.Join(dir, "prepare")
	raw, _ = prepare.CanonicalBytes()
	writePruneCLIFile(t, prepareFile, raw)
	callArgs := func(request, out, peer string) []string {
		t.Helper()
		b, e := os.ReadFile(request)
		if e != nil {
			t.Fatal(e)
		}
		return args("call", "--in", request, "--in-id", custodyV2ArtifactID(b).String(), "--transport-key", keys[46], "--peer", peer, "--out", out)
	}
	prepareOut := filepath.Join(dir, "prepare-response")
	runProcessCommand(t, 10*time.Second, reviewed(callArgs(prepareFile, prepareOut, ready["address"]))...)
	raw, _ = os.ReadFile(prepareOut)
	prepared, e := v2.DecodeResponse(raw)
	if e != nil {
		t.Fatal(e)
	}
	// This fault test uses explicit fixture endorsements; the separate process
	// campaign obtains its claim and result quorums through normal witness CLI RPCs.
	claim := f.Certificate(prepared.Candidate.Claim, 70, 71, 72)
	request := v2.Request{Version: 2, Operation: v2.Execute, ScopeID: x.pin, Nonce: f.Hash("process-execute"), Prefix: []custodyfence.Certificate{claim}}
	requestFile := filepath.Join(dir, "execute")
	raw, _ = request.CanonicalBytes()
	writePruneCLIFile(t, requestFile, raw)
	responseFile := filepath.Join(dir, "lost-response")
	execute := reviewed(callArgs(requestFile, responseFile, ready["address"]))
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	_ = reader.Close()
	child := helperCommand(nil, execute...)
	child.Stdout = writer
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if e := child.Start(); e != nil {
		t.Fatal(e)
	}
	_ = writer.Close()
	if e := child.Wait(); e == nil {
		t.Fatal("broken client output succeeded")
	}
	raw, e = os.ReadFile(responseFile)
	if e != nil {
		t.Fatal("lost response before stdout", e, stderr.String())
	}
	original, e := v2.DecodeResponse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e := server.command.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := server.wait(t); e == nil {
		t.Fatal("kill accepted as graceful")
	}
	status, ok := server.command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("not a verified process kill", status)
	}
	state, e := x.legacy.base.serve.journal.State()
	if e != nil || state.Sequence != 1 {
		t.Fatal("effect count after lost output", state.Sequence, e)
	}
	server, ready = startV2Native(t, reviewed(serve), "custody_v2_serving")
	retry := reviewed(callArgs(requestFile, filepath.Join(dir, "retry"), ready["address"]))
	if _, e := runProcessCommandError(10*time.Second, retry...); e == nil {
		t.Fatal("killed target replayed effect")
	}
	request.Operation = v2.RecoverResult
	request.Nonce = f.Hash("process-recover")
	raw, _ = request.CanonicalBytes()
	recoverFile := filepath.Join(dir, "recover")
	writePruneCLIFile(t, recoverFile, raw)
	recoverOut := filepath.Join(dir, "recovered")
	runProcessCommand(t, 10*time.Second, reviewed(callArgs(recoverFile, recoverOut, ready["address"]))...)
	raw, _ = os.ReadFile(recoverOut)
	recovered, e := v2.DecodeResponse(raw)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := original.Result.CanonicalBytes()
	after, _ := recovered.Result.CanonicalBytes()
	if !bytes.Equal(before, after) {
		t.Fatal("kill/recovery refreshed result")
	}
	server.send(t, "close\n")
	if e := server.wait(t); e != nil {
		t.Fatal(e)
	}
	target, e := v2.OpenTarget(x.target, x.context, x.pin, x.sources, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if _, e := target.Prepare(); !errors.Is(e, v2.ErrConsumed) {
		t.Fatal(e)
	}
}
