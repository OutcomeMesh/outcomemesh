//go:build integration

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type pruneEffectProcess struct {
	command                      *exec.Cmd
	input                        io.WriteCloser
	output                       io.ReadCloser
	lines                        chan string
	done, readerDone, stopReader chan struct{}
	stderr                       bytes.Buffer
	err                          error // read only after done
	stopOnce                     sync.Once
}

func startPruneEffectProcess(t testing.TB, f *pruneEffectCLIFixture) *pruneEffectProcess {
	t.Helper()
	p := &pruneEffectProcess{command: helperCommand(nil, f.args("control")...), lines: make(chan string),
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
	ready := outputFields(p.line(t), "work_prune_archive_effect_ready")
	if ready["owners_retained"] != "true" || ready["effect_execution"] != "false" || ready["inventory_id"] != f.config.InventoryID.String() {
		t.Fatal("invalid effect readiness", ready)
	}
	return p
}

func (p *pruneEffectProcess) line(t testing.TB) string {
	t.Helper()
	select {
	case line, ok := <-p.lines:
		if ok {
			return line
		}
		<-p.done
		t.Fatal("effect output closed", p.err, p.stderr.String())
	case <-time.After(15 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
		t.Fatal("effect output timeout", p.stderr.String())
	}
	return ""
}

func (p *pruneEffectProcess) send(t testing.TB, line string) {
	t.Helper()
	if _, err := io.WriteString(p.input, line+"\n"); err != nil {
		t.Fatal(err)
	}
}

func (p *pruneEffectProcess) review(t testing.TB) string {
	t.Helper()
	p.send(t, "review")
	fields := outputFields(p.line(t), "work_prune_archive_effect_review")
	if fields["owners_retained"] != "true" || fields["execution_authorized"] != "false" {
		t.Fatal("invalid retained review", fields)
	}
	for line := p.line(t); line != "work_prune_archive_effect_scope_end\n"; line = p.line(t) {
	}
	return fields["review_id"]
}

func (p *pruneEffectProcess) wait(t testing.TB) error {
	t.Helper()
	select {
	case <-p.done:
		return p.err
	case <-time.After(15 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
		t.Fatal("effect process did not drain owners", p.stderr.String())
		return p.err
	}
}

func requirePruneEffectControlPlatform(t testing.TB) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native supervised pipes require macOS/Linux")
	}
}

func pruneEffectOriginalCommandFixture(t testing.TB, f *pruneEffectCLIFixture) *pruneCLIFixture {
	t.Helper()
	root := t.TempDir()
	a := f.assignments[0]
	id, _ := a.ID()
	c := &pruneCLIFixture{root: root, assignment: a,
		assignmentPath: filepath.Join(root, "assignment.omcaa"), serverKey: filepath.Join(root, "server.key"), clientKey: filepath.Join(root, "client.key")}
	encoded, _ := a.CanonicalBytes()
	writePruneCLIFile(t, c.assignmentPath, encoded)
	writePruneCLIFile(t, c.serverKey, pruneCLIKey(45).Seed())
	writePruneCLIFile(t, c.clientKey, pruneCLIKey(46).Seed())
	c.config = authoritystore.PruneCommandServiceConfig{Assignment: a, AssignmentID: id, RequestID: f.inventory.Policy.RequestID,
		ExecutorPath: f.config.ExecutorPath, ExecutorPinsPath: f.config.ExecutorPinsPath,
		ServerPeerID: pruneCLIPeer(45), ClientPeerID: pruneCLIPeer(46), Timeout: 2 * time.Second}
	for _, roots := range f.config.Authorities {
		if roots.AssignmentID == id {
			c.config.AuthorityPath, c.config.AuthorityPinsPath = roots.AuthorityPath, roots.AuthorityPinsPath
		}
	}
	return c
}

func TestProcessPruneArchiveEffectRoundTrip(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	for _, lineage := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "lineage"}[lineage], func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, lineage)
			before := f.snapshot(t)
			commandFixture := pruneEffectOriginalCommandFixture(t, f)
			_, stopCommands := startPruneCLIProcess(t, commandFixture)
			if out, err := runProcessCommandError(15*time.Second, f.args("review")...); err == nil || outputFields(out, "work_prune_archive_effect_review") != nil {
				t.Fatal("effect stole live command owners", err, out)
			}
			stopCommands(false)
			oneShot := outputFields(runProcessCommand(t, 15*time.Second, f.args("review")...), "work_prune_archive_effect_review")
			if oneShot["owners_retained"] != "false" {
				t.Fatal("one-shot retained owners")
			}
			p := startPruneEffectProcess(t, f)
			f.assertBusy(t)
			id := p.review(t)
			if id == "" || id != oneShot["review_id"] {
				t.Fatal("same source/config changed review")
			}
			f.assertBusy(t)
			if out, err := runProcessCommandError(15*time.Second, f.args("review")...); err == nil || outputFields(out, "work_prune_archive_effect_review") != nil {
				t.Fatal("duplicate runtime shared owners", err, out)
			}
			p.send(t, "execute "+id)
			result := outputFields(p.line(t), "work_prune_archive_effect_executed")
			if result["applied"] != "true" || result["completion_submitted"] != "false" {
				t.Fatal("wrong executed result", result)
			}
			f.assertBusy(t)
			p.send(t, "close")
			if err := p.wait(t); err != nil {
				t.Fatal(err, p.stderr.String())
			}
			after := f.snapshot(t)
			if after.Executor.Stage != authoritystore.PruneSucceeded || !after.EffectFound || after.Storage == before.Storage || !reflect.DeepEqual(after.Authorities, before.Authorities) {
				t.Fatal("wrong effect or automatic ticket completion")
			}
			encoded, err := hex.DecodeString(result["canonical_hex"])
			if err != nil {
				t.Fatal(err)
			}
			effect, err := workchain.DecodeCanonicalPruneEffect(encoded)
			if err != nil || !reflect.DeepEqual(effect, after.Effect) {
				t.Fatal("export differs from atomic result", err)
			}
			_, stopCompletedCommands := startPruneCLIProcess(t, commandFixture)
			stopCompletedCommands(false)
			if !reflect.DeepEqual(after, f.snapshot(t)) {
				t.Fatal("command reopen resumed or completed the effect")
			}
			for range 2 {
				if out, err := runProcessCommandError(15*time.Second, f.args("review")...); err == nil || outputFields(out, "work_prune_archive_effect_review") != nil {
					t.Fatal("terminal work became a new effect", err, out)
				}
				if !reflect.DeepEqual(after, f.snapshot(t)) {
					t.Fatal("reopen changed terminal history")
				}
			}
		})
	}
}

func TestProcessPruneArchiveEffectLifetime(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	for _, lineage := range []bool{false, true} {
		for _, ending := range []string{"close", "eof", "sigterm", "kill"} {
			t.Run(map[bool]string{false: "initial", true: "lineage"}[lineage]+"/"+ending, func(t *testing.T) {
				f := newPruneEffectCLIFixture(t, lineage)
				before := f.snapshot(t)
				p := startPruneEffectProcess(t, f)
				p.review(t)
				f.assertBusy(t)
				switch ending {
				case "close":
					p.send(t, "close")
				case "eof":
					_ = p.input.Close()
				case "sigterm":
					if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
						t.Fatal(err)
					}
				case "kill":
					if err := p.command.Process.Kill(); err != nil {
						t.Fatal(err)
					}
				}
				err := p.wait(t)
				if (ending == "close" || ending == "eof") && err != nil {
					t.Fatal("clean close failed", err, p.stderr.String())
				}
				if ending == "kill" && err == nil {
					t.Fatal("kill was reported as a successful child")
				}
				for range 2 {
					if !reflect.DeepEqual(before, f.snapshot(t)) {
						t.Fatal("shutdown/reopen advanced pending work")
					}
				}
			})
		}
	}
}

func TestProcessPruneArchiveEffectBrokenOutput(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	for _, lineage := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "lineage"}[lineage], func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, lineage)
			before := f.snapshot(t)
			runPruneBrokenOutput(t, f.args("review"), nil)
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("broken review changed owners")
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_ = reader.Close()
			defer writer.Close()
			command := helperCommand(nil, f.args("control")...)
			stdin, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			command.Stdout, command.Stderr = writer, &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(stderr.String(), "broken pipe") {
					t.Fatal("broken readiness was not reported", err, stderr.String())
				}
			case <-time.After(15 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Fatal("broken readiness retained owners")
			}
			_ = stdin.Close()
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("broken readiness advanced work")
			}
			p := startPruneEffectProcess(t, f)
			id := p.review(t)
			p.stopOnce.Do(func() { close(p.stopReader); _ = p.output.Close() })
			p.send(t, "execute "+id)
			if err := p.wait(t); err == nil || !strings.Contains(p.stderr.String(), errPruneEffectUnobserved.Error()) {
				t.Fatal("lost result was not retained as ambiguous", err, p.stderr.String())
			}
			after := f.snapshot(t)
			if after.Executor.Stage != authoritystore.PruneSucceeded || !after.EffectFound || !reflect.DeepEqual(before.Authorities, after.Authorities) {
				t.Fatal("lost result erased effect or completed tickets")
			}
			if !reflect.DeepEqual(after, f.snapshot(t)) {
				t.Fatal("lost-result reopen changed history")
			}
		})
	}
}

func TestPruneEffectNativeOutputCanBeInterrupted(t *testing.T) {
	requirePruneEffectControlPlatform(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := writer.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 1<<20)); !os.IsTimeout(err) {
		t.Fatal("pipe did not become full", err)
	}
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	owned, err := preparePruneEffectOutputPipe(writer)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := owned.Write([]byte("blocked")); done <- err }()
	select {
	case err := <-done:
		t.Fatal("full pipe write was not blocked", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !(errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe)) {
			t.Fatal("closed pipe did not interrupt write", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned output close did not interrupt write")
	}
}
