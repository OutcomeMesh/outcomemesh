//go:build integration

package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

type pruneControlProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *os.File
	lines   chan string
	done    chan struct{}
	stderr  bytes.Buffer // read only after done (Wait drains the copy goroutine)
	err     error
}

func startPruneControlProcess(t testing.TB, f *pruneCLIFixture) (*pruneControlProcess, string) {
	t.Helper()
	p := &pruneControlProcess{command: helperCommand(nil, append(f.serveArgs(), "--maintenance-control", "stdin")...),
		lines: make(chan string, 16), done: make(chan struct{})}
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
		_ = reader.Close()
		_ = writer.Close()
		_ = p.input.Close()
		t.Fatal(err)
	}
	_ = writer.Close()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 4096)
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
	ready := p.next(t, "serving_work_prune_commands")
	if ready["maintenance_control"] != "stdin" || ready["listen"] == "" {
		t.Fatal("invalid readiness", ready)
	}
	return p, ready["listen"]
}

func (p *pruneControlProcess) wait(t testing.TB) error {
	t.Helper()
	select {
	case <-p.done:
		return p.err
	case <-time.After(15 * time.Second):
		_ = p.command.Process.Kill()
		_ = p.output.Close()
		<-p.done
		t.Fatalf("maintenance process did not drain: %v %s", p.err, p.stderr.String())
	}
	return nil
}

func (p *pruneControlProcess) next(t testing.TB, prefix string) map[string]string {
	t.Helper()
	select {
	case line := <-p.lines:
		fields := outputFields(line, prefix)
		if fields == nil {
			t.Fatal("unexpected maintenance output", line)
		}
		return fields
	case <-p.done:
		t.Fatalf("process ended before %s: %v %s", prefix, p.err, p.stderr.String())
	case <-time.After(15 * time.Second):
		_ = p.command.Process.Kill()
		p.wait(t)
		t.Fatalf("missing maintenance output %s: %s", prefix, p.stderr.String())
	}
	return nil
}

func (p *pruneControlProcess) send(t testing.TB, command string) {
	t.Helper()
	if _, err := io.WriteString(p.input, command); err != nil {
		t.Fatal(err)
	}
}

func TestProcessPruneMaintenanceCLILifetime(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native live control supports macOS/Linux")
	}
	for _, point := range []string{"serving", "parked", "cancelled"} {
		for _, exit := range []string{"eof", "sigterm", "kill"} {
			t.Run(point+"/"+exit, func(t *testing.T) {
				if exit == "sigterm" && runtime.GOOS == "windows" {
					t.Skip("Unix graceful shutdown signal")
				}
				f := newPruneCLIFixture(t)
				p, address := startPruneControlProcess(t, f)
				runPruneProcessDelivery(t, f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address))
				var review map[string]string
				if point != "serving" {
					p.send(t, "review\n")
					review = p.next(t, "work_prune_maintenance_review")
					if point == "cancelled" {
						p.send(t, "cancel-before-start "+review["review_id"]+"\n")
						checkPruneCancellationOutput(t, f, p.next(t, "work_prune_maintenance_cancelled"))
					}
				}
				f.assertBusy(t)
				if output, err := runProcessCommandError(15*time.Second, f.maintenanceArgs()...); err == nil || strings.Contains(output, "work_prune_maintenance_review") {
					t.Fatal("offline process acquired live owners", err, output)
				}
				switch exit {
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
				if err := p.wait(t); (err != nil) != (exit == "kill") {
					t.Fatal("wrong process shutdown", err, p.stderr.String())
				}
				before, authority := f.snapshot(t)
				want := authoritystore.PruneAdmitted
				if point == "cancelled" {
					want = authoritystore.PruneCancelled
				}
				if before.Stage != want || before.Protection.Pending != nil || authority.Authority.Sequence != 1 || authority.Authority.Pending != 1 {
					t.Fatal("shutdown promoted work or lost terminal")
				}
				for range 2 {
					retained := preparationProcessFields(t, f.maintenanceArgs())
					if point == "parked" && !reflect.DeepEqual(review, retained) {
						t.Fatal("restart changed confirmed review")
					}
					state, observed := f.snapshot(t)
					if !reflect.DeepEqual(before, state) || !reflect.DeepEqual(authority, observed) {
						t.Fatal("offline restart resumed work")
					}
				}
			})
		}
	}
}

func TestProcessPruneMaintenanceCLIBrokenPipe(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native live control supports macOS/Linux")
	}
	for _, point := range []string{"review", "cancel"} {
		t.Run(point, func(t *testing.T) {
			f := newPruneCLIFixture(t)
			p, address := startPruneControlProcess(t, f)
			runPruneProcessDelivery(t, f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address))
			command := "review\n"
			if point == "cancel" {
				p.send(t, command)
				review := p.next(t, "work_prune_maintenance_review")
				command = "cancel-before-start " + review["review_id"] + "\n"
			}
			_ = p.output.Close()
			p.send(t, command)
			var exited *exec.ExitError
			if err := p.wait(t); !errors.As(err, &exited) || exited.ExitCode() != 2 || !strings.Contains(p.stderr.String(), "broken pipe") {
				t.Fatal("SIGPIPE bypassed cleanup", err, p.stderr.String())
			}
			state, authority := f.snapshot(t)
			if authority.Authority.Sequence != 1 || authority.Authority.Pending != 1 {
				t.Fatal("stdout completed work")
			}
			review := preparationProcessFields(t, f.maintenanceArgs())
			args := append(f.maintenanceArgs(), "--mode", "cancel", "--expected-review-id", review["review_id"])
			if point == "cancel" {
				if state.Stage != authoritystore.PruneCancelled || !strings.Contains(p.stderr.String(), errPruneMaintenanceUnobserved.Error()) {
					t.Fatal("lost cancellation output was treated as no commit")
				}
			} else if state.Stage != authoritystore.PruneAdmitted {
				t.Fatal("review executed cancellation")
			}
			// The standalone CLI must also preserve cancellation on actual EPIPE.
			runPruneBrokenOutput(t, args, errPruneMaintenanceUnobserved)
			review = preparationProcessFields(t, f.maintenanceArgs())
			checkPruneCancellationOutput(t, f, preparationProcessFields(t, pruneCLISet(args, "expected-review-id", review["review_id"])))
		})
	}
}
