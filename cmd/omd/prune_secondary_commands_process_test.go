//go:build integration

package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func startPruneSecondaryCLIProcess(t testing.TB, args []string) (string, func(bool)) {
	t.Helper()
	command := helperCommand(nil, args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan string, 1), make(chan struct{})
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	var once sync.Once
	stop := func(kill bool) {
		once.Do(func() {
			var signalErr error
			if kill {
				signalErr = command.Process.Kill()
			} else {
				signalErr = command.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Error("secondary CLI process did not stop")
			}
			if signalErr != nil || (kill && waitErr == nil) || (!kill && waitErr != nil) {
				t.Errorf("secondary CLI shutdown signal=%v exit=%v stderr=%s", signalErr, waitErr, stderr.String())
			}
		})
	}
	t.Cleanup(func() { stop(true) })
	select {
	case line := <-ready:
		fields := outputFields(line, "serving_work_prune_secondary_commands")
		if fields["listen"] == "" || fields["execution_enabled"] != "false" || fields["command_only"] != "true" || fields["automatic_resume"] != "false" {
			stop(true)
			t.Fatalf("invalid secondary service readiness: %q stderr=%s", line, stderr.String())
		}
		return fields["listen"], stop
	case <-done:
		t.Fatalf("secondary CLI exited before readiness: %v stderr=%s", waitErr, stderr.String())
	case <-time.After(15 * time.Second):
		stop(true)
		t.Fatalf("secondary CLI startup timeout: %s", stderr.String())
	}
	return "", stop
}

func TestProcessPruneSecondaryCLIRecovery(t *testing.T) {
	for _, mode := range []string{"sigterm", "kill"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "sigterm" && runtime.GOOS == "windows" {
				t.Skip("SIGTERM is not a Windows graceful shutdown mechanism")
			}
			f := newPruneSecondaryCLIFixture(t)
			before := f.snapshot(t)
			_, stop := startPruneSecondaryCLIProcess(t, f.serveArgs("both"))
			if output, err := runProcessCommandError(15*time.Second, f.serveArgs("both")...); err == nil || strings.Contains(output, "serving_work_prune_secondary_commands") {
				t.Fatal("second process shared protected owners", err, output)
			}
			stop(mode == "kill")
			if after := f.snapshot(t); !reflect.DeepEqual(before, after) {
				t.Fatal("process restart resumed a command")
			}
			address, stop := startPruneSecondaryCLIProcess(t, f.serveArgs("admit"))
			admission := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)
			admitted := runPruneProcessDelivery(t, admission)
			stop(mode == "kill")
			if got := runPruneProcessDelivery(t, pruneCLISet(admission, "peer", "offline")); !reflect.DeepEqual(got, admitted) {
				t.Fatal("client restart lost secondary admission receipt")
			}
			state := f.snapshot(t)
			if state.executor.Stage != authoritystore.PruneAdmitted || state.secondary.Authority.Sequence != 1 || state.secondary.Authority.Pending != 1 {
				t.Fatal("secondary process admission executed or repeated work")
			}
			path, id := f.prepareCompletion(t) // separately owned offline transition
			primary := f.coordinator(t, true)
			address, stop = startPruneSecondaryCLIProcess(t, f.serveArgs("complete"))
			completion := f.deliveryArgs(pruneCompletionCommand, path, id, address)
			completed := runPruneProcessDelivery(t, completion)
			stop(mode == "kill")
			if err := primary.Close(); err != nil {
				t.Fatal(err)
			}
			if got := runPruneProcessDelivery(t, pruneCLISet(completion, "peer", "offline")); !reflect.DeepEqual(got, completed) {
				t.Fatal("client restart lost secondary completion receipt")
			}
			state = f.snapshot(t)
			if state.executor.Stage != authoritystore.PruneCancelled || state.secondary.Authority.Sequence != 2 || state.secondary.Authority.Pending != 0 {
				t.Fatal("secondary process completion did not drain exactly once")
			}
			for _, change := range []struct{ flag, value string }{{"inventory-id", pruneCLIHash(99).String()}, {"key", f.clientKey}, {"executor", filepath.Join(f.root, "missing")}} {
				if output, err := runProcessCommandError(15*time.Second, pruneCLISet(f.serveArgs("complete"), change.flag, change.value)...); err == nil || strings.Contains(output, "serving_work_prune_secondary_commands") {
					t.Fatal("invalid process scope reported readiness", err, output)
				}
			}
		})
	}
}

func TestProcessPruneSecondaryCLIBrokenOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SIGPIPE regression")
	}
	f := newPruneSecondaryCLIFixture(t)
	before := f.snapshot(t)
	runPruneBrokenOutput(t, f.serveArgs("both"), nil)
	if after := f.snapshot(t); !reflect.DeepEqual(before, after) {
		t.Fatal("broken readiness changed original owner state")
	}
	address, stop := startPruneSecondaryCLIProcess(t, f.serveArgs("admit"))
	admission := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)
	runPruneBrokenOutput(t, admission, admissionwire.ErrUnconfirmed)
	stop(false)
	admitted := runPruneProcessDelivery(t, pruneCLISet(admission, "peer", "offline"))
	path, id := f.prepareCompletion(t)
	address, stop = startPruneSecondaryCLIProcess(t, f.serveArgs("complete"))
	completion := f.deliveryArgs(pruneCompletionCommand, path, id, address)
	runPruneBrokenOutput(t, completion, completionwire.ErrUnconfirmed)
	stop(false)
	completed := runPruneProcessDelivery(t, pruneCLISet(completion, "peer", "offline"))
	if got := runPruneProcessDelivery(t, pruneCLISet(admission, "peer", "offline")); !reflect.DeepEqual(got, admitted) {
		t.Fatal("broken output retried secondary admission")
	}
	if got := runPruneProcessDelivery(t, pruneCLISet(completion, "peer", "offline")); !reflect.DeepEqual(got, completed) {
		t.Fatal("broken output retried secondary completion")
	}
	state := f.snapshot(t)
	if state.executor.Stage != authoritystore.PruneCancelled || state.secondary.Authority.Sequence != 2 || state.secondary.Authority.Pending != 0 {
		t.Fatal("broken output replayed a secondary command")
	}
}
