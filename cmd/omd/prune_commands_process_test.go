//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func TestProcessPruneCommandCLIBrokenPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SIGPIPE regression")
	}
	f := newPruneCLIFixture(t)
	runPruneBrokenOutput(t, f.serveArgs(), nil)
	if s, c := f.snapshot(t); s.Stage != authoritystore.PrunePrepared || c.Authority.Sequence != 0 {
		t.Fatal("broken readiness advanced state")
	}
	address, stop := startPruneCLIProcess(t, f)
	admission := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)
	runPruneBrokenOutput(t, admission, admissionwire.ErrUnconfirmed)
	stop(false)
	admitted := runPruneProcessDelivery(t, pruneCLISet(admission, "peer", "offline"))
	path, id := f.prepareCompletion(t)
	address, stop = startPruneCLIProcess(t, f)
	completion := f.deliveryArgs(pruneCompletionCommand, path, id, address)
	runPruneBrokenOutput(t, completion, completionwire.ErrUnconfirmed)
	stop(false)
	completed := runPruneProcessDelivery(t, pruneCLISet(completion, "peer", "offline"))
	if got := runPruneProcessDelivery(t, pruneCLISet(admission, "peer", "offline")); !reflect.DeepEqual(got, admitted) {
		t.Fatal("broken output retried admission")
	}
	if got := runPruneProcessDelivery(t, pruneCLISet(completion, "peer", "offline")); !reflect.DeepEqual(got, completed) {
		t.Fatal("broken output retried completion")
	}
	if s, c := f.snapshot(t); s.Stage != authoritystore.PruneCancelled || c.Authority.Sequence != 2 || c.Authority.Pending != 0 {
		t.Fatal("broken output replayed work")
	}
}

func runPruneBrokenOutput(t testing.TB, arguments []string, unconfirmed error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	defer writer.Close()
	var stderr bytes.Buffer
	command := helperCommand(ctx, arguments...)
	command.Stdout, command.Stderr = writer, &stderr
	err = command.Run()
	var exited *exec.ExitError
	// TestOMDHelperProcess maps returned command errors to exit 2 (main uses 1).
	if !errors.As(err, &exited) || exited.ExitCode() != 2 || !strings.Contains(stderr.String(), "broken pipe") {
		t.Fatalf("broken stdout bypassed returned CLI error: exit=%v stderr=%s", err, stderr.String())
	}
	if unconfirmed != nil && !strings.Contains(stderr.String(), unconfirmed.Error()) {
		t.Fatal("stdout failure lost delivery ambiguity", stderr.String())
	}
}

func TestProcessPruneCommandCLIRecovery(t *testing.T) {
	for _, mode := range []string{"sigterm", "kill"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "sigterm" && runtime.GOOS == "windows" {
				t.Skip("SIGTERM is not a Windows graceful shutdown mechanism")
			}
			f := newPruneCLIFixture(t)
			before, coord := f.snapshot(t)
			_, stop := startPruneCLIProcess(t, f)
			f.assertBusy(t)
			if output, err := runProcessCommandError(15*time.Second, f.serveArgs()...); err == nil || strings.Contains(output, "serving_work_prune_commands") {
				t.Fatal("second service shared roots", err, output)
			}
			stop(mode == "kill")
			for range 2 {
				s, c := f.snapshot(t)
				if !reflect.DeepEqual(before, s) || !reflect.DeepEqual(coord, c) {
					t.Fatal("start/stop resumed work")
				}
			}
			address, stop := startPruneCLIProcess(t, f)
			admission := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)
			admitted := runPruneProcessDelivery(t, admission)
			stop(mode == "kill")
			if got := runPruneProcessDelivery(t, pruneCLISet(admission, "peer", "offline")); !reflect.DeepEqual(got, admitted) {
				t.Fatal("client restart did not retain receipt")
			}
			s, c := f.snapshot(t)
			if s.Stage != authoritystore.PruneAdmitted || c.Authority.Sequence != 1 || c.Authority.Pending != 1 {
				t.Fatal("admission command executed or repeated work")
			}
			path, id := f.prepareCompletion(t)
			address, stop = startPruneCLIProcess(t, f)
			completion := f.deliveryArgs(pruneCompletionCommand, path, id, address)
			completed := runPruneProcessDelivery(t, completion)
			stop(mode == "kill")
			if got := runPruneProcessDelivery(t, pruneCLISet(completion, "peer", "offline")); !reflect.DeepEqual(got, completed) {
				t.Fatal("completion restart lost original exchange")
			}
			s, c = f.snapshot(t)
			if s.Stage != authoritystore.PruneCancelled || c.Authority.Sequence != 2 || c.Authority.Pending != 0 {
				t.Fatal("completion did not drain exactly once")
			}
			retirePruneCLI(t, f)
			before, coord = f.snapshot(t)
			// Preserve the old receipts outside the disposable fixture. Removing
			// only this local observation must never recreate the signed command.
			for _, item := range []struct{ root, name string }{{f.admissionPath, "ack.omcar"}, {path, "ack.omccr"}} {
				if err := os.Rename(filepath.Join(item.root, "received", item.name), filepath.Join(t.TempDir(), item.name)); err != nil {
					t.Fatal(err)
				}
			}
			address, stop = startPruneCLIProcess(t, f)
			for _, item := range []struct {
				args     []string
				original map[string]string
			}{{admission, admitted}, {completion, completed}} {
				retried := runPruneProcessDelivery(t, pruneCLISet(item.args, "peer", address))
				if retried["entry_id"] != item.original["entry_id"] || retried["nonce"] == item.original["nonce"] {
					t.Fatal("historical retry changed the entry or reused an exchange")
				}
			}
			stop(mode == "kill")
			for range 2 {
				s, c := f.snapshot(t)
				if !reflect.DeepEqual(before, s) || !reflect.DeepEqual(coord, c) {
					t.Fatal("historical process retry advanced retired assignment")
				}
			}
			for _, change := range []struct{ flag, value string }{{"assignment-id", pruneCLIHash(99).String()}, {"key", f.serverKey}, {"outbox", filepath.Join(f.root, "missing")}} {
				if output, err := runProcessCommandError(15*time.Second, pruneCLISet(admission, change.flag, change.value)...); err == nil || strings.Contains(output, "work_prune_delivery") {
					t.Fatal("invalid command printed success", err, output)
				}
			}
			if _, err := os.Lstat(filepath.Join(f.root, "missing")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("process created missing outbox")
			}
		})
	}
}

func retirePruneCLI(t testing.TB, f *pruneCLIFixture) {
	t.Helper()
	e, c := f.owners(t)
	defer e.Close()
	defer c.Close()
	evidence := pruneCLIHash(80)
	for _, kind := range []custodyauthority.Kind{custodyauthority.Stop, custodyauthority.Retire} {
		snapshot, err := c.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		entry := signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: f.config.AssignmentID,
			ExpectedSequence: snapshot.Authority.Sequence, ExpectedHead: snapshot.Authority.HeadID,
			Kind: kind, EvidenceID: evidence})
		commit, err := c.Append(t.Context(), entry)
		if err != nil {
			t.Fatal(err)
		}
		evidence = commit.EntryID
	}
}

func runPruneProcessDelivery(t testing.TB, args []string) map[string]string {
	t.Helper()
	output := runProcessCommand(t, 15*time.Second, args...)
	fields := outputFields(output, "work_prune_delivery")
	if fields["delivery_confirmed"] != "true" || fields["execution_authorized"] != "false" || fields["historical_only"] != "true" || fields["automatic_retry"] != "false" {
		t.Fatal("process delivery overclaimed authority", output)
	}
	for _, field := range []string{"entry_id", "intent_id", "nonce"} {
		if id, err := parseHash(fields[field]); err != nil || id == (types.Hash{}) {
			t.Fatal("missing delivery ID", output)
		}
	}
	return fields
}

func startPruneCLIProcess(t testing.TB, f *pruneCLIFixture) (string, func(bool)) {
	t.Helper()
	command := helperCommand(nil, f.serveArgs()...)
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
			var err error
			if kill {
				err = command.Process.Kill()
			} else {
				err = command.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Error("prune CLI process did not stop")
			}
			// Wait drains stderr before diagnostics; an early helper failure must
			// not masquerade as our requested successful shutdown or crash.
			if err != nil || (kill && waitErr == nil) || (!kill && waitErr != nil) {
				t.Errorf("prune CLI shutdown signal=%v exit=%v stderr=%s", err, waitErr, stderr.String())
			}
		})
	}
	t.Cleanup(func() { stop(true) })
	select {
	case line := <-ready:
		fields := outputFields(line, "serving_work_prune_commands")
		if fields["listen"] == "" || fields["peer_id"] != f.config.ServerPeerID.String() || fields["execution_enabled"] != "false" {
			stop(true)
			t.Fatalf("invalid prune service readiness: %q stderr=%s", line, stderr.String())
		}
		return fields["listen"], stop
	case <-done:
		t.Fatalf("prune CLI exited before ready: %v stderr=%s", waitErr, stderr.String())
	case <-time.After(15 * time.Second):
		stop(true)
		t.Fatalf("prune CLI startup timeout: %s", stderr.String())
	}
	return "", stop
}
