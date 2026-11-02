//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

func startScheduledDeliveryProcess(t testing.TB, args []string) (string, func(bool)) {
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
	ready, done := make(chan []byte, 1), make(chan struct{})
	go func() { line, _ := bufio.NewReader(stdout).ReadBytes('\n'); ready <- line }()
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
				t.Error("scheduled service did not stop")
			}
			if signalErr != nil || (kill && waitErr == nil) || (!kill && waitErr != nil) {
				t.Errorf("scheduled shutdown: signal=%v exit=%v stderr=%s", signalErr, waitErr, stderr.String())
			}
		})
	}
	t.Cleanup(func() { stop(true) })
	select {
	case raw := <-ready:
		return scheduledDeliveryReady(t, raw), stop
	case <-done:
		t.Fatalf("service exited before readiness: %v %s", waitErr, stderr.String())
	case <-time.After(15 * time.Second):
		stop(true)
		t.Fatalf("service readiness timeout: %s", stderr.String())
	}
	return "", stop
}

func TestProcessPruneScheduledDeliveryCLIRestartAndBrokenOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX owner locks and signal handling")
	}
	h := scheduledDeliveryCLIHarness{
		run: func(args []string, out io.Writer) error {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			command := helperCommand(ctx, args...)
			command.Stdout = out
			var stderr bytes.Buffer
			command.Stderr = &stderr
			err := command.Run()
			if ctx.Err() != nil {
				t.Fatalf("command timed out: %s %s", args[0], stderr.String())
			}
			if err != nil {
				t.Logf("%s: %s", args[0], stderr.String())
			}
			return err
		},
		start:  func(args []string) (string, func(bool)) { return startScheduledDeliveryProcess(t, args) },
		broken: func(args []string, expected error) { runPruneBrokenOutput(t, args, expected) },
	}
	scheduledDeliveryCLILifecycle(t, h, true)
}
