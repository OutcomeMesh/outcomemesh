//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const helperProcessEnvironment = "OUTCOMEMESH_TEST_HELPER_PROCESS"

// TestProcessQUICRestartSoak is intentionally behind the integration build tag.
// OUTCOMEMESH_SOAK_CYCLES may raise the default three restart/sync cycles to 100.
func TestProcessQUICRestartSoak(t *testing.T) {
	cycles := 3
	if text := os.Getenv("OUTCOMEMESH_SOAK_CYCLES"); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 1 || parsed > 100 {
			t.Fatalf("OUTCOMEMESH_SOAK_CYCLES must be 1..100, got %q", text)
		}
		cycles = parsed
	}
	root := t.TempDir()
	dataA := root + "/node-a"
	dataB := root + "/node-b"
	keyA := root + "/node-a.key"
	keyB := root + "/node-b.key"
	writeProcessKey(t, keyA, "a")
	writeProcessKey(t, keyB, "b")
	for _, data := range []string{dataA, dataB} {
		runProcessCommand(t, 20*time.Second,
			"init", "--data", data, "--network", "20260827", "--timestamp", "1700000000",
			"--difficulty-bits", "0", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
		)
	}

	for cycle := 0; cycle < cycles; cycle++ {
		runProcessCommand(t, 20*time.Second, "mine", "--data", dataA, "--count", "2")
		server, peerID, address := startQUICServerProcess(t, dataA, keyA)
		runProcessCommand(t, 30*time.Second,
			"sync-quic", "--data", dataB, "--key", keyB, "--peer", address, "--peer-id", peerID,
		)
		runProcessCommand(t, 20*time.Second, "verify", "--data", dataB)
		stopQUICServerProcess(t, server)
	}

	statusA := runProcessCommand(t, 20*time.Second, "status", "--data", dataA)
	statusB := runProcessCommand(t, 20*time.Second, "status", "--data", dataB)
	wantHeight := fmt.Sprintf("height=%d", cycles*2)
	if !strings.Contains(statusA, wantHeight) || !strings.Contains(statusB, wantHeight) {
		t.Fatalf("process nodes did not converge to %s\nnode-a: %s\nnode-b: %s", wantHeight, statusA, statusB)
	}
}

// TestOMDHelperProcess executes exactly one CLI command in a separate process.
func TestOMDHelperProcess(t *testing.T) {
	if os.Getenv(helperProcessEnvironment) != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "missing helper command")
		os.Exit(2)
	}
	if err := run(os.Args[separator+1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	os.Exit(0)
}

type serverProcess struct {
	command *exec.Cmd
	stderr  *bytes.Buffer
}

func startQUICServerProcess(t testing.TB, data, key string) (*serverProcess, string, string) {
	t.Helper()
	command := helperCommand(nil,
		"serve-quic", "--data", data, "--key", key,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--max-connections", "8", "--max-streams-per-peer", "2",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil || !command.ProcessState.Exited() {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	lineResult := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lineResult <- line
	}()
	var line string
	select {
	case line = <-lineResult:
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("detached QUIC server startup timeout stderr=%s", stderr.String())
	}
	values := make(map[string]string)
	fields := strings.Fields(strings.TrimSpace(line))
	for _, field := range fields {
		keyValue := strings.SplitN(field, "=", 2)
		if len(keyValue) == 2 {
			values[keyValue[0]] = keyValue[1]
		}
	}
	peerID := values["peer_id"]
	address := strings.Split(values["listen"], ",")[0]
	if len(fields) == 0 || fields[0] != "serving_quic" || peerID == "" || address == "" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid detached QUIC server line %q stderr=%s", line, stderr.String())
	}
	return &serverProcess{command: command, stderr: stderr}, peerID, address
}

func stopQUICServerProcess(t testing.TB, server *serverProcess) {
	t.Helper()
	if err := server.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal QUIC server: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("QUIC server shutdown: %v stderr=%s", err, server.stderr.String())
		}
	case <-time.After(20 * time.Second):
		_ = server.command.Process.Kill()
		t.Fatalf("QUIC server shutdown timeout stderr=%s", server.stderr.String())
	}
}

func runProcessCommand(t testing.TB, timeout time.Duration, arguments ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := helperCommand(ctx, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("command %q: %v\n%s", arguments, err, output)
	}
	return string(output)
}

func helperCommand(ctx context.Context, arguments ...string) *exec.Cmd {
	commandArguments := append([]string{"-test.run=^TestOMDHelperProcess$", "--"}, arguments...)
	var command *exec.Cmd
	if ctx == nil {
		command = exec.Command(os.Args[0], commandArguments...)
	} else {
		command = exec.CommandContext(ctx, os.Args[0], commandArguments...)
	}
	command.Env = append(os.Environ(), helperProcessEnvironment+"=1")
	return command
}

func writeProcessKey(t testing.TB, path, label string) {
	t.Helper()
	seed := types.DomainHash("test/cmd/process/key", []byte(label))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	if err := os.WriteFile(path, privateKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
}
