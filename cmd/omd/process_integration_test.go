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
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
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

func TestProcessWorkGraphActivationQUICRestart(t *testing.T) {
	root := t.TempDir()
	dataA := root + "/work-node-a"
	dataB := root + "/work-node-b"
	keyA := root + "/work-node-a.key"
	keyB := root + "/work-node-b.key"
	writeProcessKey(t, keyA, "work-a")
	writeProcessKey(t, keyB, "work-b")
	for _, data := range []string{dataA, dataB} {
		runProcessCommand(t, 20*time.Second,
			"init", "--data", data, "--network", "20260828", "--timestamp", "1700000000",
			"--difficulty-bits", "12", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
		)
	}
	document, err := loadGenesis(dataA)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{dataA, dataB} {
		runProcessCommand(t, 20*time.Second,
			"work-enable", "--data", data, "--activation-height", "2",
			"--confirm-genesis", genesisID.String(), "--max-trees", "4",
			"--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10),
		)
	}
	runProcessCommand(t, 30*time.Second, "work-mine", "--data", dataA, "--count", "5")
	server, peerID, address := startWorkQUICServerProcess(t, dataA, keyA)
	runProcessCommand(t, 30*time.Second,
		"work-sync-quic", "--data", dataB, "--key", keyB, "--peer", address, "--peer-id", peerID,
	)
	relayProcessWorkShares(t, dataB, keyB, address, peerID, 2)
	minedQUIC := runProcessCommand(t, 40*time.Second,
		"work-mine-quic", "--data", dataB, "--key", keyB, "--peer", address,
		"--peer-id", peerID, "--count", "1", "--relay-every", "128",
	)
	if fields := outputFields(minedQUIC, "work_mined_quic"); fields["height"] != "6" || fields["relayed_shares"] == "" ||
		fields["pending_relay"] == "" || fields["anchor_notified"] != "true" {
		t.Fatalf("cooperative miner output is incomplete: %s", minedQUIC)
	}
	stopQUICServerProcess(t, server)
	if output := server.stderr.String(); !strings.Contains(output, "work_relay") || !strings.Contains(output, "accepted=2") ||
		!strings.Contains(output, "chain_notification") || !strings.Contains(output, "height=6") {
		t.Fatalf("versioned server did not admit shares and the notified anchor: %s", output)
	}
	runProcessCommand(t, 20*time.Second, "work-verify", "--data", dataB)
	runProcessCommand(t, 20*time.Second, "work-verify", "--data", dataA)

	statusA := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataA)
	statusB := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataB)
	fieldsA := outputFields(statusA, "work_status")
	fieldsB := outputFields(statusB, "work_status")
	if fieldsA["height"] != "6" || fieldsB["height"] != "6" || fieldsA["tip"] == "" ||
		fieldsA["tip"] != fieldsB["tip"] || fieldsA["state"] != fieldsB["state"] ||
		fieldsA["cumulative_work"] != fieldsB["cumulative_work"] {
		t.Fatalf("versioned process nodes did not converge\nnode-a: %s\nnode-b: %s", statusA, statusB)
	}
	if output, err := runProcessCommandError(20*time.Second, "mine", "--data", dataB, "--count", "1"); err == nil || !strings.Contains(output, "use the explicit work-* command") {
		t.Fatalf("legacy mutation guard err=%v output=%s", err, output)
	}
	statusAfterRestart := runProcessCommand(t, 20*time.Second, "work-status", "--data", dataB)
	if fields := outputFields(statusAfterRestart, "work_status"); fields["tip"] != fieldsA["tip"] || fields["trees"] == "0/4" {
		t.Fatalf("versioned restart lost forest state: %s", statusAfterRestart)
	}
}

func relayProcessWorkShares(
	t testing.TB,
	data string,
	key string,
	peerAddress string,
	peerIDText string,
	count int,
) {
	t.Helper()
	_, store, router, _, err := openWorkNode(data)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	defer router.Close()
	manager, err := workround.NewManager(router, unixNow, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	round, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	miner := types.Address(types.DomainHash("test/omd/process-work-relay-miner"))
	for index := 0; index < count; index++ {
		template, err := round.Template(miner, inclusion)
		if err != nil {
			t.Fatal(err)
		}
		for nonce := uint64(0); ; {
			share, _, err := workgraph.Mine(context.Background(), template, nonce)
			if err != nil {
				t.Fatal(err)
			}
			hard, err := workgraph.MeetsAnchor(share)
			if err != nil {
				t.Fatal(err)
			}
			if !hard {
				if _, err := round.Add(share); err != nil {
					t.Fatal(err)
				}
				break
			}
			nonce = share.Nonce + 1
		}
	}
	privateKey, err := loadPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	host, err := libp2ptransport.New(ctx, privateKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	expected, err := parseHash(peerIDText)
	if err != nil {
		t.Fatal(err)
	}
	stream, remote, err := host.OpenWorkGraphStream(ctx, peerAddress, &expected)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := round.Relay(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	if remote != expected || stats.Accepted != count || stats.Rejected != 0 {
		t.Fatalf("WorkGraph process relay remote=%s stats=%+v", remote, stats)
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

func startWorkQUICServerProcess(t testing.TB, data, key string) (*serverProcess, string, string) {
	t.Helper()
	command := helperCommand(nil,
		"work-serve-quic", "--data", data, "--key", key,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--max-connections", "8",
		"--max-chain-streams", "2", "--max-chain-streams-per-peer", "1",
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
		t.Fatalf("detached versioned QUIC server startup timeout stderr=%s", stderr.String())
	}
	values := outputFields(line, "serving_work_quic")
	peerID := values["peer_id"]
	address := strings.Split(values["listen"], ",")[0]
	if peerID == "" || address == "" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid detached versioned server line %q stderr=%s", line, stderr.String())
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

func runProcessCommandError(timeout time.Duration, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := helperCommand(ctx, arguments...).CombinedOutput()
	return string(output), err
}

func outputFields(output, prefix string) map[string]string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || fields[0] != prefix {
			continue
		}
		result := make(map[string]string, len(fields)-1)
		for _, field := range fields[1:] {
			keyValue := strings.SplitN(field, "=", 2)
			if len(keyValue) == 2 {
				result[keyValue[0]] = keyValue[1]
			}
		}
		return result
	}
	return nil
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
