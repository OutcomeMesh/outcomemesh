//go:build integration && (darwin || linux)

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
)

func startWitnessProcess(t testing.TB, args []string) *pruneControlProcess {
	t.Helper()
	p := &pruneControlProcess{command: helperCommand(nil, args...), lines: make(chan string, 128), done: make(chan struct{})}
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
	p.command.Stdout = writer
	p.command.Stderr = &p.stderr
	if err := p.command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scan := bufio.NewScanner(reader)
		for scan.Scan() {
			p.lines <- scan.Text()
		}
	}()
	go func() { p.err = p.command.Wait(); <-readDone; close(p.done) }()
	t.Cleanup(func() { _ = p.command.Process.Kill(); _ = p.input.Close(); _ = p.output.Close(); _ = p.wait(t) })
	return p
}
func witnessProcessFields(t testing.TB, args []string) map[string]string {
	t.Helper()
	text := runProcessCommand(t, 20*time.Second, args...)
	return pruneCLIFields(strings.SplitN(text, "\n", 2)[0])
}

func TestProcessWitnessLostOutputKillAndExactColdRecovery(t *testing.T) {
	s := f.Scope()
	sid, _ := s.ID()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	scopeFile := filepath.Join(dir, "scope")
	b, _ := s.CanonicalBytes()
	writePruneCLIFile(t, scopeFile, b)
	key, networkKey, clientKey := filepath.Join(dir, "sign"), filepath.Join(dir, "transport"), filepath.Join(dir, "client")
	for path, seed := range map[string]byte{key: 70, networkKey: 90, clientKey: 99} {
		writePruneCLIFile(t, path, f.Key(seed).Seed())
	}
	clientPub := f.Public(99)
	networkPub := f.Public(90)
	clientID, _ := transportPeer(clientPub)
	root := filepath.Join(dir, "original")
	args := []string{witnessServerCommand, "--scope", scopeFile, "--scope-id", sid.String(), "--root", root, "--witness-public-key", types.Hash(f.Public(70)).String(), "--expected-sequence", "0", "--expected-head", sid.String(), "--sign-key", key, "--transport-key", networkKey, "--transport-public-key", types.Hash(networkPub).String(), "--clients", clientID.String()}
	created := witnessProcessFields(t, append(args, "--mode", "create-review"))
	witnessProcessFields(t, append(args, "--mode", "create", "--expected-review-id", created["review_id"]))
	view := witnessProcessFields(t, args)
	server := startWitnessProcess(t, append(args, "--mode", "serve", "--expected-review-id", view["review_id"]))
	ready := remoteProcessNext(t, server, "custody_witness_serving")
	claim := f.Sign(s, custodyfence.Position{HeadID: sid}, custodyfence.Claim, types.Hash{}, types.Hash{})
	cid, _ := claim.ID()
	command := filepath.Join(dir, "command")
	b, _ = claim.CanonicalBytes()
	writePruneCLIFile(t, command, b)
	requestPath := filepath.Join(dir, "request")
	build := []string{witnessRequestCommand, "--scope", scopeFile, "--scope-id", sid.String(), "--kind", "vote", "--expected-sequence", "0", "--expected-head", sid.String(), "--nonce", f.Hash("process-nonce").String(), "--command", command, "--command-id", cid.String(), "--out", requestPath}
	view = witnessProcessFields(t, build)
	published := witnessProcessFields(t, append(build, "--mode", "publish", "--expected-review-id", view["review_id"]))
	responsePath := filepath.Join(dir, "response")
	call := []string{witnessClientCommand, "--scope", scopeFile, "--scope-id", sid.String(), "--witness-public-key", types.Hash(f.Public(70)).String(), "--request", requestPath, "--request-id", published["request_id"], "--transport-key", clientKey, "--transport-public-key", types.Hash(clientPub).String(), "--server-transport-public-key", types.Hash(networkPub).String(), "--peer", ready["address"], "--out", responsePath}
	view = witnessProcessFields(t, call)
	exchange := append(call, "--mode", "exchange", "--expected-review-id", view["review_id"])
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	child := helperCommand(nil, exchange...)
	var stderr bytes.Buffer
	child.Stdout = writer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if err := child.Wait(); err == nil {
		t.Fatal("broken output was reported successful")
	}
	retained, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatal("response lost before stdout", err, stderr.String())
	}
	response, err := witnesswire.DecodeResponse(retained)
	if err != nil || response.Observation.PendingID != cid {
		t.Fatal("durable vote missing", err)
	}
	if err := server.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := server.wait(t); err == nil {
		t.Fatal("server was not killed")
	}
	status, ok := server.command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("did not observe selected SIGKILL")
	}
	if _, err := runProcessCommandError(10*time.Second, args...); err == nil {
		t.Fatal("cold open adopted unretained pending state")
	}
	args = append(args, "--pending-id", cid.String())
	view = witnessProcessFields(t, args)
	server = startWitnessProcess(t, append(args, "--mode", "serve", "--expected-review-id", view["review_id"]))
	ready = remoteProcessNext(t, server, "custody_witness_serving")
	call = replaceRemoteCLIFlag(call, "--peer", ready["address"])
	view = witnessProcessFields(t, call)
	witnessProcessFields(t, append(call, "--mode", "exchange", "--expected-review-id", view["review_id"]))
	again, err := os.ReadFile(responsePath)
	if err != nil || !bytes.Equal(retained, again) {
		t.Fatal("cold retry returned another response", err)
	}
	server.send(t, "close\n")
	if err := server.wait(t); err != nil {
		t.Fatal(err)
	}
	_, pin, err := custodyfence.Inspect(root, s, sid, f.Public(70), custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}, PendingID: cid})
	if err != nil || pin.PendingID != cid {
		t.Fatal("close released original vote lock", err)
	}
}

// Test-only immutable fixture export for controlled native/WAN acceptance.
// It contains public deterministic test seeds; it is absent from normal omd.
func TestExportWitnessNetworkFixture(t *testing.T) {
	parent := os.Getenv("OMESH_WITNESS_EXPORT_PARENT")
	if parent == "" {
		t.Skip("explicit private witness fixture export")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("private existing export parent required", err)
	}
	dir, err := os.MkdirTemp(parent, "witness-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	s := f.Scope()
	// Every controlled export is a distinct test incarnation. A failed WAN
	// attempt is retained; another campaign must not bootstrap its old scope.
	s.AssignmentID = f.Hash("wan-incarnation:" + dir)
	sid, _ := s.ID()
	b, _ := s.CanonicalBytes()
	writePruneCLIFile(t, filepath.Join(dir, "scope"), b)
	claim := f.Sign(s, custodyfence.Position{HeadID: sid}, custodyfence.Claim, types.Hash{}, types.Hash{})
	cid, _ := claim.ID()
	unknown := f.Sign(s, custodyfence.Position{Sequence: 1, HeadID: cid}, custodyfence.MarkUnknown, cid, f.Hash("wan-unknown"))
	uid, _ := unknown.ID()
	result := f.Sign(s, custodyfence.Position{Sequence: 2, HeadID: uid}, custodyfence.RecordResult, cid, f.Hash("wan-opaque-result"))
	conflict := f.Sign(s, custodyfence.Position{HeadID: sid}, custodyfence.CloseUnclaimed, types.Hash{}, f.Hash("wan-unclaimed"))
	commands := map[string]string{}
	for name, c := range map[string]custodyfence.Command{"claim": claim, "unknown": unknown, "result": result, "conflict": conflict} {
		raw, _ := c.CanonicalBytes()
		writePruneCLIFile(t, filepath.Join(dir, name), raw)
		id, _ := c.ID()
		commands[name] = id.String()
	}
	var members []map[string]string
	for i := 0; i < 4; i++ {
		member := filepath.Join(dir, string(rune('0'+i)))
		if err := os.Mkdir(member, 0o700); err != nil {
			t.Fatal(err)
		}
		writePruneCLIFile(t, filepath.Join(member, "sign.seed"), f.Key(byte(70+i)).Seed())
		writePruneCLIFile(t, filepath.Join(member, "transport.seed"), f.Key(byte(90+i)).Seed())
		members = append(members, map[string]string{"signing_public_key": types.Hash(f.Public(byte(70 + i))).String(), "transport_public_key": types.Hash(f.Public(byte(90 + i))).String()})
	}
	writePruneCLIFile(t, filepath.Join(dir, "client.seed"), f.Key(99).Seed())
	clientID, _ := transportPeer(f.Public(99))
	metadata := map[string]any{"scope_id": sid.String(), "members": members, "commands": commands, "client_public_key": types.Hash(f.Public(99)).String(), "client_peer_id": clientID.String(), "opaque_result_is_not_custody_proof": true}
	raw, _ := json.MarshalIndent(metadata, "", "  ")
	writePruneCLIFile(t, filepath.Join(dir, "public.json"), raw)
	t.Log("witness_fixture_path=" + dir)
}
