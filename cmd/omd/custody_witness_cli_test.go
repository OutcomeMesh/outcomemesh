package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
)

func witnessRun(t testing.TB, args []string) map[string]string {
	t.Helper()
	var out bytes.Buffer
	if err := runWitness(t.Context(), args, nil, &out); err != nil {
		t.Fatal(args[0], err)
	}
	return pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
}
func witnessPublish(t testing.TB, args []string) map[string]string {
	t.Helper()
	view := witnessRun(t, args)
	return witnessRun(t, append(replaceRemoteCLIFlag(args, "--mode", "publish"), "--expected-review-id", view["review_id"]))
}

type witnessCLIServer struct {
	input  *io.PipeWriter
	done   chan error
	ready  map[string]string
	cancel context.CancelFunc
}

func startWitnessCLIServer(t testing.TB, args []string) *witnessCLIServer {
	t.Helper()
	view := witnessRun(t, replaceRemoteCLIFlag(args, "--mode", "review"))
	args = append(replaceRemoteCLIFlag(args, "--mode", "serve"), "--expected-review-id", view["review_id"])
	ctx, cancel := context.WithCancel(t.Context())
	in, input := io.Pipe()
	out, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- runWitness(ctx, args, in, writer); _ = writer.Close() }()
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(out)
		if scan.Scan() {
			ready <- scan.Text()
		} else {
			ready <- ""
		}
	}()
	s := &witnessCLIServer{input: input, done: done, cancel: cancel}
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = out.Close() })
	select {
	case text := <-ready:
		s.ready = pruneCLIFields(text)
		if s.ready["scope_id"] == "" {
			select {
			case err := <-done:
				t.Fatal("server startup", text, err)
			default:
				t.Fatal("server ready absent", text)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}
	return s
}
func (s *witnessCLIServer) close(t testing.TB) {
	t.Helper()
	_, _ = io.WriteString(s.input, "close\n")
	select {
	case err := <-s.done:
		if err != nil {
			t.Fatal("witness close", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("witness close did not drain")
	}
	s.cancel()
}

func TestWitnessCLIEnrollmentQuorumCallsAndColdPins(t *testing.T) {
	scope := f.Scope()
	sid, _ := scope.ID()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	scopeFile := filepath.Join(dir, "scope")
	b, _ := scope.CanonicalBytes()
	writePruneCLIFile(t, scopeFile, b)
	common := []string{"--scope", scopeFile, "--scope-id", sid.String()}
	clientPublic := f.Public(99)
	clientID, _ := transportPeer(clientPublic)
	clientKey := filepath.Join(dir, "client.seed")
	writePruneCLIFile(t, clientKey, f.Key(99).Seed())
	claim := f.Sign(scope, custodyfence.Position{HeadID: sid}, custodyfence.Claim, types.Hash{}, types.Hash{})
	claimID, _ := claim.ID()
	commandFile := filepath.Join(dir, "command")
	b, _ = claim.CanonicalBytes()
	writePruneCLIFile(t, commandFile, b)
	var pairs []map[string]string
	var servers []*witnessCLIServer
	var serverArgs [][]string
	for i := 0; i < 3; i++ {
		root := filepath.Join(dir, "root-"+strconv.Itoa(i))
		key := filepath.Join(dir, "sign-"+strconv.Itoa(i))
		networkKey := filepath.Join(dir, "network-"+strconv.Itoa(i))
		member, network := f.Public(byte(70+i)), f.Public(byte(90+i))
		writePruneCLIFile(t, key, f.Key(byte(70+i)).Seed())
		writePruneCLIFile(t, networkKey, f.Key(byte(90+i)).Seed())
		args := append([]string{witnessServerCommand}, common...)
		args = append(args, "--root", root, "--witness-public-key", types.Hash(member).String(), "--expected-sequence", "0", "--expected-head", sid.String(), "--sign-key", key, "--transport-key", networkKey, "--transport-public-key", types.Hash(network).String(), "--clients", clientID.String())
		createView := witnessRun(t, append(args, "--mode", "create-review"))
		witnessRun(t, append(args, "--mode", "create", "--expected-review-id", createView["review_id"]))
		// Missing seed paths must remain unread during existing-root review.
		withoutKeys := replaceRemoteCLIFlag(replaceRemoteCLIFlag(args, "--sign-key", filepath.Join(dir, "missing")), "--transport-key", filepath.Join(dir, "missing-transport"))
		if fields := witnessRun(t, withoutKeys); fields["keys_loaded"] != "false" {
			t.Fatal(fields)
		}
		server := startWitnessCLIServer(t, args)
		servers = append(servers, server)
		serverArgs = append(serverArgs, args)
		reqPath, respPath := filepath.Join(dir, "request-"+strconv.Itoa(i)), filepath.Join(dir, "response-"+strconv.Itoa(i))
		requestArgs := append([]string{witnessRequestCommand}, common...)
		requestArgs = append(requestArgs, "--kind", "vote", "--expected-sequence", "0", "--expected-head", sid.String(), "--nonce", f.Hash("cli-nonce-"+strconv.Itoa(i)).String(), "--command", commandFile, "--command-id", claimID.String(), "--out", reqPath)
		published := witnessPublish(t, requestArgs)
		requestID := published["request_id"]
		call := append([]string{witnessClientCommand}, common...)
		call = append(call, "--witness-public-key", types.Hash(member).String(), "--request", reqPath, "--request-id", requestID, "--transport-key", clientKey, "--transport-public-key", types.Hash(clientPublic).String(), "--server-transport-public-key", types.Hash(network).String(), "--peer", server.ready["address"], "--out", respPath)
		view := witnessRun(t, call)
		exchange := append(call, "--mode", "exchange", "--expected-review-id", view["review_id"])
		witnessRun(t, exchange)
		witnessRun(t, exchange) // exact immutable response retry
		pairs = append(pairs, map[string]string{"request": reqPath, "response": respPath})
	}
	pairsPath := filepath.Join(dir, "pairs.json")
	b, _ = json.Marshal(pairs)
	writePruneCLIFile(t, pairsPath, b)
	certPath := filepath.Join(dir, "certificate")
	assemble := append([]string{witnessQuorumCommand}, common...)
	assemble = append(assemble, "--pairs", pairsPath, "--command-id", claimID.String(), "--out", certPath)
	result := witnessPublish(t, assemble)
	b, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := custodyfence.DecodeCertificate(b)
	if err != nil || cert.Verify(scope) != nil || len(cert.Votes) != 3 {
		t.Fatal("real CLI quorum", err)
	}
	for i, server := range servers {
		server.close(t)
		var out bytes.Buffer
		if err := runWitness(t.Context(), serverArgs[i], nil, &out); err == nil {
			t.Fatal("cold open silently adopted pending vote")
		}
		args := append(serverArgs[i], "--pending-id", claimID.String())
		witnessRun(t, args)
		commit := append(args, "--certificate", certPath, "--certificate-id", result["artifact_id"])
		view := witnessRun(t, commit)
		witnessRun(t, append(commit, "--mode", "commit", "--expected-review-id", view["review_id"]))
		updated := replaceRemoteCLIFlag(replaceRemoteCLIFlag(serverArgs[i], "--expected-sequence", "1"), "--expected-head", claimID.String())
		witnessRun(t, updated)
	}
}

func TestWitnessCLIRejectsOutputInsideRootBeforeVote(t *testing.T) {
	s := f.Scope()
	id, _ := s.ID()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	scopeFile := filepath.Join(dir, "scope")
	b, _ := s.CanonicalBytes()
	writePruneCLIFile(t, scopeFile, b)
	key := filepath.Join(dir, "seed")
	writePruneCLIFile(t, key, f.Key(70).Seed())
	root := filepath.Join(dir, "owner")
	w, err := custodyfence.Create(root, s, id, f.Key(70))
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	c := f.Sign(s, custodyfence.Position{HeadID: id}, custodyfence.Claim, types.Hash{}, types.Hash{})
	cid, _ := c.ID()
	command := filepath.Join(dir, "command")
	b, _ = c.CanonicalBytes()
	writePruneCLIFile(t, command, b)
	args := []string{witnessServerCommand, "--scope", scopeFile, "--scope-id", id.String(), "--root", root, "--witness-public-key", types.Hash(f.Public(70)).String(), "--expected-sequence", "0", "--expected-head", id.String(), "--sign-key", key, "--command", command, "--command-id", cid.String(), "--out", filepath.Join(root, "forbidden")}
	var out bytes.Buffer
	if err := runWitness(t.Context(), args, nil, &out); err == nil {
		t.Fatal("owner output was accepted")
	}
	_, pin, err := custodyfence.Inspect(root, s, id, f.Public(70), custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: id}})
	if err != nil || !pin.PendingID.IsZero() {
		t.Fatal("invalid output published a vote", err)
	}
	_ = witnesswire.MaxFrameBytes // keep codec bound visible in CLI coverage
}
