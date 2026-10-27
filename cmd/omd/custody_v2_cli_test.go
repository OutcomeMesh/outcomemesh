package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

type v2CLIDriver func(testing.TB, []string) string
type v2CLIStart func(testing.TB, []string, string) (string, func())

func v2InProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	var e error
	if args[0] == custodyV2Command {
		e = runCustodyV2(t.Context(), args, nil, &out)
	} else {
		e = runWitness(t.Context(), args, nil, &out)
	}
	if e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}
func v2InProcessStart(t testing.TB, args []string, prefix string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	in, input := io.Pipe()
	out, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		var e error
		if args[0] == custodyV2Command {
			e = runCustodyV2(ctx, args, in, writer)
		} else {
			e = runWitness(ctx, args, in, writer)
		}
		_ = writer.Close()
		done <- e
	}()
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(out)
		if scan.Scan() {
			ready <- scan.Text()
		} else {
			ready <- ""
		}
	}()
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = out.Close() })
	select {
	case line := <-ready:
		fields := pruneCLIFields(line)
		if !strings.HasPrefix(line, prefix+" ") || fields["address"] == "" {
			select {
			case e := <-done:
				t.Fatal(line, e)
			default:
				t.Fatal(line)
			}
		}
		return fields["address"], func() {
			_, _ = io.WriteString(input, "close\n")
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server drain")
			}
			cancel()
			_ = out.Close()
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server readiness")
	}
	return "", func() {}
}
func runV2CLICampaign(t testing.TB, driver v2CLIDriver, start v2CLIStart) {
	t.Helper()
	x := newCustodyV2Fixture(t)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	c := x.context
	keys := map[byte]string{}
	for _, seed := range []byte{1, 4, 14, 15, 46, 61, 70, 71, 72, 90, 91, 92} {
		keys[seed] = filepath.Join(dir, "key-"+strconv.Itoa(int(seed)))
		writePruneCLIFile(t, keys[seed], f.Key(seed).Seed())
	}
	vrun := func(args []string) map[string]string {
		t.Helper()
		review := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
		if review["keys_loaded"] != "false" || review["review_id"] == "" {
			t.Fatal(review)
		}
		return pruneCLIFields(strings.SplitN(driver(t, append(args, "--mode", "run", "--expected-review-id", review["review_id"])), "\n", 2)[0])
	}
	c.Plan.AuditSignature = [64]byte{}
	c.Plan.ServeSignature = [64]byte{}
	c.Plan.AuthoritySignature = [64]byte{}
	raw, _ := json.Marshal(c)
	draft := filepath.Join(dir, "draft-0.json")
	writePruneCLIFile(t, draft, raw)
	for i, role := range []string{"audit", "serve", "authority"} {
		out := filepath.Join(dir, "draft-"+strconv.Itoa(i+1)+".json")
		seed := byte(4)
		if role == "authority" {
			seed = 1
		}
		vrun([]string{custodyV2Command, "--action", "draft-sign", "--draft", draft, "--sign-role", role, "--sign-key", keys[seed], "--out", out})
		draft = out
	}
	contextFile := filepath.Join(dir, "context")
	vrun([]string{custodyV2Command, "--action", "context", "--draft", draft, "--out", contextFile})
	cid, _ := x.context.ID()
	common := []string{"--context", contextFile, "--context-id", cid.String(), "--scope-id", x.pin.String()}
	args := func(action string, extra ...string) []string {
		a := append([]string{custodyV2Command, "--action", action}, common...)
		return append(a, extra...)
	}
	scopeFile := filepath.Join(dir, "scope")
	vrun(args("scope", "--out", scopeFile))
	wcommon := []string{"--scope", scopeFile, "--scope-id", x.pin.String()}
	targetRoot := filepath.Join(dir, "target-original")
	acceptorRoot := filepath.Join(dir, "acceptor-original")
	vrun(args("create-target", "--root", targetRoot, "--journal", x.sources.Journal, "--objects", x.sources.Objects))
	vrun(args("create-acceptor", "--root", acceptorRoot, "--journal", x.legacy.base.config.Audit.JournalPath))
	serve := args("serve-target", "--root", targetRoot, "--journal", x.sources.Journal, "--objects", x.sources.Objects, "--sign-key", keys[14], "--replica-key", keys[61], "--transport-key", keys[15])
	review := pruneCLIFields(strings.SplitN(driver(t, serve), "\n", 2)[0])
	address, closeTarget := start(t, append(serve, "--mode", "run", "--expected-review-id", review["review_id"]), "custody_v2_serving")
	var witnesses []string
	var closeWitnesses []func()
	for i := 0; i < 3; i++ {
		member, transport := f.Public(byte(70+i)), f.Public(byte(90+i))
		client, _ := transportPeer(f.Public(46))
		base := append([]string{witnessServerCommand}, wcommon...)
		base = append(base, "--root", filepath.Join(dir, "witness-"+strconv.Itoa(i)), "--witness-public-key", types.Hash(member).String(), "--expected-sequence", "0", "--expected-head", x.pin.String(), "--sign-key", keys[byte(70+i)], "--transport-key", keys[byte(90+i)], "--transport-public-key", types.Hash(transport).String(), "--clients", client.String())
		view := pruneCLIFields(strings.SplitN(driver(t, append(base, "--mode", "create-review")), "\n", 2)[0])
		driver(t, append(base, "--mode", "create", "--expected-review-id", view["review_id"]))
		view = pruneCLIFields(strings.SplitN(driver(t, base), "\n", 2)[0])
		address, close := start(t, append(base, "--mode", "serve", "--expected-review-id", view["review_id"]), "custody_witness_serving")
		witnesses = append(witnesses, address)
		closeWitnesses = append(closeWitnesses, close)
	}
	certify := func(commandFile, label string) string {
		t.Helper()
		raw, e := os.ReadFile(commandFile)
		if e != nil {
			t.Fatal(e)
		}
		cmd, e := custodyfence.DecodeCommand(raw)
		if e != nil {
			t.Fatal(e)
		}
		id, _ := cmd.ID()
		var pairs []map[string]string
		wrun := func(a []string, mode string) map[string]string {
			t.Helper()
			view := pruneCLIFields(strings.SplitN(driver(t, a), "\n", 2)[0])
			return pruneCLIFields(strings.SplitN(driver(t, append(a, "--mode", mode, "--expected-review-id", view["review_id"])), "\n", 2)[0])
		}
		for i := 0; i < 3; i++ {
			reqFile, respFile := filepath.Join(dir, label+"-req-"+strconv.Itoa(i)), filepath.Join(dir, label+"-resp-"+strconv.Itoa(i))
			a := append([]string{witnessRequestCommand}, wcommon...)
			a = append(a, "--kind", "vote", "--expected-sequence", strconv.FormatUint(cmd.ExpectedSequence, 10), "--expected-head", cmd.ExpectedHead.String(), "--nonce", f.Hash(label+strconv.Itoa(i)).String(), "--command", commandFile, "--command-id", id.String(), "--out", reqFile)
			request := wrun(a, "publish")
			a = append([]string{witnessClientCommand}, wcommon...)
			member, transport, client := f.Public(byte(70+i)), f.Public(byte(90+i)), f.Public(46)
			a = append(a, "--witness-public-key", types.Hash(member).String(), "--request", reqFile, "--request-id", request["request_id"], "--transport-key", keys[46], "--transport-public-key", types.Hash(client).String(), "--server-transport-public-key", types.Hash(transport).String(), "--peer", witnesses[i], "--out", respFile)
			wrun(a, "exchange")
			pairs = append(pairs, map[string]string{"request": reqFile, "response": respFile})
		}
		pairFile := filepath.Join(dir, label+"-pairs.json")
		raw, _ = json.Marshal(pairs)
		writePruneCLIFile(t, pairFile, raw)
		certFile := filepath.Join(dir, label+"-qc")
		a := append([]string{witnessQuorumCommand}, wcommon...)
		a = append(a, "--pairs", pairFile, "--command-id", id.String(), "--out", certFile)
		cert := wrun(a, "publish")
		for i := 0; i < 3; i++ {
			reqFile, respFile := filepath.Join(dir, label+"-commit-req-"+strconv.Itoa(i)), filepath.Join(dir, label+"-commit-resp-"+strconv.Itoa(i))
			a := append([]string{witnessRequestCommand}, wcommon...)
			a = append(a, "--kind", "commit", "--expected-sequence", strconv.FormatUint(cmd.ExpectedSequence, 10), "--expected-head", cmd.ExpectedHead.String(), "--pending-id", id.String(), "--nonce", f.Hash(label+"commit"+strconv.Itoa(i)).String(), "--certificate", certFile, "--certificate-id", cert["artifact_id"], "--out", reqFile)
			request := wrun(a, "publish")
			a = append([]string{witnessClientCommand}, wcommon...)
			member, transport, client := f.Public(byte(70+i)), f.Public(byte(90+i)), f.Public(46)
			a = append(a, "--witness-public-key", types.Hash(member).String(), "--request", reqFile, "--request-id", request["request_id"], "--transport-key", keys[46], "--transport-public-key", types.Hash(client).String(), "--server-transport-public-key", types.Hash(transport).String(), "--peer", witnesses[i], "--out", respFile)
			wrun(a, "exchange")
		}
		return certFile
	}
	artifact := func(path string) string {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return custodyV2ArtifactID(raw).String()
	}
	requestAndCall := func(op string, extra ...string) (string, string, string) {
		t.Helper()
		req, resp := filepath.Join(dir, op+"-req"), filepath.Join(dir, op+"-resp")
		vrun(args("request", append([]string{"--operation", op, "--nonce", f.Hash(op).String(), "--out", req}, extra...)...))
		vrun(args("call", "--in", req, "--in-id", artifact(req), "--transport-key", keys[46], "--peer", address, "--out", resp))
		raw, _ := os.ReadFile(req)
		r, _ := v2.DecodeRequest(raw)
		id, _ := r.ID()
		return req, resp, id.String()
	}
	req, resp, requestID := requestAndCall("prepare")
	claimCommand := filepath.Join(dir, "claim-command")
	vrun(args("extract", "--in", resp, "--in-id", artifact(resp), "--request", req, "--request-id", requestID, "--part", "claim", "--out", claimCommand))
	claim := certify(claimCommand, "claim")
	req, resp, requestID = requestAndCall("execute", "--claim", claim, "--claim-id", artifact(claim))
	resultFile, resultCommand := filepath.Join(dir, "result"), filepath.Join(dir, "result-command")
	for part, path := range map[string]string{"result": resultFile, "result-command": resultCommand} {
		vrun(args("extract", "--in", resp, "--in-id", artifact(resp), "--request", req, "--request-id", requestID, "--part", part, "--out", path))
	}
	resultQC := certify(resultCommand, "result")
	bundleFile := filepath.Join(dir, "bundle")
	vrun(args("bundle", "--in", resultFile, "--in-id", artifact(resultFile), "--claim", claim, "--claim-id", artifact(claim), "--result-certificate", resultQC, "--result-certificate-id", artifact(resultQC), "--out", bundleFile))
	ackFile := filepath.Join(dir, "accepted")
	vrun(args("accept", "--root", acceptorRoot, "--journal", x.legacy.base.config.Audit.JournalPath, "--sign-key", keys[1], "--in", bundleFile, "--in-id", artifact(bundleFile), "--out", ackFile))
	raw, e := os.ReadFile(ackFile)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := v2.DecodeReceipt(raw)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(bundleFile)
	bundle, _ := v2.DecodeBundle(raw)
	if e := ack.Verify(x.context, bundle); e != nil {
		t.Fatal(e)
	}
	closeTarget()
	for _, close := range closeWitnesses {
		close()
	}
	// Cold result recovery requires the same claim and performs no new execution.
	target, e := v2.OpenTarget(targetRoot, x.context, x.pin, x.sources, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if _, e := target.Prepare(); !errors.Is(e, v2.ErrConsumed) {
		t.Fatal("CLI effect reactivated", e)
	}
	retained, e := target.ReadResult()
	if e != nil {
		t.Fatal(e)
	}
	one, _ := retained.ID()
	two, _ := bundle.Result.ID()
	if one != two {
		t.Fatal("CLI result changed")
	}
}
func TestCustodyV2CLICompleteWitnessBoundJob(t *testing.T) {
	runV2CLICampaign(t, v2InProcess, v2InProcessStart)
}
func TestCustodyV2CLIReviewAndPreflightHaveNoEffect(t *testing.T) {
	x := newCustodyV2Fixture(t)
	dir := t.TempDir()
	raw, _ := x.context.CanonicalBytes()
	path := filepath.Join(dir, "context")
	writePruneCLIFile(t, path, raw)
	cid, _ := x.context.ID()
	base := []string{custodyV2Command, "--context", path, "--context-id", cid.String(), "--scope-id", x.pin.String()}
	key := filepath.Join(dir, "role.seed")
	writePruneCLIFile(t, key, []byte("not a seed; review must not read it"))
	outPath := filepath.Join(dir, "out")
	args := append(base, "--action", "receipt", "--root", x.acceptor, "--journal", x.legacy.base.config.Audit.JournalPath, "--sign-key", key, "--out", outPath)
	text := v2InProcess(t, args)
	if !strings.Contains(text, "keys_loaded=false owners_opened=false") {
		t.Fatal(text)
	}
	// Cross-action review IDs and writes inside an original source are refused.
	review := pruneCLIFields(strings.SplitN(text, "\n", 2)[0])
	bad := replaceRemoteCLIFlag(args, "--action", "resume")
	bad = append(bad, "--bundle-id", f.Hash("not-retained").String(), "--mode", "run", "--expected-review-id", review["review_id"])
	var output bytes.Buffer
	if e := runCustodyV2(t.Context(), bad, nil, &output); e == nil {
		t.Fatal("cross-action review")
	}
	inside := replaceRemoteCLIFlag(args, "--out", filepath.Join(x.legacy.base.config.Audit.JournalPath, "forbidden"))
	if e := runCustodyV2(t.Context(), inside, nil, &output); e == nil {
		t.Fatal("output inside source")
	}
	if _, e := os.Stat(outPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("review wrote output", e)
	}
}
