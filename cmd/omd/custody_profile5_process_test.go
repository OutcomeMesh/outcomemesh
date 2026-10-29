//go:build integration && (darwin || linux)

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	source "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	gw "github.com/outcomemesh/outcomemesh/node/custodygateway"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

type profile5NativeSide struct {
	fixture                 gatewayFixture
	socket, descriptor, pin string
	position                wire.Position
	process                 *execProfile5
	socketID                types.Hash
}
type execProfile5 struct {
	cancel context.CancelFunc
	wait   func(bool)
}

// The service lifetime is the enclosing two-minute campaign. Individual CLI
// children retain their existing fifteen-second deadline; no timeout is raised.
func profile5NativeStartLong(t testing.TB, s *profile5NativeSide, recovery string) {
	t.Helper()
	cutoverWrite(t, s.pin, s.position)
	args := []string{custodyGatewayCommand, "--action", "serve", "--root", s.fixture.root, "--descriptor", s.descriptor, "--descriptor-id", s.fixture.id.String(), "--socket", s.socket, "--position", s.pin}
	if recovery != "" {
		args = append(args, "--request", recovery)
	}
	args = gatewayReviewed(t, gatewayCLIInProcess, args)
	ctx, cancel := context.WithCancel(t.Context())
	child := helperCommand(ctx, args...)
	pipe, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if e = child.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	scanner := bufio.NewScanner(pipe)
	if !scanner.Scan() {
		child.Wait()
		cancel()
		t.Fatal("service readiness", stderr.String())
	}
	fields := pruneCLIFields(scanner.Text())
	s.socketID, e = witnessID("socket-id", fields["socket_id"])
	if e != nil {
		t.Fatal(e)
	}
	s.process = &execProfile5{cancel: cancel, wait: func(kill bool) {
		if kill {
			_ = child.Process.Kill()
		} else {
			_ = child.Process.Signal(syscall.SIGTERM)
		}
		e := child.Wait()
		cancel()
		if !kill && e != nil {
			t.Fatal("service stop", e, stderr.String())
		}
	}}
	t.Cleanup(func() { cancel(); _ = child.Process.Kill() })
}
func stopProfile5Native(t testing.TB, s *profile5NativeSide, kill bool) {
	t.Helper()
	s.process.wait(kill)
	args := []string{custodyGatewayCommand, "--action", "cleanup-socket", "--root", s.fixture.root, "--socket", s.socket, "--socket-id", s.socketID.String()}
	gatewayCLIInProcess(t, gatewayReviewed(t, gatewayCLIInProcess, args))
}
func TestProcessProfile5UIDExecutionLostReplyAndFullClosure(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires Linux peer credentials and a distinct unprivileged UID")
	}
	s := source.New(t)
	x := profile5Prepare(t, s.Genesis, s.Enrollment, []cut.SourceLocation{s.A, s.B}, []types.Hash{s.AP.PlacementID, s.BP.PlacementID}, s.Objects)
	ap, _ := x.oa.Position()
	bp, _ := x.ob.Position()
	x.oa.Close()
	x.ob.Close()
	public, e := os.MkdirTemp("/tmp", "omesh-profile5-public-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(public)
	if e = os.Chmod(public, 0755); e != nil {
		t.Fatal(e)
	}
	outDir := filepath.Join(public, "replies")
	if e = os.Mkdir(outDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(outDir, 65534, 65534); e != nil {
		t.Fatal(e)
	}
	side := func(name string, z gatewayFixture, p wire.Position) *profile5NativeSide {
		d := filepath.Join(public, name+".descriptor")
		b, _ := z.descriptor.CanonicalBytes()
		if e = os.WriteFile(d, b, 0644); e != nil {
			t.Fatal(e)
		}
		return &profile5NativeSide{fixture: z, socket: filepath.Join(public, name+".sock"), descriptor: d, pin: filepath.Join(z.dir, "current-position.json"), position: p}
	}
	a := side("a", x.a, ap)
	b := side("b", x.b, bp)
	profile5NativeStartLong(t, a, "")
	profile5NativeStartLong(t, b, "")
	clientKey := filepath.Join(x.a.dir, "client.seed")
	writePruneCLIFile(t, clientKey, []byte(hex.EncodeToString(f.Key(14).Seed())))
	call := func(side *profile5NativeSide, p v2.ProtectedCommand, label string, lose bool) ([]byte, string) {
		t.Helper()
		admitRaw, _ := p.Admission.CanonicalBytes()
		dto := profile5CommandInput{Kind: p.Kind, Admission: admitRaw, Data: p.Data, Now: p.Now}
		if p.Kind == v2.ProtectedServe {
			cert, parent, e := decodeNativeServe(p.Data)
			if e != nil {
				t.Fatal(e)
			}
			dto.Data = nil
			dto.Certificate, _ = cert.CanonicalBytes()
			if parent != nil {
				dto.Parent, _ = parent.CanonicalBytes()
			}
		}
		in := filepath.Join(x.a.dir, label+".command.json")
		cutoverWrite(t, in, dto)
		command := filepath.Join(x.a.dir, label+".command")
		profile5CLIAction(t, []string{custodyProfile5Command, "--action", "command", "--input", in, "--out", command})
		payload, e := os.ReadFile(command)
		if e != nil {
			t.Fatal(e)
		}
		rq := profile5RequestInput{DescriptorID: side.fixture.id, Before: side.position, Nonce: f.Hash(label), Payload: payload}
		in = filepath.Join(x.a.dir, label+".request.json")
		cutoverWrite(t, in, rq)
		request := filepath.Join(public, label+".request")
		profile5CLIAction(t, []string{custodyProfile5Command, "--action", "sign-request", "--input", in, "--key", clientKey, "--out", request})
		if e = os.Chmod(request, 0644); e != nil {
			t.Fatal(e)
		}
		response := filepath.Join(outDir, label+".response")
		args := []string{custodyGatewayCommand, "--action", "call", "--descriptor", side.descriptor, "--descriptor-id", side.fixture.id.String(), "--socket", side.socket, "--request", request, "--out", response}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		child := helperCommand(ctx, args...)
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		text, e := child.CombinedOutput()
		if e != nil {
			t.Fatal("participant review", e, string(text))
		}
		review := pruneCLIFields(strings.SplitN(string(text), "\n", 2)[0])
		child = helperCommand(ctx, append(args, "--mode", "run", "--expected-review-id", review["review_id"])...)
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		var stderr bytes.Buffer
		child.Stderr = &stderr
		if lose {
			r, w, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			r.Close()
			child.Stdout = w
			e = child.Run()
			w.Close()
			if e == nil || ctx.Err() != nil {
				t.Fatal("lost output", e, ctx.Err(), stderr.String())
			}
		} else if e = child.Run(); e != nil {
			t.Fatal("participant call", label, e, stderr.String())
		}
		packet, e := os.ReadFile(response)
		if e != nil {
			t.Fatal(e)
		}
		reply, e := wire.DecodeResponse(packet)
		if e != nil {
			t.Fatal(e)
		}
		req, e := os.ReadFile(request)
		if e != nil {
			t.Fatal(e)
		}
		q, _, e := wire.DecodeRuntimeRequest(req)
		if e != nil || reply.Verify(side.fixture.descriptor, q) != nil {
			t.Fatal(e)
		}
		side.position, _ = reply.Position()
		extracted := filepath.Join(x.a.dir, label+".data")
		profile5CLIAction(t, []string{custodyProfile5Command, "--action", "extract", "--input", response, "--descriptor", side.descriptor, "--descriptor-id", side.fixture.id.String(), "--out", extracted})
		data, e := os.ReadFile(extracted)
		if e != nil {
			t.Fatal(e)
		}
		return data, request
	}
	raw, _ := call(b, v2.ProtectedCommand{Kind: v2.ProtectedPrepare, Admission: x.admission, Now: 1}, "prepare", false)
	candidate, e := v2.DecodeCandidate(raw)
	if e != nil {
		t.Fatal(e)
	}
	scope, _ := x.context.Scope()
	witnesses := profile5OriginalWitnessGroup(t, scope)
	claim := witnesses.certify(t, candidate.Claim)
	raw, _ = claim.CanonicalBytes()
	before := b.position
	resultRaw, attempt := call(b, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.admission, Now: 1, Data: raw}, "execute", true)
	result, e := v2.DecodeResult(resultRaw)
	if e != nil || result.Verify(x.context, claim) != nil {
		t.Fatal(e)
	}
	stopProfile5Native(t, b, true)
	b.position = before
	profile5NativeStartLong(t, b, attempt)
	// Exact old request at the before-position returns the identical retained
	// response after the volatile session disappeared, without reading/signing anew.
	response := filepath.Join(outDir, "cold.response")
	args := []string{custodyGatewayCommand, "--action", "call", "--descriptor", b.descriptor, "--descriptor-id", b.fixture.id.String(), "--request", attempt, "--socket", b.socket, "--out", response}
	reviewed := gatewayReviewed(t, gatewayCLIInProcess, args)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	child := helperCommand(ctx, reviewed...)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, e := child.CombinedOutput()
	cancel()
	if e != nil {
		t.Fatal("cold retry", e, string(out))
	}
	packet, e := os.ReadFile(response)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := wire.DecodeResponse(packet)
	if e != nil || !bytes.Equal(reply.Data, resultRaw) {
		t.Fatal("cold retry changed result", e)
	}
	b.position, _ = reply.Position()
	prefix, _ := v2.EncodeProtectedPrefix([]custodyfence.Certificate{claim})
	raw, _ = call(b, v2.ProtectedCommand{Kind: v2.ProtectedResultCommand, Admission: x.admission, Now: 1, Data: prefix}, "record-command", false)
	record, e := custodyfence.DecodeCommand(raw)
	if e != nil {
		t.Fatal(e)
	}
	qc := witnesses.certify(t, record)
	bundle := v2.Bundle{Version: 2, Result: result, Chain: []custodyfence.Certificate{claim, qc}}
	raw, _ = bundle.CanonicalBytes()
	ackRaw, _ := call(a, v2.ProtectedCommand{Kind: v2.ProtectedAccept, Admission: x.admission, Now: 1, Data: raw}, "accept", false)
	ack, e := v2.DecodeReceipt(ackRaw)
	if e != nil || ack.Verify(x.context, bundle) != nil {
		t.Fatal(e)
	}
	proposal, e := v2.NewServeFulfilled(x.context, bundle, ack)
	if e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"authority", "consumer"} {
		seed := byte(101)
		if role == "consumer" {
			seed = 4
		}
		proposal, e = proposal.Sign(x.context, role, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	decision, e := proposal.Decision(x.context, f.Key(101))
	if e != nil {
		t.Fatal(e)
	}
	serveScope, _ := x.context.ServeScope()
	cert := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: profile5WitnessQuorum(t, serveScope, decision)[0]}
	data, _ := gw.EncodeExecutionServe(cert, nil)
	raw, _ = call(a, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.admission, Now: 1, Data: data}, "serve-a", false)
	ar, e := v2.DecodeServeReceipt(raw)
	if e != nil {
		t.Fatal(e)
	}
	data, _ = gw.EncodeExecutionServe(cert, &ar)
	raw, _ = call(b, v2.ProtectedCommand{Kind: v2.ProtectedServe, Admission: x.admission, Now: 1, Data: data}, "serve-b", false)
	br, e := v2.DecodeServeReceipt(raw)
	if e != nil {
		t.Fatal(e)
	}
	closure := v2.AdmissionClosure{Serve: cert, A: ar, B: br}
	if e = closure.Verify(x.context); e != nil {
		t.Fatal(e)
	}
	x.admitCertificate(t, v2.AdmissionClose, &closure)
	state := x.state.Snapshot()
	if state.SpentOperations != 2 || state.PendingOperations != 0 || state.SourceSequence != 1 {
		t.Fatal(state)
	}
	stopProfile5Native(t, a, false)
	stopProfile5Native(t, b, false)
	t.Log("Linux UID0 service / UID65534 participant: real protected proof, killed B after lost reply, identical cold retry, A acceptance, protected Serve closure and original admission accounting")
}
func decodeNativeServe(raw []byte) (v2.ServeCertificate, *v2.ServeReceipt, error) {
	d := codec.NewDecoder(raw)
	b, e := d.BytesField(v2.MaximumServeCertificateBytes)
	if e != nil {
		return v2.ServeCertificate{}, nil, e
	}
	c, e := v2.DecodeServeCertificate(b)
	if e != nil {
		return c, nil, e
	}
	b, e = d.BytesField(v2.MaximumProtectedServeReceiptBytes)
	if e != nil || d.Finish() != nil {
		return c, nil, fmt.Errorf("serve envelope")
	}
	if len(b) == 0 {
		return c, nil, nil
	}
	p, e := v2.DecodeServeReceipt(b)
	return c, &p, e
}
