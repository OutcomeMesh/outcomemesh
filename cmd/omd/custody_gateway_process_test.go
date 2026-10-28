//go:build integration && (darwin || linux)

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

// This child checks actual kernel permissions, not a simulated UID parameter.
func TestGatewayParticipantCannotReadPrivateRoots(t *testing.T) {
	if os.Getenv("OMESH_GATEWAY_PRIVATE_PROBE") != "1" {
		return
	}
	if os.Geteuid() != 65534 {
		t.Fatal("probe did not drop identity")
	}
	var paths []string
	if e := json.Unmarshal([]byte(os.Getenv("OMESH_GATEWAY_PRIVATE_PATHS")), &paths); e != nil {
		t.Fatal(e)
	}
	for _, p := range paths {
		f, e := os.Open(p)
		if e == nil {
			f.Close()
			t.Fatal("participant read private file", p)
		}
		if !errors.Is(e, os.ErrPermission) {
			t.Fatal("not a permission denial", p, e)
		}
	}
}
func TestGatewayParticipantMalformedFrames(t *testing.T) {
	if os.Getenv("OMESH_GATEWAY_FRAME_PROBE") != "1" {
		return
	}
	if os.Geteuid() != 65534 {
		t.Fatal("probe UID")
	}
	socket := os.Getenv("OMESH_GATEWAY_SOCKET")
	for _, raw := range [][]byte{{0, 0, 0, 0}, {0, 0, 1, 0}, {0, 0, 0, 5, 'x'}} {
		c, e := net.Dial("unix", socket)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e = c.Write(raw); e != nil {
			t.Fatal(e)
		}
		c.(*net.UnixConn).CloseWrite()
		var b [1]byte
		_, e = c.Read(b[:])
		c.Close()
		if e == nil || !errors.Is(e, io.EOF) && !errors.Is(e, syscall.ECONNRESET) {
			t.Fatal("malformed frame not closed", e)
		}
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], wire.MaximumRequestBytes)
	raw := append(head[:], make([]byte, wire.MaximumRequestBytes)...)
	c, e := net.Dial("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(raw)
	var b [1]byte
	if _, e = c.Read(b[:]); e == nil {
		t.Fatal("unsigned request accepted")
	}
}
func TestProcessGatewayUIDIsolationRestartAndRevocation(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires native Linux root launcher and a distinct unprivileged UID")
	}
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		return runProcessCommand(t, 15*time.Second, args...)
	}
	runSourceHandoffFixture(t, sourceHandoffCLIInProcess, func(g v2.AdmissionGenesis, b v2.EnrollmentBinding, l []cut.SourceLocation, p []types.Hash, objects string) {
		z := gatewayPrepare(t, driver, g, b, l[1], p[1], objects)
		public, e := os.MkdirTemp("/tmp", "omesh-gateway-public-")
		if e != nil {
			t.Fatal(e)
		}
		defer os.RemoveAll(public)
		if e = os.Chmod(public, 0755); e != nil {
			t.Fatal(e)
		}
		outputDir := filepath.Join(public, "replies")
		if e = os.Mkdir(outputDir, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(outputDir, 65534, 65534); e != nil {
			t.Fatal(e)
		}
		descriptor := filepath.Join(public, "descriptor")
		raw, _ := z.descriptor.CanonicalBytes()
		if e = os.WriteFile(descriptor, raw, 0644); e != nil {
			t.Fatal(e)
		}
		socket := filepath.Join(public, "gateway.sock")
		position := filepath.Join(z.dir, "position.json")
		cutoverWrite(t, position, wire.Position{})
		// Run a real independent participant process. It inherits no service key or
		// source handle and has no root/service UID privileges.
		probe := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestGatewayParticipantCannotReadPrivateRoots$", "-test.timeout=15s")
		paths, _ := json.Marshal([]string{filepath.Join(z.root, "key"), filepath.Join(z.root, "config"), filepath.Join(l[1].Journal, "source-handoff.omcsh"), filepath.Join(z.config.Objects, "chunk-"+g.Manifest.Chunks[0].ID.String()+".omwc")})
		probe.Env = append(os.Environ(), "OMESH_GATEWAY_PRIVATE_PROBE=1", "OMESH_GATEWAY_PRIVATE_PATHS="+string(paths))
		probe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		probeOut, e := probe.CombinedOutput()
		if e != nil {
			t.Fatal("private-key/source isolation", e, string(probeOut))
		}
		base := []string{custodyGatewayCommand, "--action", "serve", "--root", z.root, "--descriptor", descriptor, "--descriptor-id", z.id.String(), "--position", position, "--socket", socket}
		start := func(args []string) (*exec.Cmd, context.CancelFunc, types.Hash) {
			t.Helper()
			reviewed := gatewayReviewed(t, driver, args)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			child := helperCommand(ctx, reviewed...)
			pipe, e := child.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			var errout bytes.Buffer
			child.Stderr = &errout
			if e = child.Start(); e != nil {
				cancel()
				t.Fatal(e)
			}
			t.Cleanup(func() { cancel(); _ = child.Process.Kill() })
			scanner := bufio.NewScanner(pipe)
			if !scanner.Scan() {
				child.Wait()
				cancel()
				t.Fatal("missing service readiness", errout.String())
			}
			fields := pruneCLIFields(scanner.Text())
			if fields["execution_granted"] != "false" {
				t.Fatal(fields)
			}
			id, e := witnessID("socket-id", fields["socket_id"])
			if e != nil {
				t.Fatal(e)
			}
			return child, cancel, id
		}
		stop := func(child *exec.Cmd, cancel context.CancelFunc, kill bool) {
			t.Helper()
			if kill {
				_ = child.Process.Kill()
			} else {
				_ = child.Process.Signal(syscall.SIGTERM)
			}
			e := child.Wait()
			cancel()
			if !kill && e != nil {
				t.Fatal("service stop", e)
			}
		}
		child, cancel, socketID := start(base)
		malformed := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestGatewayParticipantMalformedFrames$", "-test.timeout=15s")
		malformed.Env = append(os.Environ(), "OMESH_GATEWAY_FRAME_PROBE=1", "OMESH_GATEWAY_SOCKET="+socket)
		malformed.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if raw, e := malformed.CombinedOutput(); e != nil {
			t.Fatal("malformed-frame isolation", e, string(raw))
		}
		liveCleanup := []string{custodyGatewayCommand, "--action", "cleanup-socket", "--root", z.root, "--socket", socket, "--socket-id", socketID.String()}
		reviewed := gatewayReviewed(t, driver, liveCleanup)
		if e = runCustodyGateway(t.Context(), reviewed, &bytes.Buffer{}); e == nil {
			t.Fatal("removed active socket")
		}
		call := func(q wire.Request, label string, lose bool) (wire.Response, error) {
			t.Helper()
			request := filepath.Join(public, label+".request")
			raw, _ := q.CanonicalBytes()
			if e = os.WriteFile(request, raw, 0644); e != nil {
				t.Fatal(e)
			}
			response := filepath.Join(outputDir, label+".response")
			args := []string{custodyGatewayCommand, "--action", "call", "--descriptor", descriptor, "--descriptor-id", z.id.String(), "--request", request, "--socket", socket, "--out", response}
			ctx, done := context.WithTimeout(t.Context(), 15*time.Second)
			defer done()
			review := helperCommand(ctx, args...)
			review.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
			text, e := review.CombinedOutput()
			if e != nil {
				return wire.Response{}, fmt.Errorf("participant review: %w: %s", e, text)
			}
			fields := pruneCLIFields(strings.SplitN(string(text), "\n", 2)[0])
			args = append(args, "--mode", "run", "--expected-review-id", fields["review_id"])
			command := helperCommand(ctx, args...)
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
			var errout bytes.Buffer
			command.Stderr = &errout
			if lose {
				r, w, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				r.Close()
				command.Stdout = w
				e = command.Run()
				w.Close()
				if e == nil || ctx.Err() != nil {
					t.Fatal("lost public output", e, ctx.Err())
				}
			} else {
				e = command.Run()
				if e != nil {
					return wire.Response{}, fmt.Errorf("participant call: %w: %s", e, errout.String())
				}
			}
			raw, e = os.ReadFile(response)
			if e != nil {
				return wire.Response{}, e
			}
			r, e := wire.DecodeResponse(raw)
			if e == nil {
				e = r.Verify(z.descriptor, q)
			}
			return r, e
		}
		q := gatewayRequest(t, z.descriptor, wire.Position{}, wire.ReadChunk, g.Manifest.Chunks[0].ID, "native-read", 14)
		r, e := call(q, "first", true)
		if e != nil {
			t.Fatal(e)
		}
		pin, _ := r.Position()
		if len(r.Data) == 0 {
			t.Fatal("empty chunk")
		}
		if _, e = call(gatewayRequest(t, z.descriptor, pin, wire.Inspect, types.Hash{}, "unlisted", 101), "unlisted", false); e == nil {
			t.Fatal("unlisted key accepted")
		}
		if _, e = call(gatewayRequest(t, z.descriptor, wire.Position{}, wire.Inspect, types.Hash{}, "stale-slot", 14), "stale-slot", false); e == nil {
			t.Fatal("stale slot accepted")
		}
		// The service owner UID cannot use the participant socket, even with a valid
		// old participant signature. Kernel peer credentials must agree too.
		req := filepath.Join(public, "first.request")
		args := []string{custodyGatewayCommand, "--action", "call", "--descriptor", descriptor, "--descriptor-id", z.id.String(), "--request", req, "--socket", socket, "--out", filepath.Join(z.dir, "wrong-uid")}
		if e = runCustodyGateway(t.Context(), gatewayReviewed(t, gatewayCLIInProcess, args), &bytes.Buffer{}); e == nil {
			t.Fatal("owner UID bypassed client identity")
		}
		stop(child, cancel, true)
		// Stale sockets remain evidence and cannot be silently unlinked by restart.
		args = gatewayReviewed(t, gatewayCLIInProcess, base)
		if e = runCustodyGateway(t.Context(), args, &bytes.Buffer{}); e == nil {
			t.Fatal("restart adopted unreviewed live position")
		}
		driver(t, gatewayReviewed(t, driver, liveCleanup))
		requestPath := filepath.Join(public, "first.request")
		recoverArgs := append(append([]string{}, base...), "--request", requestPath)
		child, cancel, socketID = start(recoverArgs)
		rr, e := call(q, "retry", false)
		if e != nil {
			t.Fatal(e)
		}
		before, _ := r.CanonicalBytes()
		after, _ := rr.CanonicalBytes()
		if !bytes.Equal(before, after) {
			t.Fatal("retry changed original response")
		}
		revoke := gatewayRequest(t, z.descriptor, pin, wire.Revoke, types.Hash{}, "native-revoke", 110)
		rr, e = call(revoke, "revoke", false)
		if e != nil {
			t.Fatal(e)
		}
		end, _ := rr.Position()
		if _, e = call(q, "old-after-revoke", false); e == nil {
			t.Fatal("old participant still reads")
		}
		stop(child, cancel, false)
		cleanup := replaceRemoteCLIFlag(liveCleanup, "--socket-id", socketID.String())
		cutoverWrite(t, position, end)
		if e = runCustodyGateway(t.Context(), gatewayReviewed(t, gatewayCLIInProcess, base), &bytes.Buffer{}); e == nil {
			t.Fatal("silently removed stale socket")
		}
		driver(t, gatewayReviewed(t, driver, cleanup))
		cutoverWrite(t, position, end)
		child, cancel, socketID = start(base)
		if _, e = call(gatewayRequest(t, z.descriptor, end, wire.Inspect, types.Hash{}, "after restart revoke", 14), "denied", false); e == nil {
			t.Fatal("restart restored access")
		}
		stop(child, cancel, false)
		cleanup = replaceRemoteCLIFlag(cleanup, "--socket-id", socketID.String())
		driver(t, gatewayReviewed(t, driver, cleanup))
		t.Log("native gateway: service UID=0 participant UID=65534; private files denied; original chunk read; wrong UID denied; lost reply exact retry; kill/restart; permanent revocation")
	})
}
