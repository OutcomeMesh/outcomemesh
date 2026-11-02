//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	relay "github.com/outcomemesh/outcomemesh/node/pruneservice/servicerelay"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// Network helpers use the same real owner fixture as the UID isolation campaign.
// Transport keys below are public test fixtures, never deployment credentials.
func pruneNetworkRelay(t *testing.T, ctx context.Context, public, control string, replay bool) {
	if os.Geteuid() != pruneProcessParticipantUID {
		t.Fatal("relay UID")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("relay supplementary groups", err)
	}
	m := pruneReadProcessManifest(t, public)
	d, _ := pruneDecodeProcessManifest(t, m)
	if !replay {
		for _, p := range m.PrivatePaths {
			f, e := os.Open(p)
			if e == nil {
				f.Close()
				t.Fatal("relay opened original private storage")
			}
			if !errors.Is(e, fs.ErrPermission) {
				t.Fatal("kernel did not deny relay", e)
			}
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	prefix := "live"
	if replay {
		prefix = "replay"
	}
	descriptor := filepath.Join(cwd, prefix+".descriptor")
	seed := filepath.Join(cwd, prefix+".seed")
	writePruneCLIFile(t, descriptor, m.Descriptor)
	writePruneCLIFile(t, seed, pruneCLIKey(190).Seed())
	did, _ := d.ID()
	listen := os.Getenv(pruneProcessEnv + "LISTEN")
	if listen == "" {
		listen = "/ip4/127.0.0.1/udp/0/quic-v1"
	}
	args := []string{pruneServiceCommand, "--action", "relay-serve", "--descriptor", descriptor, "--descriptor-id", did.String(), "--socket", m.Socket, "--transport-key", seed, "--transport-public-key", hex.EncodeToString(pruneCLIKey(190)[32:]), "--client-transport-keys", hex.EncodeToString(pruneCLIKey(191)[32:]), "--listen", listen, "--timeout", "15s"}
	id := pruneServiceCLIReview(t, args)
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pruneWaitMarker(run, filepath.Join(control, "stop-"+prefix+"-relay")); cancel() }()
	out := pruneEffectTestWriter(func(b []byte) (int, error) {
		var ready struct {
			Event            string
			Addresses        []string
			ExecutionGranted bool
		}
		if e := json.Unmarshal(b, &ready); e != nil || ready.Event != "prune_relay_ready" || ready.ExecutionGranted || len(ready.Addresses) == 0 {
			return 0, errors.New("invalid relay readiness")
		}
		if e := os.WriteFile(filepath.Join(cwd, prefix+".ready"), b, 0644); e != nil {
			return 0, e
		}
		return len(b), nil
	})
	if err = runPruneServiceCLIContext(run, append(args, "--mode", "run", "--expected-review-id", id), out); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func pruneNetworkClient(t *testing.T, ctx context.Context, public, mode string, replay bool) {
	if os.Geteuid() != pruneProcessParticipantUID {
		t.Fatal("network client UID")
	}
	m := pruneReadProcessManifest(t, public)
	d, q := pruneDecodeProcessManifest(t, m)
	did, _ := d.ID()
	routeRaw, err := os.ReadFile(os.Getenv(pruneProcessEnv + "ROUTE"))
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimSpace(string(routeRaw))
	if address == "" {
		t.Fatal("missing pinned route")
	}
	if m.Failure != "" && !replay {
		cfg := libp2ptransport.DefaultConfig()
		cfg.Listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1"}
		host, e := libp2ptransport.New(ctx, pruneCLIKey(191), cfg, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer host.Close()
		var local, remote [32]byte
		copy(local[:], pruneCLIKey(191)[32:])
		copy(remote[:], pruneCLIKey(190)[32:])
		calls := 0
		_, e = relay.Call(ctx, host, address, local, remote, d, q, 15*time.Second, func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
			calls++
			_, draft, err := ch.Candidate.Draft()
			if err != nil {
				return draft, err
			}
			return draft.Sign(pruneCLIKey(4))
		})
		if e == nil || calls != 1 {
			t.Fatal("fault did not hold approved remote request", e, calls)
		}
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if mode == "held" || os.Getenv(pruneProcessEnv+"DROP_RESPONSE") == "1" {
		cfg := libp2ptransport.DefaultConfig()
		cfg.Listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1"}
		host, e := libp2ptransport.New(ctx, pruneCLIKey(191), cfg, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer host.Close()
		var local, remote [32]byte
		copy(local[:], pruneCLIKey(191)[32:])
		copy(remote[:], pruneCLIKey(190)[32:])
		if mode == "held" {
			calls := 0
			_, e = relay.Call(ctx, host, address, local, remote, d, q, 10*time.Second, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
				calls++
				return custodyfence.Command{}, io.ErrClosedPipe
			})
			want := 1
			if replay {
				want = 0
			}
			if e == nil || calls != want {
				t.Fatal("held exchange", e, calls)
			}
			return
		}
		// Stop after the original owner has published a response but before the
		// client reads its payload. The next process has no result to assume.
		stream, _, e := host.OpenPruneServiceStream(ctx, address, relay.PeerID(remote))
		if e != nil {
			t.Fatal(e)
		}
		defer stream.Reset()
		if e = stream.SetDeadline(time.Now().Add(15 * time.Second)); e != nil {
			t.Fatal(e)
		}
		raw, _ := q.CanonicalBytes()
		if e = wire.WriteFrame(stream, wire.RequestFrame, raw); e != nil {
			t.Fatal(e)
		}
		raw, e = wire.ReadExpectedFrame(stream, wire.ChallengeFrame)
		if e != nil {
			t.Fatal(e)
		}
		ch, e := wire.DecodeChallenge(raw)
		if e != nil || ch.Verify(d, q) != nil {
			t.Fatal("challenge", e)
		}
		_, cmd, e := ch.Candidate.Draft()
		if e != nil {
			t.Fatal(e)
		}
		cmd, e = cmd.Sign(pruneCLIKey(4))
		if e != nil {
			t.Fatal(e)
		}
		raw, _ = cmd.CanonicalBytes()
		if e = wire.WriteFrame(stream, wire.ApprovalFrame, raw); e != nil {
			t.Fatal(e)
		}
		if e = stream.CloseWrite(); e != nil {
			t.Fatal(e)
		}
		var header [5]byte
		if _, e = io.ReadFull(stream, header[:]); e != nil || header[0] != wire.ResponseFrame {
			t.Fatal("original outcome header", e)
		}
		return
	}
	prefix := "live"
	if replay {
		prefix = "replay"
	}
	descriptor, request, seed, consumer := filepath.Join(cwd, prefix+".descriptor"), filepath.Join(cwd, prefix+".request"), filepath.Join(cwd, prefix+".transport"), filepath.Join(cwd, "consumer.seed")
	writePruneCLIFile(t, descriptor, m.Descriptor)
	writePruneCLIFile(t, request, m.Request)
	writePruneCLIFile(t, seed, pruneCLIKey(191).Seed())
	if !replay {
		writePruneCLIFile(t, consumer, pruneCLIKey(4).Seed())
	} else if _, e := os.Stat(consumer); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("cold replay must have no consumer seed", e)
	}
	output := filepath.Join(cwd, prefix+".response")
	args := []string{pruneServiceCommand, "--action", "remote-call", "--descriptor", descriptor, "--descriptor-id", did.String(), "--request", request, "--address", address, "--transport-key", seed, "--transport-public-key", hex.EncodeToString(pruneCLIKey(191)[32:]), "--relay-public-key", hex.EncodeToString(pruneCLIKey(190)[32:]), "--key", consumer, "--challenge-out", filepath.Join(cwd, prefix+".challenge"), "--approval-out", filepath.Join(cwd, prefix+".approval"), "--out", output, "--timeout", "15s"}
	pruneServiceCLIRun(t, args)
	raw := pruneServiceCLIRead(t, output)
	r, e := wire.DecodeResponse(raw)
	if e != nil || r.Verify(d, q) != nil {
		t.Fatal("network result", e)
	}
	if replay {
		if !bytes.Equal(raw, m.Response) {
			t.Fatal("cold replay changed original signed bytes")
		}
		if _, e = os.Stat(filepath.Join(cwd, prefix+".approval")); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("cold replay created approval", e)
		}
	} else {
		if e = os.Remove(consumer); e != nil {
			t.Fatal(e)
		}
	}
	// Retained output also works without a transport seed or a reachable server.
	if e = os.Remove(seed); e != nil {
		t.Fatal(e)
	}
	pruneServiceCLIRun(t, args)
}
