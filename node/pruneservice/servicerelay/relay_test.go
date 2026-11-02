package servicerelay

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

//go:embed testdata/public_exchange.json
var publicFixture []byte

type fixture struct {
	d wire.Descriptor
	q wire.Request
	c wire.Challenge
	r wire.Response
}

func loadFixture(t testing.TB) fixture {
	t.Helper()
	var all [][]byte
	if err := json.Unmarshal(publicFixture, &all); err != nil {
		t.Fatal(err)
	}
	d, e := wire.DecodeDescriptor(all[0])
	if e != nil {
		t.Fatal(e)
	}
	q, e := wire.DecodeRequest(all[1])
	if e != nil {
		t.Fatal(e)
	}
	c, e := wire.DecodeChallenge(all[2])
	if e != nil {
		t.Fatal(e)
	}
	r, e := wire.DecodeResponse(all[3])
	if e != nil {
		t.Fatal(e)
	}
	return fixture{d, q, c, r}
}
func relayConfig() libp2ptransport.Config {
	c := libp2ptransport.DefaultConfig()
	c.Listen = []string{"/ip4/127.0.0.1/udp/0/quic-v1"}
	return c
}
func clientHost(t testing.TB, k byte) *libp2ptransport.Host {
	t.Helper()
	h, e := libp2ptransport.New(t.Context(), fencetest.Key(k), relayConfig(), nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestPruneServiceRelaySignedApprovalReplayAndRestart(t *testing.T) {
	f := loadFixture(t)
	host := clientHost(t, 121)
	var forwarded atomic.Int32
	startRelay := func(fresh bool) *Service {
		s, e := start(t.Context(), f.d, fencetest.Key(120), relayConfig(), [][32]byte{fencetest.Public(121)}, time.Second, func(ctx context.Context, q wire.Request, a approval) (wire.Response, error) {
			forwarded.Add(1)
			if q != f.q {
				return wire.Response{}, wire.ErrAccess
			}
			if fresh {
				cmd, e := a(ctx, f.c)
				if e != nil {
					return wire.Response{}, e
				}
				scope, draft, _ := f.c.Candidate.Draft()
				draft.Signature = cmd.Signature
				if cmd != draft || cmd.Verify(scope) != nil {
					return wire.Response{}, wire.ErrAccess
				}
			}
			return f.r, nil
		})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	s := startRelay(true)
	calls := 0
	r, err := Call(t.Context(), host, s.Addresses()[0], fencetest.Public(121), fencetest.Public(120), f.d, f.q, time.Second, func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		calls++
		if err := ch.Verify(f.d, f.q); err != nil {
			return custodyfence.Command{}, err
		}
		_, draft, _ := ch.Candidate.Draft()
		return draft.Sign(fencetest.Key(1))
	})
	if err != nil || calls != 1 {
		t.Fatal("fresh exchange", err, calls)
	}
	a, _ := r.CanonicalBytes()
	want, _ := f.r.CanonicalBytes()
	if !bytes.Equal(a, want) {
		t.Fatal("response changed")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = startRelay(false)
	r, err = Call(t.Context(), host, s.Addresses()[0], fencetest.Public(121), fencetest.Public(120), f.d, f.q, time.Second, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
		t.Error("replay requested signature")
		return custodyfence.Command{}, io.ErrClosedPipe
	})
	if err != nil {
		t.Fatal("cold relay replay", err)
	}
	a, _ = r.CanonicalBytes()
	if !bytes.Equal(a, want) || forwarded.Load() != 2 {
		t.Fatal("historical exchange changed")
	}
}

func TestPruneServiceRelayRefusesPeersRolesAndApprovalSubstitution(t *testing.T) {
	f := loadFixture(t)
	var calls atomic.Int32
	s, e := start(t.Context(), f.d, fencetest.Key(120), relayConfig(), [][32]byte{fencetest.Public(121)}, time.Second, func(ctx context.Context, q wire.Request, a approval) (wire.Response, error) {
		calls.Add(1)
		_, e := a(ctx, f.c)
		return f.r, e
	})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	h := clientHost(t, 121)
	other := clientHost(t, 122)
	for _, tc := range []struct {
		host          *libp2ptransport.Host
		local, remote [32]byte
	}{{other, fencetest.Public(122), fencetest.Public(120)}, {h, fencetest.Public(121), fencetest.Public(123)}, {h, f.d.Policy.Owner, fencetest.Public(120)}, {h, fencetest.Public(121), f.d.Transport}} {
		if _, e = Call(t.Context(), tc.host, s.Addresses()[0], tc.local, tc.remote, f.d, f.q, 200*time.Millisecond, nil); e == nil {
			t.Fatal("unauthorized transport accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected peer reached local owner")
	}
	_, e = Call(t.Context(), h, s.Addresses()[0], fencetest.Public(121), fencetest.Public(120), f.d, f.q, time.Second, func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		_, draft, _ := ch.Candidate.Draft()
		draft.EvidenceID = fencetest.Hash("foreign")
		return draft.Sign(fencetest.Key(1))
	})
	if e == nil {
		t.Fatal("substituted signed approval accepted")
	}
	for _, peers := range [][][32]byte{nil, {fencetest.Public(121), fencetest.Public(121)}, {f.d.Policy.Owner}, {f.d.Transport}, {fencetest.Public(120)}} {
		if bad, e := start(t.Context(), f.d, fencetest.Key(120), relayConfig(), peers, time.Second, func(context.Context, wire.Request, approval) (wire.Response, error) { return f.r, nil }); e == nil {
			bad.Close()
			t.Fatal("invalid allowlist accepted")
		}
	}
}

func TestPruneServiceRelayApprovalEOFAndShutdownDrain(t *testing.T) {
	f := loadFixture(t)
	var approved atomic.Int32
	started := make(chan struct{})
	s, e := start(t.Context(), f.d, fencetest.Key(120), relayConfig(), [][32]byte{fencetest.Public(121)}, time.Second, func(ctx context.Context, q wire.Request, a approval) (wire.Response, error) {
		close(started)
		_, e := a(ctx, f.c)
		if e == nil {
			approved.Add(1)
		}
		return f.r, e
	})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	h := clientHost(t, 121)
	stream, _, e := h.OpenPruneServiceStream(t.Context(), s.Addresses()[0], s.ID())
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	raw, _ := f.q.CanonicalBytes()
	if e = wire.WriteFrame(stream, wire.RequestFrame, raw); e != nil {
		t.Fatal(e)
	}
	if _, e = wire.ReadExpectedFrame(stream, wire.ChallengeFrame); e != nil {
		t.Fatal(e)
	}
	_, draft, _ := f.c.Candidate.Draft()
	cmd, _ := draft.Sign(fencetest.Key(1))
	raw, _ = cmd.CanonicalBytes()
	if e = wire.WriteFrame(stream, wire.ApprovalFrame, raw); e != nil {
		t.Fatal(e)
	}
	// Valid signature without the final EOF cannot escape to the local owner.
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("no forward")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if approved.Load() != 0 {
		t.Fatal("unclosed approval authorized owner")
	}
	if _, _, e = wire.ReadFrame(stream); e == nil {
		t.Fatal("shutdown produced success")
	}
}

func TestPruneServiceRelayRequiresExplicitRegistration(t *testing.T) {
	f := loadFixture(t)
	h := clientHost(t, 121)
	remote := clientHost(t, 120)
	_, err := Call(t.Context(), h, remote.Addresses()[0], fencetest.Public(121), fencetest.Public(120), f.d, f.q, time.Second, nil)
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("unexpected default protocol", err)
	}
}
