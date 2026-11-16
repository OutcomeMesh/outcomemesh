package servicerelay

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// Public V1 vectors for the descriptor and request in public_exchange.json.
// The issuing authority and guard approved key 94, using replacement authority 95.
//
//go:embed testdata/successor_exchange.json
var successorFixture []byte

func loadSuccessorExchange(t testing.TB) (fixture, wire.Response) {
	t.Helper()
	f := loadFixture(t)
	var records [][]byte
	if err := json.Unmarshal(successorFixture, &records); err != nil || len(records) != 3 {
		t.Fatal("invalid fixture", err)
	}
	var err error
	f.c, err = wire.DecodeChallenge(records[0])
	if err != nil || f.c.Verify(f.d, f.q) != nil {
		t.Fatal("invalid successor challenge", err)
	}
	f.r, err = wire.DecodeResponse(records[1])
	if err != nil || f.r.Verify(f.d, f.q) != nil {
		t.Fatal("invalid successor result", err)
	}
	settlement, err := wire.DecodeResponse(records[2])
	if err != nil || settlement.Verify(f.d, f.q) != nil {
		t.Fatal("invalid successor settlement", err)
	}
	return f, settlement
}

func TestSuccessorRelayApprovesAndReplaysHistoricalSettlement(t *testing.T) {
	f, settled := loadSuccessorExchange(t)
	var forwards atomic.Int32
	s, err := start(t.Context(), f.d, fencetest.Key(120), relayConfig(), [][32]byte{fencetest.Public(121)}, 5*time.Second, func(ctx context.Context, _ wire.Request, approve approval) (wire.Response, error) {
		if forwards.Add(1) == 1 {
			_, err := approve(ctx, f.c)
			return f.r, err
		}
		return settled, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	host := clientHost(t, 121)
	var approvals atomic.Int32
	for _, want := range []wire.Response{f.r, settled} {
		r, err := Call(t.Context(), host, s.Addresses()[0], fencetest.Public(121), fencetest.Public(120), f.d, f.q, 5*time.Second,
			func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
				approvals.Add(1)
				_, draft, err := ch.Candidate.Draft()
				if err != nil {
					return custodyfence.Command{}, err
				}
				return draft.Sign(fencetest.Key(1))
			})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := r.CanonicalBytes()
		expected, _ := want.CanonicalBytes()
		if !bytes.Equal(raw, expected) {
			t.Fatal("changed successor proof bytes")
		}
	}
	if approvals.Load() != 1 || forwards.Load() != 2 {
		t.Fatal("incorrect number of approvals or forwards")
	}
}

func TestSuccessorRelayChecksWholeAllowlistBeforeForwarding(t *testing.T) {
	f, settled := loadSuccessorExchange(t)
	host := clientHost(t, 121)
	for _, tc := range []struct {
		name     string
		conflict [32]byte
		reply    *wire.Response
	}{
		{"challenge/successor", f.c.Candidate.ServiceSigner(), nil},
		{"result/authority", f.c.Candidate.Succession.Replacement.Request.Authority, &f.r},
		{"settlement/session", f.c.Candidate.Session, &settled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forwards, approvals atomic.Int32
			// The authenticated client uses key 121. Only another allowed client
			// collides, so this failure must come from the receiver's check.
			s, err := start(t.Context(), f.d, fencetest.Key(120), relayConfig(), [][32]byte{fencetest.Public(121), tc.conflict}, 5*time.Second, func(ctx context.Context, _ wire.Request, approve approval) (wire.Response, error) {
				forwards.Add(1)
				if tc.reply != nil {
					return *tc.reply, nil
				}
				_, err := approve(ctx, f.c)
				return wire.Response{}, err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = Call(t.Context(), host, s.Addresses()[0], fencetest.Public(121), fencetest.Public(120), f.d, f.q, 5*time.Second,
				func(context.Context, wire.Challenge) (custodyfence.Command, error) {
					approvals.Add(1)
					return custodyfence.Command{}, wire.ErrAccess
				}); err == nil || forwards.Load() != 1 || approvals.Load() != 0 {
				t.Fatal("accepted colliding transport in receiver allowlist", err)
			}
		})
	}
}

func TestSuccessorClientChecksBothPeerKeysOnFirstFrame(t *testing.T) {
	f, settled := loadSuccessorExchange(t)
	for _, tc := range []struct {
		name          string
		local, remote byte
		kind          uint8
		encode        func() ([]byte, error)
	}{
		{"local-successor", 94, 120, wire.ChallengeFrame, f.c.CanonicalBytes},
		{"remote-successor", 121, 94, wire.ResponseFrame, f.r.CanonicalBytes},
		{"remote-authority", 121, 95, wire.ResponseFrame, settled.CanonicalBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, remote := clientHost(t, tc.local), clientHost(t, tc.remote)
			payload, err := tc.encode()
			if err != nil {
				t.Fatal(err)
			}
			var replies, approvals atomic.Int32
			// This test endpoint returns a valid pre-recorded artifact directly
			// so only the caller can reject the overlapping role.
			err = remote.SetPruneServiceHandler([]types.Hash{local.ID()}, func(_ context.Context, _ types.Hash, stream network.Stream) {
				defer stream.Close()
				if _, err := wire.ReadExpectedFrame(stream, wire.RequestFrame); err != nil {
					return
				}
				replies.Add(1)
				if wire.WriteFrame(stream, tc.kind, payload) == nil && stream.CloseWrite() == nil {
					wire.RequireEOF(stream)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = Call(t.Context(), local, remote.Addresses()[0], fencetest.Public(tc.local), fencetest.Public(tc.remote), f.d, f.q, 5*time.Second,
				func(context.Context, wire.Challenge) (custodyfence.Command, error) {
					approvals.Add(1)
					return custodyfence.Command{}, wire.ErrAccess
				})
			if !errors.Is(err, wire.ErrAccess) || replies.Load() != 1 || approvals.Load() != 0 {
				t.Fatal("client accepted colliding transport", err, replies.Load(), approvals.Load())
			}
		})
	}
}

func TestRelayRejectsOutcomeForAnotherApprovedSession(t *testing.T) {
	original := loadFixture(t)
	f, _ := loadSuccessorExchange(t)
	var approvals atomic.Int32
	s, err := start(t.Context(), f.d, fencetest.Key(120), relayConfig(), [][32]byte{fencetest.Public(121)}, 5*time.Second, func(ctx context.Context, _ wire.Request, approve approval) (wire.Response, error) {
		if _, err := approve(ctx, f.c); err != nil {
			return wire.Response{}, err
		}
		approvals.Add(1)
		return original.r, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	host := clientHost(t, 121)
	stream, _, err := host.OpenPruneServiceStream(t.Context(), s.Addresses()[0], s.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err = stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	req, _ := f.q.CanonicalBytes()
	if err = wire.WriteFrame(stream, wire.RequestFrame, req); err != nil {
		t.Fatal(err)
	}
	raw, err := wire.ReadExpectedFrame(stream, wire.ChallengeFrame)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := wire.DecodeChallenge(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, draft, err := ch.Candidate.Draft()
	if err != nil {
		t.Fatal(err)
	}
	command, err := draft.Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = command.CanonicalBytes()
	if err = wire.WriteFrame(stream, wire.ApprovalFrame, raw); err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = wire.ReadExpectedFrame(stream, wire.ResponseFrame); err == nil || approvals.Load() != 1 {
		t.Fatal("relay returned a response from a different session", err, approvals.Load())
	}
}
