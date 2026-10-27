package custodyv2

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnessnet"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func liveFixture(t testing.TB) fixture {
	t.Helper()
	c := fixtureContext(t)
	// Re-sign the public test receipt before creating any source. Golden receipt
	// times must never turn these live-clock tests into a dated fixture.
	now := uint64(time.Now().Unix())
	raw, e := c.Initial.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	binary.BigEndian.PutUint64(raw[len(raw)-112:len(raw)-104], now-10)
	binary.BigEndian.PutUint64(raw[len(raw)-104:len(raw)-96], now+10_000)
	unsigned := raw[:len(raw)-64]
	hash := types.DomainHash("OMESH/workgraph/archive/replica-receipt/signature/v0", unsigned)
	copy(raw[len(raw)-64:], ed25519.Sign(f.Key(61), hash[:]))
	c.Initial, e = workarchive.DecodeReplicaReceipt(raw)
	if e != nil {
		t.Fatal(e)
	}
	c.Previous = c.Initial
	base := c.Assignment.Base
	c.Assignment.Base, e = workarchive.CreateRemoteCustodyAuthorityAssignment(c.Manifest, c.Initial, c.CustodyPolicy, base.IncarnationID, base.AuthorityPublicKey, base.Consumers, base.MaximumOperations, base.MaximumPending, base.RemoteControlPublicKey, base.RemoteTransportPublicKey)
	if e != nil {
		t.Fatal(e)
	}
	aid, e := c.Assignment.ID()
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.AssignmentID = aid
	c.Plan.Intent.AssignmentID = aid
	c.Plan.Intent.PriorReceiptID, _ = c.Initial.ID()
	challenge, e := workarchive.CreateCustodyChallenge(c.Manifest, c.Initial, f.Key(3), now, 60, 1, c.Initial.RetainUntil+1)
	if e != nil {
		t.Fatal(e)
	}
	p := c.Plan
	p.Challenge = challenge
	p.Intent.Nonce = challenge.Nonce
	p.Intent.IssuedAt = challenge.IssuedAt
	p.Intent.ExpiresAt = challenge.ExpiresAt
	p.Intent.RenewUntil = challenge.RenewUntil
	p.Intent.RequestedSamples = challenge.RequestedSamples
	for _, role := range []string{"audit", "serve", "authority"} {
		seed := byte(4)
		if role == "authority" {
			seed = 1
		}
		p, e = p.Sign(role, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	c.Plan = p
	return fixtureWithContext(t, c)
}
func startTarget(t testing.TB, x fixture, name string) *Service {
	t.Helper()
	target := x.target(t, name)
	server, e := Start(t.Context(), target, f.Key(15), libp2ptransport.DefaultConfig(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}
func openClient(t testing.TB, seed byte) *libp2ptransport.Host {
	t.Helper()
	h, e := libp2ptransport.New(t.Context(), f.Key(seed), libp2ptransport.DefaultConfig(), nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}
func call(t testing.TB, h *libp2ptransport.Host, s *Service, c Context, r Request) (Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	stream, _, e := h.OpenCustodyV2Stream(ctx, s.Addresses()[0], s.ID())
	if e != nil {
		return Response{}, e
	}
	return Exchange(ctx, stream, c, r, time.Second)
}
func TestQUICSessionClaimQuorumResultAndOriginalSource(t *testing.T) {
	x := liveFixture(t)
	server := startTarget(t, x, "target")
	client := openClient(t, 46)
	scope, _ := x.c.Scope()
	var witnesses []*witnessnet.Service
	for i := byte(0); i < 4; i++ {
		w, e := custodyfence.Create(filepath.Join(x.root, "witness-"+string(rune('0'+i))), scope, x.pin, f.Key(70+i))
		if e != nil {
			t.Fatal(e)
		}
		s, e := witnessnet.Start(t.Context(), w, scope, x.pin, f.Key(90+i), libp2ptransport.DefaultConfig(), []types.Hash{client.ID()}, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		witnesses = append(witnesses, s)
		t.Cleanup(func() { _ = s.Close() })
	}
	certify := func(command custodyfence.Command) custodyfence.Certificate {
		t.Helper()
		var requests []witnesswire.Request
		var responses []witnesswire.Response
		for i := 0; i < 3; i++ {
			s := witnesses[i]
			r := witnesswire.Request{Version: 1, Kind: witnesswire.Vote, ScopeID: x.pin, Nonce: f.Hash("vote"), Expected: custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: command.ExpectedSequence, HeadID: command.ExpectedHead}}, Command: command}
			stream, _, e := client.OpenCustodyWitnessStream(t.Context(), s.Addresses()[0], s.ID())
			if e != nil {
				t.Fatal(e)
			}
			reply, e := witnesswire.Exchange(t.Context(), stream, scope, f.Public(byte(70+i)), r, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			requests = append(requests, r)
			responses = append(responses, reply)
		}
		q, e := witnesswire.Assemble(scope, requests, responses)
		if e != nil {
			t.Fatal(e)
		}
		cid, _ := command.ID()
		for i := 0; i < 4; i++ {
			s := witnesses[i]
			pin := custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: command.ExpectedSequence, HeadID: command.ExpectedHead}}
			if i < 3 {
				pin.PendingID = cid
			}
			r := witnesswire.Request{Version: 1, Kind: witnesswire.Commit, ScopeID: x.pin, Nonce: f.Hash("commit"), Expected: pin, Certificate: q}
			stream, _, e := client.OpenCustodyWitnessStream(t.Context(), s.Addresses()[0], s.ID())
			if e != nil {
				t.Fatal(e)
			}
			if _, e := witnesswire.Exchange(t.Context(), stream, scope, f.Public(byte(70+i)), r, time.Second); e != nil {
				t.Fatal(e)
			}
		}
		return q
	}
	prepare := Request{Version: Version2, Operation: Prepare, ScopeID: x.pin, Nonce: f.Hash("prepare")}
	candidate, e := call(t, client, server, x.c, prepare)
	if e != nil {
		t.Fatal(e)
	}
	claim := certify(candidate.Candidate.Claim)
	execute := Request{Version: Version2, Operation: Execute, ScopeID: x.pin, Nonce: f.Hash("execute"), Prefix: []custodyfence.Certificate{claim}}
	// The effect and result are durable, but the first response disappears.
	server.op.Lock()
	server.hook = func(stage string) error { return errors.New("lost completed reply") }
	server.op.Unlock()
	if _, e := call(t, client, server, x.c, execute); e == nil {
		t.Fatal("expected reply loss")
	}
	server.op.Lock()
	server.hook = nil
	server.op.Unlock()
	if _, e := call(t, client, server, x.c, execute); e == nil {
		t.Fatal("retried effect")
	}
	// A controller can mark unknown; the matching result still resolves this same slot.
	cid, _ := claim.Command.ID()
	unknown, e := (custodyfence.Command{Version: 1, ScopeID: x.pin, ExpectedSequence: 1, ExpectedHead: cid, Kind: custodyfence.MarkUnknown, ClaimID: cid, EvidenceID: f.Hash("missing-reply")}).Sign(f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	unknownQC := certify(unknown)
	recover := Request{Version: Version2, Operation: RecoverResult, ScopeID: x.pin, Nonce: f.Hash("recover"), Prefix: []custodyfence.Certificate{claim, unknownQC}}
	result, e := call(t, client, server, x.c, recover)
	if e != nil {
		t.Fatal(e)
	}
	resultQC := certify(result.Command)
	bundle := Bundle{Version: Version2, Result: result.Result, Chain: []custodyfence.Certificate{claim, unknownQC, resultQC}}
	a := x.acceptor(t)
	ack, e := a.Accept(t.Context(), bundle, uint64(time.Now().Unix()))
	if e != nil {
		t.Fatal(e)
	}
	if e := ack.Verify(x.c, bundle); e != nil {
		t.Fatal(e)
	}
	if e := server.Close(); e != nil {
		t.Fatal(e)
	}
	target := x.reopen(t, "target")
	retained, e := target.ReadResult()
	if e != nil {
		t.Fatal(e)
	}
	one, _ := retained.ID()
	two, _ := result.Result.ID()
	if one != two {
		t.Fatal("recovery refreshed effect")
	}
	for _, w := range witnesses {
		if e := w.Close(); e != nil {
			t.Fatal(e)
		}
	}
	for i := byte(0); i < 4; i++ {
		q, _ := resultQC.Command.ID()
		w, e := custodyfence.Open(filepath.Join(x.root, "witness-"+string(rune('0'+i))), scope, x.pin, f.Key(70+i), custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: 3, HeadID: q}})
		if e != nil {
			t.Fatal(e)
		}
		state, _, e := w.Snapshot()
		_ = w.Close()
		if e != nil || state.SessionID != SessionID(result.Result.SessionPublicKey) || !state.ObligationHeld {
			t.Fatal("witness lost session or cleared hold", e)
		}
	}
}
func TestQUICRejectsUnauthenticatedLegacyAndIncompleteRequests(t *testing.T) {
	x := liveFixture(t)
	server := startTarget(t, x, "target")
	bad := openClient(t, 99)
	good := openClient(t, 46)
	r := Request{Version: Version2, Operation: Prepare, ScopeID: x.pin, Nonce: f.Hash("prepare")}
	if _, e := call(t, bad, server, x.c, r); e == nil {
		t.Fatal("unauthorized peer")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if stream, _, e := good.OpenCustodyWitnessStream(ctx, server.Addresses()[0], server.ID()); e == nil {
		_ = stream.Close()
		t.Fatal("legacy witness endpoint enabled")
	}
	if stream, _, e := good.OpenArchiveCustodyStream(ctx, server.Addresses()[0], server.ID()); e == nil {
		_ = stream.Close()
		t.Fatal("legacy custody effect endpoint enabled")
	}
	if stream, _, e := good.OpenRemoteCustodyControlStream(ctx, server.Addresses()[0], server.ID()); e == nil {
		_ = stream.Close()
		t.Fatal("legacy control endpoint enabled")
	}
	// A complete frame plus trailing data must be rejected before session creation.
	stream, _, e := good.OpenCustodyV2Stream(ctx, server.Addresses()[0], server.ID())
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	if e := WriteRequest(stream, r); e != nil {
		t.Fatal(e)
	}
	_, _ = stream.Write([]byte{1})
	_ = stream.CloseWrite()
	if _, e := ReadResponse(stream); e == nil {
		t.Fatal("trailing request accepted")
	}
	server.target.r.mu.Lock()
	candidate := server.target.candidate
	server.target.r.mu.Unlock()
	if candidate != nil {
		t.Fatal("malformed request prepared session")
	}
	if _, e := os.Stat(filepath.Join(server.target.r.path, "consumed")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("malformed request consumed effect", e)
	}
}
