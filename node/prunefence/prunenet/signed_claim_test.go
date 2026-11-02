package prunenet_test

import (
	"bytes"
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestPruneSignedClaimPartitionAndColdRetryWithoutConsumerKey(t *testing.T) {
	n := newClosureNetwork(t, 0)
	key := f.Key(1)
	command, err := n.claim.Sign(key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	collect := func() (custodyfence.Certificate, error) {
		return prunenet.CollectSignedClaim(t.Context(), n.client, f.Public(99), n.endpoints, time.Second, n.scope, command)
	}
	n.services[0].Close()
	n.services[1].Close()
	if partial, err := collect(); err == nil || !reflect.DeepEqual(partial, custodyfence.Certificate{}) {
		t.Fatal("minority escaped as an approval", err)
	}
	n.restart(t, 1, command)
	q, err := collect()
	if err != nil || q.Command != command || q.Verify(n.scope) != nil || len(q.Votes) != 3 {
		t.Fatal("original signed command failed to obtain quorum", err)
	}
	before, _ := q.CanonicalBytes()
	for i := 1; i < 4; i++ {
		n.restart(t, i, command)
	}
	again, err := collect()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := again.CanonicalBytes()
	if !bytes.Equal(before, after) {
		t.Fatal("cold retry replaced original votes")
	}
	competing := n.claim
	competing.EvidenceID = f.Hash("another-session")
	competing, err = competing.Sign(f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	if q, err := prunenet.CollectSignedClaim(t.Context(), n.client, f.Public(99), n.endpoints, time.Second, n.scope, competing); err == nil || !reflect.DeepEqual(q, custodyfence.Certificate{}) {
		t.Fatal("competing session acquired the already claimed slot", err)
	}
}

func TestPruneSignedClaimRejectsInvalidCommandBeforeAnyDial(t *testing.T) {
	policy := prunefence.Policy{Owner: f.Public(1), Controller: f.Public(2), Threshold: 3, Witnesses: f.Scope().Witnesses}
	scope, err := policy.Scope(f.Hash("assignment"), f.Hash("request"))
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := scope.ID()
	draft := custodyfence.Command{Version: 1, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.Claim, EvidenceID: f.Hash("candidate")}
	command, err := draft.Sign(f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(t.Context(), f.Key(99), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	var calls atomic.Int32
	var endpoints []prunenet.Endpoint
	for i := byte(0); i < 4; i++ {
		server, err := libp2ptransport.New(t.Context(), f.Key(90+i), libp2ptransport.DefaultConfig(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		if err := server.SetCustodyWitnessHandler([]types.Hash{client.ID()}, func(_ context.Context, _ types.Hash, stream network.Stream) {
			calls.Add(1)
			_ = stream.Reset()
		}); err != nil {
			t.Fatal(err)
		}
		endpoints = append(endpoints, prunenet.Endpoint{Witness: f.Public(70 + i), Transport: f.Public(90 + i), Address: server.Addresses()[0]})
	}
	sign := func(c custodyfence.Command, seed byte) custodyfence.Command {
		t.Helper()
		out, err := c.Sign(f.Key(seed))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, name := range []string{"unsigned", "bad-signature", "other-signer", "wrong-scope", "wrong-kind", "wrong-sequence", "wrong-head", "legacy-version", "missing-evidence", "cancelled", "nil-context", "wrong-transport"} {
		t.Run(name, func(t *testing.T) {
			bad := command
			ctx := t.Context()
			local := f.Public(99)
			switch name {
			case "unsigned":
				bad.Signature = [64]byte{}
			case "bad-signature":
				bad.Signature[0] ^= 1
			case "other-signer":
				bad = sign(bad, 3)
			case "wrong-scope":
				bad.ScopeID = f.Hash("other-scope")
				bad = sign(bad, 1)
			case "wrong-kind":
				bad.Kind = custodyfence.CloseUnclaimed
				bad = sign(bad, 2)
			case "wrong-sequence":
				bad.ExpectedSequence = 1
				bad = sign(bad, 1)
			case "wrong-head":
				bad.ExpectedHead = f.Hash("later-head")
				bad = sign(bad, 1)
			case "legacy-version":
				bad.Version, bad.EvidenceID = 0, types.Hash{}
				bad = sign(bad, 1)
			case "missing-evidence":
				bad.EvidenceID = types.Hash{}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			case "wrong-transport":
				local = f.Public(98)
			}
			q, err := prunenet.CollectSignedClaim(ctx, client, local, endpoints, time.Second, scope, bad)
			if err == nil || !reflect.DeepEqual(q, custodyfence.Certificate{}) || calls.Load() != 0 {
				t.Fatal("invalid command reached witnesses or produced approval", err, calls.Load())
			}
		})
	}
	// The same live endpoints must actually receive a valid command. This makes
	// the zero-dial assertions above independent of connection configuration.
	q, err := prunenet.CollectSignedClaim(t.Context(), client, f.Public(99), endpoints, time.Second, scope, command)
	if err == nil || !reflect.DeepEqual(q, custodyfence.Certificate{}) || calls.Load() != 4 {
		t.Fatal("valid command did not reach all original witnesses", err, calls.Load())
	}
}
