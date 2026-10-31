package prunenet_test

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnessnet"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type closureNetwork struct {
	client    *libp2ptransport.Host
	scope     custodyfence.Scope
	intent    prunefence.ClosureIntent
	claim     custodyfence.Command
	endpoints []prunenet.Endpoint
	services  []*witnessnet.Service
	paths     []string
}

func newClosureNetwork(t *testing.T, claims int) *closureNetwork {
	t.Helper()
	intent := prunefence.ClosureIntent{Policy: prunefence.Policy{Owner: f.Public(1), Controller: f.Public(2), Threshold: 3, Witnesses: f.Scope().Witnesses}, AssignmentID: f.Hash("closure-assignment"), RequestID: f.Hash("closure-request")}
	scope, _, err := intent.Draft()
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := scope.ID()
	client, err := libp2ptransport.New(t.Context(), f.Key(99), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	session, err := prunefence.NewSession(intent.Policy, prunefence.Binding{AssignmentID: intent.AssignmentID, RequestID: intent.RequestID, OperationID: f.Hash("operation"), InventoryID: f.Hash("inventory"), ExecutorBindingID: f.Hash("executor"), StoragePairID: f.Hash("storage")})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	candidate, _ := session.Candidate()
	_, draft, _ := candidate.Draft()
	signed, err := draft.Sign(f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	n := &closureNetwork{client: client, scope: scope, intent: intent, claim: draft}
	for i := 0; i < 4; i++ {
		path := filepath.Join(t.TempDir(), "witness")
		n.paths = append(n.paths, path)
		w, err := custodyfence.Create(path, scope, sid, f.Key(70+byte(i)))
		if err != nil {
			t.Fatal(err)
		}
		if i < claims {
			if _, err = w.Vote(signed); err != nil {
				t.Fatal(err)
			}
		}
		server := n.start(t, w, i)
		n.services = append(n.services, server)
		n.endpoints = append(n.endpoints, prunenet.Endpoint{Witness: f.Public(70 + byte(i)), Transport: f.Public(90 + byte(i)), Address: server.Addresses()[0]})
	}
	return n
}
func (n *closureNetwork) start(t *testing.T, w *custodyfence.Witness, i int) *witnessnet.Service {
	t.Helper()
	sid, _ := n.scope.ID()
	server, err := witnessnet.Start(t.Context(), w, n.scope, sid, f.Key(90+byte(i)), libp2ptransport.DefaultConfig(), []types.Hash{n.client.ID()}, time.Second)
	if err != nil {
		w.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server
}
func (n *closureNetwork) closeSlot(ctx context.Context) (prunefence.Closure, error) {
	return prunenet.CollectClosure(ctx, n.client, f.Key(2), f.Public(99), n.endpoints, time.Second, n.intent)
}
func (n *closureNetwork) restart(t *testing.T, i int, attempt custodyfence.Command) {
	t.Helper()
	n.services[i].Close()
	sid, _ := n.scope.ID()
	w, err := custodyfence.RecoverVote(n.paths[i], n.scope, sid, f.Key(70+byte(i)), custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}, attempt)
	if err != nil {
		t.Fatal(err)
	}
	server := n.start(t, w, i)
	n.services[i] = server
	n.endpoints[i].Address = server.Addresses()[0]
}
func TestPruneFenceClosureNetworkClaimIntersection(t *testing.T) {
	for claims := 0; claims <= 3; claims++ {
		t.Run(strconv.Itoa(claims), func(t *testing.T) {
			n := newClosureNetwork(t, claims)
			closed, err := n.closeSlot(t.Context())
			if (err == nil) != (claims < 2) {
				t.Fatalf("claims=%d closure error=%v", claims, err)
			}
			if err != nil && !reflect.DeepEqual(closed, prunefence.Closure{}) {
				t.Fatal("partial closure escaped")
			}
			_, claimErr := prunenet.Collect(t.Context(), n.client, f.Key(1), f.Public(99), n.endpoints, time.Second, n.scope, n.claim)
			if (claimErr == nil) != (claims >= 3) {
				t.Fatalf("conflicting claim result: %v", claimErr)
			}
		})
	}
}
func TestPruneFenceClosureNetworkLostReplyOutageAndColdRetry(t *testing.T) {
	n := newClosureNetwork(t, 0)
	n.services[0].Close()
	n.services[1].Close()
	if _, err := n.closeSlot(t.Context()); err == nil {
		t.Fatal("two votes accepted")
	}
	_, draft, _ := n.intent.Draft()
	command, err := draft.Sign(f.Key(2))
	if err != nil {
		t.Fatal(err)
	}
	n.restart(t, 1, command)
	closed, err := n.closeSlot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := closed.CanonicalBytes()
	// Lost caller output and cold services retain the same exact three-vote proof.
	for i := 1; i < 4; i++ {
		n.restart(t, i, command)
	}
	again, err := n.closeSlot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after, _ := again.CanonicalBytes()
	if !bytes.Equal(before, after) {
		t.Fatal("cold retry changed evidence")
	}
	if _, err := prunenet.CollectClosure(t.Context(), n.client, f.Key(1), f.Public(99), n.endpoints, time.Second, n.intent); err == nil {
		t.Fatal("owner closed controller slot")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := n.closeSlot(ctx); err == nil {
		t.Fatal("cancelled collection succeeded")
	}
}
func TestPruneFenceClosureNetworkConcurrentClaim(t *testing.T) {
	n := newClosureNetwork(t, 0)
	var closeErr, claimErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() { defer wait.Done(); _, closeErr = n.closeSlot(t.Context()) }()
	go func() {
		defer wait.Done()
		_, claimErr = prunenet.Collect(t.Context(), n.client, f.Key(1), f.Public(99), n.endpoints, time.Second, n.scope, n.claim)
	}()
	wait.Wait()
	if closeErr == nil && claimErr == nil {
		t.Fatal("conflicting complete quorums")
	}
	// A split vote may hold both outcomes; it must not manufacture progress.
}
