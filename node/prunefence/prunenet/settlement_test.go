package prunenet_test

import (
	"bytes"
	"reflect"
	"sync"
	"testing"
	"time"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
)

func networkSettlementProposal(t *testing.T, n *closureNetwork, effect string) prunefence.SettlementProposal {
	t.Helper()
	c := prunefence.Candidate{Policy: n.intent.Policy, Binding: prunefence.Binding{AssignmentID: n.intent.AssignmentID, RequestID: n.intent.RequestID, OperationID: f.Hash("operation"), InventoryID: f.Hash("inventory"), ExecutorBindingID: f.Hash("executor"), StoragePairID: f.Hash("storage")}, Session: f.Public(10)}
	_, draft, err := c.Draft()
	if err != nil {
		t.Fatal(err)
	}
	command, err := draft.Sign(f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	p := prunefence.SettlementProposal{Claim: prunefence.Claim{Candidate: c, Certificate: f.Certificate(command, 70, 71, 72)}, EffectID: f.Hash(effect)}
	for _, v := range []struct {
		role string
		seed byte
	}{{"owner", 1}, {"controller", 2}} {
		review, _ := p.ReviewID(v.role)
		p, err = p.Sign(v.role, review, f.Key(v.seed))
		if err != nil {
			t.Fatal(err)
		}
	}
	return p
}
func TestPruneSettlementNetworkOutageLostReplyAndRestart(t *testing.T) {
	n := newClosureNetwork(t, 0, true)
	p := networkSettlementProposal(t, n, "effect")
	collect := func(p prunefence.SettlementProposal) (prunefence.Settlement, error) {
		return prunenet.CollectSettlement(t.Context(), n.client, f.Key(2), f.Public(99), n.endpoints, time.Second, p)
	}
	half := p
	half.OwnerSignature = [64]byte{}
	if _, err := collect(half); err == nil {
		t.Fatal("unsigned proposal reached quorum")
	}
	n.services[0].Close()
	n.services[1].Close()
	minority, err := collect(p)
	if err == nil || !reflect.DeepEqual(minority, prunefence.Settlement{}) {
		t.Fatal("minority escaped", err)
	}
	_, draft, _ := p.Draft()
	command, _ := draft.Sign(f.Key(2))
	n.restart(t, 1, command)
	certificate, err := collect(p)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := certificate.CanonicalBytes()
	for i := 1; i < 4; i++ {
		n.restart(t, i, command)
	}
	retry, err := collect(p)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := retry.CanonicalBytes()
	if !bytes.Equal(before, after) {
		t.Fatal("cold retry changed votes")
	}
	if _, err := collect(networkSettlementProposal(t, n, "different effect")); err == nil {
		t.Fatal("conflicting decision after restart")
	}
	// Execution and decision endpoints are not interchangeable.
	execution := newClosureNetwork(t, 0)
	if _, err := prunenet.CollectSettlement(t.Context(), execution.client, f.Key(2), f.Public(99), execution.endpoints, time.Second, p); err == nil {
		t.Fatal("execution enrollment accepted settlement scope")
	}
}
func TestPruneSettlementNetworkConcurrentConflictingProposals(t *testing.T) {
	n := newClosureNetwork(t, 0, true)
	a := networkSettlementProposal(t, n, "a")
	b := networkSettlementProposal(t, n, "b")
	var ae, be error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, ae = prunenet.CollectSettlement(t.Context(), n.client, f.Key(2), f.Public(99), n.endpoints, time.Second, a)
	}()
	go func() {
		defer wait.Done()
		_, be = prunenet.CollectSettlement(t.Context(), n.client, f.Key(2), f.Public(99), n.endpoints, time.Second, b)
	}()
	wait.Wait()
	if ae == nil && be == nil {
		t.Fatal("conflicting quorums")
	}
}
