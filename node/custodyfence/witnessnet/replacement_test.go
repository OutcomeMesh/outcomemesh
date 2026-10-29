package witnessnet

import (
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
	store "github.com/outcomemesh/outcomemesh/node/custodyguard"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestWitnessQUICReplacementKeepsLogicalMemberAcrossLostReplyAndRestart(t *testing.T) {
	s := f.Scope()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	g, e := store.Create(filepath.Join(dir, "guard"), store.Config{Subjects: s.Witnesses, Limit: 16, Revoker: f.Public(250), Replacer: f.Public(249)})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	s.Guard = g.Identity().PublicKey
	sid, _ := s.ID()
	pin := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}
	cmd := f.Sign(s, pin.Position, custodyfence.Claim, types.Hash{}, types.Hash{})
	path := filepath.Join(dir, "original-witness")
	w, e := custodyfence.Create(path, s, sid, f.Key(70))
	if e != nil {
		t.Fatal(e)
	}
	w.SetGuard(g)
	if _, e = w.Vote(cmd); e != nil {
		t.Fatal(e)
	}
	_, pending, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	rev, e := (guard.Revocation{GuardID: g.Identity().ID(), Subject: f.Public(70), Authority: f.Public(250), ReasonID: f.Hash("incident")}).Sign(f.Key(250))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.Revoke(t.Context(), rev); e != nil {
		t.Fatal(e)
	}
	rid, _ := rev.ID()
	before, e := g.Position()
	if e != nil {
		t.Fatal(e)
	}
	q, e := (guard.Replacement{GuardID: g.Identity().ID(), Subject: f.Public(70), Successor: f.Public(232), Authority: f.Public(249), RevocationID: rid, EvidenceID: f.Hash("pending root inventory"), Before: before}).Accept(f.Key(232))
	if e != nil {
		t.Fatal(e)
	}
	q, e = q.Authorize(f.Key(249))
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := g.Replace(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	w, e = custodyfence.Open(path, s, sid, f.Key(232), pending, receipt)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { w.Close() }()
	w.SetGuard(g)
	client, e := libp2ptransport.New(t.Context(), f.Key(99), libp2ptransport.DefaultConfig(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	clients := []types.Hash{client.ID()}
	config := libp2ptransport.DefaultConfig()
	if service, e := Start(t.Context(), w, s, sid, f.Key(232), config, clients, time.Second); e == nil {
		service.Close()
		t.Fatal("successor signing key reused for transport")
	}
	service, e := Start(t.Context(), w, s, sid, f.Key(90), config, clients, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { service.Close() }()
	req := witnesswire.Request{Kind: witnesswire.Vote, ScopeID: sid, Nonce: f.Hash("replacement exchange"), Expected: pending, Command: cmd}
	call := func() (witnesswire.Response, error) {
		stream, _, e := client.OpenCustodyWitnessStream(t.Context(), service.Addresses()[0], service.ID())
		if e != nil {
			return witnesswire.Response{}, e
		}
		return witnesswire.Exchange(t.Context(), stream, s, f.Public(70), req, time.Second)
	}
	service.hook = func(string) error { return io.ErrClosedPipe }
	if _, e = call(); !errors.Is(e, witnesswire.ErrUnconfirmed) {
		t.Fatal("lost response not unknown", e)
	}
	// Close drains the stream before changing the hook or reopening the journal.
	if e = service.Close(); e != nil {
		t.Fatal(e)
	}
	w, e = custodyfence.Open(path, s, sid, f.Key(232), pending, receipt)
	if e != nil {
		t.Fatal(e)
	}
	w.SetGuard(g)
	service, e = Start(t.Context(), w, s, sid, f.Key(90), config, clients, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	response, e := call()
	if e != nil {
		t.Fatal(e)
	}
	if response.Vote.Replacement == nil || response.Observation.Replacement == nil || response.Vote.Witness != f.Public(232) {
		t.Fatal("successor proof absent")
	}
	if e = witnesswire.ValidateResponse(s, req, response, f.Public(70)); e != nil {
		t.Fatal(e)
	}
	if e = witnesswire.ValidateResponse(s, req, response, f.Public(232)); e == nil {
		t.Fatal("successor became a new member")
	}
	position, e := g.Position()
	if e != nil || position.Sequence != 3 {
		t.Fatal("restart/reset consumed another choice", e, position)
	}
}
