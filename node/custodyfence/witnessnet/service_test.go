package witnessnet

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type cluster struct {
	scope   custodyfence.Scope
	id      types.Hash
	servers []*Service
	client  *libp2ptransport.Host
	roots   []string
}

func newCluster(t testing.TB) *cluster {
	t.Helper()
	s := f.Scope()
	id, _ := s.ID()
	client, err := libp2ptransport.New(t.Context(), f.Key(99), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	c := &cluster{scope: s, id: id, client: client}
	for i := 0; i < 4; i++ {
		root := filepath.Join(t.TempDir(), "witness")
		w, err := custodyfence.Create(root, s, id, f.Key(byte(70+i)))
		if err != nil {
			t.Fatal(err)
		}
		service, err := Start(t.Context(), w, s, id, f.Key(byte(90+i)), libp2ptransport.DefaultConfig(), []types.Hash{client.ID()}, time.Second)
		if err != nil {
			_ = w.Close()
			t.Fatal(err)
		}
		c.servers = append(c.servers, service)
		c.roots = append(c.roots, root)
		t.Cleanup(func() { _ = service.Close() })
	}
	return c
}
func (c *cluster) call(t testing.TB, i int, r witnesswire.Request) (witnesswire.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	s := c.servers[i]
	stream, _, err := c.client.OpenCustodyWitnessStream(ctx, s.Addresses()[0], s.ID())
	if err != nil {
		return witnesswire.Response{}, err
	}
	return witnesswire.Exchange(ctx, stream, c.scope, s.public, r, time.Second)
}
func (c *cluster) request(kind witnesswire.Kind, p custodyfence.WitnessPin, command custodyfence.Command, cert custodyfence.Certificate, label string) witnesswire.Request {
	return witnesswire.Request{Kind: kind, ScopeID: c.id, Nonce: f.Hash(label), Expected: p, Command: command, Certificate: cert}
}
func (c *cluster) quorum(t testing.TB, command custodyfence.Command, label string) (custodyfence.Certificate, []witnesswire.Response) {
	t.Helper()
	var reqs []witnesswire.Request
	var replies []witnesswire.Response
	for i := 0; i < 3; i++ {
		p := custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: command.ExpectedSequence, HeadID: command.ExpectedHead}}
		r := c.request(witnesswire.Vote, p, command, custodyfence.Certificate{}, label+string(rune('0'+i)))
		reply, err := c.call(t, i, r)
		if err != nil {
			t.Fatal(err)
		}
		reqs = append(reqs, r)
		replies = append(replies, reply)
	}
	cert, err := witnesswire.Assemble(c.scope, reqs, replies)
	if err != nil {
		t.Fatal(err)
	}
	return cert, replies
}
func (c *cluster) commit(t testing.TB, cert custodyfence.Certificate, label string) {
	t.Helper()
	id, _ := cert.Command.ID()
	for i := 0; i < 3; i++ {
		p := custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: cert.Command.ExpectedSequence, HeadID: cert.Command.ExpectedHead}, PendingID: id}
		r := c.request(witnesswire.Commit, p, custodyfence.Command{}, cert, label+string(rune('0'+i)))
		if _, err := c.call(t, i, r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWitnessQUICQuorumUnknownResultAndCopiedOwner(t *testing.T) {
	c := newCluster(t)
	initial := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: c.id}}
	claim := f.Sign(c.scope, initial.Position, custodyfence.Claim, types.Hash{}, types.Hash{})
	claimID, _ := claim.ID()
	cert, _ := c.quorum(t, claim, "claim")
	if err := c.servers[3].Close(); err != nil {
		t.Fatal(err)
	} // three independent members suffice
	// Lose one committed reply. The caller receives uncertainty, but exact retry
	// recovers only that transition and never creates another position.
	s := c.servers[0]
	s.op.Lock()
	s.hook = func(string) error { return errors.New("lost committed response") }
	s.op.Unlock()
	r := c.request(witnesswire.Commit, initial, custodyfence.Command{}, cert, "lost-commit")
	if _, err := c.call(t, 0, r); !errors.Is(err, witnesswire.ErrUnconfirmed) {
		t.Fatal("lost output was confirmed", err)
	}
	s.op.Lock()
	s.hook = nil
	s.op.Unlock()
	if _, err := c.call(t, 0, r); err != nil {
		t.Fatal("exact commit recovery", err)
	}
	c.commit(t, cert, "commit-claim")
	unknown := f.Sign(c.scope, custodyfence.Position{Sequence: 1, HeadID: claimID}, custodyfence.MarkUnknown, claimID, f.Hash("unknown-observation"))
	unknownCert, _ := c.quorum(t, unknown, "unknown")
	c.commit(t, unknownCert, "commit-unknown")
	uid, _ := unknown.ID()
	reissue := f.Sign(c.scope, custodyfence.Position{Sequence: 2, HeadID: uid}, custodyfence.Claim, types.Hash{}, types.Hash{})
	for i := 0; i < 3; i++ {
		r := c.request(witnesswire.Vote, custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: 2, HeadID: uid}}, reissue, custodyfence.Certificate{}, "forbidden-reissue")
		if _, err := c.call(t, i, r); err == nil {
			t.Fatal("unknown outcome acquired another claim")
		}
	}
	result := f.Sign(c.scope, custodyfence.Position{Sequence: 2, HeadID: uid}, custodyfence.RecordResult, claimID, f.Hash("exact-original-result"))
	qc, _ := c.quorum(t, result, "result")
	c.commit(t, qc, "commit-result")
	copied := f.Sign(c.scope, custodyfence.Position{Sequence: 2, HeadID: uid}, custodyfence.RecordResult, claimID, f.Hash("copied-owner-conflict"))
	for i := 0; i < 3; i++ {
		r := c.request(witnesswire.Vote, custodyfence.WitnessPin{Position: copiedPosition(copied)}, copied, custodyfence.Certificate{}, "copied-journal")
		if _, err := c.call(t, i, r); err == nil {
			t.Fatal("old participant journal/key bypassed independent witness")
		}
		x, _, err := c.servers[i].witness.Snapshot()
		if err != nil || x.Position.Sequence != 3 || x.Phase != custodyfence.ResultRecorded || !x.ObligationHeld {
			t.Fatal(x, err)
		}
	}
}
func copiedPosition(c custodyfence.Command) custodyfence.Position {
	return custodyfence.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead}
}

func TestWitnessQUICRejectsRoguePeerTrailingInputAndWrongPins(t *testing.T) {
	c := newCluster(t)
	p := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: c.id}}
	claim := f.Sign(c.scope, p.Position, custodyfence.Claim, types.Hash{}, types.Hash{})
	r := c.request(witnesswire.Vote, p, claim, custodyfence.Certificate{}, "before-mutation")
	s := c.servers[0]
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	stream, _, err := c.client.OpenCustodyWitnessStream(ctx, s.Addresses()[0], s.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := witnesswire.WriteRequest(stream, r); err != nil {
		t.Fatal(err)
	}
	_, _ = stream.Write([]byte{1})
	_ = stream.CloseWrite()
	if _, err := io.ReadAll(stream); err == nil {
		t.Fatal("trailing request got clean successful EOF")
	}
	_ = stream.Close()
	rogue, err := libp2ptransport.New(t.Context(), f.Key(100), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rogue.Close()
	stream, _, err = rogue.OpenCustodyWitnessStream(ctx, s.Addresses()[0], s.ID())
	if err == nil {
		_, err = witnesswire.Exchange(ctx, stream, c.scope, s.public, r, time.Second)
	}
	if err == nil {
		t.Fatal("unlisted authenticated peer reached witness")
	}
	wrongPublic := f.Public(101)
	wrong, _ := transport.PeerIDFromPublicKey(wrongPublic[:])
	if stream, _, err := c.client.OpenCustodyWitnessStream(ctx, s.Addresses()[0], wrong); err == nil {
		_ = stream.Close()
		t.Fatal("wrong transport pin accepted")
	}
	r.Expected.PendingID = f.Hash("unretained-vote")
	if _, err := c.call(t, 0, r); err == nil {
		t.Fatal("wrong pending pin accepted")
	}
	x, pin, err := s.witness.Snapshot()
	if err != nil || x.Phase != custodyfence.Unused || pin != p {
		t.Fatal("refusals changed original state", x, pin, err)
	}
}

func TestWitnessQUICCopiedMemberCountsOnceAndCannotFormConflictingQuorum(t *testing.T) {
	c := newCluster(t)
	cloneRoot := filepath.Join(t.TempDir(), "copy")
	if err := os.Mkdir(cloneRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(c.roots[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(c.roots[0], e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cloneRoot, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w, err := custodyfence.Open(cloneRoot, c.scope, c.id, f.Key(70), custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: c.id}})
	if err != nil {
		t.Fatal(err)
	}
	clone, err := Start(t.Context(), w, c.scope, c.id, f.Key(94), libp2ptransport.DefaultConfig(), []types.Hash{c.client.ID()}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Close()
	claim := f.Sign(c.scope, custodyfence.Position{HeadID: c.id}, custodyfence.Claim, types.Hash{}, types.Hash{})
	qc, _ := c.quorum(t, claim, "original-claim")
	c.commit(t, qc, "original-commit")
	r := c.request(witnesswire.Commit, custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: c.id}}, custodyfence.Command{}, qc, "copy-follows-certified-prefix")
	callClone := func(r witnesswire.Request) (witnesswire.Response, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		stream, _, err := c.client.OpenCustodyWitnessStream(ctx, clone.Addresses()[0], clone.ID())
		if err != nil {
			return witnesswire.Response{}, err
		}
		return witnesswire.Exchange(ctx, stream, c.scope, f.Public(70), r, time.Second)
	}
	if _, err := callClone(r); err != nil {
		t.Fatal(err)
	}
	if _, err := c.call(t, 3, r); err != nil {
		t.Fatal("fourth member follows the certified prefix", err)
	}
	cid, _ := claim.ID()
	p := custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: 1, HeadID: cid}}
	original := f.Sign(c.scope, p.Position, custodyfence.RecordResult, cid, f.Hash("original"))
	_, _ = c.quorum(t, original, "original-result")
	conflict := f.Sign(c.scope, p.Position, custodyfence.RecordResult, cid, f.Hash("conflict"))
	r = c.request(witnesswire.Vote, p, conflict, custodyfence.Certificate{}, "copied-witness-result")
	copied, err := callClone(r)
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := c.call(t, 3, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witnesswire.Assemble(c.scope, []witnesswire.Request{r, r}, []witnesswire.Response{copied, fourth}); err == nil {
		t.Fatal("one cloned witness plus minority formed quorum")
	}
	if _, err := witnesswire.Assemble(c.scope, []witnesswire.Request{r, r, r}, []witnesswire.Response{copied, copied, fourth}); err == nil {
		t.Fatal("duplicate member counted twice")
	}
}
