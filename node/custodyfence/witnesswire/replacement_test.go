package witnesswire

import (
	"bytes"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	guardstore "github.com/outcomemesh/outcomemesh/node/custodyguard"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func replacementFixture(t testing.TB) (custodyfence.Scope, Request, Response, Response, Response) {
	t.Helper()
	s := f.Scope()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	g, e := guardstore.Create(filepath.Join(root, "guard"), guardstore.Config{Subjects: s.Witnesses, Limit: 16, Revoker: f.Public(90), Replacer: f.Public(91)})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	s.Guard = g.Identity().PublicKey
	sid, _ := s.ID()
	pin := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}
	cmd := f.Sign(s, pin.Position, custodyfence.Claim, types.Hash{}, types.Hash{})
	req := Request{Kind: Vote, ScopeID: sid, Nonce: f.Hash("replacement-request"), Expected: pin, Command: cmd}
	rid, _ := req.ID()
	path := filepath.Join(root, "original-witness")
	w, e := custodyfence.Create(path, s, sid, f.Key(70))
	if e != nil {
		t.Fatal(e)
	}
	w.SetGuard(g)
	old, e := w.Vote(cmd)
	if e != nil {
		t.Fatal(e)
	}
	obs, e := w.Observe(rid)
	if e != nil {
		t.Fatal(e)
	}
	oldResponse := Response{Observation: obs, Vote: old}
	_, pending, e := w.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	revoke, e := (guard.Revocation{GuardID: g.Identity().ID(), Subject: f.Public(70), Authority: f.Public(90), ReasonID: f.Hash("incident")}).Sign(f.Key(90))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.Revoke(t.Context(), revoke); e != nil {
		t.Fatal(e)
	}
	before, e := g.Position()
	if e != nil {
		t.Fatal(e)
	}
	revID, _ := revoke.ID()
	r, e := (guard.Replacement{GuardID: g.Identity().ID(), Subject: f.Public(70), Successor: f.Public(92), Authority: f.Public(91), RevocationID: revID, EvidenceID: f.Hash("pending inventory"), Before: before}).Accept(f.Key(92))
	if e != nil {
		t.Fatal(e)
	}
	r, e = r.Authorize(f.Key(91))
	if e != nil {
		t.Fatal(e)
	}
	proof, e := g.Replace(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	if stale, e := custodyfence.Open(path, s, sid, f.Key(92), pin, proof); e == nil {
		stale.Close()
		t.Fatal("pending obligation disappeared")
	}
	w, e = custodyfence.Open(path, s, sid, f.Key(92), pending, proof)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.SetGuard(g)
	conflict := f.Sign(s, pin.Position, custodyfence.CloseUnclaimed, types.Hash{}, f.Hash("conflicting close"))
	if _, e = w.Vote(conflict); e == nil {
		t.Fatal("replacement unlocked pending vote")
	}
	vote, e := w.Vote(cmd)
	if e != nil {
		t.Fatal(e)
	}
	obs, e = w.Observe(rid)
	if e != nil {
		t.Fatal(e)
	}
	response := Response{Observation: obs, Vote: vote}
	if e = ValidateResponse(s, req, response, f.Public(70)); e != nil {
		t.Fatal(e)
	}
	other, e := custodyfence.Create(filepath.Join(root, "other-witness"), s, sid, f.Key(71))
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	other.SetGuard(g)
	otherVote, e := other.Vote(cmd)
	if e != nil {
		t.Fatal(e)
	}
	otherObs, e := other.Observe(rid)
	if e != nil {
		t.Fatal(e)
	}
	return s, req, oldResponse, response, Response{Observation: otherObs, Vote: otherVote}
}
func TestReplacementWitnessPendingNetworkProofAndLogicalQuorum(t *testing.T) {
	s, req, old, response, other := replacementFixture(t)
	raw, e := response.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeResponse(raw)
	if e != nil || ValidateResponse(s, req, got, f.Public(70)) != nil {
		t.Fatal("replacement response codec", e)
	}
	if ValidateResponse(s, req, got, f.Public(92)) == nil {
		t.Fatal("successor counted as new member")
	}
	if _, e = Assemble(s, []Request{req, req}, []Response{old, response}); e == nil {
		t.Fatal("old plus new counted twice")
	}
	q := custodyfence.Certificate{Command: req.Command, Votes: []custodyfence.Vote{old.Vote, response.Vote}}
	q.Votes = append(q.Votes, other.Vote)
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if q.Verify(s) == nil {
		t.Fatal("duplicate witness quorum")
	}
	for _, b := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
		if _, e = DecodeResponse(b); e == nil {
			t.Fatal("noncanonical replacement reply")
		}
	}
	bad := response
	bad.Vote.Replacement = nil
	if ValidateResponse(s, req, bad, f.Public(70)) == nil {
		t.Fatal("vote proof stripped")
	}
	bad = response
	bad.Observation.Replacement = nil
	if ValidateResponse(s, req, bad, f.Public(70)) == nil {
		t.Fatal("observation proof stripped")
	}
	wrong := s
	wrong.Guard = f.Public(93)
	if ValidateResponse(wrong, req, response, f.Public(70)) == nil {
		t.Fatal("foreign guard")
	}
}
func FuzzReplacementWitnessCodecs(fz *testing.F) {
	_, q, _, r, _ := replacementFixture(fz)
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{q, r, r.Vote, r.Observation} {
		b, e := v.CanonicalBytes()
		if e != nil {
			fz.Fatal(e)
		}
		fz.Add(b)
	}
	cert := custodyfence.Certificate{Command: q.Command, Votes: []custodyfence.Vote{r.Vote}}
	b, e := cert.CanonicalBytes()
	if e != nil {
		fz.Fatal(e)
	}
	fz.Add(b)
	fz.Fuzz(func(t *testing.T, raw []byte) {
		check := func(v interface{ CanonicalBytes() ([]byte, error) }, e error) {
			if e == nil {
				b, e := v.CanonicalBytes()
				if e != nil || !bytes.Equal(raw, b) {
					t.Fatal("noncanonical replacement wire")
				}
			}
		}
		a, e := DecodeResponse(raw)
		check(a, e)
		v, e := custodyfence.DecodeVote(raw)
		check(v, e)
		o, e := custodyfence.DecodeObservation(raw)
		check(o, e)
		c, e := custodyfence.DecodeCertificate(raw)
		check(c, e)
	})
}
