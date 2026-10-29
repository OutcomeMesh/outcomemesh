package custodyfence

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard"
)

func TestIndependentGuardFencesCopiedWitnessKeysAndFreshStores(t *testing.T) {
	s := testScope()
	g, e := guard.Create(root(t), guard.Config{Subjects: s.Witnesses, Limit: 32})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	server := httptest.NewServer(guard.Handler(g))
	defer server.Close()
	client := guard.Client{URL: server.URL}
	s.Guard = g.Identity().PublicKey
	sid, _ := s.ID()
	p := Position{HeadID: sid}
	claim := signed(t, s, p, Claim, types.Hash{}, types.Hash{})
	other := signed(t, s, p, CloseUnclaimed, types.Hash{}, testHash(27))
	cert := Certificate{Command: claim}
	for seed := byte(3); seed <= 5; seed++ {
		path := root(t)
		w, e := Create(path, s, sid, testKey(seed))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Vote(claim); e == nil {
			t.Fatal("missing guard accepted")
		}
		w.SetGuard(client)
		v, e := w.Vote(claim)
		if e != nil {
			t.Fatal(e)
		}
		cert.Votes = append(cert.Votes, v)
		_, pin, e := w.Snapshot()
		if e != nil {
			t.Fatal(e)
		}
		w.Close()
		// A complete rollback/recreated root with the same key has no local lock.
		clone, e := Create(filepath.Join(filepath.Dir(root(t)), "clone"), s, sid, testKey(seed))
		if e != nil {
			t.Fatal(e)
		}
		clone.SetGuard(client)
		if _, e = clone.Vote(other); e == nil {
			t.Fatal("cloned key and reset journal equivocated")
		}
		clone.Close()
		w, e = Open(path, s, sid, testKey(seed), pin)
		if e != nil {
			t.Fatal(e)
		}
		w.SetGuard(client)
		again, e := w.Vote(claim)
		w.Close()
		if e != nil || again != v {
			t.Fatal("cold exact retry", e)
		}
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	if e = cert.Verify(s); e != nil {
		t.Fatal(e)
	}
	raw, e := cert.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeCertificate(raw)
	if e != nil || decoded.Verify(s) != nil {
		t.Fatal("guarded certificate codec", e)
	}
	bare := cert
	bare.Votes = append([]Vote(nil), cert.Votes...)
	for i := range bare.Votes {
		bare.Votes[i].GuardSeal = [64]byte{}
	}
	if bare.Verify(s) == nil {
		t.Fatal("stripping seals bypassed scope")
	}
	forged := certificate(t, other, 3, 4, 5)
	if forged.Verify(s) == nil {
		t.Fatal("raw copied quorum bypass")
	}
	for i := range forged.Votes {
		forged.Votes[i].GuardSeal = cert.Votes[i].GuardSeal
	}
	if forged.Verify(s) == nil {
		t.Fatal("rebound guard seals")
	}
	old := s
	old.Guard = [32]byte{}
	if cert.Verify(old) == nil {
		t.Fatal("scope downgrade")
	}
	sb, _ := s.CanonicalBytes()
	againScope, e := DecodeScope(sb)
	if e != nil || againScope.Guard != s.Guard {
		t.Fatal("scope codec", e)
	}
}
