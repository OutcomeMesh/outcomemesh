package prunefence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	p "github.com/outcomemesh/outcomemesh/node/prunefence"
)

func policy() p.Policy {
	return p.Policy{Owner: f.Public(1), Controller: f.Public(2), Threshold: 3, Witnesses: f.Scope().Witnesses}
}
func binding() p.Binding {
	return p.Binding{RequestID: f.Hash("request"), AssignmentID: f.Hash("assignment"), OperationID: f.Hash("operation"), InventoryID: f.Hash("inventory"), ExecutorBindingID: f.Hash("executor"), StoragePairID: f.Hash("storage")}
}
func claim(t testing.TB, c p.Candidate) custodyfence.Certificate {
	t.Helper()
	_, d, e := c.Draft()
	if e != nil {
		t.Fatal(e)
	}
	d, e = d.Sign(f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	return f.Certificate(d, 70, 71, 72)
}

func TestPruneFenceLiveSessionAndExactResult(t *testing.T) {
	s, e := p.NewSession(policy(), binding())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, _ := s.Candidate()
	q := claim(t, c)
	permit, proof, e := s.Authorize(q)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.Authorize(q); e == nil {
		t.Fatal("second authorization")
	}
	if _, e := permit.Seal(f.Hash("effect")); e == nil {
		t.Fatal("sealed before target consumption")
	}
	if e := permit.Consume(f.Hash("wrong operation"), binding().StoragePairID); e == nil {
		t.Fatal("wrong operation consumed")
	}
	if e := permit.Consume(binding().OperationID, f.Hash("wrong storage pair")); e == nil {
		t.Fatal("wrong storage pair consumed")
	}
	if e := permit.Consume(binding().OperationID, binding().StoragePairID); e != nil {
		t.Fatal(e)
	}
	if e := permit.Consume(binding().OperationID, binding().StoragePairID); e == nil {
		t.Fatal("permit replay")
	}
	r, e := permit.Seal(f.Hash("effect"))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := r.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := p.DecodeResult(raw)
	if e != nil {
		t.Fatal(e)
	}
	again, _ := decoded.CanonicalBytes()
	if !bytes.Equal(raw, again) {
		t.Fatal("changed result")
	}
	if _, e := permit.Seal(f.Hash("other effect")); e == nil {
		t.Fatal("second effect")
	}
	clone, e := p.NewSession(policy(), binding())
	if e != nil {
		t.Fatal(e)
	}
	defer clone.Close()
	if _, _, e := clone.Authorize(proof.Certificate); e == nil {
		t.Fatal("disk/public claim recreated private session")
	}
	decoded.EffectID = f.Hash("other effect")
	if _, e := decoded.CanonicalBytes(); e == nil {
		t.Fatal("substituted effect")
	}
}

func TestPruneFenceConcurrentConsumptionAndDetachedClaim(t *testing.T) {
	s, err := p.NewSession(policy(), binding())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, _ := s.Candidate()
	permit, returned, err := s.Authorize(claim(t, c))
	if err != nil {
		t.Fatal(err)
	}
	returned.Candidate.Policy.Witnesses[0] = f.Public(250)
	returned.Certificate.Votes[0].Signature[0] ^= 1
	var accepted atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if permit.Consume(binding().OperationID, binding().StoragePairID) == nil {
				accepted.Add(1)
			}
		}()
	}
	group.Wait()
	if accepted.Load() != 1 {
		t.Fatal("capability consumed more than once", accepted.Load())
	}
	r, err := permit.Seal(f.Hash("effect"))
	if err != nil {
		t.Fatal("caller changed internal claim", err)
	}
	if _, err := r.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
}

func TestPruneFenceCanonicalVectors(t *testing.T) {
	c := p.Candidate{Policy: policy(), Binding: binding(), Session: f.Public(250)}
	q := p.Claim{Candidate: c, Certificate: claim(t, c)}
	craw, _ := c.CanonicalBytes()
	cid, _ := q.Certificate.Command.ID()
	effect := f.Hash("effect")
	message := types.DomainHash("OMESH/prune-fence/result/sign/v0", craw, cid[:], effect[:])
	r := p.Result{Claim: q, EffectID: effect}
	copy(r.Signature[:], ed25519.Sign(f.Key(250), message[:]))
	praw, _ := c.Policy.CanonicalBytes()
	qraw, _ := q.CanonicalBytes()
	rraw, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	vectors := []struct {
		name string
		raw  []byte
		size int
		sha  string
	}{
		{"policy", praw, 236, "6efb23c3f67cd66fe45468f44e194aa80fa897fadf9575a8fcb4aa53cd91431d"},
		{"candidate", craw, 472, "1b8e1135192b67b6c34b9b4a73ee6a63a3b88aeb64d7b092aee94e30e19213f6"},
		{"claim", qraw, 1122, "83a63e2c685834f6b8b441e3062e0928b864f3a79ee94094b4af67dac5adb424"},
		{"result", rraw, 1230, "1964e0025b96abc4690f622bac05c43623100754c30a928db840204c9357a505"},
	}
	for _, v := range vectors {
		if len(v.raw) != v.size || fmt.Sprintf("%x", sha256.Sum256(v.raw)) != v.sha {
			t.Fatal("canonical vector changed", v.name)
		}
	}
}
func TestPruneFenceQuorumAndPolicyCannotBeSubstituted(t *testing.T) {
	s, e := p.NewSession(policy(), binding())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, _ := s.Candidate()
	q := claim(t, c)
	for _, name := range []string{"minority", "duplicate", "session", "inventory", "scope", "signature"} {
		t.Run(name, func(t *testing.T) {
			bad := p.Claim{Candidate: c, Certificate: q}
			bad.Certificate.Votes = append([]custodyfence.Vote(nil), q.Votes...)
			switch name {
			case "minority":
				bad.Certificate.Votes = bad.Certificate.Votes[:2]
			case "duplicate":
				bad.Certificate.Votes[1] = bad.Certificate.Votes[0]
			case "session":
				bad.Candidate.Session = f.Public(99)
			case "inventory":
				bad.Candidate.Binding.InventoryID = f.Hash("changed")
			case "scope":
				bad.Candidate.Binding.RequestID = f.Hash("changed")
			case "signature":
				bad.Certificate.Command.Signature[0] ^= 1
			}
			if bad.Verify() == nil {
				t.Fatal("invalid claim accepted")
			}
		})
	}
	changed := binding()
	changed.InventoryID = f.Hash("other")
	a, _ := policy().Scope(changed.AssignmentID, changed.RequestID)
	b, _ := policy().Scope(binding().AssignmentID, binding().RequestID)
	aid, _ := a.ID()
	bid, _ := b.ID()
	if aid != bid {
		t.Fatal("new inventory escaped original witness slot")
	}
}
func FuzzPruneFenceArtifacts(fuzz *testing.F) {
	praw, _ := policy().CanonicalBytes()
	fuzz.Add(byte(0), praw)
	s, e := p.NewSession(policy(), binding())
	if e != nil {
		fuzz.Fatal(e)
	}
	defer s.Close()
	c, _ := s.Candidate()
	craw, _ := c.CanonicalBytes()
	fuzz.Add(byte(1), craw)
	permit, q, e := s.Authorize(claim(fuzz, c))
	if e != nil {
		fuzz.Fatal(e)
	}
	qraw, _ := q.CanonicalBytes()
	fuzz.Add(byte(2), qraw)
	if e := permit.Consume(binding().OperationID, binding().StoragePairID); e != nil {
		fuzz.Fatal(e)
	}
	r, e := permit.Seal(f.Hash("effect"))
	if e != nil {
		fuzz.Fatal(e)
	}
	rraw, _ := r.CanonicalBytes()
	fuzz.Add(byte(3), rraw)
	fuzz.Fuzz(func(t *testing.T, kind byte, raw []byte) {
		var encoded []byte
		var err error
		switch kind % 4 {
		case 0:
			v, e := p.DecodePolicy(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 1:
			v, e := p.DecodeCandidate(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 2:
			v, e := p.DecodeClaim(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 3:
			v, e := p.DecodeResult(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		}
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("noncanonical artifact", err)
		}
	})
}
