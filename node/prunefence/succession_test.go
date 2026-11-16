package prunefence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	p "github.com/outcomemesh/outcomemesh/node/prunefence"
)

func replacementRequest(t testing.TB, guardID, revokedID types.Hash, before guardwire.Position, old, successor byte) guardwire.Replacement {
	t.Helper()
	q := guardwire.Replacement{GuardID: guardID, Subject: f.Public(old), Successor: f.Public(successor), Authority: f.Public(94),
		RevocationID: revokedID, EvidenceID: f.Hash("incident inventory"), Before: before}
	q, err := q.Accept(f.Key(successor))
	if err != nil {
		t.Fatal(err)
	}
	q, err = q.Authorize(f.Key(94))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func signedReceipt(t testing.TB, old, successor, guard byte) guardwire.ReplacementReceipt {
	t.Helper()
	q := replacementRequest(t, f.Hash("guard identity"), f.Hash("revoked"), guardwire.Position{Sequence: 1, Head: f.Hash("guard head")}, old, successor)
	r, err := (guardwire.ReplacementReceipt{Request: q, Guard: f.Public(guard)}).Sign(f.Key(guard))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signSuccession(t testing.TB, v p.Policy, receipt guardwire.ReplacementReceipt) p.ServiceSuccession {
	t.Helper()
	s, err := (p.ServiceSuccession{Replacement: receipt}).Sign(v, binding(), f.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPruneServiceSuccessionReplacementAuthorityRoles(t *testing.T) {
	v := servicePolicy(t)
	v.Guard = f.Public(99)
	b := binding()
	pid, err := v.ID()
	if err != nil {
		t.Fatal(err)
	}
	bid, err := b.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []byte{1, 2, 70, 71, 72, 73, 99, 91, 94} {
		q := guardwire.Replacement{GuardID: f.Hash("guard identity"), Subject: v.Service.Service, Successor: f.Public(95), Authority: f.Public(authority), RevocationID: f.Hash("revoked"), EvidenceID: f.Hash("inventory"), Before: guardwire.Position{Sequence: 1, Head: f.Hash("head")}}
		q, err = q.Accept(f.Key(95))
		if err != nil {
			t.Fatal(err)
		}
		q, err = q.Authorize(f.Key(authority))
		if err != nil {
			t.Fatal(err)
		}
		r, err := (guardwire.ReplacementReceipt{Request: q, Guard: v.Service.Guard}).Sign(f.Key(92))
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := r.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		// Sign outside the succession API to exercise the public verifier even
		// when the authorized roles overlap and the local signing API refuses.
		statement := types.DomainHash("OMESH/prune-fence/service-succession/statement/v0", pid[:], bid[:], receipt)
		h := types.DomainHash("OMESH/prune-fence/service-succession/sign/v0", statement[:])
		s := p.ServiceSuccession{Replacement: r}
		copy(s.IssuerSignature[:], ed25519.Sign(f.Key(91), h[:]))
		allowed := authority == 91 || authority == 94
		if got := s.Verify(v, b) == nil; got != allowed {
			t.Fatalf("replacement authority %d accepted=%v", authority, got)
		}
		_, err = (p.ServiceSuccession{Replacement: r}).Sign(v, b, f.Key(91))
		if (err == nil) != allowed {
			t.Fatalf("issuer signature for replacement authority %d: %v", authority, err)
		}
	}
}

func TestPruneServiceSuccessionPinsIssuerAndAdmission(t *testing.T) {
	v := servicePolicy(t)
	r := signedReceipt(t, 90, 95, 92)
	draft := p.ServiceSuccession{Replacement: r}
	unsigned, err := draft.ReviewID(v, binding())
	if err != nil {
		t.Fatal(err)
	}
	if draft.Verify(v, binding()) == nil {
		t.Fatal("unsigned succession")
	}
	for _, key := range []ed25519.PrivateKey{nil, f.Key(1), f.Key(90), f.Key(92), f.Key(94), f.Key(95)} {
		if _, e := draft.Sign(v, binding(), key); e == nil {
			t.Fatal("wrong issuer")
		}
	}
	s := signSuccession(t, v, r)
	if err := s.Verify(v, binding()); err != nil {
		t.Fatal(err)
	}
	id, err := s.ID(v, binding())
	if err != nil || id == unsigned {
		t.Fatal("signed ID", err)
	}
	for _, mutate := range []func(*p.Binding){func(b *p.Binding) { b.RequestID[0] ^= 1 }, func(b *p.Binding) { b.AssignmentID[0] ^= 1 }, func(b *p.Binding) { b.OperationID[0] ^= 1 }, func(b *p.Binding) { b.InventoryID[0] ^= 1 }, func(b *p.Binding) { b.ExecutorBindingID[0] ^= 1 }, func(b *p.Binding) { b.StoragePairID[0] ^= 1 }} {
		b := binding()
		mutate(&b)
		if s.Verify(v, b) == nil {
			t.Fatal("foreign binding accepted")
		}
	}
	alt := v
	alt.Guard = f.Public(99)
	if s.Verify(alt, binding()) == nil || s.Verify(policy(), binding()) == nil {
		t.Fatal("foreign policy")
	}
	for _, old := range []byte{93, 96} {
		if _, err := (p.ServiceSuccession{Replacement: signedReceipt(t, old, 95, 92)}).Sign(v, binding(), f.Key(91)); err == nil {
			t.Fatal("foreign subject")
		}
	}
	if _, err := (p.ServiceSuccession{Replacement: signedReceipt(t, 90, 95, 99)}).Sign(v, binding(), f.Key(91)); err == nil {
		t.Fatal("foreign guard")
	}
	for _, role := range []byte{1, 2, 70, 71, 72, 73, 91, 99} {
		if _, err := (p.ServiceSuccession{Replacement: signedReceipt(t, 90, role, 92)}).Sign(alt, binding(), f.Key(91)); err == nil {
			t.Fatal("conflicting role", role)
		}
	}
	s.Replacement.Request.RevocationID[0] ^= 1
	if s.Verify(v, binding()) == nil {
		t.Fatal("replacement mutated")
	}
}

// Assemble the candidate signing preimage independently of the candidate encoder.
func fixedSuccessorCandidate(t testing.TB, v p.Policy, s p.ServiceSuccession, session, signer byte) p.Candidate {
	t.Helper()
	b := binding()
	c := p.Candidate{Policy: v, Binding: b, Session: f.Public(session), Succession: &s}
	pol, err := v.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.CanonicalBytes(v, b)
	if err != nil {
		t.Fatal(err)
	}
	e := codec.NewEncoder(2048)
	e.Fixed([]byte("OMPRFC00"))
	e.U16(2)
	e.BytesField(pol)
	for _, id := range []types.Hash{b.RequestID, b.AssignmentID, b.OperationID, b.InventoryID, b.ExecutorBindingID, b.StoragePairID, types.Hash(c.Session)} {
		e.Fixed(id[:])
	}
	e.Fixed(proof)
	h := types.DomainHash("OMESH/prune-fence/service-session/sign/v2", e.Bytes())
	copy(c.ServiceSignature[:], ed25519.Sign(f.Key(signer), h[:]))
	return c
}

func TestPruneServiceSuccessionWireVectors(t *testing.T) {
	v := servicePolicy(t)
	s := signSuccession(t, v, signedReceipt(t, 90, 95, 92))
	b := binding()
	proof, err := s.CanonicalBytes(v, b)
	if err != nil {
		t.Fatal(err)
	}
	oldScope, err := v.Scope(b.AssignmentID, b.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	c := fixedSuccessorCandidate(t, v, s, 250, 95)
	raw, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	scope, command, err := c.Draft()
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := scope.ID()
	oldID, _ := oldScope.ID()
	if sid != oldID || command.EvidenceID != types.DomainHash("OMESH/prune-fence/session/id/v2", raw) {
		t.Fatal("witness claim changed slots or omits V2 candidate")
	}
	for i, item := range []struct {
		raw  []byte
		want string
	}{{proof, "542:2070085fe51b049e9949c6d72ac1f5cf18d850e7c22b0bcfc3227330059ef60b"}, {raw, "1376:61ca822ec533ad5019283331b25c49f74feac6509405b38d84178aa27698483a"}} {
		if got := fmt.Sprintf("%d:%x", len(item.raw), sha256.Sum256(item.raw)); got != item.want {
			t.Errorf("vector %d: %s", i, got)
		}
	}
	for _, bad := range [][]byte{nil, proof[:9], proof[:len(proof)-1], append(bytes.Clone(proof), 0)} {
		if _, err := p.DecodeServiceSuccession(bad, v, b); err == nil {
			t.Fatal("succession framing")
		}
	}
	for _, idx := range []int{8, 9, 10, len(proof) - 65, len(proof) - 1} {
		bad := bytes.Clone(proof)
		bad[idx] ^= 1
		if _, err := p.DecodeServiceSuccession(bad, v, b); err == nil {
			t.Fatal("mutated proof byte", idx)
		}
	}
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0), make([]byte, p.MaximumCandidateBytes+1)} {
		if _, err := p.DecodeCandidate(bad); err == nil {
			t.Fatal("candidate framing")
		}
	}
	for _, idx := range []int{8, 9, len(raw) - 65, len(raw) - 1} {
		bad := bytes.Clone(raw)
		bad[idx] ^= 1
		if _, err := p.DecodeCandidate(bad); err == nil {
			t.Fatal("mutated candidate byte", idx)
		}
	}
	if _, err := fixedSuccessorCandidate(t, v, s, 250, 90).CanonicalBytes(); err == nil {
		t.Fatal("original key signed successor candidate")
	}
	if _, err := fixedSuccessorCandidate(t, v, s, 95, 95).CanonicalBytes(); err == nil {
		t.Fatal("successor reused as volatile key")
	}
	// A larger enrolled roster must round-trip without changing legacy limits.
	v.Witnesses = nil
	for k := byte(10); k < 26; k++ {
		v.Witnesses = append(v.Witnesses, f.Public(k))
	}
	slices.SortFunc(v.Witnesses, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	v.Threshold = 11
	s = signSuccession(t, v, signedReceipt(t, 90, 95, 92))
	big := fixedSuccessorCandidate(t, v, s, 250, 95)
	large, err := big.CanonicalBytes()
	if err != nil || len(large) <= 1536 {
		t.Fatal("maximum roster", len(large), err)
	}
	parsed, err := p.DecodeCandidate(large)
	if err != nil || parsed.ServiceSigner() != f.Public(95) {
		t.Fatal("maximum roster decode", err)
	}
}
