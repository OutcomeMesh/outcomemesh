package prunefence_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	p "github.com/outcomemesh/outcomemesh/node/prunefence"
)

func settlementProposal(t testing.TB) p.SettlementProposal {
	t.Helper()
	c := p.Candidate{Policy: policy(), Binding: binding(), Session: f.Public(10)}
	return p.SettlementProposal{Claim: p.Claim{Candidate: c, Certificate: claim(t, c)}, EffectID: f.Hash("settled effect")}
}
func signedSettlement(t testing.TB) p.Settlement {
	t.Helper()
	proposal := settlementProposal(t)
	for _, v := range []struct {
		role string
		seed byte
	}{{"owner", 1}, {"controller", 2}} {
		review, err := proposal.ReviewID(v.role)
		if err != nil {
			t.Fatal(err)
		}
		proposal, err = proposal.Sign(v.role, review, f.Key(v.seed))
		if err != nil {
			t.Fatal(err)
		}
	}
	_, draft, err := proposal.Draft()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := draft.Sign(f.Key(2))
	if err != nil {
		t.Fatal(err)
	}
	return p.Settlement{Proposal: proposal, Certificate: f.Certificate(signed, 70, 71, 72)}
}
func TestPruneSettlementCanonicalVectors(t *testing.T) {
	s := signedSettlement(t)
	raw, err := s.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	claim, _ := s.Proposal.Claim.CanonicalBytes()
	proposal := append([]byte("OMPRSP00\x00\x00"), binary.AppendUvarint(nil, uint64(len(claim)))...)
	proposal = append(proposal, claim...)
	proposal = append(proposal, s.Proposal.EffectID[:]...)
	proposal = append(proposal, s.Proposal.OwnerSignature[:]...)
	proposal = append(proposal, s.Proposal.ControllerSignature[:]...)
	got, _ := s.Proposal.CanonicalBytes()
	if !bytes.Equal(got, proposal) {
		t.Fatal("proposal layout")
	}
	q, _ := s.Certificate.CanonicalBytes()
	want := append([]byte("OMPRSC00\x00\x00"), binary.AppendUvarint(nil, uint64(len(proposal)))...)
	want = append(want, proposal...)
	want = binary.AppendUvarint(want, uint64(len(q)))
	want = append(want, q...)
	if !bytes.Equal(raw, want) {
		t.Fatal("certificate layout")
	}
	for _, v := range []struct {
		name string
		raw  []byte
		size int
		sha  string
	}{
		{"proposal", proposal, 1294, "34a6213471346af17bfda977be65c39152d3e61d682245470e2c71ef59342fc7"}, {"settlement", raw, 1944, "3fce34f303f546c1e4907aef6b6f97b7ba2182c37ff50b11711c5e46cab8612f"},
	} {
		digest := fmt.Sprintf("%x", sha256.Sum256(v.raw))
		if len(v.raw) != v.size || digest != v.sha {
			t.Errorf("%s size=%d sha=%s", v.name, len(v.raw), digest)
		}
	}
	original, _ := policy().Scope(binding().AssignmentID, binding().RequestID)
	sid, _ := original.ID()
	decision, _, _ := s.Proposal.Draft()
	did, _ := decision.ID()
	if sid == did || original.Guard != decision.Guard || original.Owner != decision.Owner || original.Controller != decision.Controller {
		t.Fatal("decision scope changed original roles")
	}
}
func TestPruneSettlementRequiresBothOriginalRolesAndSeparateDecision(t *testing.T) {
	p0 := settlementProposal(t)
	if p0.Verify() == nil {
		t.Fatal("unsigned decision")
	}
	review, _ := p0.ReviewID("owner")
	if _, err := p0.Sign("owner", review, f.Key(2)); err == nil {
		t.Fatal("role key swap")
	}
	if _, err := p0.Sign("owner", f.Hash("stale"), f.Key(1)); err == nil {
		t.Fatal("stale review")
	}
	if _, err := p0.ReviewID("session"); err == nil {
		t.Fatal("invented role")
	}
	half, err := p0.Sign("owner", review, f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	if half.Verify() == nil {
		t.Fatal("single role decision")
	}
	if _, _, err := half.Draft(); err == nil {
		t.Fatal("single role voted")
	}
	s := signedSettlement(t)
	raw, _ := s.CanonicalBytes()
	for _, name := range []string{"effect", "claim", "owner", "controller", "swapped-signatures", "minority", "duplicate", "execution-scope", "kind", "position", "evidence", "vote", "signature"} {
		t.Run(name, func(t *testing.T) {
			bad, _ := p.DecodeSettlement(raw)
			switch name {
			case "effect":
				bad.Proposal.EffectID = f.Hash("other")
			case "claim":
				bad.Proposal.Claim.Candidate.Binding.InventoryID = f.Hash("other")
			case "owner":
				bad.Proposal.OwnerSignature = [64]byte{}
			case "controller":
				bad.Proposal.ControllerSignature = [64]byte{}
			case "swapped-signatures":
				bad.Proposal.OwnerSignature, bad.Proposal.ControllerSignature = bad.Proposal.ControllerSignature, bad.Proposal.OwnerSignature
			case "minority":
				bad.Certificate.Votes = bad.Certificate.Votes[:2]
			case "duplicate":
				bad.Certificate.Votes[1] = bad.Certificate.Votes[0]
			case "execution-scope":
				bad.Certificate = bad.Proposal.Claim.Certificate
			case "kind":
				bad.Certificate.Command.Kind = custodyfence.RecordResult
			case "position":
				bad.Certificate.Command.ExpectedSequence = 1
			case "evidence":
				bad.Certificate.Command.EvidenceID = f.Hash("other")
			case "vote":
				bad.Certificate.Votes[0].Signature[0] ^= 1
			case "signature":
				bad.Certificate.Command.Signature[0] ^= 1
			}
			if bad.Verify() == nil {
				t.Fatal("accepted substituted settlement")
			}
		})
	}
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0), bytes.Repeat([]byte{1}, p.MaximumSettlementBytes+1)} {
		if _, err := p.DecodeSettlement(bad); err == nil {
			t.Fatal("malformed settlement")
		}
	}
	if _, err := p.DecodeResult(raw); err == nil {
		t.Fatal("manufactured session result")
	}
	if _, err := p.DecodeClosure(raw); err == nil {
		t.Fatal("manufactured pre-start closure")
	}
	if _, err := p.DecodeClaim(raw); err == nil {
		t.Fatal("manufactured execution claim")
	}
	// An inventory/session change must still contend for the same decision slot.
	changed := s.Proposal
	changed.Claim.Candidate.Binding.InventoryID = f.Hash("copy")
	a, _ := changed.Claim.Candidate.Policy.SettlementScope(binding().AssignmentID, binding().RequestID)
	b, _, _ := s.Proposal.Draft()
	aid, _ := a.ID()
	bid, _ := b.ID()
	if aid != bid {
		t.Fatal("copy escaped decision slot")
	}
}
func FuzzPruneSettlementArtifacts(fuzz *testing.F) {
	s := signedSettlement(fuzz)
	raw, _ := s.CanonicalBytes()
	praw, _ := s.Proposal.CanonicalBytes()
	fuzz.Add(byte(0), praw)
	fuzz.Add(byte(1), raw)
	fuzz.Fuzz(func(t *testing.T, kind byte, raw []byte) {
		var encoded []byte
		var err error
		if kind%2 == 0 {
			v, e := p.DecodeSettlementProposal(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		} else {
			v, e := p.DecodeSettlement(raw)
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
