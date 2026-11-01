package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func pruneSettlementVector(t testing.TB) PruneSettlement {
	t.Helper()
	effect, err := workchain.DecodeCanonicalPruneEffect(fixedScheduledPrune(t).Effect)
	if err != nil {
		t.Fatal(err)
	}
	operation, _ := effect.Operation.FenceOperationID()
	eid, _ := effect.ID()
	c := prunefence.Candidate{Policy: pruneFencePolicy(), Session: testPublic(10), Binding: prunefence.Binding{AssignmentID: effect.Operation.AssignmentID, RequestID: testHash(2), OperationID: operation, InventoryID: testHash(3), ExecutorBindingID: testHash(4), StoragePairID: testHash(5)}}
	_, claimDraft, err := c.Draft()
	if err != nil {
		t.Fatal(err)
	}
	claimCommand, err := claimDraft.Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	proposal := prunefence.SettlementProposal{Claim: prunefence.Claim{Candidate: c, Certificate: f.Certificate(claimCommand, 70, 71, 72)}, EffectID: eid}
	for _, v := range []struct {
		role string
		seed byte
	}{{"owner", 4}, {"controller", 1}} {
		review, _ := proposal.ReviewID(v.role)
		proposal, err = proposal.Sign(v.role, review, testKey(v.seed))
		if err != nil {
			t.Fatal(err)
		}
	}
	_, draft, err := proposal.Draft()
	if err != nil {
		t.Fatal(err)
	}
	command, err := draft.Sign(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return PruneSettlement{Effect: effect, Decision: prunefence.Settlement{Proposal: proposal, Certificate: f.Certificate(command, 70, 71, 72)}}
}
func TestPruneSettlementCodec(t *testing.T) {
	s := pruneSettlementVector(t)
	raw, err := s.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	effect, _ := s.Effect.CanonicalBytes()
	decision, _ := s.Decision.CanonicalBytes()
	want := append([]byte("OMCPSE00\x00\x00"), binary.AppendUvarint(nil, uint64(len(effect)))...)
	want = append(want, effect...)
	want = binary.AppendUvarint(want, uint64(len(decision)))
	want = append(want, decision...)
	if !bytes.Equal(raw, want) {
		t.Fatal("record layout")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	id, _ := s.ID()
	if id != types.DomainHash("OMESH/custody-prune/settlement/id/v0", want) {
		t.Fatal("wrong ID domain")
	}
	if len(raw) != 2552 || digest != "e1140183c9beadf96afd8bebe26c58f1067cd4936b199359278339b524e1fa8f" || id.String() != "259312dd26ce2ca92efa07efefd12e1469a379856f2a057d2b7b99ff2b6958dd" {
		t.Fatalf("size=%d sha=%s id=%s", len(raw), digest, id.String())
	}
	for n := 0; n < len(raw); n++ {
		if _, err := DecodePruneSettlement(raw[:n]); err == nil {
			t.Fatal("truncated", n)
		}
	}
	badVersion := bytes.Clone(raw)
	badVersion[9] = 1
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), badVersion, make([]byte, MaximumPruneSettlementBytes+1)} {
		if _, err := DecodePruneSettlement(bad); err == nil {
			t.Fatal("noncanonical")
		}
	}
	bad, _ := DecodePruneSettlement(raw)
	bad.Effect.VerifiedAt++
	if _, err := bad.CanonicalBytes(); err == nil {
		t.Fatal("substituted effect")
	}
}
