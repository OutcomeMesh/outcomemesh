package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type scheduledPrunePlanVector struct {
	Plan                                                                                           []byte
	PlanID, AdmissionReviewID, AdmissionEntryReviewID, CompletionReviewID, CompletionEntryReviewID types.Hash
	Completion                                                                                     []byte
}

func fixedScheduledPrunePlan(t testing.TB) scheduledPrunePlanVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/scheduled_prune_plan_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var v scheduledPrunePlanVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func TestScheduledPrunePlanAndSignaturesCanonicalVectors(t *testing.T) {
	vector := fixedScheduledPrunePlan(t)
	p, err := DecodeScheduledPrunePlan(vector.Plan)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := p.ID()
	if id != vector.PlanID {
		t.Fatal("plan vector changed", id)
	}
	old := fixedScheduledPrune(t)
	v, err := DecodeScheduledPruneInventory(old.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	projected := planFromInventory(v)
	raw, _ := projected.CanonicalBytes()
	if !bytes.Equal(raw, vector.Plan) {
		t.Fatal("plan projection changed")
	}
	if _, err := DecodeScheduledPruneInventory(vector.Plan); err == nil {
		t.Fatal("plan granted inventory")
	}
	if _, err := DecodeScheduledPrunePlan(old.Inventory); err == nil {
		t.Fatal("inventory passed as plan")
	}
	for _, raw := range [][]byte{nil, vector.Plan[:len(vector.Plan)-1], append(bytes.Clone(vector.Plan), 0)} {
		if _, err := DecodeScheduledPrunePlan(raw); err == nil {
			t.Fatal("invalid framing")
		}
	}
	badVersion := bytes.Clone(vector.Plan)
	badVersion[9] = 1
	if _, err := DecodeScheduledPrunePlan(badVersion); err == nil {
		t.Fatal("future plan version accepted")
	}
	bad := p
	bad.ExecutorBindingID = v.ExecutorBindingID
	if _, err := bad.ID(); err == nil {
		t.Fatal("bound executor smuggled into plan")
	}
	bad = p
	bad.Replicas = append([]ScheduledPruneReplica(nil), p.Replicas...)
	bad.Replicas[0].Admission = v.Replicas[0].Admission
	if _, err := bad.ID(); err == nil {
		t.Fatal("admission smuggled into plan")
	}
	a := v.Replicas[0].Assignment
	c := v.Replicas[0].Admission.Command
	unsigned := c
	unsigned.Signature = [64]byte{}
	review, err := custodyauthority.ScheduledPruneCommandReviewID(a, unsigned)
	if err != nil || review != vector.AdmissionReviewID {
		t.Fatal("admission signature message changed", err)
	}
	signed, err := custodyauthority.SignReviewedScheduledPruneCommand(a, unsigned, review, testKey(4))
	if err != nil || signed != c {
		t.Fatal("admission signature changed", err)
	}
	er, err := custodyauthority.ScheduledPruneEntryReviewID(a, signed)
	if err != nil || er != vector.AdmissionEntryReviewID {
		t.Fatal("entry message changed", err)
	}
	entry, err := custodyauthority.CosignReviewedScheduledPruneCommand(a, signed, er, testKey(1))
	if err != nil || entry != v.Replicas[0].Admission {
		t.Fatal("admission cosignature changed", err)
	}
	effect, err := workchain.DecodeCanonicalPruneEffect(old.Effect)
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := entry.ID()
	aid, _ := a.ID()
	complete, err := BuildScheduledPruneCompletion(p, v, effect, aid, custodyauthority.Position{Sequence: c.ExpectedSequence + 1, HeadID: ticket})
	if err != nil {
		t.Fatal(err)
	}
	cr, err := custodyauthority.ScheduledPruneCommandReviewID(a, complete)
	if err != nil || cr != vector.CompletionReviewID {
		t.Fatal("completion signature message changed", err)
	}
	cc, err := custodyauthority.SignReviewedScheduledPruneCommand(a, complete, cr, testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	ce, err := custodyauthority.ScheduledPruneEntryReviewID(a, cc)
	if err != nil || ce != vector.CompletionEntryReviewID {
		t.Fatal("completion entry message changed", err)
	}
	done, err := custodyauthority.CosignReviewedScheduledPruneCommand(a, cc, ce, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	doneBytes, _ := done.CanonicalBytes()
	if !bytes.Equal(doneBytes, vector.Completion) {
		t.Fatal("completion cosignature changed")
	}
	path := filepath.Join(t.TempDir(), "plan")
	for i := 0; i < 2; i++ {
		if err := SaveScheduledPrunePlan(t.Context(), path, p, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadScheduledPrunePlan(path, id); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadScheduledPrunePlan(path, testHash(215)); err == nil {
		t.Fatal("wrong plan pin accepted")
	}
	for _, name := range []string{"effect-storage", "effect-ticket", "effect-scope", "effect-height", "assignment", "position", "inventory"} {
		t.Run(name, func(t *testing.T) {
			e := effect
			vv := v
			who := aid
			pos := custodyauthority.Position{Sequence: c.ExpectedSequence + 1, HeadID: ticket}
			switch name {
			case "effect-storage":
				e.Operation.StorageID = testHash(216)
			case "effect-ticket":
				e.Operation.TicketID = testHash(216)
			case "effect-scope":
				e.Operation.ScheduleID = testHash(216)
			case "effect-height":
				e.Operation.Boundary.RadixActivationHeight++
			case "assignment":
				who = testHash(216)
			case "position":
				pos.HeadID = testHash(216)
			case "inventory":
				vv.StoragePairID = testHash(216)
			}
			if _, err := BuildScheduledPruneCompletion(p, vv, e, who, pos); err == nil {
				t.Fatal("substituted completion accepted")
			}
		})
	}
}
func FuzzDecodeScheduledPrunePlan(f *testing.F) {
	v := fixedScheduledPrunePlan(f)
	f.Add(v.Plan)
	f.Add([]byte("OMCSPPLN"))
	f.Add(fixedScheduledPrune(f).Inventory)
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeScheduledPrunePlan(raw)
		if err != nil {
			return
		}
		out, err := p.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, out) {
			t.Fatal("noncanonical plan accepted", err)
		}
		if _, err := DecodeScheduledPruneInventory(raw); err == nil {
			t.Fatal("plan became inventory")
		}
	})
}
