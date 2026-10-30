package store

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type migratedPruneVector struct {
	Inventory, Proof, Outcome, Entry                                       []byte
	InventoryID, PolicyID, ScheduleID, EvidenceID, ReviewID, EntryReviewID types.Hash
	Position                                                               custodyauthority.Position
	Kind                                                                   string
}

func fixedMigratedPrune(t testing.TB) []migratedPruneVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/migrated_prune_completion_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var v []migratedPruneVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func migratedVectorContext(t testing.TB, v migratedPruneVector) (MigratedPruneContext, MigratedPruneOutcome) {
	t.Helper()
	inventory, err := DecodeArchivePruneInventory(v.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := workarchive.DecodeCustodyScheduleProof(v.Proof)
	if err != nil {
		t.Fatal(err)
	}
	c := MigratedPruneContext{Inventory: inventory, InventoryID: v.InventoryID, PolicyID: v.PolicyID, ScheduleID: v.ScheduleID, Proof: proof}
	var o MigratedPruneOutcome
	if v.Kind == "effect" {
		e, err := workchain.DecodeCanonicalPruneEffect(v.Outcome)
		if err != nil {
			t.Fatal(err)
		}
		o.Effect = &e
	} else {
		e, err := DecodePruneCancellation(v.Outcome)
		if err != nil {
			t.Fatal(err)
		}
		o.Cancellation = &e
	}
	return c, o
}
func TestPruneMigratedCompletionGolden(t *testing.T) {
	for _, v := range fixedMigratedPrune(t) {
		t.Run(v.Kind, func(t *testing.T) {
			c, o := migratedVectorContext(t, v)
			id, err := o.EvidenceID(c)
			if err != nil || id != v.EvidenceID {
				t.Fatal("outcome ID changed", err)
			}
			draft, err := BuildMigratedPruneCompletion(c, o, v.Position)
			if err != nil {
				t.Fatal(err)
			}
			a, err := c.SelectedAssignment()
			if err != nil {
				t.Fatal(err)
			}
			review, err := custodyauthority.ScheduledPruneCommandReviewID(a, draft)
			if err != nil || review != v.ReviewID {
				t.Fatal("signature message changed", err)
			}
			signed, err := custodyauthority.SignReviewedScheduledPruneCommand(a, draft, review, testKey(4))
			if err != nil {
				t.Fatal(err)
			}
			entryReview, err := custodyauthority.ScheduledPruneEntryReviewID(a, signed)
			if err != nil || entryReview != v.EntryReviewID {
				t.Fatal("cosignature message changed", err)
			}
			entry, err := custodyauthority.CosignReviewedScheduledPruneCommand(a, signed, entryReview, testKey(1))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := entry.CanonicalBytes()
			if !bytes.Equal(raw, v.Entry) {
				t.Fatal("completion bytes changed")
			}
			if _, err := custodyauthority.PruneCommandReviewID(a, draft); err == nil {
				t.Fatal("legacy signer accepted migrated completion")
			}
			for _, pos := range []custodyauthority.Position{{Sequence: 0, HeadID: v.Position.HeadID}, {Sequence: 1, HeadID: v.Position.HeadID}, {Sequence: ^uint64(0), HeadID: v.Position.HeadID}} {
				if _, err := BuildMigratedPruneCompletion(c, o, pos); err == nil {
					t.Fatal("invalid migration position accepted")
				}
			}
		})
	}
}
func FuzzPruneMigratedOutcome(f *testing.F) {
	vectors := fixedMigratedPrune(f)
	for i, v := range vectors {
		f.Add(byte(i), v.Outcome)
	}
	f.Fuzz(func(t *testing.T, which byte, raw []byte) {
		v := vectors[int(which)%len(vectors)]
		c, _ := migratedVectorContext(t, v)
		var o MigratedPruneOutcome
		if v.Kind == "effect" {
			e, err := workchain.DecodeCanonicalPruneEffect(raw)
			if err != nil {
				return
			}
			o.Effect = &e
		} else {
			e, err := DecodePruneCancellation(raw)
			if err != nil {
				return
			}
			o.Cancellation = &e
		}
		draft, err := BuildMigratedPruneCompletion(c, o, v.Position)
		if err != nil {
			return
		}
		encoded, err := o.Artifact()
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("noncanonical retained outcome")
		}
		id, err := o.EvidenceID(c)
		if err != nil || draft.EvidenceID != id || draft.ScheduleID != v.ScheduleID || draft.Kind != custodyauthority.Complete {
			t.Fatal("unbound completion")
		}
	})
}
