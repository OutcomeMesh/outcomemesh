package store

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type scheduledCancellationCompletionVector struct {
	AssignmentID, ReviewID, EntryReviewID types.Hash
	Entry                                 []byte
}
type scheduledCancellationVector struct {
	Cancellation   []byte
	CancellationID types.Hash
	Completions    []scheduledCancellationCompletionVector
}

func fixedScheduledCancellation(t testing.TB) scheduledCancellationVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/scheduled_prune_cancellation_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var v scheduledCancellationVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func TestPruneScheduledCancellationSignatureVectors(t *testing.T) {
	vector := fixedScheduledCancellation(t)
	inventory, err := DecodeScheduledPruneInventory(fixedScheduledPrune(t).Inventory)
	if err != nil {
		t.Fatal(err)
	}
	cancellation, err := DecodePruneCancellation(vector.Cancellation)
	if err != nil {
		t.Fatal(err)
	}
	outcome := ScheduledPruneOutcome{Cancellation: &cancellation}
	id, err := outcome.EvidenceID(inventory)
	if err != nil || id != vector.CancellationID {
		t.Fatal("cancellation binding changed", err)
	}
	raw, err := outcome.Artifact()
	if err != nil || !bytes.Equal(raw, vector.Cancellation) {
		t.Fatal("cancellation bytes changed", err)
	}
	if len(vector.Completions) != len(inventory.Replicas) {
		t.Fatal("missing replica vectors")
	}
	p := planFromInventory(inventory)
	for i, s := range inventory.Replicas {
		aid, _ := s.Assignment.ID()
		ticket, _ := s.Admission.ID()
		expected := vector.Completions[i]
		draft, err := BuildScheduledPruneOutcomeCompletion(p, inventory, outcome, aid, custodyauthority.Position{Sequence: s.Admission.Command.ExpectedSequence + 1, HeadID: ticket})
		if err != nil {
			t.Fatal(err)
		}
		review, err := custodyauthority.ScheduledPruneCommandReviewID(s.Assignment, draft)
		if err != nil || review != expected.ReviewID || aid != expected.AssignmentID {
			t.Fatal("completion signature message changed", err)
		}
		signed, err := custodyauthority.SignReviewedScheduledPruneCommand(s.Assignment, draft, review, testKey(4))
		if err != nil {
			t.Fatal(err)
		}
		er, err := custodyauthority.ScheduledPruneEntryReviewID(s.Assignment, signed)
		if err != nil || er != expected.EntryReviewID {
			t.Fatal("completion cosignature message changed", err)
		}
		entry, err := custodyauthority.CosignReviewedScheduledPruneCommand(s.Assignment, signed, er, testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := entry.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, expected.Entry) {
			t.Fatal("signed cancellation completion changed", err)
		}
		decoded, err := custodyauthority.DecodeEntry(expected.Entry)
		if err != nil || decoded != entry {
			t.Fatal("frozen entry invalid", err)
		}
	}
}

func FuzzPruneScheduledOutcome(f *testing.F) {
	fixed := fixedScheduledPrune(f)
	v, err := DecodeScheduledPruneInventory(fixed.Inventory)
	if err != nil {
		f.Fatal(err)
	}
	cancel := fixedScheduledCancellation(f)
	f.Add(byte(0), fixed.Effect)
	f.Add(byte(1), cancel.Cancellation)
	f.Add(byte(1), []byte("OMCPCL"))
	f.Fuzz(func(t *testing.T, kind byte, raw []byte) {
		var o ScheduledPruneOutcome
		if kind%2 == 0 {
			effect, err := workchain.DecodeCanonicalPruneEffect(raw)
			if err != nil {
				return
			}
			o.Effect = &effect
		} else {
			cancellation, err := DecodePruneCancellation(raw)
			if err != nil {
				return
			}
			o.Cancellation = &cancellation
		}
		encoded, err := o.Artifact()
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("noncanonical outcome", err)
		}
		id, err := o.EvidenceID(v)
		if err != nil {
			return
		}
		if o.Cancellation != nil && id != cancel.CancellationID {
			t.Fatal("substituted cancellation accepted")
		}
		if o.Effect != nil {
			original, err := workchain.DecodeCanonicalPruneEffect(fixed.Effect)
			if err != nil || !reflect.DeepEqual(o.Effect.Operation, original.Operation) {
				t.Fatal("substituted effect operation accepted", err)
			}
		}
	})
}
