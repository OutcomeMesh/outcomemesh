package store

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type scheduledPruneVector struct {
	Inventory, Request, Floor, Effect []byte
	InventoryID, RequestID, EffectID  types.Hash
}

func TestScheduledPruneAdmissionDraftRejectsTargetSubstitution(t *testing.T) {
	v := fixedScheduledPrune(t)
	inventory, err := DecodeScheduledPruneInventory(v.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	s := inventory.Replicas[0]
	c := s.Admission.Command
	position := custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead}
	for _, mutate := range []func(*PruneRequest){
		func(r *PruneRequest) { r.ScheduleID = testHash(188) },
		func(r *PruneRequest) { r.Boundary.BaseID = testHash(189) },
		func(r *PruneRequest) { r.Boundary.Anchor.ID = testHash(190) },
		func(r *PruneRequest) { r.Boundary.AncestryRoot = testHash(191) },
		func(r *PruneRequest) { r.Boundary.RadixActivationHeight++ },
	} {
		r := inventory.Request
		mutate(&r)
		if _, err := BuildScheduledPruneAdmission(s.Assignment, s.Proof, inventory.OriginalPolicy, r, position); err == nil {
			t.Fatal("substituted target accepted for signing")
		}
	}
	draft, err := BuildScheduledPruneAdmission(s.Assignment, s.Proof, inventory.OriginalPolicy, inventory.Request, position)
	c.Signature = [64]byte{}
	if err != nil || draft != c {
		t.Fatal("original reviewed draft changed", err)
	}
}

func fixedScheduledPrune(t testing.TB) scheduledPruneVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/scheduled_prune_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var v scheduledPruneVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestScheduledPruneCanonicalVectors(t *testing.T) {
	v := fixedScheduledPrune(t)
	inventory, err := DecodeScheduledPruneInventory(v.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	id, err := inventory.ID()
	if err != nil || id != v.InventoryID {
		t.Fatal("inventory vector changed", err)
	}
	request, err := DecodePruneRequest(v.Request)
	if err != nil {
		t.Fatal(err)
	}
	id, err = request.ID()
	if err != nil || id != v.RequestID {
		t.Fatal("request vector changed", err)
	}
	effect, err := workchain.DecodeCanonicalPruneEffect(v.Effect)
	if err != nil {
		t.Fatal(err)
	}
	id, err = effect.ID()
	if err != nil || id != v.EffectID {
		t.Fatal("effect vector changed", err)
	}
	floor, err := workchain.DecodeCanonicalFloor(v.Floor)
	if err != nil || floor.RadixActivationHeight == 0 {
		t.Fatal("floor vector", err)
	}
	for _, check := range []struct {
		raw    []byte
		offset int
		decode func([]byte) error
	}{
		{v.Inventory, 8, func(b []byte) error { _, err := DecodeScheduledPruneInventory(b); return err }},
		{v.Request, 8, func(b []byte) error { _, err := DecodePruneRequest(b); return err }},
		{v.Floor, 0, func(b []byte) error { _, err := workchain.DecodeCanonicalFloor(b); return err }},
		{v.Effect, 8, func(b []byte) error { _, err := workchain.DecodeCanonicalPruneEffect(b); return err }},
	} {
		for _, raw := range [][]byte{nil, check.raw[:len(check.raw)-1], append(bytes.Clone(check.raw), 0)} {
			if err := check.decode(raw); err == nil {
				t.Fatal("noncanonical length accepted")
			}
		}
		for _, version := range []byte{1, 3, 255} {
			bad := bytes.Clone(check.raw)
			bad[check.offset], bad[check.offset+1] = 0, version
			if err := check.decode(bad); err == nil {
				t.Fatal("version substitution accepted")
			}
		}
	}
	for _, mutate := range []func(*ScheduledPruneInventory){
		func(v *ScheduledPruneInventory) { v.ReplicaPolicy.RequiredReplicas = 1 },
		func(v *ScheduledPruneInventory) { v.Replicas = v.Replicas[:1] },
		func(v *ScheduledPruneInventory) { v.Replicas[1] = v.Replicas[0] },
		func(v *ScheduledPruneInventory) { v.Request.ScheduleID = testHash(180) },
		func(v *ScheduledPruneInventory) { v.Request.Boundary.RadixActivationHeight++ },
		func(v *ScheduledPruneInventory) { v.Replicas[0].Admission = v.Replicas[1].Admission },
		func(v *ScheduledPruneInventory) { v.OriginalPolicy.TrustedAttestors = nil },
		func(v *ScheduledPruneInventory) { v.Replicas[0].Receipt = v.Replicas[1].Receipt },
	} {
		bad, err := DecodeScheduledPruneInventory(v.Inventory)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&bad)
		if _, err := bad.ID(); err == nil {
			t.Fatal("substituted quorum accepted")
		}
	}
}

func FuzzDecodeScheduledPruneInventory(f *testing.F) {
	v := fixedScheduledPrune(f)
	f.Add(v.Inventory)
	f.Add([]byte("OMCSPINV"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := DecodeScheduledPruneInventory(raw)
		if err != nil {
			return
		}
		encoded, err := v.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("accepted noncanonical inventory", err)
		}
	})
}

func FuzzScheduledPruneStorageFormats(f *testing.F) {
	v := fixedScheduledPrune(f)
	f.Add(byte(0), v.Request)
	f.Add(byte(1), v.Floor)
	f.Add(byte(2), v.Effect)
	f.Fuzz(func(t *testing.T, kind byte, raw []byte) {
		var encoded []byte
		var err error
		switch kind % 3 {
		case 0:
			v, e := DecodePruneRequest(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 1:
			v, e := workchain.DecodeCanonicalFloor(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 2:
			v, e := workchain.DecodeCanonicalPruneEffect(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		}
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("accepted noncanonical storage format", err)
		}
	})
}
