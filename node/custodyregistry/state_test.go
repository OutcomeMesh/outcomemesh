package custodyregistry

import (
	"errors"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
)

func TestRegistryReferenceStateSelectsOneExactAssignmentForever(t *testing.T) {
	g, s := registryFixture(t)
	id, _ := g.ID()
	state, e := NewState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	initial := state.Snapshot()
	if initial.Position.Sequence != 0 || initial.Position.HeadID != id || initial.SelectionFinal || !initial.SelectedAssignmentID.IsZero() || initial.MaximumOperations != g.MaximumOperations || initial.MaximumPending != g.MaximumPending {
		t.Fatal("unexpected unselected state", initial)
	}
	weak := registryCertificate(t, g, s, 111, 112)
	if state.Apply(weak) == nil || state.Snapshot() != initial {
		t.Fatal("weak selection changed state")
	}
	q := registryCertificate(t, g, s)
	if e := state.Apply(q); e != nil {
		t.Fatal(e)
	}
	actual := state.Snapshot()
	sid, _ := s.ID()
	aid, _ := s.Initial.Assignment.ID()
	gid, _ := s.Initial.ID()
	did, _ := s.Initial.DescriptorID()
	if actual.Position.Sequence != 1 || actual.Position.HeadID != sid || !actual.SelectionFinal || actual.SelectedAssignmentID != aid || actual.SelectedGenesisID != gid || actual.SelectedDescriptorID != did || actual.MaximumOperations != g.MaximumOperations {
		t.Fatal("wrong permanent selection", actual)
	}
	for _, candidate := range []Selection{s, registryOtherSelection(t, g, s)} {
		if e := state.ValidateNext(candidate); !errors.Is(e, ErrSelected) {
			t.Fatal("final state accepted another candidate", e)
		}
		if e := state.Apply(registryCertificate(t, g, candidate)); !errors.Is(e, ErrSelected) || state.Snapshot() != actual {
			t.Fatal("selection replay/reset changed state", e)
		}
	}
	// Mutating a detached diagnostic never advances, clears or spends a slot.
	copy := actual
	copy.Position.Sequence = 0
	copy.SelectionFinal = false
	copy.SelectedAssignmentID = types.Hash{}
	if state.Snapshot() != actual {
		t.Fatal("detached diagnostic changed state")
	}
}

func TestRegistryReferenceStateFreezesDescriptorAndRefusesWrongPins(t *testing.T) {
	g, s := registryFixture(t)
	id, _ := g.ID()
	if _, e := NewState(g, f.Hash("wrong-anchor")); e == nil {
		t.Fatal("wrong independent pin accepted")
	}
	if _, e := NewState(g, types.Hash{}); e == nil {
		t.Fatal("missing independent pin accepted")
	}
	state, e := NewState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	before := state.Snapshot()
	// The retained reference descriptor is independent of caller-owned slices.
	g.Witnesses[0] = f.Public(99)
	if state.Snapshot() != before || state.ValidateNext(s) != nil {
		t.Fatal("caller mutation replaced frozen descriptor")
	}
	g, s = registryFixture(t)
	other := g
	other.MaximumOperations++
	x := s
	x.DescriptorID, _ = other.DescriptorID()
	x = registrySign(t, other, x)
	if state.Apply(registryCertificate(t, other, x)) == nil || state.Snapshot() != before {
		t.Fatal("same anchor with alternate policy replaced enrolled descriptor")
	}
	q := registryCertificate(t, g, s)
	q.Selection.IssuerSignature[0] ^= 1
	if state.Apply(q) == nil || state.Snapshot() != before {
		t.Fatal("invalid role signature changed state")
	}
	var nilState *State
	if nilState.ValidateNext(s) == nil || nilState.Apply(q) == nil || nilState.Snapshot() != (Snapshot{}) {
		t.Fatal("nil state accepted operation")
	}
}

func TestRegistryReferenceConcurrentSelectionHasOneAtomicWinner(t *testing.T) {
	g, selection := registryFixture(t)
	id, _ := g.ID()
	state, e := NewState(g, id)
	if e != nil {
		t.Fatal(e)
	}
	q := registryCertificate(t, g, selection)
	outcomes := make(chan error, 16)
	var workers sync.WaitGroup
	for i := 0; i < cap(outcomes); i++ {
		workers.Go(func() { outcomes <- state.Apply(q) })
	}
	for i := 0; i < 32; i++ {
		snapshot := state.Snapshot()
		if snapshot.Position.Sequence == 0 {
			if snapshot.SelectionFinal || !snapshot.SelectedAssignmentID.IsZero() || !snapshot.SelectedGenesisID.IsZero() || !snapshot.SelectedDescriptorID.IsZero() {
				t.Fatal("partial unselected snapshot")
			}
		} else if snapshot.Position.Sequence != 1 || !snapshot.SelectionFinal || snapshot.SelectedAssignmentID.IsZero() || snapshot.SelectedGenesisID.IsZero() || snapshot.SelectedDescriptorID.IsZero() {
			t.Fatal("partial selected snapshot")
		}
	}
	workers.Wait()
	close(outcomes)
	winners := 0
	for e := range outcomes {
		if e == nil {
			winners++
		} else if e != ErrSelected {
			t.Fatal("unexpected concurrent selection error", e)
		}
	}
	if winners != 1 {
		t.Fatal("one registry slot selected more than one assignment", winners)
	}
}
