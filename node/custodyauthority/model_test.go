package custodyauthority

import (
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// This independent small model tracks admission/closure sets, not the machine's
// counters or request index. Generated commands are signed but may be invalid
// for the current phase, role, ticket or capacity.
func FuzzAuthorityDrainStateMachine(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{0, 0, 0, 0, 0, 0})
	f.Add([]byte{2, 3, 0, 4, 1, 3})
	f.Fuzz(func(t *testing.T, choices []byte) {
		if len(choices) > 24 {
			choices = choices[:24]
		}
		a := testAssignment()
		state := testState(t, a)
		opened := make(map[types.Hash]byte)
		used := make(map[operationKey]bool)
		var tickets []types.Hash
		var history []Entry
		phase := Accepting
		for index, choice := range choices {
			before := testSnapshot(t, state)
			kind := Kind(choice%4 + 1)
			actor := byte(4 + (choice/4)%3)
			purpose := Purpose(1 << ((choice / 12) % 3))
			operation, ticket, evidence := types.Hash{}, types.Hash{}, types.Hash{}
			switch kind {
			case Admit:
				operation = testHash(byte(40 + choice%5))
			case Complete:
				purpose = 0
				evidence = testHash(byte(100 + index))
				ticket = testHash(90)
				if len(tickets) > 0 {
					ticket = tickets[int(choice/4)%len(tickets)]
				}
			case Stop:
				purpose = 0
				evidence = testHash(20)
				if choice&16 == 0 {
					actor = 1
				}
			case Retire:
				purpose = 0
				evidence = before.StopID
				if evidence.IsZero() {
					evidence = testHash(20)
				}
				if choice&16 == 0 {
					actor = 1
				}
			}
			entry := testEntry(t, state, kind, purpose, actor, operation, ticket, evidence)
			key := operationKey{testPublic(actor), operation}
			valid := false
			switch kind {
			case Admit:
				valid = phase == Accepting && actor == byte(4+(choice/12)%3) && !used[key] && len(used) < int(a.MaximumOperations) && len(opened) < int(a.MaximumPending)
			case Complete:
				owner, exists := opened[ticket]
				valid = phase != Retired && exists && owner == actor
			case Stop:
				valid = phase == Accepting && actor == 1
			case Retire:
				valid = phase == Stopping && actor == 1 && len(opened) == 0
			}
			err := state.Apply(entry)
			if (err == nil) != valid {
				t.Fatalf("model differs at %d kind=%d actor=%d phase=%d pending=%d: %v", index, kind, actor, phase, len(opened), err)
			}
			if err != nil {
				if !reflect.DeepEqual(before, testSnapshot(t, state)) {
					t.Fatal("rejection changed state")
				}
				continue
			}
			id, _ := entry.ID()
			history = append(history, entry)
			switch kind {
			case Admit:
				opened[id] = actor
				used[key] = true
				tickets = append(tickets, id)
			case Complete:
				delete(opened, ticket)
			case Stop:
				phase = Stopping
			case Retire:
				phase = Retired
			}
			after := testSnapshot(t, state)
			if after.Phase != phase || int(after.Pending) != len(opened) || len(after.Operations) != len(used) || after.Sequence != uint64(len(history)) {
				t.Fatal("model/state counters differ")
			}
			replayed, err := Replay(a, after.AssignmentID, history, Position{after.Sequence, after.HeadID})
			if err != nil || !reflect.DeepEqual(testSnapshot(t, replayed), after) {
				t.Fatal("replay differs from application", err)
			}
		}
	})
}
