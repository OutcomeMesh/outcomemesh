package custodyauthority

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func scheduleEntry(t testing.TB, s *State, kind Kind, purpose Purpose, actor byte, schedule, operation, ticket, evidence types.Hash) Entry {
	t.Helper()
	p := testSnapshot(t, s)
	c, err := (Command{Version: ScheduleVersion2, ScheduleID: schedule, AssignmentID: p.AssignmentID, ExpectedSequence: p.Sequence, ExpectedHead: p.HeadID, Kind: kind, Purpose: purpose, OperationID: operation, TicketID: ticket, EvidenceID: evidence}).Sign(testKey(actor))
	if err != nil {
		t.Fatal(err)
	}
	e, err := SignEntry(c, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestSchedulePreservesSpentPendingAndDrainCapacity(t *testing.T) {
	a := testAssignment()
	a.MaximumOperations = 2
	s := testState(t, a)
	var history []Entry
	apply := func(e Entry) types.Hash { history = append(history, e); return applyTestEntry(t, s, e) }
	first := apply(testEntry(t, s, Admit, Audit, 4, testHash(20), types.Hash{}, types.Hash{}))
	apply(testEntry(t, s, Complete, 0, 4, types.Hash{}, first, testHash(21)))
	second := apply(testEntry(t, s, Admit, Serve, 5, testHash(22), types.Hash{}, types.Hash{}))
	before := testSnapshot(t, s)
	scope := testHash(77)
	apply(scheduleEntry(t, s, MigrateSchedule, 0, 2, scope, types.Hash{}, types.Hash{}, types.Hash{}))
	after := testSnapshot(t, s)
	if after.Pending != before.Pending || after.Phase != before.Phase || !reflect.DeepEqual(after.Operations, before.Operations) || after.ScheduleID != scope {
		t.Fatal("migration changed obligations")
	}
	denyTestEntry(t, s, testEntry(t, s, Complete, 0, 5, types.Hash{}, second, testHash(23)), ErrAssignment)
	denyTestEntry(t, s, scheduleEntry(t, s, Complete, 0, 5, testHash(78), types.Hash{}, second, testHash(23)), ErrAssignment)
	denyTestEntry(t, s, scheduleEntry(t, s, MigrateSchedule, 0, 2, scope, types.Hash{}, types.Hash{}, types.Hash{}), ErrAssignment)
	denyTestEntry(t, s, scheduleEntry(t, s, Admit, Audit, 4, scope, testHash(24), types.Hash{}, types.Hash{}), ErrLimit)
	stop := apply(scheduleEntry(t, s, Stop, 0, 1, scope, types.Hash{}, types.Hash{}, testHash(25)))
	denyTestEntry(t, s, scheduleEntry(t, s, Retire, 0, 1, scope, types.Hash{}, types.Hash{}, stop), ErrOutstanding)
	apply(scheduleEntry(t, s, Complete, 0, 5, scope, types.Hash{}, second, testHash(23)))
	apply(scheduleEntry(t, s, Retire, 0, 1, scope, types.Hash{}, types.Hash{}, stop))
	final := testSnapshot(t, s)
	if final.Sequence != MaximumEntries(a) || final.Phase != Retired {
		t.Fatal("lost drain capacity")
	}
	id, _ := a.ID()
	replay, err := Replay(a, id, history, Position{Sequence: final.Sequence, HeadID: final.HeadID})
	if err != nil || !reflect.DeepEqual(testSnapshot(t, replay), final) {
		t.Fatal("replay changed obligations", err)
	}
}
func TestScheduleMigrationRolesStoppingAndRemoteGate(t *testing.T) {
	s := testState(t, testAssignment())
	scope := testHash(77)
	denyTestEntry(t, s, scheduleEntry(t, s, MigrateSchedule, 0, 4, scope, types.Hash{}, types.Hash{}, types.Hash{}), ErrAssignment)
	applyTestEntry(t, s, testEntry(t, s, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(20)))
	before := testSnapshot(t, s)
	applyTestEntry(t, s, scheduleEntry(t, s, MigrateSchedule, 0, 2, scope, types.Hash{}, types.Hash{}, types.Hash{}))
	after := testSnapshot(t, s)
	if after.Phase != Stopping || before.StopID != after.StopID || before.StopIntentID != after.StopIntentID {
		t.Fatal("reopened stopping assignment")
	}
	remote := testState(t, remoteTestAssignment(t))
	denyTestEntry(t, remote, scheduleEntry(t, remote, MigrateSchedule, 0, 2, scope, types.Hash{}, types.Hash{}, types.Hash{}), ErrAssignment)
}
func TestScheduleCodecCanonicalAndDomainIsolation(t *testing.T) {
	s := testState(t, testAssignment())
	e := scheduleEntry(t, s, MigrateSchedule, 0, 2, testHash(77), types.Hash{}, types.Hash{}, types.Hash{})
	b, err := e.CanonicalBytes()
	if err != nil || len(b) != MaximumEntryBytes {
		t.Fatal(err, len(b))
	}
	decoded, err := DecodeEntry(b)
	if err != nil || decoded != e {
		t.Fatal("roundtrip", err)
	}
	for i := range b {
		changed := bytes.Clone(b)
		changed[i] ^= 1
		if _, err := DecodeEntry(changed); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
		if _, err := DecodeEntry(b[:i]); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
	if _, err := DecodeEntry(append(bytes.Clone(b), 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
	c := e.Command
	c.Version = Version0
	if _, err := c.Sign(testKey(2)); err == nil {
		t.Fatal("legacy schedule accepted")
	}
	c = e.Command
	c.ScheduleID = types.Hash{}
	if _, err := c.Sign(testKey(2)); err == nil {
		t.Fatal("missing schedule accepted")
	}
	id, _ := e.ID()
	if id.String() != "600d67ae84ee481323e5f07d409a5ff6eb0b97bef120df6ed1d5bf2034ed1732" {
		t.Fatal("schedule entry vector changed", id)
	}
}
func FuzzDecodeScheduleEntry(f *testing.F) {
	s := testState(f, testAssignment())
	e := scheduleEntry(f, s, MigrateSchedule, 0, 2, testHash(77), types.Hash{}, types.Hash{}, types.Hash{})
	b, _ := e.CanonicalBytes()
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEntry(b)
		if err != nil {
			return
		}
		canonical, err := e.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, b) {
			t.Fatal("noncanonical accepted")
		}
	})
}
