package custodyauthority

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}
func testPublic(seed byte) [ed25519.PublicKeySize]byte {
	return [ed25519.PublicKeySize]byte(testKey(seed).Public().(ed25519.PublicKey))
}
func testHash(label byte) types.Hash {
	return types.DomainHash("test/custody-authority", []byte{label})
}

func testAssignment() Assignment {
	a := Assignment{Version: Version0, NetworkID: 77, GenesisID: testHash(1), ActivationHeight: 10,
		BaseID: testHash(2), ManifestID: testHash(3), StatementID: testHash(4), InitialReceiptID: testHash(5),
		CustodyPolicyID: testHash(6), IncarnationID: testHash(7), AuthorityPublicKey: testPublic(1), ReplicaPublicKey: testPublic(2),
		Auditors:          [][ed25519.PublicKeySize]byte{testPublic(3)},
		Consumers:         []Consumer{{testPublic(4), Audit}, {testPublic(5), Serve}, {testPublic(6), Prune}},
		MaximumOperations: 4, MaximumPending: 2}
	sort.Slice(a.Consumers, func(i, j int) bool {
		return bytes.Compare(a.Consumers[i].PublicKey[:], a.Consumers[j].PublicKey[:]) < 0
	})
	return a
}

func testState(t testing.TB, a Assignment) *State {
	t.Helper()
	id, err := a.ID()
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewState(a, id)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func testSnapshot(t testing.TB, state *State) Snapshot {
	t.Helper()
	snapshot, err := state.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testEntry(t testing.TB, state *State, kind Kind, purpose Purpose, actor byte, operation, ticket, evidence types.Hash) Entry {
	t.Helper()
	snapshot := testSnapshot(t, state)
	c := Command{Version: Version0, AssignmentID: snapshot.AssignmentID, ExpectedSequence: snapshot.Sequence, ExpectedHead: snapshot.HeadID,
		Kind: kind, Purpose: purpose, OperationID: operation, TicketID: ticket, EvidenceID: evidence}
	c, err := c.Sign(testKey(actor))
	if err != nil {
		t.Fatal(err)
	}
	e, err := SignEntry(c, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func applyTestEntry(t testing.TB, state *State, entry Entry) types.Hash {
	t.Helper()
	before := testSnapshot(t, state)
	if err := state.ValidateNext(entry); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, testSnapshot(t, state)) {
		t.Fatal("validation mutated state")
	}
	if err := state.Apply(entry); err != nil {
		t.Fatal(err)
	}
	id, err := entry.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func denyTestEntry(t testing.TB, state *State, entry Entry, want error) {
	t.Helper()
	before := testSnapshot(t, state)
	if err := state.ValidateNext(entry); !errors.Is(err, want) {
		t.Fatalf("validation err=%v want=%v", err, want)
	}
	if err := state.Apply(entry); !errors.Is(err, want) {
		t.Fatalf("apply err=%v want=%v", err, want)
	}
	if !reflect.DeepEqual(before, testSnapshot(t, state)) {
		t.Fatal("rejected command mutated state")
	}
}

func testHistory(t testing.TB) (Assignment, []Entry, Snapshot) {
	t.Helper()
	a := testAssignment()
	state := testState(t, a)
	var history []Entry
	apply := func(e Entry) types.Hash { history = append(history, e); return applyTestEntry(t, state, e) }
	first := apply(testEntry(t, state, Admit, Audit, 4, testHash(10), types.Hash{}, types.Hash{}))
	second := apply(testEntry(t, state, Admit, Serve, 5, testHash(11), types.Hash{}, types.Hash{}))
	stop := apply(testEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(20)))
	apply(testEntry(t, state, Complete, 0, 4, types.Hash{}, first, testHash(30)))
	apply(testEntry(t, state, Complete, 0, 5, types.Hash{}, second, testHash(31)))
	apply(testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, stop))
	return a, history, testSnapshot(t, state)
}

func TestAuthorityStopsAdmissionAndDrainsExactConsumers(t *testing.T) {
	a := testAssignment()
	state := testState(t, a)
	ticket := applyTestEntry(t, state, testEntry(t, state, Admit, Audit, 4, testHash(10), types.Hash{}, types.Hash{}))
	stop := applyTestEntry(t, state, testEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(20)))
	denyTestEntry(t, state, testEntry(t, state, Admit, Serve, 5, testHash(11), types.Hash{}, types.Hash{}), ErrPhase)
	denyTestEntry(t, state, testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, stop), ErrOutstanding)
	denyTestEntry(t, state, testEntry(t, state, Complete, 0, 5, types.Hash{}, ticket, testHash(30)), ErrActor)
	denyTestEntry(t, state, testEntry(t, state, Complete, 0, 1, types.Hash{}, ticket, testHash(30)), ErrActor)
	denyTestEntry(t, state, testEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(21)), ErrPhase)
	applyTestEntry(t, state, testEntry(t, state, Complete, 0, 4, types.Hash{}, ticket, testHash(30)))
	denyTestEntry(t, state, testEntry(t, state, Complete, 0, 4, types.Hash{}, ticket, testHash(30)), ErrOperation)
	denyTestEntry(t, state, testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, testHash(21)), ErrPhase)
	retirement := applyTestEntry(t, state, testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, stop))
	final := testSnapshot(t, state)
	if final.Phase != Retired || final.Pending != 0 || final.StopID != stop || final.StopIntentID != testHash(20) || final.RetirementID != retirement {
		t.Fatalf("bad final state: %+v", final)
	}
	denyTestEntry(t, state, testEntry(t, state, Admit, Audit, 4, testHash(12), types.Hash{}, types.Hash{}), ErrPhase)
	denyTestEntry(t, state, testEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(20)), ErrPhase)
	denyTestEntry(t, state, testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, stop), ErrPhase)
}

func TestAuthorityReplaysPinnedHistoryWithoutReleasingOutstandingWork(t *testing.T) {
	a, history, final := testHistory(t)
	for length := 0; length <= len(history); length++ {
		pin := Position{Sequence: uint64(length), HeadID: final.AssignmentID}
		if length > 0 {
			pin.HeadID, _ = history[length-1].ID()
		}
		state, err := Replay(a, final.AssignmentID, history[:length], pin)
		if err != nil {
			t.Fatal(err)
		}
		if length == 3 || length == 4 {
			before := testSnapshot(t, state)
			if before.Phase != Stopping || before.Pending == 0 {
				t.Fatal("restart released outstanding work")
			}
			denyTestEntry(t, state, testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, before.StopID), ErrOutstanding)
			// Repeated observations do not manufacture a timeout or completion.
			for range 10 {
				if !reflect.DeepEqual(before, testSnapshot(t, state)) {
					t.Fatal("read changed pending operations")
				}
			}
		}
		for _, entry := range history[length:] {
			if err := state.Apply(entry); err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(testSnapshot(t, state), final) {
			t.Fatal("replay diverged")
		}
	}
	for _, entries := range [][]Entry{nil, history[:2], history[:5], append(append([]Entry(nil), history...), history[5])} {
		if _, err := Replay(a, final.AssignmentID, entries, Position{final.Sequence, final.HeadID}); !errors.Is(err, ErrHead) {
			t.Fatal("accepted a different prefix under final pin", err)
		}
	}
	mutated := append([]Entry(nil), history...)
	mutated[0], mutated[1] = mutated[1], mutated[0]
	if _, err := Replay(a, final.AssignmentID, mutated, Position{final.Sequence, final.HeadID}); !errors.Is(err, ErrHead) {
		t.Fatal("accepted reordered history", err)
	}
	if _, err := Replay(a, final.AssignmentID, history, Position{final.Sequence, testHash(90)}); !errors.Is(err, ErrHead) {
		t.Fatal("accepted substituted tail", err)
	}
}

func TestAuthorityAdmissionLimitsKeepDrainCapacity(t *testing.T) {
	a := testAssignment()
	a.MaximumOperations, a.MaximumPending = 2, 1
	state := testState(t, a)
	firstEntry := testEntry(t, state, Admit, Audit, 4, testHash(10), types.Hash{}, types.Hash{})
	first := applyTestEntry(t, state, firstEntry)
	denyTestEntry(t, state, testEntry(t, state, Admit, Serve, 5, testHash(11), types.Hash{}, types.Hash{}), ErrLimit)
	denyTestEntry(t, state, firstEntry, ErrHead)
	applyTestEntry(t, state, testEntry(t, state, Complete, 0, 4, types.Hash{}, first, testHash(30)))
	denyTestEntry(t, state, testEntry(t, state, Admit, Audit, 4, testHash(10), types.Hash{}, types.Hash{}), ErrOperation)
	operation, exists := state.LookupOperation(testPublic(4), testHash(10))
	if !exists || operation.TicketID != first || operation.CompletionID.IsZero() || operation.EvidenceID != testHash(30) {
		t.Fatal("retry lost completed operation")
	}
	second := applyTestEntry(t, state, testEntry(t, state, Admit, Serve, 5, testHash(11), types.Hash{}, types.Hash{}))
	applyTestEntry(t, state, testEntry(t, state, Complete, 0, 5, types.Hash{}, second, testHash(31)))
	denyTestEntry(t, state, testEntry(t, state, Admit, Prune, 6, testHash(12), types.Hash{}, types.Hash{}), ErrLimit)
	stop := applyTestEntry(t, state, testEntry(t, state, Stop, 0, 1, types.Hash{}, types.Hash{}, testHash(20)))
	applyTestEntry(t, state, testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, stop))
	if got := testSnapshot(t, state); got.Sequence != 6 || got.Phase != Retired || len(got.Operations) != 2 {
		t.Fatalf("admission budget consumed drain reserve: %+v", got)
	}
}

func TestAuthorityRejectsWrongRolesAndBindings(t *testing.T) {
	state := testState(t, testAssignment())
	for _, actor := range []byte{1, 2, 3, 5, 6, 99} {
		denyTestEntry(t, state, testEntry(t, state, Admit, Audit, actor, testHash(10), types.Hash{}, types.Hash{}), ErrActor)
	}
	denyTestEntry(t, state, testEntry(t, state, Stop, 0, 4, types.Hash{}, types.Hash{}, testHash(20)), ErrActor)
	denyTestEntry(t, state, testEntry(t, state, Retire, 0, 1, types.Hash{}, types.Hash{}, testHash(20)), ErrPhase)
	denyTestEntry(t, state, testEntry(t, state, Complete, 0, 4, types.Hash{}, testHash(88), testHash(30)), ErrOperation)
	base := testEntry(t, state, Admit, Audit, 4, testHash(10), types.Hash{}, types.Hash{})
	for _, change := range []struct {
		name   string
		mutate func(*Command)
		want   error
	}{
		{"assignment", func(c *Command) { c.AssignmentID = testHash(90) }, ErrAssignment},
		{"sequence", func(c *Command) { c.ExpectedSequence++ }, ErrHead},
		{"head", func(c *Command) { c.ExpectedHead = testHash(90) }, ErrHead},
	} {
		t.Run(change.name, func(t *testing.T) {
			c := base.Command
			change.mutate(&c)
			c, err := c.Sign(testKey(4))
			if err != nil {
				t.Fatal(err)
			}
			e, err := SignEntry(c, testKey(1))
			if err != nil {
				t.Fatal(err)
			}
			denyTestEntry(t, state, e, change.want)
		})
	}
	wrong, err := SignEntry(base.Command, testKey(99))
	if err != nil {
		t.Fatal(err)
	}
	denyTestEntry(t, state, wrong, ErrAssignment)
	base.Signature[0] ^= 1
	denyTestEntry(t, state, base, ErrEntry)
}

func TestAuthorityConcurrentCompareAndAppendHasOneWinner(t *testing.T) {
	state := testState(t, testAssignment())
	const contenders = 16
	entries := make([]Entry, contenders)
	for i := range entries {
		entries[i] = testEntry(t, state, Admit, Audit, 4, testHash(byte(40+i)), types.Hash{}, types.Hash{})
	}
	start := make(chan struct{})
	results := make(chan error, contenders)
	var readers sync.WaitGroup
	for _, entry := range entries {
		go func(e Entry) { <-start; results <- state.Apply(e) }(entry)
	}
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for range 100 {
				snapshot, _ := state.Snapshot()
				if len(snapshot.Operations) > 0 {
					snapshot.Operations[0].EvidenceID = testHash(99)
				}
				state.LookupOperation(testPublic(4), testHash(40))
			}
		}()
	}
	close(start)
	winners := 0
	for range contenders {
		if err := <-results; err == nil {
			winners++
		} else if !errors.Is(err, ErrHead) {
			t.Fatal(err)
		}
	}
	readers.Wait()
	final := testSnapshot(t, state)
	if winners != 1 || final.Sequence != 1 || final.Pending != 1 || len(final.Operations) != 1 || !final.Operations[0].EvidenceID.IsZero() {
		t.Fatalf("bad concurrent result: winners=%d state=%+v", winners, final)
	}
}

func TestAuthorityAssignmentAndSnapshotsAreDetached(t *testing.T) {
	a := testAssignment()
	state := testState(t, a)
	for i := range a.Consumers {
		a.Consumers[i].Purposes = 0
	}
	a.Auditors[0] = testPublic(99)
	entry := testEntry(t, state, Admit, Audit, 4, testHash(10), types.Hash{}, types.Hash{})
	applyTestEntry(t, state, entry)
	snapshot := testSnapshot(t, state)
	snapshot.Operations[0].CompletionID = testHash(30)
	operation, _ := state.LookupOperation(testPublic(4), testHash(10))
	operation.CompletionID = testHash(31)
	if !testSnapshot(t, state).Operations[0].CompletionID.IsZero() {
		t.Fatal("caller mutated internal state")
	}
	var zero State
	if _, err := zero.Snapshot(); !errors.Is(err, ErrAssignment) {
		t.Fatal("zero state reported valid snapshot", err)
	}
	if err := zero.Apply(entry); !errors.Is(err, ErrAssignment) {
		t.Fatal("zero state accepted entry", err)
	}
	if _, err := NewState(testAssignment(), types.Hash{}); !errors.Is(err, ErrAssignment) {
		t.Fatal("missing independent assignment pin", err)
	}
}
