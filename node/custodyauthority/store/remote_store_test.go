package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

type remoteStoreFixture struct {
	assignment custodyauthority.Assignment
	id         types.Hash
	history    []custodyauthority.Entry
	snapshots  []custodyauthority.Snapshot
}

func remoteStoreSign(t testing.TB, draft custodyauthority.Command, actor byte) custodyauthority.Entry {
	t.Helper()
	command, err := draft.Sign(testKey(actor))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func remoteStoreCommand(t testing.TB, a custodyauthority.Assignment, snapshot custodyauthority.Snapshot,
	kind custodyauthority.Kind, purpose custodyauthority.Purpose, operation, ticket, evidence types.Hash, actor byte,
) custodyauthority.Entry {
	t.Helper()
	return remoteStoreSign(t, custodyauthority.Command{Version: a.Version, AssignmentID: snapshot.AssignmentID,
		ExpectedSequence: snapshot.Sequence, ExpectedHead: snapshot.HeadID, Kind: kind, Purpose: purpose,
		OperationID: operation, TicketID: ticket, EvidenceID: evidence}, actor)
}

// One NEW assignment and original coordinator; no B authority or copied roots.
// Both ordinary Audit and Serve tickets exist before the remote hold begins.
func newRemoteStoreFixture(t testing.TB) remoteStoreFixture {
	t.Helper()
	a, err := custodyauthority.WithRemoteParticipant(testAssignment(), testPublic(11), testPublic(12))
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.ID()
	if err != nil {
		t.Fatal(err)
	}
	state, err := custodyauthority.NewState(a, id)
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := state.Snapshot()
	f := remoteStoreFixture{assignment: a, id: id, snapshots: []custodyauthority.Snapshot{initial}}
	appendEntry := func(entry custodyauthority.Entry) {
		t.Helper()
		if err := state.Apply(entry); err != nil {
			t.Fatal(err)
		}
		snapshot, err := state.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		f.history, f.snapshots = append(f.history, entry), append(f.snapshots, snapshot)
	}
	ordinary := func(kind custodyauthority.Kind, purpose custodyauthority.Purpose, operation, ticket, evidence types.Hash, actor byte) {
		t.Helper()
		appendEntry(remoteStoreCommand(t, a, f.snapshots[len(f.snapshots)-1], kind, purpose, operation, ticket, evidence, actor))
	}
	ordinary(custodyauthority.Admit, custodyauthority.Audit, testHash(100), types.Hash{}, types.Hash{}, 4)
	ordinary(custodyauthority.Admit, custodyauthority.Serve, testHash(101), types.Hash{}, types.Hash{}, 4)
	serveID, _ := f.history[1].ID()
	begin, err := custodyauthority.BuildRemoteBeginCommand(a, f.history[1], testHash(102), position(f.snapshots[2]))
	if err != nil {
		t.Fatal(err)
	}
	appendEntry(remoteStoreSign(t, begin, 11))
	drained, err := custodyauthority.BuildRemoteDrainedCommand(a, f.history[2], testHash(103), position(f.snapshots[3]))
	if err != nil {
		t.Fatal(err)
	}
	appendEntry(remoteStoreSign(t, drained, 11))
	auditID, _ := f.history[0].ID()
	ordinary(custodyauthority.Complete, 0, types.Hash{}, auditID, testHash(104), 4)
	ordinary(custodyauthority.Complete, 0, types.Hash{}, serveID, testHash(105), 4)
	ordinary(custodyauthority.Stop, 0, types.Hash{}, types.Hash{}, testHash(106), 1)
	ordinary(custodyauthority.Retire, 0, types.Hash{}, types.Hash{}, f.snapshots[7].StopID, 1)
	return f
}

func (f remoteStoreFixture) coordinator(t testing.TB, prefix int) (*Coordinator, string, string) {
	t.Helper()
	aPath, jPath := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "pins")
	owner, err := CreateCoordinatedAuthority(aPath, jPath, f.assignment, f.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	for _, entry := range f.history[:prefix] {
		appendCoordinated(t, owner, entry)
	}
	return owner, aPath, jPath
}

func (f remoteStoreFixture) open(t testing.TB, aPath, jPath string) *Coordinator {
	t.Helper()
	owner, err := OpenCoordinator(aPath, jPath, f.assignment, f.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner
}

func (f remoteStoreFixture) blockedEntries(t testing.TB, snapshot custodyauthority.Snapshot) []custodyauthority.Entry {
	t.Helper()
	audit, _ := f.history[0].ID()
	serve, _ := f.history[1].ID()
	return []custodyauthority.Entry{
		remoteStoreCommand(t, f.assignment, snapshot, custodyauthority.Admit, custodyauthority.Audit, testHash(110), types.Hash{}, types.Hash{}, 4),
		remoteStoreCommand(t, f.assignment, snapshot, custodyauthority.Complete, 0, types.Hash{}, audit, testHash(111), 4),
		remoteStoreCommand(t, f.assignment, snapshot, custodyauthority.Complete, 0, types.Hash{}, serve, testHash(112), 4),
		remoteStoreCommand(t, f.assignment, snapshot, custodyauthority.Stop, 0, types.Hash{}, types.Hash{}, testHash(113), 1),
		remoteStoreCommand(t, f.assignment, snapshot, custodyauthority.Retire, 0, types.Hash{}, types.Hash{}, testHash(114), 1),
		remoteStoreCommand(t, f.assignment, snapshot, custodyauthority.RemoteBegin, custodyauthority.Serve, testHash(115), serve, testHash(101), 11),
	}
}

func TestRemoteStoreAndCoordinatorFenceEveryNewTransition(t *testing.T) {
	f := newRemoteStoreFixture(t)
	for _, coordinated := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw-store", true: "original-coordinator"}[coordinated], func(t *testing.T) {
			var appendEntry func(custodyauthority.Entry) (Commit, error)
			var current func() custodyauthority.Snapshot
			var roots []string
			if coordinated {
				owner, aPath, jPath := f.coordinator(t, 3)
				_ = owner.Close()
				owner = f.open(t, aPath, jPath)
				appendEntry = func(entry custodyauthority.Entry) (Commit, error) { return owner.Append(t.Context(), entry) }
				current = func() custodyauthority.Snapshot { return testCoordination(t, owner).Authority }
				roots = []string{aPath, jPath}
			} else {
				path := filepath.Join(t.TempDir(), "authority")
				owner, err := Create(path, f.assignment, f.id)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range f.history[:3] {
					if _, err := owner.Append(t.Context(), entry); err != nil {
						t.Fatal(err)
					}
				}
				_ = owner.Close()
				owner, err = Open(path, f.assignment, f.id, position(f.snapshots[3]))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = owner.Close() })
				appendEntry = func(entry custodyauthority.Entry) (Commit, error) { return owner.Append(t.Context(), entry) }
				current = func() custodyauthority.Snapshot { return testSnapshot(t, owner) }
				roots = []string{path}
			}
			before := custodyCommandPathTrees(t, roots)
			for _, entry := range f.blockedEntries(t, current()) {
				if _, err := appendEntry(entry); !errors.Is(err, custodyauthority.ErrRemoteActive) {
					t.Fatalf("kind=%d bypassed intrinsic remote hold: %v", entry.Command.Kind, err)
				}
			}
			for _, old := range f.history[:3] {
				result, err := appendEntry(old)
				if err != nil || result.Appended || !reflect.DeepEqual(result.Snapshot, f.snapshots[3]) {
					t.Fatal("historical lookup cleared or duplicated the remote hold", result, err)
				}
			}
			if !reflect.DeepEqual(current(), f.snapshots[3]) || !reflect.DeepEqual(custodyCommandPathTrees(t, roots), before) {
				t.Fatal("rejected commands/history lookup changed durable remote state")
			}
			for _, next := range f.history[3:] {
				if _, err := appendEntry(next); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(current(), f.snapshots[8]) {
				t.Fatal("explicit drain/completions did not preserve remote history")
			}
		})
	}
}

func TestRemoteOperationGuardRequiresConfirmedDrain(t *testing.T) {
	f := newRemoteStoreFixture(t)
	owner, aPath, jPath := f.coordinator(t, 3)
	bindings := make([]OperationBinding, 0, 2)
	for _, admission := range f.history[:2] {
		ticket, _ := admission.ID()
		c := admission.Command
		bindings = append(bindings, OperationBinding{AssignmentID: f.id, TicketID: ticket,
			ConsumerPublicKey: c.ActorPublicKey, OperationID: c.OperationID, Purpose: c.Purpose})
	}
	check := func(want error) {
		t.Helper()
		for _, binding := range bindings {
			err := owner.WithOperation(t.Context(), binding, func() error { t.Error("remote/unconfirmed work entered live callback"); return nil })
			if !errors.Is(err, want) {
				t.Fatal("live operation crossed remote/pending fence", err)
			}
		}
	}
	check(custodyauthority.ErrRemoteActive)
	// A B-signed/co-signed Drained value alone does not change the owner.
	if _, err := f.history[3].CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	check(custodyauthority.ErrRemoteActive)
	owner.mu.Lock()
	err := owner.journal.prepare(t.Context(), f.history[3])
	if err == nil {
		_, err = owner.authority.Append(t.Context(), f.history[3])
	}
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	status := testCoordination(t, owner)
	if status.Pending == nil || status.Authority.Remote != nil || status.Confirmed != position(f.snapshots[3]) {
		t.Fatal("fixture did not reach decided-but-unconfirmed drain", status)
	}
	check(ErrPendingAttempt)
	_ = owner.Close()
	owner = f.open(t, aPath, jPath)
	check(ErrPendingAttempt)
	if result, err := owner.Resume(t.Context()); err != nil || result.Appended || !reflect.DeepEqual(result.Snapshot, f.snapshots[4]) {
		t.Fatal("explicit resume changed/repeated the already decided drain", result, err)
	}
	status = testCoordination(t, owner)
	if status.Pending != nil || status.Authority.Pending != 2 || status.Authority.Remote != nil {
		t.Fatal("drain implicitly completed an admitted ticket", status)
	}
	beginID, _ := f.history[2].ID()
	drainID, _ := f.history[3].ID()
	serveID, _ := f.history[1].ID()
	for _, operation := range status.Authority.Operations {
		if operation.TicketID == serveID && (operation.RemoteBeginID != beginID || operation.RemoteDrainID != drainID ||
			operation.RemotePlanID != testHash(102) || operation.RemoteTombstoneID != testHash(103)) {
			t.Fatal("confirmed drain lost immutable session provenance", operation)
		}
	}
	// This is a checked local callback under the recovered original owner, not
	// remote execution or a grant from the detached B command.
	if err := owner.WithOperation(t.Context(), bindings[0], func() error { return nil }); err != nil {
		t.Fatal("confirmed drain did not restore ordinary local operation checks", err)
	}
	checkSealedServe := func() {
		t.Helper()
		if err := owner.WithOperation(t.Context(), bindings[1], func() error {
			t.Error("sealed remote Serve entered a generic live callback")
			return nil
		}); !errors.Is(err, custodyauthority.ErrOperation) {
			t.Fatal("drained ticket became a generic offline Serve fallback", err)
		}
	}
	checkSealedServe()
	_ = owner.Close()
	owner = f.open(t, aPath, jPath)
	checkSealedServe()
	if err := owner.WithOperation(t.Context(), bindings[0], func() error { return nil }); err != nil {
		t.Fatal("reopen incorrectly consumed the unrelated Audit ticket", err)
	}
	repeat := f.blockedEntries(t, status.Authority)[5]
	if _, err := owner.Append(t.Context(), repeat); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal("the drained Serve ticket started a second remote session", err)
	}
}

func TestRemoteStoreRejectsLegacyPruneDeliveryEnvelopes(t *testing.T) {
	f := newRemoteStoreFixture(t)
	admit := remoteStoreCommand(t, f.assignment, f.snapshots[0], custodyauthority.Admit, custodyauthority.Prune, testHash(120), types.Hash{}, types.Hash{}, 4)
	complete := remoteStoreCommand(t, f.assignment, f.snapshots[1], custodyauthority.Complete, 0, types.Hash{}, testHash(121), testHash(122), 4)
	client, server := testHash(123), testHash(124)
	admission := AdmissionIntent{ClientPeerID: client, ServerPeerID: server, Entry: admit}
	completion := CompletionIntent{ClientPeerID: client, ServerPeerID: server, Entry: complete}
	if _, err := admission.CanonicalBytes(); !errors.Is(err, ErrAdmissionIntent) {
		t.Fatal("legacy admission envelope accepted V1", err)
	}
	if _, err := completion.CanonicalBytes(); !errors.Is(err, ErrCompletionIntent) {
		t.Fatal("legacy completion envelope accepted V1", err)
	}
	for _, test := range []struct {
		prefix string
		entry  custodyauthority.Entry
	}{
		{"OMCASEND\x00\x00", admit}, {"OMCCSEND\x00\x00", complete},
	} {
		b, _ := test.entry.CanonicalBytes()
		input := append([]byte(test.prefix), client[:]...)
		input = append(input, server[:]...)
		input = append(input, b...)
		if bytes.HasPrefix(input, []byte("OMCASEND")) {
			if _, err := DecodeAdmissionIntent(input); err == nil {
				t.Fatal("legacy decoder accepted V1 admission")
			}
		} else if _, err := DecodeCompletionIntent(input); err == nil {
			t.Fatal("legacy decoder accepted V1 completion")
		}
	}
	for _, kind := range []string{"admission", "completion"} {
		path := filepath.Join(t.TempDir(), kind)
		if kind == "admission" {
			if _, err := CreateAdmissionOutbox(path, f.assignment, admission, testHash(125)); !errors.Is(err, ErrAdmissionIntent) {
				t.Fatal("legacy outbox accepted a V1 assignment", err)
			}
		} else if _, err := CreateCompletionOutbox(path, f.assignment, completion, testHash(125)); !errors.Is(err, ErrCompletionIntent) {
			t.Fatal("legacy outbox accepted a V1 assignment", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("rejected legacy outbox created a root", err)
		}
	}
	// Relabelling the commands back to V0 does not make the V1 assignment a
	// valid legacy Prune destination, even though the old envelope is canonical.
	admitV0, completeV0 := admit.Command, complete.Command
	admitV0.Version, admitV0.Signature = custodyauthority.Version0, [64]byte{}
	completeV0.Version, completeV0.Signature = custodyauthority.Version0, [64]byte{}
	admission.Entry, completion.Entry = remoteStoreSign(t, admitV0, 4), remoteStoreSign(t, completeV0, 4)
	admissionID, err := admission.ID()
	if err != nil {
		t.Fatal("V0 envelope changed", err)
	}
	completionID, err := completion.ID()
	if err != nil {
		t.Fatal("V0 envelope changed", err)
	}
	if _, err := CreateAdmissionOutbox(filepath.Join(t.TempDir(), "relabeled-admit"), f.assignment, admission, admissionID); !errors.Is(err, ErrAdmissionIntent) {
		t.Fatal("legacy admission destination accepted V1 assignment", err)
	}
	if _, err := CreateCompletionOutbox(filepath.Join(t.TempDir(), "relabeled-complete"), f.assignment, completion, completionID); !errors.Is(err, ErrCompletionIntent) {
		t.Fatal("legacy completion destination accepted V1 assignment", err)
	}
}

func TestRemoteRecoverAndReopenRejectPendingClosure(t *testing.T) {
	f := newRemoteStoreFixture(t)
	owner, aPath, jPath := f.coordinator(t, 3)
	_ = owner.Close()
	closure := f.blockedEntries(t, f.snapshots[3])[1]
	before := custodyCommandPathTrees(t, []string{aPath, jPath})
	if raw, err := Recover(aPath, f.assignment, f.id, position(f.snapshots[3]), closure); !errors.Is(err, custodyauthority.ErrRemoteActive) {
		if raw != nil {
			_ = raw.Close()
		}
		t.Fatal("raw uncertain-append recovery bypassed active remote hold", err)
	}
	if !reflect.DeepEqual(custodyCommandPathTrees(t, []string{aPath, jPath}), before) {
		t.Fatal("rejected recovery changed remote history")
	}
	b, err := closure.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(jPath, intentsName, entryName(4)), b)
	if reopened, err := OpenCoordinator(aPath, jPath, f.assignment, f.id); !errors.Is(err, custodyauthority.ErrRemoteActive) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("reopen promoted a forbidden retained completion", err)
	}
	// The malformed intent is preserved, and failed replay releases its locks.
	if got, err := os.ReadFile(filepath.Join(jPath, intentsName, entryName(4))); err != nil || !bytes.Equal(got, b) {
		t.Fatal("reopen erased or changed the rejected attempt", err)
	}
	raw, err := Open(aPath, f.assignment, f.id, position(f.snapshots[3]))
	if err != nil {
		t.Fatal("failed coordinator open leaked authority ownership", err)
	}
	defer raw.Close()
	if got := testSnapshot(t, raw); !reflect.DeepEqual(got, f.snapshots[3]) {
		t.Fatal("rejected pending completion lost the intrinsic fence", got)
	}
}

func TestRemoteCoordinatorReopensBeyondVersionZeroHistoryLimit(t *testing.T) {
	f := newRemoteStoreFixture(t)
	a := f.assignment
	a.MaximumOperations, a.MaximumPending = 3, 2
	id, _ := a.ID()
	owner, err := CreateCoordinatedAuthority(filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "pins"), a, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	for index := byte(0); index < 3; index++ {
		admission := remoteStoreCommand(t, a, testCoordination(t, owner).Authority, custodyauthority.Admit, custodyauthority.Serve, testHash(130+index), types.Hash{}, types.Hash{}, 4)
		ticket, _ := admission.ID()
		appendCoordinated(t, owner, admission)
		begin, err := custodyauthority.BuildRemoteBeginCommand(a, admission, testHash(140+index), testCoordination(t, owner).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		begun := remoteStoreSign(t, begin, 11)
		appendCoordinated(t, owner, begun)
		drain, err := custodyauthority.BuildRemoteDrainedCommand(a, begun, testHash(150+index), testCoordination(t, owner).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		appendCoordinated(t, owner, remoteStoreSign(t, drain, 11))
		appendCoordinated(t, owner, remoteStoreCommand(t, a, testCoordination(t, owner).Authority, custodyauthority.Complete, 0, types.Hash{}, ticket, testHash(160+index), 4))
	}
	appendCoordinated(t, owner, remoteStoreCommand(t, a, testCoordination(t, owner).Authority, custodyauthority.Stop, 0, types.Hash{}, types.Hash{}, testHash(170), 1))
	appendCoordinated(t, owner, remoteStoreCommand(t, a, testCoordination(t, owner).Authority, custodyauthority.Retire, 0, types.Hash{}, types.Hash{}, testCoordination(t, owner).Authority.StopID, 1))
	before := testCoordination(t, owner)
	if before.Confirmed.Sequence != custodyauthority.MaximumEntries(a) || before.Confirmed.Sequence <= 2*uint64(a.MaximumOperations)+2 {
		t.Fatal("fixture did not exceed the V0 history bound", before)
	}
	aPath, jPath := owner.authority.path, owner.journal.path
	_ = owner.Close()
	owner, err = OpenCoordinator(aPath, jPath, a, id)
	if err != nil || !reflect.DeepEqual(testCoordination(t, owner), before) {
		t.Fatal("V1 history was truncated or rejected using V0 capacity", err)
	}
}
