package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func testPublic(seed byte) [32]byte { return [32]byte(testKey(seed).Public().(ed25519.PublicKey)) }

func testHash(seed byte) types.Hash { return types.DomainHash("test/authority-store", []byte{seed}) }

func testAssignment() custodyauthority.Assignment {
	return custodyauthority.Assignment{NetworkID: 77, GenesisID: testHash(1), ActivationHeight: 10,
		BaseID: testHash(2), ManifestID: testHash(3), StatementID: testHash(4), InitialReceiptID: testHash(5),
		CustodyPolicyID: testHash(6), IncarnationID: testHash(7), AuthorityPublicKey: testPublic(1), ReplicaPublicKey: testPublic(2),
		Auditors: [][32]byte{testPublic(3)}, Consumers: []custodyauthority.Consumer{{PublicKey: testPublic(4), Purposes: custodyauthority.AllPurposes}},
		MaximumOperations: 4, MaximumPending: 2}
}

func testAssignmentID(t testing.TB) types.Hash {
	t.Helper()
	id, err := testAssignment().ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func initialPosition(t testing.TB) custodyauthority.Position {
	return custodyauthority.Position{HeadID: testAssignmentID(t)}
}

func position(snapshot custodyauthority.Snapshot) custodyauthority.Position {
	return custodyauthority.Position{Sequence: snapshot.Sequence, HeadID: snapshot.HeadID}
}

func testSnapshot(t testing.TB, store *Store) custodyauthority.Snapshot {
	t.Helper()
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func newTestStore(t testing.TB) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authority")
	store, err := Create(path, testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, path
}

func testOpen(t testing.TB, path string, expected custodyauthority.Position) *Store {
	t.Helper()
	store, err := Open(path, testAssignment(), testAssignmentID(t), expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testEntry(t testing.TB, snapshot custodyauthority.Snapshot, kind custodyauthority.Kind, operation, ticket, evidence types.Hash) custodyauthority.Entry {
	t.Helper()
	actor := byte(4)
	purpose := custodyauthority.Purpose(0)
	if kind == custodyauthority.Stop || kind == custodyauthority.Retire {
		actor = 1
	}
	if kind == custodyauthority.Admit {
		purpose = custodyauthority.Audit
	}
	command := custodyauthority.Command{AssignmentID: snapshot.AssignmentID, ExpectedSequence: snapshot.Sequence, ExpectedHead: snapshot.HeadID,
		Kind: kind, Purpose: purpose, OperationID: operation, TicketID: ticket, EvidenceID: evidence}
	command, err := command.Sign(testKey(actor))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func testHistory(t testing.TB) ([]custodyauthority.Entry, []custodyauthority.Snapshot) {
	t.Helper()
	state, err := custodyauthority.NewState(testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := state.Snapshot()
	snapshots := []custodyauthority.Snapshot{snapshot}
	var history []custodyauthority.Entry
	apply := func(kind custodyauthority.Kind, operation, ticket, evidence types.Hash) types.Hash {
		entry := testEntry(t, snapshot, kind, operation, ticket, evidence)
		if err := state.Apply(entry); err != nil {
			t.Fatal(err)
		}
		snapshot, _ = state.Snapshot()
		history, snapshots = append(history, entry), append(snapshots, snapshot)
		return snapshot.HeadID
	}
	first := apply(custodyauthority.Admit, testHash(10), types.Hash{}, types.Hash{})
	second := apply(custodyauthority.Admit, testHash(11), types.Hash{}, types.Hash{})
	stop := apply(custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(20))
	apply(custodyauthority.Complete, types.Hash{}, first, testHash(30))
	apply(custodyauthority.Complete, types.Hash{}, second, testHash(31))
	apply(custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)
	return history, snapshots
}

func appendTest(t testing.TB, store *Store, entry custodyauthority.Entry) Commit {
	t.Helper()
	result, err := store.Append(context.Background(), entry)
	if err != nil || !result.Appended {
		t.Fatalf("append: %+v %v", result, err)
	}
	return result
}

func writeTestFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStorePersistsEveryDrainPrefixAndExactRetries(t *testing.T) {
	history, snapshots := testHistory(t)
	for prefix := 0; prefix <= len(history); prefix++ {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			store, path := newTestStore(t)
			for index, entry := range history[:prefix] {
				result := appendTest(t, store, entry)
				if !reflect.DeepEqual(result.Snapshot, snapshots[index+1]) || result.EntryID != snapshots[index+1].HeadID {
					t.Fatal("durable result differs from reference replay")
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store = testOpen(t, path, position(snapshots[prefix]))
			if !reflect.DeepEqual(testSnapshot(t, store), snapshots[prefix]) {
				t.Fatal("restart changed pending/completed/stop state")
			}
			for _, entry := range history[:prefix] {
				result, err := store.Append(context.Background(), entry)
				id, _ := entry.ID()
				if err != nil || result.Appended || result.EntryID != id || !reflect.DeepEqual(result.Snapshot, snapshots[prefix]) {
					t.Fatalf("historical retry must report CURRENT state: %+v %v", result, err)
				}
			}
			for _, entry := range history[prefix:] {
				appendTest(t, store, entry)
			}
			if !reflect.DeepEqual(testSnapshot(t, store), snapshots[len(history)]) {
				t.Fatal("drain continuation differs")
			}
			files, err := os.ReadDir(filepath.Join(path, entriesName))
			if err != nil || len(files) != len(history) {
				t.Fatalf("duplicate or missing history: %d %v", len(files), err)
			}
		})
	}
}

func TestStoreRequiresIndependentExactPins(t *testing.T) {
	history, snapshots := testHistory(t)
	store, path := newTestStore(t)
	appendTest(t, store, history[0])
	_ = store.Close()
	for _, pin := range []custodyauthority.Position{{}, position(snapshots[0]), position(snapshots[2]), {Sequence: 1, HeadID: testHash(99)}} {
		if opened, err := Open(path, testAssignment(), testAssignmentID(t), pin); err == nil {
			_ = opened.Close()
			t.Fatalf("accepted wrong pin %+v", pin)
		}
	}
	if opened, err := Open(path, testAssignment(), testHash(99), position(snapshots[1])); err == nil {
		_ = opened.Close()
		t.Fatal("accepted wrong assignment pin")
	}
	other := testAssignment()
	other.IncarnationID = testHash(98)
	otherID, _ := other.ID()
	if opened, err := Open(path, other, otherID, position(snapshots[1])); err == nil {
		_ = opened.Close()
		t.Fatal("accepted another valid assignment")
	}
	store = testOpen(t, path, position(snapshots[1]))
	if testSnapshot(t, store).Pending != 1 {
		t.Fatal("pin errors changed outstanding operations")
	}
}

func TestStoreUncertainRecoveryAdmitsOnlyExactAttempt(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			store, path := newTestStore(t)
			appendTest(t, store, history[0])
			if committed {
				appendTest(t, store, history[1])
			}
			_ = store.Close()
			recovered, err := Recover(path, testAssignment(), testAssignmentID(t), position(snapshots[1]), history[1])
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Close()
			want := snapshots[1]
			if committed {
				want = snapshots[2]
			}
			if !reflect.DeepEqual(testSnapshot(t, recovered), want) {
				t.Fatal("recovery appended/forgot an operation")
			}
			result, err := recovered.Append(context.Background(), history[1])
			if err != nil || result.Appended == committed || !reflect.DeepEqual(result.Snapshot, snapshots[2]) {
				t.Fatalf("retry resolved incorrectly: %+v %v", result, err)
			}
		})
	}
	store, path := newTestStore(t)
	for _, entry := range history[:2] {
		appendTest(t, store, entry)
	}
	_ = store.Close()
	sibling := testEntry(t, snapshots[1], custodyauthority.Admit, testHash(90), types.Hash{}, types.Hash{})
	for _, candidate := range []custodyauthority.Entry{history[0], history[2], sibling, {}} {
		if opened, err := Recover(path, testAssignment(), testAssignmentID(t), position(snapshots[1]), candidate); err == nil {
			_ = opened.Close()
			t.Fatal("recovery selected a different or malformed attempt")
		}
	}
	if opened, err := Recover(path, testAssignment(), testAssignmentID(t), position(snapshots[0]), history[0]); err == nil {
		_ = opened.Close()
		t.Fatal("recovery accepted more than one unpinned entry")
	}
	store = testOpen(t, path, position(snapshots[2]))
	appendTest(t, store, history[2])
	_ = store.Close()
	invalid := testEntry(t, snapshots[3], custodyauthority.Retire, types.Hash{}, types.Hash{}, snapshots[3].StopID)
	if opened, err := Recover(path, testAssignment(), testAssignmentID(t), position(snapshots[3]), invalid); !errors.Is(err, custodyauthority.ErrOutstanding) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("recovery ignored unresolved consumers: %v", err)
	}
}

func TestStoreNeverBootstrapsMissingOrPartialHistory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := Open(missing, testAssignment(), testAssignmentID(t), initialPosition(t)); err == nil {
		t.Fatal("open created a missing root")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed open touched missing root")
	}
	if _, err := Create(missing, testAssignment(), testHash(99)); err == nil {
		t.Fatal("invalid bootstrap pin accepted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid assignment touched disk")
	}
	if err := os.Mkdir(missing, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(missing, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing empty root was bootstrapped: %v", err)
	}
	for _, name := range []string{readyName, assignmentName, lockName, entriesName, pendingName} {
		t.Run(name, func(t *testing.T) {
			store, path := newTestStore(t)
			_ = store.Close()
			if err := os.Remove(filepath.Join(path, name)); err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t)); err == nil {
				_ = opened.Close()
				t.Fatal("partial root was repaired")
			}
			if _, err := os.Lstat(filepath.Join(path, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("open recreated a missing dependency")
			}
			if _, err := Create(path, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
				t.Fatal("create repaired a partial root")
			}
		})
	}
}

func TestStoreFailedInitializationNeverAdmitsWork(t *testing.T) {
	for _, stage := range []string{"before-ready", "ready-file-synced", "ready-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authority")
			injected := errors.New("initialization interrupted")
			store, err := create(path, testAssignment(), testAssignmentID(t), storeHooks{at: func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) || store != nil {
				t.Fatalf("failed initialization returned a handle: %v", err)
			}
			if _, err := Create(path, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
				t.Fatal("retry rebuilt a partial root")
			}
			opened, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t))
			if stage == "before-ready" {
				if err == nil {
					_ = opened.Close()
					t.Fatal("missing initialization marker accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if testSnapshot(t, opened).Pending != 0 {
				t.Fatal("initialization admitted work")
			}
		})
	}
}

func TestStoreRejectedCommandsLeaveHistoryUntouched(t *testing.T) {
	history, snapshots := testHistory(t)
	store, path := newTestStore(t)
	for _, entry := range history[:3] {
		appendTest(t, store, entry)
	}
	before := testSnapshot(t, store)
	invalid := []custodyauthority.Entry{
		{},
		testEntry(t, snapshots[0], custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{}),
		testEntry(t, before, custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{}),
		testEntry(t, before, custodyauthority.Retire, types.Hash{}, types.Hash{}, before.StopID),
		testEntry(t, before, custodyauthority.Complete, types.Hash{}, testHash(98), testHash(99)),
	}
	for _, entry := range invalid {
		if result, err := store.Append(context.Background(), entry); err == nil || !reflect.DeepEqual(result, Commit{}) {
			t.Fatalf("invalid append leaked a result: %+v %v", result, err)
		}
		if !reflect.DeepEqual(testSnapshot(t, store), before) {
			t.Fatal("invalid append changed state")
		}
	}
	files, _ := os.ReadDir(filepath.Join(path, entriesName))
	temps, _ := os.ReadDir(filepath.Join(path, pendingName))
	if len(files) != 3 || len(temps) != 0 {
		t.Fatal("rejected commands published files")
	}
}

func TestStoreFailurePoisonsHandleAndRecoveryKeepsDecision(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, stage := range []string{"before-write", "before-file-sync", "file-synced", "before-publish", "after-publish", "directory-sync-error", "directory-synced", "after-apply"} {
		t.Run(stage, func(t *testing.T) {
			store, path := newTestStore(t)
			injected := errors.New("simulated storage failure")
			store.hooks.at = func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}
			if stage == "directory-sync-error" {
				store.hooks.syncEntriesDirectory = func(string) error { return injected }
			}
			result, err := store.Append(context.Background(), history[0])
			if !errors.Is(err, ErrUncertain) || !errors.Is(err, injected) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatalf("failed I/O acknowledged an admission: %+v %v", result, err)
			}
			if _, err := store.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain memory exposed as current state")
			}
			if _, err := store.Append(context.Background(), history[0]); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain handle retried without replay")
			}
			_ = store.Close()
			store, err = Recover(path, testAssignment(), testAssignmentID(t), initialPosition(t), history[0])
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			published := stage == "after-publish" || stage == "directory-sync-error" || stage == "directory-synced" || stage == "after-apply"
			want := snapshots[0]
			if published {
				want = snapshots[1]
			}
			if !reflect.DeepEqual(testSnapshot(t, store), want) {
				t.Fatal("recovery selected the wrong side of publication")
			}
			result, err = store.Append(context.Background(), history[0])
			if err != nil || result.Appended == published || !reflect.DeepEqual(result.Snapshot, snapshots[1]) {
				t.Fatalf("retry created/lost an operation: %+v %v", result, err)
			}
		})
	}
}

func TestStoreCancellationRespectsPublicationBoundary(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, stage := range []string{"already-cancelled", "before-publish", "after-publish", "directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			store, path := newTestStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "already-cancelled" {
				cancel()
			}
			store.hooks.at = func(at string) error {
				if at == stage {
					cancel()
				}
				return nil
			}
			result, err := store.Append(ctx, history[0])
			committed := stage == "after-publish" || stage == "directory-synced"
			if committed {
				if err != nil || !result.Appended || !reflect.DeepEqual(result.Snapshot, snapshots[1]) {
					t.Fatalf("post-publication cancellation discarded decision: %+v %v", result, err)
				}
			} else if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatalf("pre-publication cancellation admitted work: %+v %v", result, err)
			}
			want := snapshots[0]
			if committed {
				want = snapshots[1]
			}
			if !reflect.DeepEqual(testSnapshot(t, store), want) {
				t.Fatal("cancellation changed the wrong state")
			}
			_ = store.Close()
			testOpen(t, path, position(want))
		})
	}
}

func TestStoreOwnsOnePermanentLockAndSerializesSameHead(t *testing.T) {
	store, path := newTestStore(t)
	lockInfo, err := os.Lstat(filepath.Join(path, lockName))
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t)); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatalf("second store bypassed ownership: %v", err)
	}
	before := testSnapshot(t, store)
	entries := make([]custodyauthority.Entry, 16)
	for index := range entries {
		entries[index] = testEntry(t, before, custodyauthority.Admit, testHash(byte(40+index)), types.Hash{}, types.Hash{})
	}
	results := make(chan error, len(entries))
	var wg sync.WaitGroup
	for _, entry := range entries {
		wg.Go(func() {
			_, err := store.Append(context.Background(), entry)
			results <- err
		})
	}
	wg.Go(func() {
		for range 16 {
			if _, err := store.Snapshot(); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, custodyauthority.ErrHead) {
			t.Fatal(err)
		}
	}
	if winners != 1 || testSnapshot(t, store).Pending != 1 {
		t.Fatalf("same-head winners=%d", winners)
	}
	current := testSnapshot(t, store)
	current.Operations[0].OperationID = testHash(99)
	if reflect.DeepEqual(testSnapshot(t, store), current) {
		t.Fatal("returned snapshot aliases live operations")
	}
	current = testSnapshot(t, store)
	_ = store.Close()
	_ = store.Close()
	store = testOpen(t, path, position(current))
	after, err := os.Lstat(filepath.Join(path, lockName))
	if err != nil || !os.SameFile(lockInfo, after) {
		t.Fatal("lock inode was replaced on restart")
	}
	if !reflect.DeepEqual(testSnapshot(t, store), current) {
		t.Fatal("restart changed concurrency winner")
	}
}

func TestStoreNilClosedAndInvalidContext(t *testing.T) {
	history, _ := testHistory(t)
	for _, store := range []*Store{nil, {}} {
		if _, err := store.Snapshot(); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if _, err := store.Append(context.Background(), history[0]); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	store, _ := newTestStore(t)
	if _, err := store.Append(nil, history[0]); !errors.Is(err, ErrStore) {
		t.Fatal("nil context accepted")
	}
	_ = store.Close()
	if _, err := store.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed state accessible")
	}
}

func TestStoreFullAdmissionBudgetRetainsDrainCapacity(t *testing.T) {
	assignment := testAssignment()
	assignment.MaximumOperations, assignment.MaximumPending = 2, 1
	id, err := assignment.ID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authority")
	store, err := Create(path, assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	appendKind := func(kind custodyauthority.Kind, operation, ticket, evidence types.Hash) types.Hash {
		entry := testEntry(t, testSnapshot(t, store), kind, operation, ticket, evidence)
		return appendTest(t, store, entry).EntryID
	}
	first := appendKind(custodyauthority.Admit, testHash(10), types.Hash{}, types.Hash{})
	appendKind(custodyauthority.Complete, types.Hash{}, first, testHash(20))
	second := appendKind(custodyauthority.Admit, testHash(11), types.Hash{}, types.Hash{})
	stop := appendKind(custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(21))
	appendKind(custodyauthority.Complete, types.Hash{}, second, testHash(22))
	appendKind(custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)
	terminal := testSnapshot(t, store)
	if terminal.Sequence != 2*uint64(assignment.MaximumOperations)+2 || terminal.Phase != custodyauthority.Retired || terminal.Pending != 0 {
		t.Fatalf("drain capacity was consumed by admissions: %+v", terminal)
	}
	_ = store.Close()
	store, err = Open(path, assignment, id, position(terminal))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(testSnapshot(t, store), terminal) {
		t.Fatal("maximum-length history failed to replay")
	}
	entry := testEntry(t, terminal, custodyauthority.Admit, testHash(12), types.Hash{}, types.Hash{})
	if _, err := store.Append(t.Context(), entry); !errors.Is(err, custodyauthority.ErrPhase) {
		t.Fatalf("exhausted retired store admitted work: %v", err)
	}
}
