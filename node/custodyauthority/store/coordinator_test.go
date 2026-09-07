package store

import (
	"bytes"
	"context"
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

func newTestCoordinator(t testing.TB) (*Coordinator, string, string) {
	t.Helper()
	authority, authorityPath := newTestStore(t)
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "intent-journal")
	coordinator, err := CreateCoordinator(authorityPath, journalPath, testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	return coordinator, authorityPath, journalPath
}

func testOpenCoordinator(t testing.TB, authorityPath, journalPath string) *Coordinator {
	t.Helper()
	coordinator, err := OpenCoordinator(authorityPath, journalPath, testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	return coordinator
}

func testCoordination(t testing.TB, coordinator *Coordinator) Coordination {
	t.Helper()
	state, err := coordinator.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func appendCoordinated(t testing.TB, coordinator *Coordinator, entry custodyauthority.Entry) Commit {
	t.Helper()
	result, err := coordinator.Append(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func setCoordinatorHooks(coordinator *Coordinator, hooks storeHooks) {
	coordinator.journal.hooks = hooks
	setAuthorityHooks(coordinator.authority, hooks)
}

var appendStages = []string{"before-write", "before-file-sync", "file-synced", "before-publish", "after-publish", "directory-synced", "after-apply"}

func isPublishedStage(stage string) bool {
	return stage == "after-publish" || stage == "directory-synced" || stage == "after-apply"
}

func TestCoordinatorReplaysConfirmedHistoryWithoutNewWrites(t *testing.T) {
	history, snapshots := testHistory(t)
	for prefix := 0; prefix <= len(history); prefix++ {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			coordinator, authorityPath, journalPath := newTestCoordinator(t)
			for index, entry := range history[:prefix] {
				result := appendCoordinated(t, coordinator, entry)
				if !result.Appended || !reflect.DeepEqual(result.Snapshot, snapshots[index+1]) {
					t.Fatal("coordinated result differs from kernel")
				}
			}
			_ = coordinator.Close()
			coordinator = testOpenCoordinator(t, authorityPath, journalPath)
			status := testCoordination(t, coordinator)
			if status.Pending != nil || status.Confirmed != position(snapshots[prefix]) || !reflect.DeepEqual(status.Authority, snapshots[prefix]) {
				t.Fatal("restart did not retain exact confirmations")
			}
			for _, entry := range history[:prefix] {
				result := appendCoordinated(t, coordinator, entry)
				if result.Appended || !reflect.DeepEqual(result.Snapshot, snapshots[prefix]) {
					t.Fatal("old retry produced a new or stale admission")
				}
			}
			for _, name := range []string{intentsName, confirmedName} {
				files, err := os.ReadDir(filepath.Join(journalPath, name))
				if err != nil || len(files) != prefix {
					t.Fatalf("retry/restart changed %s: %v", name, err)
				}
			}
			for _, entry := range history[prefix:] {
				appendCoordinated(t, coordinator, entry)
			}
			if !reflect.DeepEqual(testCoordination(t, coordinator).Authority, snapshots[len(history)]) {
				t.Fatal("reopened coordinator changed drain/retirement")
			}
		})
	}
}

func TestCoordinatorRecoversEveryAmbiguousPublicationBoundary(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, part := range []string{"intent", "authority", "confirm"} {
		for _, stage := range appendStages {
			t.Run(part+"/"+stage, func(t *testing.T) {
				coordinator, authorityPath, journalPath := newTestCoordinator(t)
				injected := errors.New("interrupted publication")
				setCoordinatorHooks(coordinator, storeHooks{at: func(at string) error {
					if at == part+"-"+stage {
						return injected
					}
					return nil
				}})
				result, err := coordinator.Append(t.Context(), history[0])
				if !errors.Is(err, ErrUncertain) || !errors.Is(err, injected) || !reflect.DeepEqual(result, Commit{}) {
					t.Fatalf("failed persistence acknowledged work: %+v %v", result, err)
				}
				if _, err := coordinator.Snapshot(); !errors.Is(err, ErrUncertain) {
					t.Fatal("uncertain state remained observable")
				}
				if _, err := coordinator.Resume(t.Context()); !errors.Is(err, ErrUncertain) {
					t.Fatal("failed handle resumed without replay")
				}
				_ = coordinator.Close()
				coordinator = testOpenCoordinator(t, authorityPath, journalPath)
				prepared := part != "intent" || isPublishedStage(stage)
				decided := part == "confirm" || (part == "authority" && isPublishedStage(stage))
				confirmed := part == "confirm" && isPublishedStage(stage)
				checkRecoveredCoordination(t, coordinator, history[0], snapshots[0], snapshots[1], prepared, decided, confirmed)
				result = appendCoordinated(t, coordinator, history[0])
				if result.Appended == decided || !reflect.DeepEqual(result.Snapshot, snapshots[1]) {
					t.Fatal("retry duplicated or forgot its decision")
				}
				status := testCoordination(t, coordinator)
				if status.Pending != nil || status.Confirmed != position(snapshots[1]) {
					t.Fatal("retry returned before independent confirmation")
				}
			})
		}
	}
}

func checkRecoveredCoordination(t testing.TB, coordinator *Coordinator, entry custodyauthority.Entry, before, after custodyauthority.Snapshot, prepared, decided, confirmed bool) {
	t.Helper()
	status := testCoordination(t, coordinator)
	wantPin, wantObserved := position(before), before
	if decided {
		wantObserved = after
	}
	if confirmed {
		wantPin = position(after)
	}
	if status.Confirmed != wantPin || !reflect.DeepEqual(status.Authority, wantObserved) {
		t.Fatalf("open advanced a pin or lost a decision: %+v", status)
	}
	if prepared && !confirmed {
		if status.Pending == nil || *status.Pending != entry {
			t.Fatal("exact pending intent was lost or substituted")
		}
	} else if status.Pending != nil {
		t.Fatal("open invented pending work")
	}
}

func TestCoordinatorIntentCannotBeCancelledSubstitutedOrBypassed(t *testing.T) {
	history, snapshots := testHistory(t)
	coordinator, authorityPath, journalPath := newTestCoordinator(t)
	ctx, cancel := context.WithCancel(context.Background())
	setCoordinatorHooks(coordinator, storeHooks{at: func(stage string) error {
		if stage == "intent-after-apply" {
			cancel()
		}
		return nil
	}})
	if result, err := coordinator.Append(ctx, history[0]); !errors.Is(err, ErrPendingAttempt) || !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, Commit{}) {
		t.Fatalf("cancelled retained intent was dropped or acknowledged: %+v %v", result, err)
	}
	_ = coordinator.Close()
	coordinator = testOpenCoordinator(t, authorityPath, journalPath)
	checkRecoveredCoordination(t, coordinator, history[0], snapshots[0], snapshots[1], true, false, false)
	sibling := testEntry(t, snapshots[0], custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{})
	stop := testEntry(t, snapshots[0], custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(98))
	for _, other := range []custodyauthority.Entry{sibling, stop, history[1]} {
		if _, err := coordinator.Append(t.Context(), other); !errors.Is(err, ErrPendingAttempt) {
			t.Fatalf("another command bypassed retained work: %v", err)
		}
	}
	copy := testCoordination(t, coordinator)
	copy.Pending.Signature[0] ^= 1
	if *testCoordination(t, coordinator).Pending != history[0] {
		t.Fatal("diagnostic pending entry aliases live intent")
	}
	result, err := coordinator.Resume(t.Context())
	if err != nil || !result.Appended || !reflect.DeepEqual(result.Snapshot, snapshots[1]) {
		t.Fatalf("explicit resume: %+v %v", result, err)
	}
	if _, err := coordinator.Resume(t.Context()); !errors.Is(err, ErrNoAttempt) {
		t.Fatal("resume invented another attempt")
	}
}

func TestCoordinatorCancellationAcrossIntentAndDecision(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, stage := range []string{"intent-before-publish", "intent-after-publish", "intent-directory-synced", "authority-before-publish", "authority-after-publish", "confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			coordinator, authorityPath, journalPath := newTestCoordinator(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			setCoordinatorHooks(coordinator, storeHooks{at: func(at string) error {
				if at == stage {
					cancel()
				}
				return nil
			}})
			result, err := coordinator.Append(ctx, history[0])
			decided := stage == "authority-after-publish" || stage == "confirm-before-publish"
			prepared := stage != "intent-before-publish"
			if decided {
				if err != nil || !result.Appended {
					t.Fatalf("post-decision cancellation lost confirmation: %v", err)
				}
			} else if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatalf("pre-decision cancellation returned result: %+v %v", result, err)
			}
			_ = coordinator.Close()
			coordinator = testOpenCoordinator(t, authorityPath, journalPath)
			checkRecoveredCoordination(t, coordinator, history[0], snapshots[0], snapshots[1], prepared, decided, decided)
			appendCoordinated(t, coordinator, history[0])
		})
	}
}

func TestCoordinatorNeverRepairsConfirmedAuthorityLoss(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, missing := range []string{"last-entry", "all-entries", "root"} {
		t.Run(missing, func(t *testing.T) {
			coordinator, authorityPath, journalPath := newTestCoordinator(t)
			for _, entry := range history[:3] {
				appendCoordinated(t, coordinator, entry)
			}
			_ = coordinator.Close()
			target := filepath.Join(authorityPath, entriesName, entryName(3))
			if missing == "all-entries" {
				target = filepath.Join(authorityPath, entriesName)
			} else if missing == "root" {
				target = authorityPath
			}
			preserved := filepath.Join(t.TempDir(), "preserved")
			if err := os.Rename(target, preserved); err != nil {
				t.Fatal(err)
			}
			if missing == "all-entries" {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if opened, err := OpenCoordinator(authorityPath, journalPath, testAssignment(), testAssignmentID(t)); err == nil {
				_ = opened.Close()
				t.Fatal("confirmed history was silently reconstructed")
			}
			if missing != "all-entries" {
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("open recreated lost authority data")
				}
			} else if files, err := os.ReadDir(target); err != nil || len(files) != 0 {
				t.Fatal("open repopulated missing history")
			}
			pin, err := os.ReadFile(filepath.Join(journalPath, confirmedName, confirmationName(3)))
			if err != nil || !bytes.Equal(pin, confirmationBytes(testAssignmentID(t), position(snapshots[3]))) {
				t.Fatal("failed recovery rewrote independent stop pin")
			}
		})
	}
}

func TestCoordinatorRejectsUnretainedOrForkedAuthoritySuffix(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			coordinator, authorityPath, journalPath := newTestCoordinator(t)
			appendCoordinated(t, coordinator, history[0])
			if pending {
				if err := coordinator.journal.prepare(t.Context(), history[1]); err != nil {
					t.Fatal(err)
				}
			}
			_ = coordinator.Close()
			authority := testOpen(t, authorityPath, position(snapshots[1]))
			entry := history[1]
			if pending {
				entry = testEntry(t, snapshots[1], custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{})
			}
			appendTest(t, authority, entry)
			_ = authority.Close()
			if opened, err := OpenCoordinator(authorityPath, journalPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, custodyauthority.ErrHead) {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatalf("authority's head replaced independent intent/pin: %v", err)
			}
		})
	}
}

func TestCoordinatorPinsAdvanceOnlyAfterVerifiedDurableResult(t *testing.T) {
	history, snapshots := testHistory(t)
	coordinator, _, journalPath := newTestCoordinator(t)
	var stages []string
	setCoordinatorHooks(coordinator, storeHooks{at: func(stage string) error {
		stages = append(stages, stage)
		confirmed, err := coordinator.journal.state.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(0)
		if stage == "confirm-after-apply" {
			want = 1
		}
		if confirmed.Sequence != want {
			t.Fatalf("pin applied before confirmation durability at %s", stage)
		}
		if stage == "authority-before-write" {
			if coordinator.journal.pending == nil {
				t.Fatal("authority mutation preceded durable intent")
			}
			encoded, _ := history[0].CanonicalBytes()
			actual, err := os.ReadFile(filepath.Join(journalPath, intentsName, entryName(1)))
			if err != nil || !bytes.Equal(actual, encoded) {
				t.Fatal("submitted entry differs from retained intent")
			}
		}
		if stage == "confirm-before-write" {
			actual, err := coordinator.authority.state.Snapshot()
			if err != nil || !reflect.DeepEqual(actual, snapshots[1]) {
				t.Fatal("confirmation preceded authority durable apply")
			}
		}
		return nil
	}})
	appendCoordinated(t, coordinator, history[0])
	var expected []string
	for _, prefix := range []string{"intent", "authority", "confirm"} {
		for _, stage := range appendStages {
			expected = append(expected, prefix+"-"+stage)
		}
	}
	if !reflect.DeepEqual(stages, expected) {
		t.Fatalf("persistence order: %v", stages)
	}
	for _, mutation := range []string{"id", "assignment", "sequence", "head"} {
		t.Run(mutation, func(t *testing.T) {
			coordinator, _, journalPath := newTestCoordinator(t)
			if err := coordinator.journal.prepare(t.Context(), history[0]); err != nil {
				t.Fatal(err)
			}
			result := Commit{EntryID: snapshots[1].HeadID, Snapshot: snapshots[1]}
			switch mutation {
			case "id":
				result.EntryID = testHash(99)
			case "assignment":
				result.Snapshot.AssignmentID = testHash(99)
			case "sequence":
				result.Snapshot.Sequence++
			case "head":
				result.Snapshot.HeadID = testHash(99)
			}
			if err := coordinator.journal.confirm(result); !errors.Is(err, ErrUncertain) {
				t.Fatalf("invalid result accepted as pin: %v", err)
			}
			files, err := os.ReadDir(filepath.Join(journalPath, confirmedName))
			if err != nil || len(files) != 0 {
				t.Fatal("invalid result published confirmation")
			}
		})
	}
}

func TestCoordinatorConcurrentWritersChooseOneIntent(t *testing.T) {
	coordinator, authorityPath, journalPath := newTestCoordinator(t)
	initial := testCoordination(t, coordinator).Authority
	entries := make([]custodyauthority.Entry, 16)
	for index := range entries {
		entries[index] = testEntry(t, initial, custodyauthority.Admit, testHash(byte(40+index)), types.Hash{}, types.Hash{})
	}
	results := make(chan error, len(entries))
	var wg sync.WaitGroup
	for _, entry := range entries {
		wg.Go(func() {
			_, err := coordinator.Append(context.Background(), entry)
			results <- err
		})
	}
	wg.Go(func() {
		for range 16 {
			if _, err := coordinator.Snapshot(); err != nil {
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
	if winners != 1 {
		t.Fatalf("same-head intent winners=%d", winners)
	}
	status := testCoordination(t, coordinator)
	if status.Confirmed.Sequence != 1 || status.Pending != nil || status.Authority.Pending != 1 {
		t.Fatal("concurrent admission confirmation differs")
	}
	_ = coordinator.Close()
	coordinator = testOpenCoordinator(t, authorityPath, journalPath)
	if !reflect.DeepEqual(testCoordination(t, coordinator), status) {
		t.Fatal("restart changed concurrent winner")
	}
}

func TestCoordinatorFullHistoryStillConfirmsDrainAndRetirement(t *testing.T) {
	assignment := testAssignment()
	assignment.MaximumOperations, assignment.MaximumPending = 2, 1
	id, err := assignment.ID()
	if err != nil {
		t.Fatal(err)
	}
	aPath, jPath := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "intents")
	authority, err := Create(aPath, assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	_ = authority.Close()
	coordinator, err := CreateCoordinator(aPath, jPath, assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	apply := func(kind custodyauthority.Kind, operation, ticket, evidence types.Hash) types.Hash {
		entry := testEntry(t, testCoordination(t, coordinator).Authority, kind, operation, ticket, evidence)
		return appendCoordinated(t, coordinator, entry).EntryID
	}
	first := apply(custodyauthority.Admit, testHash(10), types.Hash{}, types.Hash{})
	apply(custodyauthority.Complete, types.Hash{}, first, testHash(20))
	second := apply(custodyauthority.Admit, testHash(11), types.Hash{}, types.Hash{})
	stop := apply(custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(21))
	apply(custodyauthority.Complete, types.Hash{}, second, testHash(22))
	apply(custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)
	terminal := testCoordination(t, coordinator)
	if terminal.Confirmed.Sequence != 2*uint64(assignment.MaximumOperations)+2 || terminal.Pending != nil || terminal.Authority.Phase != custodyauthority.Retired {
		t.Fatal("confirmation history exhausted drain capacity")
	}
	_ = coordinator.Close()
	coordinator, err = OpenCoordinator(aPath, jPath, assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(testCoordination(t, coordinator), terminal) {
		t.Fatal("maximum-length intent/pin history did not replay")
	}
}
