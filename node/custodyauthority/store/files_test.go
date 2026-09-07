package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestStoreRejectsMalformedLayoutAndHistory(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, mutation := range []string{"unknown-root", "bad-ready", "wrong-ready-version", "ready-trailing", "wrong-assignment", "assignment-trailing",
		"lock-content", "slot-gap", "unknown-slot", "entry-truncated", "entry-trailing", "bad-signature", "valid-fork", "extra-entry",
		"unknown-pending", "oversized-pending", "pending-directory"} {
		t.Run(mutation, func(t *testing.T) {
			store, path := newTestStore(t)
			appendTest(t, store, history[0])
			_ = store.Close()
			entryPath := filepath.Join(path, entriesName, entryName(1))
			encoded, _ := history[0].CanonicalBytes()
			switch mutation {
			case "unknown-root":
				writeTestFile(t, filepath.Join(path, "unexpected"), nil)
			case "bad-ready":
				writeTestFile(t, filepath.Join(path, readyName), readyBytes(testHash(99)))
			case "wrong-ready-version":
				data := readyBytes(testAssignmentID(t))
				data[9] = 1
				writeTestFile(t, filepath.Join(path, readyName), data)
			case "ready-trailing":
				writeTestFile(t, filepath.Join(path, readyName), append(readyBytes(testAssignmentID(t)), 0))
			case "wrong-assignment", "assignment-trailing":
				a := testAssignment()
				if mutation == "wrong-assignment" {
					a.IncarnationID = testHash(99)
				}
				data, _ := a.CanonicalBytes()
				if mutation == "assignment-trailing" {
					data = append(data, 0)
				}
				writeTestFile(t, filepath.Join(path, assignmentName), data)
			case "lock-content":
				writeTestFile(t, filepath.Join(path, lockName), []byte{1})
			case "slot-gap", "unknown-slot":
				name := entryName(2)
				if mutation == "unknown-slot" {
					name = "unexpected"
				}
				if err := os.Rename(entryPath, filepath.Join(path, entriesName, name)); err != nil {
					t.Fatal(err)
				}
			case "entry-truncated":
				writeTestFile(t, entryPath, encoded[:len(encoded)-1])
			case "entry-trailing":
				writeTestFile(t, entryPath, append(encoded, 0))
			case "bad-signature":
				encoded[len(encoded)-1] ^= 1
				writeTestFile(t, entryPath, encoded)
			case "valid-fork":
				sibling := testEntry(t, snapshots[0], custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{})
				data, _ := sibling.CanonicalBytes()
				writeTestFile(t, entryPath, data)
			case "extra-entry":
				data, _ := history[1].CanonicalBytes()
				writeTestFile(t, filepath.Join(path, entriesName, entryName(2)), data)
			case "unknown-pending":
				writeTestFile(t, filepath.Join(path, pendingName, "entry-not-a-number"), nil)
			case "oversized-pending":
				writeTestFile(t, filepath.Join(path, pendingName, "entry-1"), make([]byte, custodyauthority.MaximumEntryBytes+1))
			case "pending-directory":
				if err := os.Mkdir(filepath.Join(path, pendingName, "entry-1"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if opened, err := Open(path, testAssignment(), testAssignmentID(t), position(snapshots[1])); err == nil {
				_ = opened.Close()
				t.Fatal("malformed store accepted")
			}
		})
	}
}

func TestStoreRejectsSymlinkedRootsAndChildren(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, name := range []string{"", lockName, assignmentName, readyName, entriesName, pendingName, filepath.Join(entriesName, entryName(1))} {
		t.Run(name, func(t *testing.T) {
			store, path := newTestStore(t)
			appendTest(t, store, history[0])
			_ = store.Close()
			original := filepath.Join(path, name)
			moved := filepath.Join(t.TempDir(), "original")
			if err := os.Rename(original, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, original); err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(path, testAssignment(), testAssignmentID(t), position(snapshots[1])); err == nil {
				_ = opened.Close()
				t.Fatal("symlinked authority data accepted")
			}
		})
	}
	store, path := newTestStore(t)
	_ = store.Close()
	target := filepath.Join(t.TempDir(), "outside")
	writeTestFile(t, target, []byte("must not become history"))
	if err := os.Symlink(target, filepath.Join(path, pendingName, "entry-1")); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t)); err == nil {
		_ = opened.Close()
		t.Fatal("symlinked pending evidence accepted")
	}
}

func TestStoreDetectsReplacedOwnershipInode(t *testing.T) {
	history, _ := testHistory(t)
	for _, name := range []string{"", lockName, entriesName, pendingName, assignmentName, readyName} {
		t.Run(name, func(t *testing.T) {
			store, path := newTestStore(t)
			original := filepath.Join(path, name)
			moved := filepath.Join(t.TempDir(), "original")
			if err := os.Rename(original, moved); err != nil {
				t.Fatal(err)
			}
			if name == "" || name == entriesName || name == pendingName {
				if err := os.Mkdir(original, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				data, err := os.ReadFile(moved)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, original, data)
			}
			if _, err := store.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatalf("ownership replacement went unnoticed: %v", err)
			}
			if _, err := store.Append(context.Background(), history[0]); !errors.Is(err, ErrUncertain) {
				t.Fatal("old owner continued after inode replacement")
			}
		})
	}
}

func TestStoreNeverPromotesOrDeletesCrashTemporaries(t *testing.T) {
	history, snapshots := testHistory(t)
	store, path := newTestStore(t)
	_ = store.Close()
	encoded, _ := history[0].CanonicalBytes()
	leftovers := map[string][]byte{"entry-1": encoded, "entry-2": encoded[:17], "entry-3": nil}
	for name, data := range leftovers {
		writeTestFile(t, filepath.Join(path, pendingName, name), data)
	}
	store = testOpen(t, path, initialPosition(t))
	if !reflect.DeepEqual(testSnapshot(t, store), snapshots[0]) {
		t.Fatal("signed temporary became a committed admission")
	}
	appendTest(t, store, history[0])
	for name, expected := range leftovers {
		actual, err := os.ReadFile(filepath.Join(path, pendingName, name))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("crash evidence was removed or modified: %s %v", name, err)
		}
	}
	_ = store.Close()
	store = testOpen(t, path, position(snapshots[1]))
	if testSnapshot(t, store).Pending != 1 {
		t.Fatal("temporary handling forgot an admission")
	}
}

func TestStoreBoundsPendingFilesAndHistoryBeforeReplay(t *testing.T) {
	history, _ := testHistory(t)
	store, path := newTestStore(t)
	for index := range MaximumPendingFiles {
		writeTestFile(t, filepath.Join(path, pendingName, fmt.Sprintf("entry-%d", index)), nil)
	}
	if _, err := store.Append(context.Background(), history[0]); !errors.Is(err, custodyauthority.ErrLimit) {
		t.Fatalf("unbounded temporary growth: %v", err)
	}
	_ = store.Close()
	store = testOpen(t, path, initialPosition(t))
	_ = store.Close()
	writeTestFile(t, filepath.Join(path, pendingName, "entry-9999"), nil)
	if opened, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t)); !errors.Is(err, custodyauthority.ErrLimit) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("unbounded pending scan: %v", err)
	}
	store, path = newTestStore(t)
	_ = store.Close()
	for index := uint64(1); index <= 2*uint64(testAssignment().MaximumOperations)+3; index++ {
		writeTestFile(t, filepath.Join(path, entriesName, entryName(index)), nil)
	}
	if opened, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t)); !errors.Is(err, custodyauthority.ErrLimit) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("unbounded history scan: %v", err)
	}
}

func TestStorePublicationNeverOverwritesACompetingSlot(t *testing.T) {
	history, snapshots := testHistory(t)
	store, path := newTestStore(t)
	sibling := testEntry(t, snapshots[0], custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{})
	data, _ := sibling.CanonicalBytes()
	competingPath := filepath.Join(path, entriesName, entryName(1))
	writeTestFile(t, competingPath, data)
	if _, err := store.Append(context.Background(), history[0]); !errors.Is(err, ErrUncertain) || !errors.Is(err, os.ErrExist) {
		t.Fatalf("competing slot was overwritten: %v", err)
	}
	actual, err := os.ReadFile(competingPath)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("competing immutable data changed")
	}
	_ = store.Close()
	if opened, err := Recover(path, testAssignment(), testAssignmentID(t), initialPosition(t), history[0]); !errors.Is(err, custodyauthority.ErrHead) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("recovery chose competing slot: %v", err)
	}
}

func TestStoreAppliesOnlyAfterDirectorySync(t *testing.T) {
	history, _ := testHistory(t)
	store, _ := newTestStore(t)
	var stages []string
	store.hooks.at = func(stage string) error {
		stages = append(stages, stage)
		current, err := store.state.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(0)
		if stage == "after-apply" {
			want = 1
		}
		if current.Sequence != want {
			t.Fatalf("state changed before persistence at %s", stage)
		}
		return nil
	}
	appendTest(t, store, history[0])
	if !reflect.DeepEqual(stages, []string{"before-write", "before-file-sync", "file-synced", "before-publish", "after-publish", "directory-synced", "after-apply"}) {
		t.Fatalf("unexpected durability order: %v", stages)
	}
}

func TestStoreCancellationWhileWaitingForWriter(t *testing.T) {
	history, _ := testHistory(t)
	store, _ := newTestStore(t)
	blocked, release := make(chan struct{}), make(chan struct{})
	store.hooks.at = func(stage string) error {
		if stage == "before-publish" {
			close(blocked)
			<-release
		}
		return nil
	}
	first := make(chan error, 1)
	go func() { _, err := store.Append(context.Background(), history[0]); first <- err }()
	<-blocked
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() { _, err := store.Append(ctx, history[1]); second <- err }()
	cancel()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting writer ignored cancellation: %v", err)
	}
	if testSnapshot(t, store).Sequence != 1 {
		t.Fatal("cancelled waiter admitted another operation")
	}
}
