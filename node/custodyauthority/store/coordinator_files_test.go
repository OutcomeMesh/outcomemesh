package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestCoordinatorBootstrapAndOpenNeverRepairMissingData(t *testing.T) {
	coordinator, authorityPath, journalPath := newTestCoordinator(t)
	_ = coordinator.Close()
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenCoordinator(authorityPath, missing, testAssignment(), testAssignmentID(t)); err == nil {
		t.Fatal("open bootstrapped missing intent journal")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("open touched missing journal")
	}
	if _, err := CreateCoordinator(authorityPath, missing, testAssignment(), testHash(99)); err == nil {
		t.Fatal("invalid assignment pin accepted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid pin created files")
	}
	if _, err := CreateCoordinator(authorityPath, journalPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing journal replaced: %v", err)
	}
	history, snapshots := testHistory(t)
	authority := testOpen(t, authorityPath, initialPosition(t))
	appendTest(t, authority, history[0])
	_ = authority.Close()
	if _, err := CreateCoordinator(authorityPath, missing, testAssignment(), testAssignmentID(t)); !errors.Is(err, custodyauthority.ErrHead) {
		t.Fatalf("new pin journal attached to used authority: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(missing, intentReadyName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed attachment published initialization")
	}
	if _, err := CreateCoordinator(authorityPath, missing, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
		t.Fatal("partial attachment was repaired")
	}
	authority = testOpen(t, authorityPath, position(snapshots[1]))
	if testSnapshot(t, authority).Pending != 1 {
		t.Fatal("failed attachment changed authority")
	}
	_ = authority.Close()
	for _, name := range []string{intentReadyName, intentLockName, assignmentName, intentsName, confirmedName, pendingName} {
		t.Run("missing/"+name, func(t *testing.T) {
			coordinator, aPath, jPath := newTestCoordinator(t)
			_ = coordinator.Close()
			if err := os.Remove(filepath.Join(jPath, name)); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); err == nil {
				_ = opened.Close()
				t.Fatal("missing journal dependency repaired")
			}
			if _, err := os.Lstat(filepath.Join(jPath, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("open recreated journal dependency")
			}
		})
	}
}

func TestCoordinatorFailedInitializationReleasesBothLocks(t *testing.T) {
	for _, stage := range []string{"intent-before-ready", "intent-ready-file-synced", "intent-ready-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			authority, aPath := newTestStore(t)
			_ = authority.Close()
			jPath := filepath.Join(t.TempDir(), "intent-journal")
			injected := errors.New("initialization storage failure")
			coordinator, err := createCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t), storeHooks{at: func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) || coordinator != nil {
				t.Fatalf("failed creation returned a usable coordinator: %v", err)
			}
			authority = testOpen(t, aPath, initialPosition(t))
			_ = authority.Close()
			if _, err := CreateCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
				t.Fatal("failed initialization was rebuilt")
			}
			coordinator, err = OpenCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t))
			if stage == "intent-before-ready" {
				if err == nil || errors.Is(err, ErrBusy) {
					_ = coordinator.Close()
					t.Fatalf("partial initialization was usable or retained its lock: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Close()
			if status := testCoordination(t, coordinator); status.Pending != nil || status.Confirmed != initialPosition(t) {
				t.Fatal("failed initialization created an intent or pin")
			}
		})
	}
}

func TestCoordinatorRequiresDisjointNonSymlinkedRoots(t *testing.T) {
	coordinator, authorityPath, journalPath := newTestCoordinator(t)
	_ = coordinator.Close()
	for _, pair := range [][2]string{{authorityPath, authorityPath}, {authorityPath, filepath.Join(authorityPath, "intents-root")},
		{authorityPath, filepath.Dir(authorityPath)}, {journalPath, journalPath}} {
		if _, err := CreateCoordinator(pair[0], pair[1], testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrRootOverlap) {
			t.Fatalf("overlapping roots: %v", err)
		}
	}
	for _, name := range []string{"", intentLockName, intentReadyName, assignmentName, intentsName, confirmedName, pendingName} {
		t.Run("symlink/"+name, func(t *testing.T) {
			coordinator, aPath, jPath := newTestCoordinator(t)
			_ = coordinator.Close()
			original, moved := filepath.Join(jPath, name), filepath.Join(t.TempDir(), "preserved")
			if err := os.Rename(original, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, original); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); err == nil {
				_ = opened.Close()
				t.Fatal("symlinked journal accepted")
			}
		})
	}
	// A symlink above the immediate parent must not disguise containment.
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(authorityPath), alias); err != nil {
		t.Fatal(err)
	}
	aliasedChild := filepath.Join(alias, filepath.Base(authorityPath), "nested-journal")
	if _, err := CreateCoordinator(authorityPath, aliasedChild, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrRootOverlap) {
		t.Fatalf("ancestor alias disguised nested roots: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(authorityPath, "nested-journal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("overlap rejection created a nested root")
	}
}

func TestCoordinatorRejectsMalformedIntentAndConfirmationHistory(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, mutation := range []string{"ready", "assignment", "unknown-root", "intent-gap", "intent-corrupt", "intent-trailing", "intent-fork",
		"pin-gap", "pin-corrupt", "pin-truncated", "pin-trailing", "two-pending", "pin-without-intent", "intent-symlink", "pin-symlink", "pending-name", "pending-size"} {
		t.Run(mutation, func(t *testing.T) {
			coordinator, authorityPath, journalPath := newTestCoordinator(t)
			appendCoordinated(t, coordinator, history[0])
			_ = coordinator.Close()
			intentPath := filepath.Join(journalPath, intentsName, entryName(1))
			pinPath := filepath.Join(journalPath, confirmedName, confirmationName(1))
			intent, _ := history[0].CanonicalBytes()
			pin := confirmationBytes(testAssignmentID(t), position(snapshots[1]))
			switch mutation {
			case "ready":
				writeTestFile(t, filepath.Join(journalPath, intentReadyName), readyBytes(testAssignmentID(t)))
			case "assignment":
				a := testAssignment()
				a.IncarnationID = testHash(99)
				data, _ := a.CanonicalBytes()
				writeTestFile(t, filepath.Join(journalPath, assignmentName), data)
			case "unknown-root":
				writeTestFile(t, filepath.Join(journalPath, "unexpected"), nil)
			case "intent-gap":
				if err := os.Rename(intentPath, filepath.Join(journalPath, intentsName, entryName(2))); err != nil {
					t.Fatal(err)
				}
			case "intent-corrupt":
				intent[len(intent)-1] ^= 1
				writeTestFile(t, intentPath, intent)
			case "intent-trailing":
				writeTestFile(t, intentPath, append(intent, 0))
			case "intent-fork":
				sibling := testEntry(t, snapshots[0], custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{})
				data, _ := sibling.CanonicalBytes()
				writeTestFile(t, intentPath, data)
			case "pin-gap":
				if err := os.Rename(pinPath, filepath.Join(journalPath, confirmedName, confirmationName(2))); err != nil {
					t.Fatal(err)
				}
			case "pin-corrupt":
				pin[len(pin)-1] ^= 1
				writeTestFile(t, pinPath, pin)
			case "pin-truncated":
				writeTestFile(t, pinPath, pin[:len(pin)-1])
			case "pin-trailing":
				writeTestFile(t, pinPath, append(pin, 0))
			case "two-pending":
				for index, entry := range history[1:3] {
					data, _ := entry.CanonicalBytes()
					writeTestFile(t, filepath.Join(journalPath, intentsName, entryName(uint64(index+2))), data)
				}
			case "pin-without-intent":
				if err := os.Remove(intentPath); err != nil {
					t.Fatal(err)
				}
			case "intent-symlink", "pin-symlink":
				target := intentPath
				if mutation == "pin-symlink" {
					target = pinPath
				}
				moved := filepath.Join(t.TempDir(), "preserved")
				if err := os.Rename(target, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, target); err != nil {
					t.Fatal(err)
				}
			case "pending-name":
				writeTestFile(t, filepath.Join(journalPath, pendingName, "unknown"), nil)
			case "pending-size":
				writeTestFile(t, filepath.Join(journalPath, pendingName, "entry-1"), make([]byte, custodyauthority.MaximumEntryBytes+1))
			}
			if opened, err := OpenCoordinator(authorityPath, journalPath, testAssignment(), testAssignmentID(t)); err == nil {
				_ = opened.Close()
				t.Fatal("malformed retained history accepted")
			}
			authority := testOpen(t, authorityPath, position(snapshots[1]))
			if !reflect.DeepEqual(testSnapshot(t, authority), snapshots[1]) {
				t.Fatal("journal rejection changed authority")
			}
		})
	}
}

func TestCoordinatorRejectsCaseAliasedNestedRootsBeforeMutation(t *testing.T) {
	coordinator, aPath, _ := newTestCoordinator(t)
	_ = coordinator.Close()
	alias := filepath.Join(filepath.Dir(aPath), strings.ToUpper(filepath.Base(aPath)))
	original, err := os.Lstat(aPath)
	if err != nil {
		t.Fatal(err)
	}
	aliased, err := os.Lstat(alias)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("filesystem is case-sensitive")
	}
	if err != nil || !os.SameFile(original, aliased) {
		t.Fatalf("unexpected case-alias fixture: %v", err)
	}
	jPath := filepath.Join(alias, "nested-journal")
	if _, err := CreateCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrRootOverlap) {
		t.Fatalf("case alias concealed a nested root: %v", err)
	}
	if _, err := os.Lstat(jPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("overlap rejection created files inside the authority root")
	}
	testOpen(t, aPath, initialPosition(t))
}

func TestCoordinatorRejectsCommandsBeforePersistingIntent(t *testing.T) {
	history, snapshots := testHistory(t)
	coordinator, _, journalPath := newTestCoordinator(t)
	for _, entry := range history[:3] {
		appendCoordinated(t, coordinator, entry)
	}
	before := testCoordination(t, coordinator)
	invalid := []custodyauthority.Entry{{}, testEntry(t, snapshots[3], custodyauthority.Admit, testHash(99), types.Hash{}, types.Hash{}),
		testEntry(t, snapshots[3], custodyauthority.Retire, types.Hash{}, types.Hash{}, snapshots[3].StopID),
		testEntry(t, snapshots[0], custodyauthority.Admit, testHash(98), types.Hash{}, types.Hash{})}
	for _, entry := range invalid {
		if result, err := coordinator.Append(t.Context(), entry); err == nil || !reflect.DeepEqual(result, Commit{}) {
			t.Fatalf("invalid entry returned result: %+v %v", result, err)
		}
		if !reflect.DeepEqual(testCoordination(t, coordinator), before) {
			t.Fatal("invalid command changed retained state")
		}
	}
	for _, directory := range []string{intentsName, confirmedName} {
		files, err := os.ReadDir(filepath.Join(journalPath, directory))
		if err != nil || len(files) != 3 {
			t.Fatal("invalid command persisted intent or pin")
		}
	}
}

func TestCoordinatorJournalBoundsAndDurabilityErrors(t *testing.T) {
	history, snapshots := testHistory(t)
	for _, directory := range []string{intentsName, confirmedName, entriesName} {
		t.Run("sync/"+directory, func(t *testing.T) {
			coordinator, aPath, jPath := newTestCoordinator(t)
			injected := errors.New("directory fsync failed")
			setCoordinatorHooks(coordinator, storeHooks{syncEntriesDirectory: func(path string) error {
				if filepath.Base(path) == directory {
					return injected
				}
				return syncDirectory(path)
			}})
			if result, err := coordinator.Append(t.Context(), history[0]); !errors.Is(err, ErrUncertain) || !errors.Is(err, injected) || !reflect.DeepEqual(result, Commit{}) {
				t.Fatalf("required sync failure returned a result: %+v %v", result, err)
			}
			_ = coordinator.Close()
			coordinator = testOpenCoordinator(t, aPath, jPath)
			appendCoordinated(t, coordinator, history[0])
			if testCoordination(t, coordinator).Confirmed != position(snapshots[1]) {
				t.Fatal("sync failure recovery lost confirmation")
			}
		})
	}
	coordinator, aPath, jPath := newTestCoordinator(t)
	for index := range MaximumPendingFiles {
		writeTestFile(t, filepath.Join(jPath, pendingName, fmt.Sprintf("entry-%d", index)), nil)
	}
	if _, err := coordinator.Append(t.Context(), history[0]); !errors.Is(err, custodyauthority.ErrLimit) {
		t.Fatalf("unbounded journal temporary growth: %v", err)
	}
	_ = coordinator.Close()
	coordinator = testOpenCoordinator(t, aPath, jPath)
	if testCoordination(t, coordinator).Pending != nil {
		t.Fatal("temporary evidence was promoted to intent")
	}
	_ = coordinator.Close()
	writeTestFile(t, filepath.Join(jPath, pendingName, "entry-99999"), nil)
	if opened, err := OpenCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, custodyauthority.ErrLimit) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("unbounded temporary scan: %v", err)
	}
}

func TestCoordinatorOwnsBothLocksAndRejectsReplacedInodes(t *testing.T) {
	coordinator, aPath, jPath := newTestCoordinator(t)
	if opened, err := OpenCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("second coordinator bypassed intent lock")
	}
	if opened, err := Open(aPath, testAssignment(), testAssignmentID(t), initialPosition(t)); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("raw authority writer bypassed coordinator")
	}
	_ = coordinator.Close()
	// The intent store has a different role marker and cannot be opened as an
	// authority simply because it contains valid authority-signed entry bytes.
	if opened, err := Open(jPath, testAssignment(), testAssignmentID(t), initialPosition(t)); err == nil {
		_ = opened.Close()
		t.Fatal("intent journal was accepted as authority")
	}
	for _, name := range []string{"", intentLockName, assignmentName, intentReadyName, intentsName, confirmedName, pendingName} {
		t.Run(name, func(t *testing.T) {
			coordinator, _, jPath := newTestCoordinator(t)
			original, moved := filepath.Join(jPath, name), filepath.Join(t.TempDir(), "preserved")
			if err := os.Rename(original, moved); err != nil {
				t.Fatal(err)
			}
			if name == "" || name == intentsName || name == confirmedName || name == pendingName {
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
			if _, err := coordinator.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatalf("replacement left old coordinator usable: %v", err)
			}
		})
	}
}

func TestCoordinatorNilClosedAndCancelledRequests(t *testing.T) {
	history, _ := testHistory(t)
	for _, coordinator := range []*Coordinator{nil, {}} {
		if _, err := coordinator.Append(t.Context(), history[0]); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if _, err := coordinator.Resume(t.Context()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if _, err := coordinator.Snapshot(); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if err := coordinator.Close(); err != nil {
			t.Fatal(err)
		}
	}
	coordinator, _, _ := newTestCoordinator(t)
	if _, err := coordinator.Append(nil, history[0]); !errors.Is(err, ErrStore) {
		t.Fatal("nil append context accepted")
	}
	if _, err := coordinator.Resume(nil); !errors.Is(err, ErrStore) {
		t.Fatal("nil resume context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := coordinator.Append(ctx, history[0]); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled request admitted")
	}
	_ = coordinator.Close()
	_ = coordinator.Close()
	if _, err := coordinator.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed coordinator remained usable")
	}
}
