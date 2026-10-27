// Package store persists the custody authority reference machine. It is a local,
// single-writer history with an optional trusted local prune executor, not a
// network authority. Its records/snapshots are not portable execution grants.
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var (
	ErrStore     = errors.New("invalid custody authority store")
	ErrBusy      = errors.New("custody authority store already has an owner")
	ErrClosed    = errors.New("custody authority store is closed")
	ErrUncertain = errors.New("custody authority persistence is uncertain; close and recover against retained pins")
)

const (
	assignmentName = "assignment.omcaa"
	readyName      = "ready.omcas"
	lockName       = "authority.lock"
	entriesName    = "entries"
	pendingName    = "pending"
	// Crash leftovers are evidence, never entries to promote or silently delete.
	// This bound is independent of the assignment's outstanding-operation limit.
	MaximumPendingFiles = 128
)

// Commit reports an ordered durable record and the CURRENT local state, even
// when retrying an old record. Appended=false is exact history lookup, not a new
// admission. Neither this result nor its detached Snapshot authorizes an effect.
type Commit struct {
	EntryID  types.Hash
	Appended bool
	Snapshot custodyauthority.Snapshot
}

// Store holds its permanent kernel lock from successful create/open to Close.
// It owns the reference state exclusively; no caller can Apply around the disk
// transaction. Use local filesystems with working locks, hard links and fsync,
// and owner-controlled paths. Copying the root/key does not copy this lock.
type Store struct {
	mu       sync.Mutex
	path     string
	lock     *os.File
	identity map[string]os.FileInfo
	state    *custodyauthority.State
	failed   bool
	hooks    storeHooks
}

// Hooks are private deterministic test boundaries, never runtime configuration.
type storeHooks struct {
	at                   func(string) error
	syncEntriesDirectory func(string) error
}

func (h storeHooks) reach(stage string) error {
	if h.at != nil {
		return h.at(stage)
	}
	return nil
}

// Create is explicit bootstrap of a NEW root, whose parent must already exist.
// It refuses even an empty/partial existing root and never cleans up failed
// initialization. The assignment ID must come from an independent trusted pin.
// Create is not a recovery function, including when an old root is missing.
func Create(path string, assignment custodyauthority.Assignment, expectedID types.Hash) (*Store, error) {
	return create(path, assignment, expectedID, storeHooks{})
}

func create(path string, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (_ *Store, err error) {
	if _, err := custodyauthority.NewState(assignment, expectedID); err != nil {
		return nil, err
	}
	encoded, err := assignment.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	path, err = storePath(path)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openLock(path, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	for _, name := range []string{entriesName, pendingName} {
		if err := os.Mkdir(filepath.Join(path, name), 0o700); err != nil {
			return nil, err
		}
		if err := syncDirectory(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := writeExclusive(filepath.Join(path, assignmentName), encoded); err != nil {
		return nil, err
	}
	// Establish every dependency before publishing the final initialization file.
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("before-ready"); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(path, readyName), readyBytes(expectedID)); err != nil {
		return nil, err
	}
	if err := hooks.reach("ready-file-synced"); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("ready-directory-synced"); err != nil {
		return nil, err
	}
	return loadLocked(path, lock, assignment, expectedID, custodyauthority.Position{HeadID: expectedID}, nil, hooks)
}

// Open only replays a complete existing store at an independently retained EXACT
// position. It creates no root, lock, directory or initialization record. A valid
// shorter prefix, different branch, or extension beyond expected is rejected.
func Open(path string, assignment custodyauthority.Assignment, expectedID types.Hash, expected custodyauthority.Position) (*Store, error) {
	return open(path, assignment, expectedID, expected, nil)
}

// Recover handles exactly one uncertain append. The caller must independently
// retain BOTH the pre-attempt position and the exact co-signed attempted entry.
// Only that position or its one-entry extension is eligible. The attempted entry
// must itself be admissible there; recovery neither publishes it nor chooses a
// different/newer head. On success use Snapshot and exact Append retry to learn
// the outcome. Missing history is still an error, never bootstrap.
func Recover(path string, assignment custodyauthority.Assignment, expectedID types.Hash, before custodyauthority.Position, attempted custodyauthority.Entry) (*Store, error) {
	return open(path, assignment, expectedID, before, &attempted)
}

func open(path string, assignment custodyauthority.Assignment, expectedID types.Hash, expected custodyauthority.Position, attempted *custodyauthority.Entry) (_ *Store, err error) {
	if _, err := custodyauthority.NewState(assignment, expectedID); err != nil {
		return nil, err
	}
	if expected.HeadID.IsZero() || expected.Sequence > custodyauthority.MaximumEntries(assignment) {
		return nil, custodyauthority.ErrHead
	}
	if attempted != nil {
		if _, err := attempted.ID(); err != nil {
			return nil, err
		}
		if attempted.Command.AssignmentID != expectedID || attempted.AuthorityPublicKey != assignment.AuthorityPublicKey ||
			attempted.Command.ExpectedSequence != expected.Sequence || attempted.Command.ExpectedHead != expected.HeadID {
			return nil, custodyauthority.ErrHead
		}
	}
	path, err = storePath(path)
	if err != nil {
		return nil, err
	}
	lock, err := openLock(path, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	return loadLocked(path, lock, assignment, expectedID, expected, attempted, storeHooks{})
}

func loadLocked(path string, lock *os.File, assignment custodyauthority.Assignment, expectedID types.Hash, expected custodyauthority.Position, attempted *custodyauthority.Entry, hooks storeHooks) (*Store, error) {
	identity, err := inspectLayout(path, lock)
	if err != nil {
		return nil, err
	}
	encoded, err := readRegular(filepath.Join(path, assignmentName), custodyauthority.MaximumAssignmentBytes)
	if err != nil {
		return nil, err
	}
	want, err := assignment.CanonicalBytes()
	if err != nil || !bytes.Equal(encoded, want) {
		return nil, errors.Join(custodyauthority.ErrAssignment, err)
	}
	ready, err := readRegular(filepath.Join(path, readyName), len(readyBytes(expectedID)))
	if err != nil || !bytes.Equal(ready, readyBytes(expectedID)) {
		return nil, errors.Join(ErrStore, err)
	}
	if _, err := inspectPending(path); err != nil {
		return nil, err
	}
	entriesPath := filepath.Join(path, entriesName)
	names, err := boundedNames(entriesPath, int(custodyauthority.MaximumEntries(assignment)))
	if err != nil {
		return nil, err
	}
	// Cardinality and filenames are checked before allocating/decoding history.
	allowed := uint64(len(names)) == expected.Sequence
	if attempted != nil && uint64(len(names)) == expected.Sequence+1 {
		allowed = true
	}
	if !allowed {
		return nil, custodyauthority.ErrHead
	}
	history := make([]custodyauthority.Entry, 0, len(names))
	for index, name := range names {
		if name != entryName(uint64(index+1)) {
			return nil, ErrStore
		}
		encoded, err := readRegular(filepath.Join(entriesPath, name), custodyauthority.MaximumEntryBytes)
		if err != nil {
			return nil, err
		}
		entry, err := custodyauthority.DecodeEntry(encoded)
		if err != nil {
			return nil, err
		}
		history = append(history, entry)
	}
	// First replay precisely the independent pre-attempt pin, even if recovery
	// sees a candidate extension. A valid candidate cannot conceal a fork below it.
	state, err := custodyauthority.Replay(assignment, expectedID, history[:expected.Sequence], expected)
	if err != nil {
		return nil, err
	}
	if attempted != nil {
		if err := state.ValidateNext(*attempted); err != nil {
			return nil, err
		}
		if uint64(len(history)) > expected.Sequence {
			if history[expected.Sequence] != *attempted {
				return nil, custodyauthority.ErrHead
			}
			if err := state.Apply(*attempted); err != nil {
				return nil, err
			}
		}
	}
	// Reading after a previous writer's failed fsync is not a durability proof.
	// Re-establish file and namespace durability before returning ANY live handle.
	for _, name := range append(names, "") {
		filePath := entriesPath
		if name != "" {
			filePath = filepath.Join(entriesPath, name)
		}
		if err := syncPath(filePath); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{assignmentName, readyName, lockName, pendingName, ""} {
		if err := syncPath(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	store := &Store{path: path, lock: lock, identity: identity, state: state, hooks: hooks}
	if err := store.check(); err != nil {
		return nil, err
	}
	return store, nil
}

// Append serializes validation, immutable publication, fsync and state apply.
// The exact same previously committed entry is an idempotent history lookup;
// different bytes at that sequence are rejected, including a new signature or
// a re-signed operation at a different head. Results always describe current
// local state, not the phase at the original admission.
//
// Cancellation is checked after acquiring the guard and immediately before
// publication. Once the final filename exists, the durability decision is no
// longer cancellable. An I/O failure poisons this handle, even if no result was
// returned; only Close plus pinned Open/Recover can establish the outcome.
func (store *Store) Append(ctx context.Context, entry custodyauthority.Entry) (Commit, error) {
	if store == nil {
		return Commit{}, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.check(); err != nil {
		return Commit{}, err
	}
	if ctx == nil {
		return Commit{}, ErrStore
	}
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	encoded, err := entry.CanonicalBytes()
	if err != nil {
		return Commit{}, err
	}
	current, err := store.state.Snapshot()
	if err != nil {
		return Commit{}, store.poison(err)
	}
	name := entryName(entry.Command.ExpectedSequence + 1)
	finalPath := filepath.Join(store.path, entriesName, name)
	if entry.Command.ExpectedSequence < current.Sequence {
		previous, err := readRegular(finalPath, custodyauthority.MaximumEntryBytes)
		if err != nil {
			return Commit{}, store.poison(err)
		}
		if !bytes.Equal(previous, encoded) {
			return Commit{}, custodyauthority.ErrHead
		}
		id, err := entry.ID()
		if err != nil {
			return Commit{}, err
		}
		return Commit{EntryID: id, Snapshot: current}, nil
	}
	if err := store.state.ValidateNext(entry); err != nil {
		return Commit{}, err
	}
	count, err := inspectPending(store.path)
	if err != nil {
		return Commit{}, store.poison(err)
	}
	if count == MaximumPendingFiles {
		return Commit{}, custodyauthority.ErrLimit
	}
	if err := store.hooks.reach("before-write"); err != nil {
		return Commit{}, store.poison(err)
	}
	file, err := os.CreateTemp(filepath.Join(store.path, pendingName), "entry-")
	if err != nil {
		return Commit{}, store.poison(err)
	}
	// On error keep this attempt for inspection; it is never replayed as history.
	err = writeAndSync(file, encoded, store.hooks)
	if err != nil {
		return Commit{}, store.poison(err)
	}
	if err := store.hooks.reach("before-publish"); err != nil {
		return Commit{}, store.poison(err)
	}
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	if err := store.check(); err != nil {
		return Commit{}, err
	}
	// No rename-overwrite and no mutable head file: the sequential name itself
	// is the decision. A crash leaves either the old prefix or this exact suffix.
	if err := os.Link(file.Name(), finalPath); err != nil {
		return Commit{}, store.poison(err)
	}
	if err := store.hooks.reach("after-publish"); err != nil {
		return Commit{}, store.poison(err)
	}
	syncEntries := store.hooks.syncEntriesDirectory
	if syncEntries == nil {
		syncEntries = syncDirectory
	}
	if err := syncEntries(filepath.Join(store.path, entriesName)); err != nil {
		return Commit{}, store.poison(err)
	}
	if err := store.hooks.reach("directory-synced"); err != nil {
		return Commit{}, store.poison(err)
	}
	if err := store.state.Apply(entry); err != nil {
		return Commit{}, store.poison(err)
	}
	if err := store.hooks.reach("after-apply"); err != nil {
		return Commit{}, store.poison(err)
	}
	current, err = store.state.Snapshot()
	if err != nil {
		return Commit{}, store.poison(err)
	}
	// Only our own temporary link is eligible for best-effort cleanup. Failure
	// cannot undo the durable entry; the bounded leftover remains inspectable.
	if err := os.Remove(file.Name()); err == nil {
		_ = syncDirectory(filepath.Join(store.path, pendingName))
	}
	return Commit{EntryID: current.HeadID, Appended: true, Snapshot: current}, nil
}

func (store *Store) Snapshot() (custodyauthority.Snapshot, error) {
	if store == nil {
		return custodyauthority.Snapshot{}, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.check(); err != nil {
		return custodyauthority.Snapshot{}, err
	}
	return store.state.Snapshot()
}

// Close releases the permanent lock inode without removing it. It is safe to
// repeat, including after a poisoned append. Close never admits/completes work.
func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lock == nil {
		return nil
	}
	err := store.lock.Close()
	store.lock, store.state = nil, nil
	return err
}

func (store *Store) poison(err error) error {
	store.failed = true
	return errors.Join(ErrUncertain, err)
}

func (store *Store) check() error {
	if store.lock == nil || store.state == nil {
		return ErrClosed
	}
	if store.failed {
		return ErrUncertain
	}
	for name, original := range store.identity {
		current, err := os.Lstat(filepath.Join(store.path, name))
		if err != nil || !os.SameFile(original, current) || original.Mode().Type() != current.Mode().Type() ||
			(original.Mode().IsRegular() && original.Size() != current.Size()) {
			return store.poison(errors.Join(ErrStore, err))
		}
	}
	return nil
}

func entryName(sequence uint64) string { return fmt.Sprintf("%016x.omcae", sequence) }

func readyBytes(id types.Hash) []byte {
	// Fixed version-0 local envelope; neither an authority entry nor a signature.
	return append([]byte{'O', 'M', 'C', 'A', 'S', 'T', 'O', 'R', 0, 0}, id[:]...)
}
