package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

const (
	intentLockName  = "intent.lock"
	intentReadyName = "ready.omcai"
	intentsName     = "intents"
	confirmedName   = "confirmed"
)

// intentJournal is accessible only under its Coordinator mutex and permanent
// process lock. Its state includes CONFIRMED decisions only; the optional next
// entry is an irrevocable intent, not an admission or a current-history pin.
type intentJournal struct {
	path     string
	lock     *os.File
	identity map[string]os.FileInfo
	state    *custodyauthority.State
	pending  *custodyauthority.Entry
	failed   bool
	hooks    storeHooks
}

func intentReadyBytes(id types.Hash) []byte {
	return append([]byte{'O', 'M', 'C', 'A', 'I', 'N', 'T', 'S', 0, 0}, id[:]...)
}

func confirmationName(sequence uint64) string { return fmt.Sprintf("%016x.omcap", sequence) }

func confirmationBytes(assignmentID types.Hash, position custodyauthority.Position) []byte {
	// Local version-0 pin envelope: magic, version, assignment, sequence, head.
	// It is not a signature or proof of remote freshness. Decode by comparing to
	// the exact bytes derived from fully replayed retained intent at this slot.
	encoded := append([]byte{'O', 'M', 'C', 'A', 'C', 'O', 'N', 'F', 0, 0}, assignmentID[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, position.Sequence)
	return append(encoded, position.HeadID[:]...)
}

func createIntentJournal(path string, assignment custodyauthority.Assignment, expectedID types.Hash, verifyAuthority func() error, hooks storeHooks) (_ *intentJournal, err error) {
	encoded, err := assignment.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openNamedLock(path, intentLockName, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	for _, name := range []string{intentsName, confirmedName, pendingName} {
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
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	// Lock order is always intent journal -> authority. The callback must hold
	// an independently pinned, initialized sequence-zero store before this
	// journal becomes ready. Explicit all-new bootstrap creates it under that
	// lock order; the existing-store constructor only opens an unused store.
	if err := verifyAuthority(); err != nil {
		return nil, err
	}
	if err := hooks.reach("intent-before-ready"); err != nil {
		return nil, err
	}
	if err := writeExclusive(filepath.Join(path, intentReadyName), intentReadyBytes(expectedID)); err != nil {
		return nil, err
	}
	if err := hooks.reach("intent-ready-file-synced"); err != nil {
		return nil, err
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := hooks.reach("intent-ready-directory-synced"); err != nil {
		return nil, err
	}
	return loadIntentJournal(path, lock, assignment, expectedID, hooks)
}

func openIntentJournal(path string, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (_ *intentJournal, err error) {
	lock, err := openNamedLock(path, intentLockName, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	return loadIntentJournal(path, lock, assignment, expectedID, hooks)
}

func loadIntentJournal(path string, lock *os.File, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (*intentJournal, error) {
	identity, err := inspectNamedLayout(path, lock, intentLockName, map[string]bool{
		assignmentName: false, intentReadyName: false, intentLockName: false,
		intentsName: true, confirmedName: true, pendingName: true, "": true,
	})
	if err != nil {
		return nil, err
	}
	expectedReady := intentReadyBytes(expectedID)
	actualReady, err := readRegular(filepath.Join(path, intentReadyName), len(expectedReady))
	if err != nil || !bytes.Equal(actualReady, expectedReady) {
		return nil, errors.Join(ErrStore, err)
	}
	expectedAssignment, err := assignment.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	actualAssignment, err := readRegular(filepath.Join(path, assignmentName), custodyauthority.MaximumAssignmentBytes)
	if err != nil || !bytes.Equal(actualAssignment, expectedAssignment) {
		return nil, errors.Join(custodyauthority.ErrAssignment, err)
	}
	if _, err := inspectPending(path); err != nil {
		return nil, err
	}
	limit := int(2*assignment.MaximumOperations + 2)
	intents, err := boundedNames(filepath.Join(path, intentsName), limit)
	if err != nil {
		return nil, err
	}
	confirmations, err := boundedNames(filepath.Join(path, confirmedName), limit)
	if err != nil {
		return nil, err
	}
	if len(intents) < len(confirmations) || len(intents) > len(confirmations)+1 {
		return nil, custodyauthority.ErrHead
	}
	state, err := custodyauthority.NewState(assignment, expectedID)
	if err != nil {
		return nil, err
	}
	journal := &intentJournal{path: path, lock: lock, identity: identity, state: state, hooks: hooks}
	for index, name := range intents {
		sequence := uint64(index + 1)
		if name != entryName(sequence) {
			return nil, ErrStore
		}
		encoded, err := readRegular(filepath.Join(path, intentsName, name), custodyauthority.MaximumEntryBytes)
		if err != nil {
			return nil, err
		}
		entry, err := custodyauthority.DecodeEntry(encoded)
		if err != nil {
			return nil, err
		}
		if err := state.ValidateNext(entry); err != nil {
			return nil, err
		}
		if index == len(confirmations) {
			journal.pending = &entry
			continue
		}
		if confirmations[index] != confirmationName(sequence) {
			return nil, ErrStore
		}
		id, err := entry.ID()
		if err != nil {
			return nil, err
		}
		expected := confirmationBytes(expectedID, custodyauthority.Position{Sequence: sequence, HeadID: id})
		actual, err := readRegular(filepath.Join(path, confirmedName, confirmations[index]), len(expected))
		if err != nil || !bytes.Equal(actual, expected) {
			return nil, errors.Join(custodyauthority.ErrHead, err)
		}
		if err := state.Apply(entry); err != nil {
			return nil, err
		}
	}
	// Re-establish intent/pin durability before using either to select an
	// authority history. Visible bytes alone cannot resolve an earlier sync error.
	for directory, names := range map[string][]string{intentsName: intents, confirmedName: confirmations} {
		for _, name := range append(names, "") {
			if err := syncPath(filepath.Join(path, directory, name)); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range []string{assignmentName, intentReadyName, intentLockName, pendingName, ""} {
		if err := syncPath(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := journal.check(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *intentJournal) check() error {
	if journal == nil || journal.lock == nil || journal.state == nil {
		return ErrClosed
	}
	if journal.failed {
		return ErrUncertain
	}
	for name, original := range journal.identity {
		current, err := os.Lstat(filepath.Join(journal.path, name))
		if err != nil || !os.SameFile(original, current) || original.Mode().Type() != current.Mode().Type() ||
			(original.Mode().IsRegular() && original.Size() != current.Size()) {
			return journal.poison(errors.Join(ErrStore, err))
		}
	}
	return nil
}

func (journal *intentJournal) poison(err error) error {
	journal.failed = true
	return errors.Join(ErrUncertain, err)
}

func (journal *intentJournal) publish(ctx context.Context, directory, name string, encoded []byte, prefix string) error {
	count, err := inspectPending(journal.path)
	if err != nil {
		return journal.poison(err)
	}
	if count == MaximumPendingFiles {
		return custodyauthority.ErrLimit
	}
	hooks := storeHooks{at: func(stage string) error { return journal.hooks.reach(prefix + "-" + stage) }}
	if err := hooks.reach("before-write"); err != nil {
		return journal.poison(err)
	}
	file, err := os.CreateTemp(filepath.Join(journal.path, pendingName), "entry-")
	if err != nil {
		return journal.poison(err)
	}
	if err := writeAndSync(file, encoded, hooks); err != nil {
		return journal.poison(err)
	}
	if err := hooks.reach("before-publish"); err != nil {
		return journal.poison(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := journal.check(); err != nil {
		return err
	}
	if err := os.Link(file.Name(), filepath.Join(journal.path, directory, name)); err != nil {
		return journal.poison(err)
	}
	if err := hooks.reach("after-publish"); err != nil {
		return journal.poison(err)
	}
	syncDir := journal.hooks.syncEntriesDirectory
	if syncDir == nil {
		syncDir = syncDirectory
	}
	if err := syncDir(filepath.Join(journal.path, directory)); err != nil {
		return journal.poison(err)
	}
	if err := hooks.reach("directory-synced"); err != nil {
		return journal.poison(err)
	}
	if err := os.Remove(file.Name()); err == nil {
		_ = syncDirectory(filepath.Join(journal.path, pendingName))
	}
	return nil
}

func (journal *intentJournal) prepare(ctx context.Context, entry custodyauthority.Entry) error {
	if journal.pending != nil {
		return ErrPendingAttempt
	}
	if err := journal.state.ValidateNext(entry); err != nil {
		return err
	}
	encoded, err := entry.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := journal.publish(ctx, intentsName, entryName(entry.Command.ExpectedSequence+1), encoded, "intent"); err != nil {
		return err
	}
	journal.pending = &entry
	if err := journal.hooks.reach("intent-after-apply"); err != nil {
		return journal.poison(err)
	}
	return nil
}

func (journal *intentJournal) confirm(result Commit) error {
	if journal.pending == nil {
		return ErrNoAttempt
	}
	entry := *journal.pending
	id, err := entry.ID()
	if err != nil {
		return journal.poison(err)
	}
	position := custodyauthority.Position{Sequence: entry.Command.ExpectedSequence + 1, HeadID: id}
	if result.EntryID != id || result.Snapshot.AssignmentID != entry.Command.AssignmentID ||
		result.Snapshot.Sequence != position.Sequence || result.Snapshot.HeadID != position.HeadID {
		return journal.poison(custodyauthority.ErrHead)
	}
	// Once the authority confirms its durable decision, finish pin publication
	// despite caller cancellation. Required I/O failure still returns no result.
	if err := journal.publish(context.Background(), confirmedName, confirmationName(position.Sequence),
		confirmationBytes(entry.Command.AssignmentID, position), "confirm"); err != nil {
		return err
	}
	if err := journal.state.Apply(entry); err != nil {
		return journal.poison(err)
	}
	journal.pending = nil
	if err := journal.hooks.reach("confirm-after-apply"); err != nil {
		return journal.poison(err)
	}
	return nil
}
