package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var (
	ErrPendingAttempt = errors.New("custody authority has a retained attempt; resume that exact entry first")
	ErrNoAttempt      = errors.New("custody authority has no retained attempt to resume")
	ErrRootOverlap    = errors.New("custody authority and intent journal roots must be disjoint")
)

// Coordination distinguishes the independently CONFIRMED position from an
// optional retained attempt and the observed local authority state. Open never
// turns an observation into a confirmation or silently submits the attempt.
// These detached diagnostics are not execution permissions or remote freshness.
type Coordination struct {
	Confirmed custodyauthority.Position
	Pending   *custodyauthority.Entry
	Authority custodyauthority.Snapshot
}

// Coordinator orders two independently retained roots: intent -> authority
// decision -> confirmation pin -> result. It holds the intent process lock
// before the authority process lock for its entire lifetime. Neither underlying
// writer is exposed. A separate physical/access-control failure domain for the
// journal is an operator deployment requirement, not something two paths prove.
type Coordinator struct {
	mu        sync.Mutex
	journal   *intentJournal
	authority *Store
	failed    bool
}

// CreateCoordinator bootstraps a NEW intent journal for an EXISTING initialized
// sequence-zero authority store. It does not create an authority, attach a new
// journal to used history, repair a partial root, or erase existing evidence.
func CreateCoordinator(authorityPath, journalPath string, assignment custodyauthority.Assignment, expectedID types.Hash) (*Coordinator, error) {
	return createCoordinator(authorityPath, journalPath, assignment, expectedID, storeHooks{})
}

func createCoordinator(authorityPath, journalPath string, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (_ *Coordinator, err error) {
	if _, err := custodyauthority.NewState(assignment, expectedID); err != nil {
		return nil, err
	}
	authorityPath, journalPath, err = coordinatorPaths(authorityPath, journalPath)
	if err != nil {
		return nil, err
	}
	var authority *Store
	defer func() {
		if err != nil && authority != nil {
			err = errors.Join(err, authority.Close())
		}
	}()
	journal, err := createIntentJournal(journalPath, assignment, expectedID, func() error {
		var openErr error
		authority, openErr = Open(authorityPath, assignment, expectedID, custodyauthority.Position{HeadID: expectedID})
		return openErr
	}, hooks)
	if err != nil {
		return nil, err
	}
	setAuthorityHooks(authority, hooks)
	return &Coordinator{journal: journal, authority: authority}, nil
}

// OpenCoordinator replays the independently configured intent journal FIRST,
// then opens the authority at its exact confirmed pin, or recovers its one exact
// retained attempt. There is no "latest head" query or missing-root fallback.
// This operation does not append or confirm work. Call Resume explicitly when
// Snapshot reports Pending, or retry Append with that same co-signed entry.
func OpenCoordinator(authorityPath, journalPath string, assignment custodyauthority.Assignment, expectedID types.Hash) (*Coordinator, error) {
	return openCoordinator(authorityPath, journalPath, assignment, expectedID, storeHooks{})
}

func openCoordinator(authorityPath, journalPath string, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (_ *Coordinator, err error) {
	if _, err := custodyauthority.NewState(assignment, expectedID); err != nil {
		return nil, err
	}
	authorityPath, journalPath, err = coordinatorPaths(authorityPath, journalPath)
	if err != nil {
		return nil, err
	}
	journal, err := openIntentJournal(journalPath, assignment, expectedID, hooks)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, journal.lock.Close())
		}
	}()
	confirmed, err := journal.state.Snapshot()
	if err != nil {
		return nil, err
	}
	pin := custodyauthority.Position{Sequence: confirmed.Sequence, HeadID: confirmed.HeadID}
	var authority *Store
	if journal.pending == nil {
		authority, err = Open(authorityPath, assignment, expectedID, pin)
	} else {
		authority, err = Recover(authorityPath, assignment, expectedID, pin, *journal.pending)
	}
	if err != nil {
		return nil, err
	}
	setAuthorityHooks(authority, hooks)
	return &Coordinator{journal: journal, authority: authority}, nil
}

func setAuthorityHooks(authority *Store, hooks storeHooks) {
	authority.hooks = storeHooks{
		at:                   func(stage string) error { return hooks.reach("authority-" + stage) },
		syncEntriesDirectory: hooks.syncEntriesDirectory,
	}
}

func (coordinator *Coordinator) Snapshot() (Coordination, error) {
	if coordinator == nil {
		return Coordination{}, ErrClosed
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return coordinator.snapshot()
}

func (coordinator *Coordinator) snapshot() (Coordination, error) {
	if coordinator.journal == nil || coordinator.authority == nil {
		return Coordination{}, ErrClosed
	}
	if coordinator.failed {
		return Coordination{}, ErrUncertain
	}
	if err := coordinator.journal.check(); err != nil {
		return Coordination{}, coordinator.poison(err)
	}
	confirmed, err := coordinator.journal.state.Snapshot()
	if err != nil {
		return Coordination{}, coordinator.poison(err)
	}
	observed, err := coordinator.authority.Snapshot()
	if err != nil {
		return Coordination{}, coordinator.poison(err)
	}
	result := Coordination{Confirmed: custodyauthority.Position{Sequence: confirmed.Sequence, HeadID: confirmed.HeadID}, Authority: observed}
	allowed := observed.Sequence == confirmed.Sequence && observed.HeadID == confirmed.HeadID
	if coordinator.journal.pending != nil {
		entry := *coordinator.journal.pending
		result.Pending = &entry
		id, err := entry.ID()
		if err != nil {
			return Coordination{}, coordinator.poison(err)
		}
		allowed = allowed || (observed.Sequence == confirmed.Sequence+1 && observed.HeadID == id)
	}
	if !allowed || observed.AssignmentID != confirmed.AssignmentID {
		return Coordination{}, coordinator.poison(custodyauthority.ErrHead)
	}
	return result, nil
}

// Append persists an admissible exact intent before submitting it to the local
// authority. It returns only after independently confirming that durable result.
// A different request cannot bypass a retained attempt, even to close/retire it.
// Exact historical retries are lookups, never another admission or effect.
func (coordinator *Coordinator) Append(ctx context.Context, entry custodyauthority.Entry) (Commit, error) {
	if coordinator == nil {
		return Commit{}, ErrClosed
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	current, err := coordinator.snapshot()
	if err != nil {
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
	if current.Pending != nil {
		if *current.Pending != entry {
			return Commit{}, ErrPendingAttempt
		}
		return coordinator.resume(ctx)
	}
	if entry.Command.ExpectedSequence < current.Confirmed.Sequence {
		retained, err := readRegular(filepath.Join(coordinator.journal.path, intentsName,
			entryName(entry.Command.ExpectedSequence+1)), custodyauthority.MaximumEntryBytes)
		if err != nil {
			return Commit{}, coordinator.poison(err)
		}
		if !bytes.Equal(encoded, retained) {
			return Commit{}, custodyauthority.ErrHead
		}
		result, err := coordinator.authority.Append(ctx, entry)
		if err != nil && (errors.Is(err, ErrUncertain) || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded))) {
			return Commit{}, coordinator.poison(err)
		}
		return result, err
	}
	if err := coordinator.journal.prepare(ctx, entry); err != nil {
		if coordinator.journal.failed {
			return Commit{}, coordinator.poison(err)
		}
		return Commit{}, err
	}
	return coordinator.resume(ctx)
}

// Resume retries only the already retained attempt. It never chooses a new
// command, drops a pending intent, fabricates completion or advances a pin from
// an observation alone. Open itself is non-submitting, so recovery is explicit.
func (coordinator *Coordinator) Resume(ctx context.Context) (Commit, error) {
	if coordinator == nil {
		return Commit{}, ErrClosed
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if _, err := coordinator.snapshot(); err != nil {
		return Commit{}, err
	}
	if ctx == nil {
		return Commit{}, ErrStore
	}
	if coordinator.journal.pending == nil {
		return Commit{}, ErrNoAttempt
	}
	return coordinator.resume(ctx)
}

func (coordinator *Coordinator) resume(ctx context.Context) (Commit, error) {
	result, err := coordinator.authority.Append(ctx, *coordinator.journal.pending)
	if err != nil {
		if !errors.Is(err, ErrUncertain) && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return Commit{}, errors.Join(ErrPendingAttempt, err)
		}
		return Commit{}, coordinator.poison(err)
	}
	if err := coordinator.journal.confirm(result); err != nil {
		return Commit{}, coordinator.poison(err)
	}
	return result, nil
}

func (coordinator *Coordinator) poison(err error) error {
	coordinator.failed = true
	return errors.Join(ErrUncertain, err)
}

// Close releases the authority lock first, then the intent lock, without
// deleting either inode or modifying any intent/confirmation. Repeated Close is
// harmless, including after an uncertain result.
func (coordinator *Coordinator) Close() error {
	if coordinator == nil {
		return nil
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	var err error
	if coordinator.authority != nil {
		err = coordinator.authority.Close()
		coordinator.authority = nil
	}
	if coordinator.journal != nil {
		err = errors.Join(err, coordinator.journal.lock.Close())
		coordinator.journal = nil
	}
	return err
}

func coordinatorPaths(authorityPath, journalPath string) (string, string, error) {
	canonical := func(path string) (string, error) {
		path, err := storePath(path)
		if err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if info != nil && !info.IsDir() {
			return "", ErrStore
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return "", err
		}
		return filepath.Join(parent, filepath.Base(path)), nil
	}
	authorityPath, err := canonical(authorityPath)
	if err != nil {
		return "", "", err
	}
	journalPath, err = canonical(journalPath)
	if err != nil {
		return "", "", err
	}
	inside := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	if inside(authorityPath, journalPath) || inside(journalPath, authorityPath) {
		return "", "", ErrRootOverlap
	}
	// String containment alone misses case-insensitive aliases and existing
	// directory aliases exposed through mount paths. Check ancestor identities
	// before creating anything, including when the candidate child is missing.
	for _, pair := range [][2]string{{authorityPath, journalPath}, {journalPath, authorityPath}} {
		root, err := os.Lstat(pair[0])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		for path := pair[1]; ; path = filepath.Dir(path) {
			ancestor, err := os.Lstat(path)
			if err == nil && os.SameFile(root, ancestor) {
				return "", "", ErrRootOverlap
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", "", err
			}
			if filepath.Dir(path) == path {
				break
			}
		}
	}
	return authorityPath, journalPath, nil
}
