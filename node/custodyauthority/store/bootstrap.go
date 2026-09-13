package store

import (
	"errors"
	"os"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// ValidateBootstrapPaths checks only the placement of two disjoint roots whose
// parents already exist. It neither opens journal contents nor creates, locks or
// syncs anything. Success is not evidence of initialization, independent failure
// domains, physical identity or permission to operate on retained data.
func ValidateBootstrapPaths(writerPath, pinPath string) error {
	_, _, err := coordinatorPaths(writerPath, pinPath)
	return err
}

// CreateCoordinatedAuthority explicitly initializes TWO NEW disjoint roots. It
// holds the intent journal lock before creating the authority and retains both
// locks until Close. Unlike CreateCoordinator, it cannot attach fresh pins to an
// existing authority. An existing or partially initialized root is never reset,
// repaired or removed, including after an uncertain initialization failure.
func CreateCoordinatedAuthority(authorityPath, journalPath string, assignment custodyauthority.Assignment, expectedID types.Hash) (*Coordinator, error) {
	return createCoordinatedAuthority(authorityPath, journalPath, assignment, expectedID, storeHooks{})
}

func createCoordinatedAuthority(authorityPath, journalPath string, assignment custodyauthority.Assignment, expectedID types.Hash, hooks storeHooks) (_ *Coordinator, err error) {
	if _, err := custodyauthority.NewState(assignment, expectedID); err != nil {
		return nil, err
	}
	authorityPath, journalPath, err = coordinatorPaths(authorityPath, journalPath)
	if err != nil {
		return nil, err
	}
	// Preflight both targets before any mutation. The exclusive constructors
	// remain the final check if another owner creates either path afterwards.
	for _, path := range []string{authorityPath, journalPath} {
		if _, err := os.Lstat(path); err == nil {
			return nil, os.ErrExist
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	var authority *Store
	var journal *intentJournal
	defer func() {
		if err != nil {
			if authority != nil {
				err = errors.Join(err, authority.Close())
			}
			if journal != nil {
				err = errors.Join(err, journal.lock.Close())
			}
		}
	}()
	journal, err = createIntentJournal(journalPath, assignment, expectedID, func() error {
		var createErr error
		authority, createErr = create(authorityPath, assignment, expectedID, storeHooks{
			at:                   func(stage string) error { return hooks.reach("authority-" + stage) },
			syncEntriesDirectory: hooks.syncEntriesDirectory,
		})
		return createErr
	}, hooks)
	if err != nil {
		return nil, err
	}
	coordinator := &Coordinator{journal: journal, authority: authority, assignmentID: expectedID}
	if _, err := coordinator.Snapshot(); err != nil {
		return nil, err
	}
	return coordinator, nil
}
