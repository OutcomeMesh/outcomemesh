package store

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// WithConfirmedRetirement holds the original coordinator and authority guards
// through a read-only review/publication callback. It re-reads and replays every
// entry to an independent exact retirement pin within the caller's finite
// maximumEntries bound. No pending attempt is resumed.
// The callback must not call this coordinator again or mutate the authority.
func (c *Coordinator) WithConfirmedRetirement(ctx context.Context, pin custodyauthority.Position, maximumEntries uint64, visit func(custodyauthority.Assignment, []custodyauthority.Entry) error) error {
	if c == nil || ctx == nil || visit == nil || maximumEntries == 0 || pin.Sequence > maximumEntries {
		return ErrStore
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	observed, err := c.snapshot()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if observed.Pending != nil {
		return ErrPendingAttempt
	}
	if pin.HeadID.IsZero() || observed.Confirmed != pin || observed.Authority.Sequence != pin.Sequence || observed.Authority.HeadID != pin.HeadID {
		return custodyauthority.ErrHead
	}
	if observed.Authority.Phase != custodyauthority.Retired || observed.Authority.Pending != 0 || observed.Authority.Remote != nil || observed.Authority.RetirementID != pin.HeadID {
		return custodyauthority.ErrOutstanding
	}
	store := c.authority
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.check(); err != nil {
		return err
	}
	raw, err := readRegular(filepath.Join(store.path, assignmentName), custodyauthority.MaximumAssignmentBytes)
	if err != nil {
		return err
	}
	assignment, err := custodyauthority.DecodeAssignment(raw)
	if err != nil {
		return err
	}
	names, err := boundedNames(filepath.Join(store.path, entriesName), int(min(maximumEntries, custodyauthority.MaximumEntries(assignment))))
	if err != nil {
		return err
	}
	if uint64(len(names)) != pin.Sequence {
		return custodyauthority.ErrHead
	}
	// Incremental growth follows decoded evidence; a declared position is not a
	// reason to allocate a history-sized slice before the files exist.
	var entries []custodyauthority.Entry
	for i, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if name != entryName(uint64(i)+1) {
			return ErrStore
		}
		raw, err := readRegular(filepath.Join(store.path, entriesName, name), custodyauthority.MaximumEntryBytes)
		if err != nil {
			return err
		}
		entry, err := custodyauthority.DecodeEntry(raw)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
	}
	if _, err := custodyauthority.Replay(assignment, c.assignmentID, entries, pin); err != nil {
		return err
	}
	if err := visit(assignment, entries); err != nil {
		return err
	}
	return errors.Join(ctx.Err(), store.check(), c.journal.check())
}
