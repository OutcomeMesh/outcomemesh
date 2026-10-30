package workchain

import (
	"bytes"
	"errors"
	"sort"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	MaximumCanonicalPruneEffectBytes = 1024
	MaximumCanonicalPruneEffects     = 65_536
)

var ErrPruneTicketConflict = errors.New("canonical prune ticket already binds a different request")

// CanonicalBytes exposes the existing bounded local floor format for retained
// maintenance requests. This is historical metadata, not a custody permit.
func (floor CanonicalFloor) CanonicalBytes() ([]byte, error) { return encodeCanonicalFloor(floor) }

func DecodeCanonicalFloor(input []byte) (CanonicalFloor, error) { return decodeCanonicalFloor(input) }

// VerifyContext checks the immutable chain-local part of an external assignment.
// WorkChain does not know the external genesis trust pin or authority membership.
func (store *Store) VerifyContext(networkID uint32, activationHeight uint64, baseID types.Hash) error {
	if store == nil {
		return ErrConfiguration
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return err
	}
	if store.persistence == nil || store.parameters.NetworkID != networkID ||
		store.parameters.ActivationHeight != activationHeight || store.baseID != baseID {
		return ErrConfiguration
	}
	return nil
}

// CanonicalPruneOperation binds an exact requested floor (including its initial
// time) to an independently admitted ticket. The caller must durably retain this
// request and enforce current authority; these unsigned fields confer no grant.
// Boundary.PruneTicketID must be zero: only the committing store installs it.
type CanonicalPruneOperation struct {
	ScheduleID   types.Hash
	AssignmentID types.Hash
	TicketID     types.Hash
	// StorageID is zero only for legacy unbound databases. Nonzero is a pinned
	// local incarnation, not a hardware identity or a database rollback counter.
	StorageID types.Hash
	Boundary  CanonicalFloor
}

// CanonicalPruneEffect records the original completed effect, not the current
// chain tip or current availability. VerifiedAt is the final authorization time.
// Its ID is a local evidence commitment, not a signature or a completion command.
type CanonicalPruneEffect struct {
	Operation  CanonicalPruneOperation
	VerifiedAt uint64
	Report     CanonicalPruneReport
}

type CanonicalPruneCommit struct {
	Applied bool
	Effect  CanonicalPruneEffect
}

// PruneCanonicalPrefixOnce atomically stores the result with the deletion,
// retained floor and byte accounting. An exact retry returns Applied=false and
// the original result without authorization, deletion or timestamp refresh,
// even after later pruning. A different request under that ticket is rejected.
//
// This is a trusted local primitive, not an authority-enforcing acceptance path.
// authorize must obey PruneCanonicalPrefixAuthorized's lifetime/locking rules.
// Recovery must first inspect CanonicalPruneEffect; absence in a new or rolled-
// back database is not permission to retry. A nonzero StorageID must match the
// bound database; a legacy zero ID is never accepted as a wildcard.
func (store *Store) PruneCanonicalPrefixOnce(
	operation CanonicalPruneOperation, authorize func() (uint64, error),
) (CanonicalPruneCommit, error) {
	if store == nil || authorize == nil || operation.validate() != nil {
		return CanonicalPruneCommit{}, ErrCanonicalPrune
	}
	operation.Boundary = cloneCanonicalFloor(operation.Boundary)
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openErrorLocked(); err != nil {
		return CanonicalPruneCommit{}, err
	}
	if store.persistence == nil || operation.Boundary.BaseID != store.baseID {
		return CanonicalPruneCommit{}, ErrCanonicalPrune
	}
	if operation.StorageID != store.persistence.storageID {
		return CanonicalPruneCommit{}, ErrStorageBinding
	}
	existing, found, err := store.persistence.pruneEffect(operation.TicketID)
	if err != nil {
		return CanonicalPruneCommit{}, err
	}
	if found {
		if !equalPruneOperation(existing.Operation, operation) {
			return CanonicalPruneCommit{}, ErrPruneTicketConflict
		}
		return CanonicalPruneCommit{Effect: existing}, nil
	}
	if store.persistence.pruneEffects >= MaximumCanonicalPruneEffects {
		return CanonicalPruneCommit{}, storage.ErrHistoryLimit
	}
	effect := CanonicalPruneEffect{Operation: operation}
	boundary := cloneCanonicalFloor(operation.Boundary)
	boundary.PruneTicketID = operation.TicketID
	if _, err := store.pruneCanonicalPrefixLocked(boundary, authorize, &effect); err != nil {
		return CanonicalPruneCommit{}, err
	}
	return CanonicalPruneCommit{Applied: true, Effect: effect}, nil
}

// CanonicalPruneEffect is a read-only result lookup under the chain lock. It does
// not execute missing work, acquire authority, or sign a terminal disposition.
func (store *Store) CanonicalPruneEffect(ticketID types.Hash) (CanonicalPruneEffect, bool, error) {
	if store == nil || ticketID.IsZero() {
		return CanonicalPruneEffect{}, false, ErrCanonicalPrune
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return CanonicalPruneEffect{}, false, err
	}
	if store.persistence == nil {
		return CanonicalPruneEffect{}, false, ErrCanonicalPrune
	}
	return store.persistence.pruneEffect(ticketID)
}

func (operation CanonicalPruneOperation) validate() error {
	if (operation.ScheduleID.IsZero() != (operation.Boundary.RadixActivationHeight == 0)) || (!operation.ScheduleID.IsZero() && operation.StorageID.IsZero()) || operation.AssignmentID.IsZero() || operation.TicketID.IsZero() ||
		!operation.Boundary.PruneTicketID.IsZero() || operation.Boundary.validate() != nil {
		return ErrCanonicalPrune
	}
	return nil
}

func equalPruneOperation(left, right CanonicalPruneOperation) bool {
	l, le := encodeCanonicalFloor(left.Boundary)
	r, re := encodeCanonicalFloor(right.Boundary)
	return le == nil && re == nil && left.AssignmentID == right.AssignmentID &&
		left.ScheduleID == right.ScheduleID && left.TicketID == right.TicketID && left.StorageID == right.StorageID && bytes.Equal(l, r)
}

func (effect CanonicalPruneEffect) validate() error {
	b := effect.Operation.Boundary
	r := effect.Report
	if effect.Operation.validate() != nil || effect.VerifiedAt < b.VerifiedAt ||
		effect.VerifiedAt >= b.RetainUntil || r.FloorID != b.Anchor.ID ||
		r.PreviousFloorID.IsZero() || r.PreviousFloorID == r.FloorID ||
		r.RemovedNodes == 0 || r.RetainedNodes == 0 || r.AddedHistoryBytes == 0 ||
		r.ReleasedHistoryBytes == 0 || r.ArchivedHeaders != b.AncestryNodes-2 {
		return ErrCanonicalPrune
	}
	return nil
}

func (effect CanonicalPruneEffect) CanonicalBytes() ([]byte, error) {
	if err := effect.validate(); err != nil {
		return nil, err
	}
	floor, err := encodeCanonicalFloor(effect.Operation.Boundary)
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumCanonicalPruneEffectBytes)
	e.Fixed([]byte("OMWCPREF"))
	version := uint16(0)
	if !effect.Operation.StorageID.IsZero() {
		version = 1
	}
	if !effect.Operation.ScheduleID.IsZero() {
		version = 2
	}
	e.U16(version)
	e.Fixed(effect.Operation.AssignmentID[:])
	e.Fixed(effect.Operation.TicketID[:])
	if version >= 1 {
		e.Fixed(effect.Operation.StorageID[:])
	}
	if version == 2 {
		e.Fixed(effect.Operation.ScheduleID[:])
	}
	e.BytesField(floor)
	e.U64(effect.VerifiedAt)
	e.Fixed(effect.Report.PreviousFloorID[:])
	e.Fixed(effect.Report.FloorID[:])
	for _, value := range []uint64{effect.Report.RemovedNodes, effect.Report.RetainedNodes,
		effect.Report.ArchivedHeaders, effect.Report.AddedHistoryBytes, effect.Report.ReleasedHistoryBytes} {
		e.U64(value)
	}
	if e.Len() > MaximumCanonicalPruneEffectBytes {
		return nil, ErrCanonicalPrune
	}
	return e.Bytes(), nil
}

func (effect CanonicalPruneEffect) ID() (types.Hash, error) {
	encoded, err := effect.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	domain := "OMESH/workgraph/canonical-prune-effect/id/v0"
	if !effect.Operation.StorageID.IsZero() {
		domain = "OMESH/workgraph/canonical-prune-effect/id/v1"
	}
	if !effect.Operation.ScheduleID.IsZero() {
		domain = "OMESH/workgraph/canonical-prune-effect/id/v2"
	}
	return types.DomainHash(domain, encoded), nil
}

func DecodeCanonicalPruneEffect(input []byte) (CanonicalPruneEffect, error) {
	if len(input) > MaximumCanonicalPruneEffectBytes {
		return CanonicalPruneEffect{}, storage.ErrCorrupt
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMWCPREF")) {
		return CanonicalPruneEffect{}, storage.ErrCorrupt
	}
	version, err := d.U16()
	if err != nil || version > 2 {
		return CanonicalPruneEffect{}, storage.ErrCorrupt
	}
	var result CanonicalPruneEffect
	for _, destination := range []*types.Hash{&result.Operation.AssignmentID, &result.Operation.TicketID} {
		value, err := d.Fixed(types.HashSize)
		if err != nil {
			return CanonicalPruneEffect{}, storage.ErrCorrupt
		}
		copy(destination[:], value)
	}
	if version >= 1 {
		value, err := d.Fixed(types.HashSize)
		if err != nil {
			return CanonicalPruneEffect{}, storage.ErrCorrupt
		}
		copy(result.Operation.StorageID[:], value)
		if result.Operation.StorageID.IsZero() {
			return CanonicalPruneEffect{}, storage.ErrCorrupt
		}
	}
	if version == 2 {
		value, err := d.Fixed(types.HashSize)
		if err != nil {
			return CanonicalPruneEffect{}, storage.ErrCorrupt
		}
		copy(result.Operation.ScheduleID[:], value)
		if result.Operation.ScheduleID.IsZero() {
			return CanonicalPruneEffect{}, storage.ErrCorrupt
		}
	}
	floorBytes, err := d.BytesField(maxCanonicalFloorBytes)
	if err != nil {
		return CanonicalPruneEffect{}, storage.ErrCorrupt
	}
	result.Operation.Boundary, err = decodeCanonicalFloor(floorBytes)
	if err != nil {
		return CanonicalPruneEffect{}, storage.ErrCorrupt
	}
	result.VerifiedAt, err = d.U64()
	if err != nil {
		return CanonicalPruneEffect{}, storage.ErrCorrupt
	}
	for _, destination := range []*types.Hash{&result.Report.PreviousFloorID, &result.Report.FloorID} {
		value, err := d.Fixed(types.HashSize)
		if err != nil {
			return CanonicalPruneEffect{}, storage.ErrCorrupt
		}
		copy(destination[:], value)
	}
	for _, destination := range []*uint64{&result.Report.RemovedNodes, &result.Report.RetainedNodes,
		&result.Report.ArchivedHeaders, &result.Report.AddedHistoryBytes, &result.Report.ReleasedHistoryBytes} {
		if *destination, err = d.U64(); err != nil {
			return CanonicalPruneEffect{}, storage.ErrCorrupt
		}
	}
	if d.Finish() != nil || result.validate() != nil {
		return CanonicalPruneEffect{}, storage.ErrCorrupt
	}
	return result, nil
}

func workPruneEffectKey(ticketID types.Hash) []byte {
	return append([]byte{workPruneEffectPrefix}, ticketID[:]...)
}

func (persistence *workPersistence) pruneEffect(ticketID types.Hash) (CanonicalPruneEffect, bool, error) {
	value, closer, err := persistence.db.Get(workPruneEffectKey(ticketID))
	if errors.Is(err, pebble.ErrNotFound) {
		return CanonicalPruneEffect{}, false, nil
	}
	if err != nil {
		return CanonicalPruneEffect{}, false, err
	}
	defer closer.Close()
	effect, err := DecodeCanonicalPruneEffect(value)
	if err != nil || effect.Operation.TicketID != ticketID || !persistence.effectSchema || effect.Operation.StorageID != persistence.storageID {
		return CanonicalPruneEffect{}, false, storage.ErrCorrupt
	}
	return effect, true, nil
}

// Verify bounded retained results against the fully recovered canonical chain.
// Historical external availability/authority claims are not re-attested here.
func (persistence *workPersistence) verifyPruneEffects(store *Store) error {
	it, err := persistence.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{workPruneEffectPrefix}, UpperBound: []byte{workPruneEffectPrefix + 1},
	})
	if err != nil {
		return err
	}
	defer it.Close()
	type interval struct{ before, after uint64 }
	intervals := make([]interval, 0)
	latestFound := false
	tipAt := func(id types.Hash) (storage.Tip, bool) {
		if id == store.baseID {
			return store.baseTip, true
		}
		if id == store.floor.Anchor.ID {
			return store.floor.Anchor, true
		}
		tip, found := store.archivedTips[id]
		return tip, found
	}
	for valid := it.First(); valid; valid = it.Next() {
		if len(intervals) >= MaximumCanonicalPruneEffects || !persistence.effectSchema ||
			!store.floor.Pruned || len(it.Key()) != 1+types.HashSize {
			return storage.ErrCorrupt
		}
		effect, err := DecodeCanonicalPruneEffect(it.Value())
		if err != nil || !bytes.Equal(it.Key()[1:], effect.Operation.TicketID[:]) || effect.Operation.StorageID != persistence.storageID {
			return storage.ErrCorrupt
		}
		b := effect.Operation.Boundary
		if b.RadixActivationHeight != 0 && b.RadixActivationHeight != store.parameters.RadixActivationHeight {
			return storage.ErrCorrupt
		}
		anchor, found := tipAt(b.Anchor.ID)
		previous, previousFound := tipAt(effect.Report.PreviousFloorID)
		if !found || !previousFound || b.BaseID != store.baseID || !storage.EqualTips(anchor, b.Anchor) ||
			anchor.Height <= previous.Height || anchor.Height > store.floor.Anchor.Height ||
			effect.Report.RemovedNodes != anchor.Height-previous.Height ||
			b.AncestryNodes-1 != anchor.Height-store.baseTip.Height {
			return storage.ErrCorrupt
		}
		intervals = append(intervals, interval{previous.Height, anchor.Height})
		if anchor.ID == store.floor.Anchor.ID {
			b.VerifiedAt, b.PruneTicketID = effect.VerifiedAt, effect.Operation.TicketID
			actual, aerr := encodeCanonicalFloor(store.floor)
			expected, eerr := encodeCanonicalFloor(b)
			if aerr != nil || eerr != nil || !bytes.Equal(actual, expected) {
				return storage.ErrCorrupt
			}
			latestFound = true
		}
	}
	if err := it.Error(); err != nil {
		return err
	}
	if persistence.effectSchema != (len(intervals) != 0) ||
		(!store.floor.PruneTicketID.IsZero() && !latestFound) {
		return storage.ErrCorrupt
	}
	// Legacy prunes can leave gaps between ticketed intervals, never overlaps.
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].after < intervals[j].after })
	for i := 1; i < len(intervals); i++ {
		if intervals[i].before < intervals[i-1].after {
			return storage.ErrCorrupt
		}
	}
	persistence.pruneEffects = uint32(len(intervals))
	return nil
}
