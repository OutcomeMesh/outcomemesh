package workchain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"path/filepath"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

var ErrRadixMigration = errors.New("protected radix migration requires the original confirmed storage pair and exact review")

var workKeyRadixMigration = []byte{0x01, 0x09}

// MaximumRadixMigrationBytes bounds one stopped-owner inventory scan. Migration
// never copies state, reissues admissions, discards effects or replaces pins.
const MaximumRadixMigrationBytes uint64 = 64 << 20

type RadixScheduleReview struct {
	StorageID, PairID, RootsID, OldConfigID, NewConfigID, InventoryID, TipID types.Hash
	Before                                                                   StoragePosition
	RadixActivationHeight, MaximumRetainedHeight                             uint64
}

func (r RadixScheduleReview) canonicalBytes() []byte {
	e := codec.NewEncoder(320)
	e.U16(0)
	for _, h := range []types.Hash{r.StorageID, r.PairID, r.RootsID, r.OldConfigID, r.NewConfigID, r.InventoryID, r.TipID} {
		e.Fixed(h[:])
	}
	e.Fixed(encodeStoragePosition(r.Before))
	e.U64(r.RadixActivationHeight)
	e.U64(r.MaximumRetainedHeight)
	return e.Bytes()
}

func (r RadixScheduleReview) ID() types.Hash {
	return types.DomainHash("OMESH/workchain/radix-schedule/review/v0", r.canonicalBytes())
}

// ReviewRadixSchedule takes no persistent action. Every database key participates
// in the review, including retained outcomes and the current canonical floor.
func (s *Store) ReviewRadixSchedule(ctx context.Context, height uint64) (RadixScheduleReview, error) {
	if s == nil {
		return RadixScheduleReview{}, ErrRadixMigration
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reviewRadixScheduleLocked(ctx, height)
}

func (s *Store) reviewRadixScheduleLocked(ctx context.Context, height uint64) (RadixScheduleReview, error) {
	if ctx == nil {
		return RadixScheduleReview{}, ErrRadixMigration
	}
	if err := ctx.Err(); err != nil {
		return RadixScheduleReview{}, err
	}
	if err := s.openErrorLocked(); err != nil {
		return RadixScheduleReview{}, err
	}
	p := s.persistence
	if p == nil || p.pins == nil || s.parameters.RadixActivationHeight != 0 || height == 0 || p.position != p.pins.confirmed {
		return RadixScheduleReview{}, ErrRadixMigration
	}
	if err := p.pins.checkTail(); err != nil {
		return RadixScheduleReview{}, err
	}
	if _, err := p.get(workKeyRadixMigration); !errors.Is(err, pebble.ErrNotFound) {
		return RadixScheduleReview{}, errors.Join(ErrRadixMigration, err)
	}
	if p.position.Sequence >= MaximumStoragePositions {
		return RadixScheduleReview{}, ErrStoragePinLimit
	}
	next := s.parameters
	next.RadixActivationHeight = height
	if next.Validate() != nil {
		return RadixScheduleReview{}, ErrRadixMigration
	}
	maxHeight := s.baseTip.Height
	for _, n := range s.nodes {
		if n.tip.Height > maxHeight {
			maxHeight = n.tip.Height
		}
	}
	for _, h := range s.archivedHeaders {
		if h.Seal.Height > maxHeight {
			maxHeight = h.Seal.Height
		}
	}
	if height <= maxHeight {
		return RadixScheduleReview{}, ErrRadixMigration
	}
	i, err := p.db.NewIter(nil)
	if err != nil {
		return RadixScheduleReview{}, err
	}
	defer i.Close()
	h := sha256.New()
	h.Write([]byte("OMESH/workchain/radix-schedule/inventory/v0"))
	var total uint64
	for valid := i.First(); valid; valid = i.Next() {
		if err := ctx.Err(); err != nil {
			return RadixScheduleReview{}, err
		}
		size := uint64(len(i.Key()) + len(i.Value()))
		if size > MaximumRadixMigrationBytes-total {
			return RadixScheduleReview{}, storage.ErrHistoryLimit
		}
		total += size
		for _, b := range [][]byte{i.Key(), i.Value()} {
			var length [8]byte
			binary.BigEndian.PutUint64(length[:], uint64(len(b)))
			h.Write(length[:])
			h.Write(b)
		}
	}
	if err := i.Error(); err != nil {
		return RadixScheduleReview{}, err
	}
	base := Base{Tip: s.baseTip, RecentTimestamps: s.baseHistory}
	var inventory types.Hash
	copy(inventory[:], h.Sum(nil))
	roots := codec.NewEncoder(len(p.rootPath) + len(p.pins.path) + 20)
	roots.BytesField([]byte(p.rootPath))
	roots.BytesField([]byte(p.pins.path))
	return RadixScheduleReview{StorageID: p.storageID, PairID: p.pins.pairID,
		RootsID:     types.DomainHash("OMESH/workchain/radix-schedule/roots/v0", roots.Bytes()),
		OldConfigID: workConfigHash(base, s.parameters), NewConfigID: workConfigHash(base, next),
		InventoryID: inventory, TipID: s.tipID, Before: p.position,
		RadixActivationHeight: height, MaximumRetainedHeight: maxHeight}, nil
}

// MigrateRadixSchedule commits only configuration, its permanent receipt and the
// independent position in one batch. All obligations retain their original IDs,
// bytes and expiry. An uncertain result must be inspected after cold reopen.
func (s *Store) MigrateRadixSchedule(ctx context.Context, height uint64, expected types.Hash) (RadixScheduleReview, error) {
	if s == nil || expected.IsZero() {
		return RadixScheduleReview{}, ErrRadixMigration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.reviewRadixScheduleLocked(ctx, height)
	if err != nil {
		return RadixScheduleReview{}, err
	}
	if r.ID() != expected {
		return RadixScheduleReview{}, ErrRadixMigration
	}
	p := s.persistence
	batch := p.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(workKeyConfig, r.NewConfigID[:], nil); err != nil {
		return RadixScheduleReview{}, err
	}
	err = p.commitBatch(batch, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		encoded := append(r.canonicalBytes(), encodeStoragePosition(*p.pins.pending)...)
		return batch.Set(workKeyRadixMigration, encoded, nil)
	}, nil)
	if err != nil {
		return RadixScheduleReview{}, err
	}
	s.parameters.RadixActivationHeight = height
	p.radixMigrationID = expected
	return r, nil
}

// OpenRadixMigratedPositionPinnedWithPolicy is an explicit cold open of a
// committed transition. expected is the independently retained review ID. It
// opens the ORIGINAL pin identity under the old configuration; the database
// must contain that exact transition at an intent in this same journal.
func OpenRadixMigratedPositionPinnedWithPolicy(path, pinsPath string, base Base, parameters workblock.Parameters, policy Policy, storageID, expected types.Hash) (_ *Store, err error) {
	if expected.IsZero() || parameters.RadixActivationHeight == 0 || parameters.Validate() != nil {
		return nil, ErrRadixMigration
	}
	path, pinsPath, err = positionPaths(path, pinsPath)
	if err != nil {
		return nil, err
	}
	old := parameters
	old.RadixActivationHeight = 0
	pins, err := openPositionPins(pinsPath, storageID, workConfigHash(base, old))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, pins.lock.Close())
		}
	}()
	return openWithPositionPinsMigration(path, base, parameters, policy, storageID, true, nil, pins, expected)
}

func decodeRadixMigration(encoded []byte) (RadixScheduleReview, StoragePosition, error) {
	r := RadixScheduleReview{}
	const reviewSize = 2 + 7*types.HashSize + 40 + 16
	if len(encoded) != reviewSize+40 {
		return r, StoragePosition{}, ErrRadixMigration
	}
	d := codec.NewDecoder(encoded)
	v, err := d.U16()
	if err != nil || v != 0 {
		return r, StoragePosition{}, ErrRadixMigration
	}
	for _, h := range []*types.Hash{&r.StorageID, &r.PairID, &r.RootsID, &r.OldConfigID, &r.NewConfigID, &r.InventoryID, &r.TipID} {
		b, e := d.Fixed(types.HashSize)
		if e != nil {
			return r, StoragePosition{}, e
		}
		copy(h[:], b)
		if h.IsZero() {
			return r, StoragePosition{}, ErrRadixMigration
		}
	}
	b, _ := d.Fixed(40)
	r.Before, err = decodeStoragePosition(b)
	if err != nil {
		return r, StoragePosition{}, err
	}
	r.RadixActivationHeight, _ = d.U64()
	r.MaximumRetainedHeight, _ = d.U64()
	b, _ = d.Fixed(40)
	after, err := decodeStoragePosition(b)
	if err != nil || after.Sequence != r.Before.Sequence+1 || after.CommitID == r.Before.CommitID || r.RadixActivationHeight <= r.MaximumRetainedHeight {
		return r, after, ErrRadixMigration
	}
	return r, after, d.Finish()
}

func (p *workPersistence) validateRadixMigration(base Base, parameters workblock.Parameters) error {
	encoded, err := p.get(workKeyRadixMigration)
	if p.radixMigrationID.IsZero() {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil
		}
		return errors.Join(ErrRadixMigration, err)
	}
	if err != nil || p.pins == nil {
		return errors.Join(ErrRadixMigration, err)
	}
	r, after, err := decodeRadixMigration(encoded)
	old := parameters
	old.RadixActivationHeight = 0
	if err != nil || r.ID() != p.radixMigrationID || r.NewConfigID != workConfigHash(base, parameters) ||
		r.OldConfigID != workConfigHash(base, old) || r.RadixActivationHeight != parameters.RadixActivationHeight ||
		r.StorageID != p.storageID || r.PairID != p.pins.pairID || p.position.Sequence < after.Sequence {
		return errors.Join(ErrRadixMigration, err)
	}
	intent, err := readPositionFile(filepath.Join(p.pins.path, "intents", positionName(after.Sequence)), positionRecordMaximum)
	if err != nil {
		return err
	}
	before, actual, err := decodePositionRecord(intent, p.pins.encodedIdentity, false)
	if err != nil || before != r.Before || actual != after {
		return errors.Join(ErrRadixMigration, err)
	}
	return nil
}
