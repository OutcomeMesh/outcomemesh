package workchain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func migrationObligations(t testing.TB, s *Store) map[string][]byte {
	t.Helper()
	i, err := s.persistence.db.NewIter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	out := map[string][]byte{}
	for ok := i.First(); ok; ok = i.Next() {
		if bytes.Equal(i.Key(), workKeyConfig) || bytes.Equal(i.Key(), workKeyPosition) || bytes.Equal(i.Key(), workKeyRadixMigration) {
			continue
		}
		out[string(i.Key())] = bytes.Clone(i.Value())
	}
	if err := i.Error(); err != nil {
		t.Fatal(err)
	}
	return out
}
func assertMigrationObligations(t testing.TB, before map[string][]byte, s *Store) {
	t.Helper()
	after := migrationObligations(t, s)
	if len(before) != len(after) {
		t.Fatal("migration changed key inventory")
	}
	for k, b := range before {
		if !bytes.Equal(b, after[k]) {
			t.Fatalf("migration changed retained key %x", k)
		}
	}
}

func TestProtectedRadixMigrationPreservesPrunedEffectsAndOldCopyFence(t *testing.T) {
	f := newPositionFixture(t, 6)
	op := f.operation()
	if _, err := f.chain.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil }); err != nil {
		t.Fatal(err)
	}
	// Retain a clean old database and old pin copy before the one-way transition.
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	oldDB, oldPins := filepath.Join(t.TempDir(), "old-db"), filepath.Join(t.TempDir(), "old-pins")
	if err := os.CopyFS(oldDB, os.DirFS(f.path)); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(oldPins, os.DirFS(f.pins)); err != nil {
		t.Fatal(err)
	}
	var err error
	f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	before := migrationObligations(t, f.chain)
	floor, _ := f.chain.CanonicalFloor()
	tip, _ := f.chain.Tip()
	ctx := context.Background()
	r, err := f.chain.ReviewRadixSchedule(ctx, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.chain.MigrateRadixSchedule(ctx, 8, types.Hash{9}); !errors.Is(err, ErrRadixMigration) {
		t.Fatal("stale review", err)
	}
	if _, err := f.chain.MigrateRadixSchedule(ctx, 8, r.ID()); err != nil {
		t.Fatal(err)
	}
	assertMigrationObligations(t, before, f.chain)
	afterFloor, _ := f.chain.CanonicalFloor()
	afterTip, _ := f.chain.Tip()
	if !storage.EqualTips(tip, afterTip) || fmt.Sprint(floor) != fmt.Sprint(afterFloor) {
		t.Fatal("floor/tip reset")
	}
	if _, err := f.chain.ReviewRadixSchedule(ctx, 9); !errors.Is(err, ErrRadixMigration) {
		t.Fatal("rescheduled", err)
	}
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	next := f.parameters
	next.RadixActivationHeight = 8
	for _, tc := range []struct {
		name, path, pins string
		migrated         bool
	}{
		{"old configuration", f.path, f.pins, false}, {"old database", oldDB, f.pins, false}, {"old pins", f.path, oldPins, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s *Store
			var err error
			if tc.migrated {
				s, err = OpenRadixMigratedPositionPinnedWithPolicy(tc.path, tc.pins, f.base, next, f.policy, testStorageID(), r.ID())
			} else {
				s, err = OpenPositionPinnedWithPolicy(tc.path, tc.pins, f.base, f.parameters, f.policy, testStorageID())
			}
			if err == nil {
				s.Close()
				t.Fatal("stale copy opened")
			}
		})
	}
	f.chain, err = OpenRadixMigratedPositionPinnedWithPolicy(f.path, f.pins, f.base, next, f.policy, testStorageID(), r.ID())
	if err != nil {
		t.Fatal(err)
	}
	assertMigrationObligations(t, before, f.chain)
	// Crossing activation keeps the old canonical floor and its effect record.
	for h := uint64(7); h <= 9; h++ {
		tip, _ := f.chain.Tip()
		b, _ := mineChild(t, f.chain, tip.ID, tip.Timestamp+next.TargetSpacing, fmt.Sprint(h))
		if _, _, err = f.chain.Commit(b, b.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, _ := f.chain.Snapshot()
	if snapshot.CommitmentVersion() != 1 {
		t.Fatal("did not enter radix")
	}
	if err = f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	f.chain, err = OpenRadixMigratedPositionPinnedWithPolicy(f.path, f.pins, f.base, next, f.policy, testStorageID(), r.ID())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.chain.CanonicalFloor()
	if fmt.Sprint(got) != fmt.Sprint(floor) {
		t.Fatal("lost original prune obligation")
	}
}

func TestProtectedRadixMigrationCrashBoundaries(t *testing.T) {
	for _, point := range []string{"database-before", "database-after", "confirmation-before-temp"} {
		t.Run(point, func(t *testing.T) {
			f := newPositionFixture(t, 3)
			before := migrationObligations(t, f.chain)
			r, err := f.chain.ReviewRadixSchedule(context.Background(), 5)
			if err != nil {
				t.Fatal(err)
			}
			hit := false
			f.chain.persistence.pins.hook = func(got string) error {
				if got == point {
					hit = true
					return errors.New("injected migration interruption")
				}
				return nil
			}
			_, err = f.chain.MigrateRadixSchedule(context.Background(), 5, r.ID())
			if !hit {
				t.Fatalf("missing fault boundary %s", point)
			}
			if !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			if err = f.chain.Close(); err != nil {
				t.Fatal(err)
			}
			next := f.parameters
			next.RadixActivationHeight = 5
			if point == "database-before" {
				f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
				if err != nil {
					t.Fatal(err)
				}
				if err = f.chain.ResumeStorageConfirmation(); !errors.Is(err, ErrStoragePinPending) {
					t.Fatal("invented no-effect disposition", err)
				}
			} else {
				f.chain, err = OpenRadixMigratedPositionPinnedWithPolicy(f.path, f.pins, f.base, next, f.policy, testStorageID(), r.ID())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.chain.Tip(); !errors.Is(err, ErrStoragePinPending) {
					t.Fatal("unconfirmed write exposed", err)
				}
				if err = f.chain.ResumeStorageConfirmation(); err != nil {
					t.Fatal(err)
				}
				if err = f.chain.ResumeStorageConfirmation(); err != nil {
					t.Fatal(err)
				}
			}
			assertMigrationObligations(t, before, f.chain)
		})
	}
}

func TestProtectedRadixMigrationRejectsChangedInventoryAndCancellation(t *testing.T) {
	f := newPositionFixture(t, 3)
	for _, h := range []uint64{0, 1, 3} {
		if _, err := f.chain.ReviewRadixSchedule(context.Background(), h); err == nil {
			t.Fatal("past activation")
		}
	}
	r, err := f.chain.ReviewRadixSchedule(context.Background(), 6)
	if err != nil {
		t.Fatal(err)
	}
	tip, _ := f.chain.Tip()
	b, _ := mineChild(t, f.chain, tip.ID, tip.Timestamp+60, "after-review")
	if _, _, err = f.chain.Commit(b, b.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err = f.chain.MigrateRadixSchedule(context.Background(), 6, r.ID()); !errors.Is(err, ErrRadixMigration) {
		t.Fatal("stale review", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = f.chain.ReviewRadixSchedule(ctx, 6); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	p, _ := f.chain.StorageProtection()
	if p.Pending != nil || p.Database != p.Confirmed {
		t.Fatal("review opened an intent")
	}
}

func migrationCodecSeed() []byte {
	r := RadixScheduleReview{StorageID: types.Hash{1}, PairID: types.Hash{2}, RootsID: types.Hash{3}, OldConfigID: types.Hash{4}, NewConfigID: types.Hash{5}, InventoryID: types.Hash{6}, TipID: types.Hash{7}, Before: StoragePosition{Sequence: 2, CommitID: types.Hash{8}}, RadixActivationHeight: 10, MaximumRetainedHeight: 4}
	return append(r.canonicalBytes(), encodeStoragePosition(StoragePosition{Sequence: 3, CommitID: types.Hash{9}})...)
}
func TestProtectedRadixMigrationCanonicalVector(t *testing.T) {
	b := migrationCodecSeed()
	r, after, err := decodeRadixMigration(b)
	if err != nil {
		t.Fatal(err)
	}
	if after.Sequence != 3 || !bytes.Equal(b, append(r.canonicalBytes(), encodeStoragePosition(after)...)) {
		t.Fatal("noncanonical receipt")
	}
	if r.ID().String() != "5ca7ffe2edaf7a437cebecb6f3ecaecf17900f8c23db0ae75fc7cde51822ef79" {
		t.Fatal("migration review vector changed", r.ID())
	}
	for _, invalid := range [][]byte{b[:len(b)-1], append(bytes.Clone(b), 0), make([]byte, len(b))} {
		if _, _, err = decodeRadixMigration(invalid); err == nil {
			t.Fatal("accepted malformed receipt")
		}
	}
}
func FuzzDecodeRadixMigration(f *testing.F) {
	f.Add(migrationCodecSeed())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, after, err := decodeRadixMigration(b)
		if err != nil {
			return
		}
		if !bytes.Equal(b, append(r.canonicalBytes(), encodeStoragePosition(after)...)) {
			t.Fatal("noncanonical migration receipt")
		}
	})
}

func TestProtectedRadixMigrationRejectsMissingReceiptAndUnpinnedStores(t *testing.T) {
	p := testParameters()
	base := testBase(t, p)
	for _, bound := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "store")
		var s *Store
		var err error
		if bound {
			s, err = CreateBoundWithPolicy(path, base, p, DefaultPolicy(), testStorageID())
		} else {
			s, err = Open(path, base, p)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.ReviewRadixSchedule(context.Background(), 5); !errors.Is(err, ErrRadixMigration) {
			t.Fatal("unpinned store migration", err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	f := newPositionFixture(t, 3)
	r, err := f.chain.ReviewRadixSchedule(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.chain.MigrateRadixSchedule(context.Background(), 5, r.ID()); err != nil {
		t.Fatal(err)
	}
	// A receipt is required even if the current position and configuration survive.
	if err = f.chain.persistence.db.Delete(workKeyRadixMigration, nil); err != nil {
		t.Fatal(err)
	}
	if err = f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	next := f.parameters
	next.RadixActivationHeight = 5
	if s, err := OpenRadixMigratedPositionPinnedWithPolicy(f.path, f.pins, f.base, next, f.policy, testStorageID(), r.ID()); err == nil {
		s.Close()
		t.Fatal("missing migration proof recreated")
	}
}
