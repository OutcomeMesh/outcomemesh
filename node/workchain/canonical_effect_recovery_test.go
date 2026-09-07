package workchain

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestCanonicalPruneEffectRejectsCorruptRecovery(t *testing.T) {
	for _, mode := range []string{
		"missing-result", "truncated", "trailing", "oversized", "wrong-key", "short-key", "wrong-base",
		"wrong-anchor", "unknown-previous", "wrong-removed", "overlapping", "schema-downgrade", "unknown-schema", "missing-schema",
		"floor-untagged", "floor-wrong-ticket", "floor-wrong-time", "floor-wrong-evidence",
	} {
		t.Run(mode, func(t *testing.T) {
			store, path, base, parameters, policy, boundary := canonicalAuthorizationFixture(t)
			op := pruneOperation(boundary, "corrupt")
			commit, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil })
			if err != nil {
				t.Fatal(err)
			}
			db := store.persistence.db
			key := workPruneEffectKey(op.TicketID)
			encoded, _ := commit.Effect.CanonicalBytes()
			put := func(key, value []byte) {
				t.Helper()
				if err := db.Set(key, value, pebble.Sync); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(key []byte) {
				t.Helper()
				if err := db.Delete(key, pebble.Sync); err != nil {
					t.Fatal(err)
				}
			}
			mutated := commit.Effect
			switch mode {
			case "missing-result":
				remove(key)
			case "truncated":
				put(key, encoded[:len(encoded)-1])
			case "trailing":
				put(key, append(encoded, 0))
			case "oversized":
				put(key, make([]byte, MaximumCanonicalPruneEffectBytes+1))
			case "wrong-key":
				remove(key)
				wrong := op.TicketID
				wrong[0] ^= 1
				put(workPruneEffectKey(wrong), encoded)
			case "short-key":
				remove(key)
				put(key[:len(key)-1], encoded)
			case "wrong-base":
				mutated.Operation.Boundary.BaseID[0] ^= 1
			case "wrong-anchor":
				mutated.Operation.Boundary.Anchor.ID[0] ^= 1
				mutated.Report.FloorID = mutated.Operation.Boundary.Anchor.ID
			case "unknown-previous":
				mutated.Report.PreviousFloorID[0] ^= 1
			case "wrong-removed":
				mutated.Report.RemovedNodes++
			case "overlapping":
				mutated.Operation.TicketID[0] ^= 1
			case "schema-downgrade":
				put(workKeySchema, []byte{0, byte(workSchemaVersion)})
			case "unknown-schema":
				put(workKeySchema, []byte{0xff, 0xff})
			case "missing-schema":
				remove(workKeySchema)
			case "floor-untagged", "floor-wrong-ticket", "floor-wrong-time", "floor-wrong-evidence":
				floor, _ := store.CanonicalFloor()
				switch mode {
				case "floor-untagged":
					floor.PruneTicketID = types.Hash{}
				case "floor-wrong-ticket":
					floor.PruneTicketID[0] ^= 1
				case "floor-wrong-time":
					floor.VerifiedAt++
				case "floor-wrong-evidence":
					floor.AvailabilityID[0] ^= 1
				}
				bytes, err := encodeCanonicalFloor(floor)
				if err != nil {
					t.Fatal(err)
				}
				put(workKeyFloor, bytes)
			}
			switch mode {
			case "wrong-base", "wrong-anchor", "unknown-previous", "wrong-removed", "overlapping":
				bytes, err := mutated.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				put(workPruneEffectKey(mutated.Operation.TicketID), bytes)
			}
			// Repair only the test's byte counter. Structural rejection must not
			// depend solely on an easily detected accounting mismatch.
			it, err := db.NewIter(&pebble.IterOptions{LowerBound: []byte{workNodePrefix}, UpperBound: []byte{workPruneEffectPrefix + 1}})
			if err != nil {
				t.Fatal(err)
			}
			var total uint64
			for valid := it.First(); valid; valid = it.Next() {
				total += uint64(len(it.Key()) + len(it.Value()))
			}
			if err := it.Error(); err != nil {
				t.Fatal(err)
			}
			if err := it.Close(); err != nil {
				t.Fatal(err)
			}
			floor, err := store.persistence.get(workKeyFloor)
			if err != nil {
				t.Fatal(err)
			}
			total += uint64(len(workKeyFloor) + len(floor))
			var history [8]byte
			binary.BigEndian.PutUint64(history[:], total)
			put(workKeyHistory, history[:])
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := OpenWithPolicy(path, base, parameters, policy)
			if opened != nil {
				_ = opened.Close()
				t.Fatal("corrupt store returned handle")
			}
			if !errors.Is(err, storage.ErrCorrupt) {
				t.Fatal("corrupt effect accepted", err)
			}
		})
	}
}

func TestCanonicalPruneEffectSchemaRequiresARealEffect(t *testing.T) {
	store, path, base, parameters, policy, _ := canonicalAuthorizationFixture(t)
	if err := store.persistence.db.Set(workKeySchema, []byte{0, byte(workEffectSchemaVersion)}, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenWithPolicy(path, base, parameters, policy); !errors.Is(err, storage.ErrCorrupt) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("empty schema upgrade accepted", err)
	}
}

func TestWorkChainDoesNotBootstrapNonemptyUnmarkedStore(t *testing.T) {
	for _, used := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign-key", true: "used-schema-four"}[used], func(t *testing.T) {
			parameters := testParameters()
			base := testBase(t, parameters)
			path := t.TempDir()
			if used {
				store, err := Open(path, base, parameters)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.persistence.db.Delete(workKeySchema, pebble.Sync); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				db, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Set([]byte{0xff}, []byte("retained unknown data"), pebble.Sync); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				store, err := Open(path, base, parameters)
				if store != nil {
					_ = store.Close()
					t.Fatal("nonempty root bootstrapped")
				}
				if !errors.Is(err, storage.ErrCorrupt) {
					t.Fatal("wrong initialization outcome", err)
				}
			}
			db, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			_, closer, err := db.Get(workKeySchema)
			if closer != nil {
				_ = closer.Close()
			}
			if !errors.Is(err, pebble.ErrNotFound) {
				t.Fatal("rejected open recreated schema", err)
			}
		})
	}
}

func TestCanonicalPruneEffectInvalidHandlesAndLegacyBoundary(t *testing.T) {
	store, _, base, parameters, _, boundary := canonicalAuthorizationFixture(t)
	op := pruneOperation(boundary, "handles")
	memory, err := New(base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	for _, handle := range []*Store{nil, memory} {
		if _, err := handle.PruneCanonicalPrefixOnce(op, func() (uint64, error) { t.Error("invalid callback"); return 200, nil }); !errors.Is(err, ErrCanonicalPrune) {
			t.Fatal(err)
		}
		if _, _, err := handle.CanonicalPruneEffect(op.TicketID); !errors.Is(err, ErrCanonicalPrune) {
			t.Fatal(err)
		}
	}
	if _, _, err := store.CanonicalPruneEffect(types.Hash{}); !errors.Is(err, ErrCanonicalPrune) {
		t.Fatal(err)
	}
	boundary.PruneTicketID = op.TicketID
	if _, err := store.PruneCanonicalPrefix(boundary); !errors.Is(err, ErrCanonicalPrune) {
		t.Fatal("legacy primitive accepted forged result link", err)
	}
	if _, err := store.PruneCanonicalPrefixAuthorized(boundary, func() (uint64, error) { t.Error("invalid callback"); return 200, nil }); !errors.Is(err, ErrCanonicalPrune) {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { t.Error("closed callback"); return 200, nil }); !errors.Is(err, storage.ErrClosed) {
		t.Fatal(err)
	}
	if _, _, err := store.CanonicalPruneEffect(op.TicketID); !errors.Is(err, storage.ErrClosed) {
		t.Fatal(err)
	}
}
