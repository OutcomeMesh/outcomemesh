package workchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func testStorageID() types.Hash { return types.DomainHash("test/workchain/storage-incarnation") }

func TestBoundStorageRequiresNewRootAndExactReopenPin(t *testing.T) {
	parameters := testParameters()
	base := testBase(t, parameters)
	policy := DefaultPolicy()
	path := filepath.Join(t.TempDir(), "bound")
	if s, err := CreateBoundWithPolicy(path, base, parameters, policy, types.Hash{}); s != nil || !errors.Is(err, ErrStorageBinding) {
		t.Fatal("zero creation pin", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid pin created a root", err)
	}
	if s, err := OpenBoundWithPolicy(path, base, parameters, policy, testStorageID()); s != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing bound root opened", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reopen created missing storage", err)
	}
	s, err := CreateBoundWithPolicy(path, base, parameters, policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyStorageID(testStorageID()); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyStorageID(types.Hash{}); !errors.Is(err, ErrStorageBinding) {
		t.Fatal("zero pin treated as wildcard", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyStorageID(testStorageID()); !errors.Is(err, storage.ErrClosed) {
		t.Fatal("closed store identity accepted", err)
	}
	if created, err := CreateBoundWithPolicy(path, base, parameters, policy, testStorageID()); created != nil || !errors.Is(err, os.ErrExist) {
		t.Fatal("existing root recreated", err)
	}
	if raw, err := OpenWithPolicy(path, base, parameters, policy); raw != nil || !errors.Is(err, ErrStorageBinding) {
		t.Fatal("bound storage reopened without a pin", err)
	}
	if wrong, err := OpenBoundWithPolicy(path, base, parameters, policy, types.DomainHash("wrong")); wrong != nil || !errors.Is(err, ErrStorageBinding) {
		t.Fatal("wrong reopen pin", err)
	}
	s, err = OpenBoundWithPolicy(path, base, parameters, policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tip, err := s.Tip()
	if err != nil || !storage.EqualTips(tip, base.Tip) {
		t.Fatal("bound initialization changed consensus state", err)
	}
	legacyPath := filepath.Join(t.TempDir(), "legacy")
	legacy, err := OpenWithPolicy(legacyPath, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()
	if bound, err := OpenBoundWithPolicy(legacyPath, base, parameters, policy, testStorageID()); bound != nil || !errors.Is(err, ErrStorageBinding) {
		t.Fatal("reopen attached an ID to legacy data", err)
	}
}

func TestBoundStoragePruneChecksPinBeforeAuthorization(t *testing.T) {
	s, path, base, parameters, policy, boundary := canonicalAuthorizationFixtureWithStorageID(t, testStorageID())
	op := pruneOperation(boundary, "storage-bound")
	for _, id := range []types.Hash{{}, types.DomainHash("wrong-incarnation")} {
		op.StorageID = id
		if _, err := s.PruneCanonicalPrefixOnce(op, func() (uint64, error) {
			t.Error("wrong database reached authorization")
			return 200, nil
		}); !errors.Is(err, ErrStorageBinding) {
			t.Fatal("wrong prune binding", err)
		}
	}
	if _, err := s.PruneCanonicalPrefixAuthorized(boundary, func() (uint64, error) {
		t.Error("unbound prune bypassed storage pin")
		return 200, nil
	}); !errors.Is(err, ErrStorageBinding) {
		t.Fatal("unbound prune allowed", err)
	}
	op.StorageID = testStorageID()
	commit, err := s.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil })
	if err != nil || !commit.Applied || commit.Effect.Operation.StorageID != op.StorageID {
		t.Fatal("bound commit", commit, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenBoundWithPolicy(path, base, parameters, policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.PruneCanonicalPrefixOnce(op, func() (uint64, error) {
		t.Error("retained effect reauthorized")
		return 300, nil
	})
	if err != nil || got.Applied || !equalPruneEffect(got.Effect, commit.Effect) {
		t.Fatal("bound result changed on reopen", err)
	}
	raw, _, _, _, _, rawBoundary := canonicalAuthorizationFixture(t)
	op.Boundary = rawBoundary
	if _, err := raw.PruneCanonicalPrefixOnce(op, func() (uint64, error) {
		t.Error("bound request ran on unbound database")
		return 200, nil
	}); !errors.Is(err, ErrStorageBinding) {
		t.Fatal("bound request accepted by raw database", err)
	}
}

func TestBoundStorageRejectsMissingChangedAndDowngradedIdentity(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "short", "zero", "changed", "schema-downgrade", "effect-schema-missing", "effect-wrong-id", "effect-unbound"} {
		t.Run(mode, func(t *testing.T) {
			s, path, base, parameters, policy, boundary := canonicalAuthorizationFixtureWithStorageID(t, testStorageID())
			op := pruneOperation(boundary, "corrupt-storage-binding")
			op.StorageID = testStorageID()
			commit, err := s.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil })
			if err != nil {
				t.Fatal(err)
			}
			db := s.persistence.db
			put := func(key, value []byte) {
				t.Helper()
				if err := db.Set(key, value, pebble.Sync); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing":
				if err := db.Delete(workKeyStorageID, pebble.Sync); err != nil {
					t.Fatal(err)
				}
			case "empty":
				put(workKeyStorageID, nil)
			case "short":
				put(workKeyStorageID, []byte{1})
			case "zero":
				put(workKeyStorageID, make([]byte, 32))
			case "changed":
				other := types.DomainHash("other-storage")
				put(workKeyStorageID, other[:])
			case "schema-downgrade":
				put(workKeySchema, []byte{0, byte(workEffectSchemaVersion)})
			case "effect-schema-missing":
				put(workKeySchema, []byte{0, byte(workBoundSchemaVersion)})
			case "effect-wrong-id", "effect-unbound":
				commit.Effect.Operation.StorageID = types.DomainHash("other-effect-storage")
				if mode == "effect-unbound" {
					commit.Effect.Operation.StorageID = types.Hash{}
					// Repair the byte count so rejection tests the binding itself.
					var history [8]byte
					binary.BigEndian.PutUint64(history[:], s.persistence.historyBytes-32)
					put(workKeyHistory, history[:])
				}
				encoded, _ := commit.Effect.CanonicalBytes()
				put(workPruneEffectKey(op.TicketID), encoded)
			}
			_ = s.Close()
			for range 2 {
				if reopened, err := OpenBoundWithPolicy(path, base, parameters, policy, testStorageID()); err == nil {
					_ = reopened.Close()
					t.Fatal("corrupt binding opened")
				}
			}
		})
	}
}

func TestBoundStorageInitializationFailureDoesNotRebind(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-commit", true: "after-commit"}[committed], func(t *testing.T) {
			p := testParameters()
			b := testBase(t, p)
			path := filepath.Join(t.TempDir(), "chain")
			injected := errors.New("lost initialization response")
			created, err := createBoundWithPolicy(path, b, p, DefaultPolicy(), testStorageID(), func(batch *pebble.Batch) error {
				if committed {
					if err := batch.Commit(pebble.Sync); err != nil {
						return err
					}
				}
				return injected
			})
			if created != nil || !errors.Is(err, injected) {
				t.Fatal("unexpected initialization outcome", err)
			}
			if recreated, err := CreateBoundWithPolicy(path, b, p, DefaultPolicy(), testStorageID()); recreated != nil || !errors.Is(err, os.ErrExist) {
				t.Fatal("uncertain initialization recreated", err)
			}
			reopened, err := OpenBoundWithPolicy(path, b, p, DefaultPolicy(), testStorageID())
			if !committed {
				if reopened != nil || err == nil {
					t.Fatal("missing identity initialized on reopen")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				_ = reopened.Close()
			}
		})
	}
}

// This limitation is deliberate: an incarnation ID is retained in a database
// copy. Independent physical/copy/rollback fencing must not be claimed from it.
func TestBoundStorageCopyRetainsLogicalIncarnation(t *testing.T) {
	s, _, base, parameters, policy, boundary := canonicalAuthorizationFixtureWithStorageID(t, testStorageID())
	copyPath := filepath.Join(t.TempDir(), "copy")
	if err := s.persistence.db.Checkpoint(copyPath); err != nil {
		t.Fatal(err)
	}
	copyStore, err := OpenBoundWithPolicy(copyPath, base, parameters, policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	op := pruneOperation(boundary, "after-copy")
	op.StorageID = testStorageID()
	if _, err := s.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil }); err != nil {
		t.Fatal(err)
	}
	if _, found, err := copyStore.CanonicalPruneEffect(op.TicketID); err != nil || found {
		t.Fatal("copy incorrectly refreshed its effect", found, err)
	}
}

func TestBoundCanonicalPruneEffectCodec(t *testing.T) {
	s, _, _, _, _, boundary := canonicalAuthorizationFixtureWithStorageID(t, testStorageID())
	op := pruneOperation(boundary, "bound-vector")
	op.StorageID = testStorageID()
	commit, err := s.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil })
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := commit.Effect.CanonicalBytes()
	id, _ := commit.Effect.ID()
	if len(encoded) != 522 || id.String() != "4ee4404d3f5ce8106b8ab018585db43f0550c22d677b1f49d74ba26b4211c103" {
		t.Fatalf("bound effect vector changed: bytes=%d id=%s", len(encoded), id)
	}
	decoded, err := DecodeCanonicalPruneEffect(encoded)
	if err != nil || !equalPruneEffect(decoded, commit.Effect) {
		t.Fatal("bound effect roundtrip", err)
	}
	for length := 0; length < len(encoded); length++ {
		if _, err := DecodeCanonicalPruneEffect(encoded[:length]); err == nil {
			t.Fatal("accepted truncated bound effect", length)
		}
	}
	for _, mode := range []string{"zero-id", "v0-tag", "unknown-version", "trailing"} {
		bad := bytes.Clone(encoded)
		switch mode {
		case "zero-id":
			clear(bad[74:106])
		case "v0-tag":
			bad[9] = 0
		case "unknown-version":
			bad[9] = 2
		case "trailing":
			bad = append(bad, 0)
		}
		if _, err := DecodeCanonicalPruneEffect(bad); err == nil {
			t.Fatal("accepted malformed bound effect", mode)
		}
	}
}
