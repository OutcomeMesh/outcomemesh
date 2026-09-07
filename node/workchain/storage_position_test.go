package workchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

type positionFixture struct {
	chain      *Store
	path, pins string
	base       Base
	parameters workblock.Parameters
	policy     Policy
	boundary   CanonicalFloor
}

func newPositionFixture(t testing.TB, blocks int) *positionFixture {
	t.Helper()
	f := &positionFixture{parameters: testParameters(), policy: DefaultPolicy()}
	f.base = testBase(t, f.parameters)
	f.path, f.pins = filepath.Join(t.TempDir(), "chain"), filepath.Join(t.TempDir(), "pins")
	f.policy.CanonicalRetention, f.policy.ForkRetention, f.policy.CheckpointEvery = 1, 1, 1
	var err error
	f.chain, err = CreatePositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.chain.Close() })
	parent, timestamp := f.base.Tip.ID, f.base.Tip.Timestamp
	for i := 0; i < blocks; i++ {
		timestamp += f.parameters.TargetSpacing
		block, _ := mineChild(t, f.chain, parent, timestamp, fmt.Sprintf("position-%d", i))
		if _, _, err := f.chain.Commit(block, timestamp); err != nil {
			t.Fatal(err)
		}
		parent, _ = block.Header.ID()
		if i == 2 {
			anchor, err := f.chain.TipByID(parent)
			if err != nil {
				t.Fatal(err)
			}
			root, count, err := f.chain.SelectedAncestryCommitment(parent)
			if err != nil {
				t.Fatal(err)
			}
			f.boundary = canonicalTestFloor(f.base.Tip.ID, anchor, root, count, "position")
		}
	}
	return f
}

func (f *positionFixture) reopen(t testing.TB) {
	t.Helper()
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
}

func (f *positionFixture) operation() CanonicalPruneOperation {
	op := pruneOperation(f.boundary, "position")
	op.StorageID = testStorageID()
	return op
}

func positionAction(t testing.TB, f *positionFixture, kind string) func() error {
	t.Helper()
	switch kind {
	case "block":
		tip, err := f.chain.Tip()
		if err != nil {
			t.Fatal(err)
		}
		block, _ := mineChild(t, f.chain, tip.ID, tip.Timestamp+f.parameters.TargetSpacing, "position-next")
		return func() error { _, _, err := f.chain.Commit(block, block.Header.Seal.Timestamp); return err }
	case "checkpoint":
		return func() error { _, err := f.chain.CreateReplayCheckpoint(); return err }
	case "fork-prune":
		block, _ := mineChild(t, f.chain, f.base.Tip.ID, f.base.Tip.Timestamp+f.parameters.TargetSpacing, "position-side")
		if _, _, err := f.chain.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		return func() error { _, err := f.chain.PruneStaleForks(); return err }
	case "canonical-prune":
		return func() error {
			_, err := f.chain.PruneCanonicalPrefixOnce(f.operation(), func() (uint64, error) { return 200, nil })
			return err
		}
	default:
		t.Fatal("unknown position test action", kind)
		return nil
	}
}

// Compare complete logical key/value state, excluding only random local pins.
// Full Open also independently validates state replay, floor and accounting.
func positionDatabaseSummary(t testing.TB, chain *Store) types.Hash {
	t.Helper()
	iter, err := chain.persistence.db.NewIter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer iter.Close()
	var data []byte
	for ok := iter.First(); ok; ok = iter.Next() {
		if bytes.Equal(iter.Key(), workKeyPositionPair) || bytes.Equal(iter.Key(), workKeyPosition) {
			continue
		}
		value, err := iter.ValueAndErr()
		if err != nil {
			t.Fatal(err)
		}
		data = binary.BigEndian.AppendUint64(data, uint64(len(iter.Key())))
		data = append(data, iter.Key()...)
		data = binary.BigEndian.AppendUint64(data, uint64(len(value)))
		data = append(data, value...)
	}
	if err := iter.Error(); err != nil {
		t.Fatal(err)
	}
	return types.DomainHash("test/workchain/position-database", data)
}

func requirePosition(t testing.TB, s *Store, sequence uint64, pending bool) StorageProtection {
	t.Helper()
	p, err := s.StorageProtection()
	if err != nil || p.Database.Sequence != sequence || (p.Pending != nil) != pending {
		t.Fatalf("protection=%+v err=%v want sequence=%d pending=%v", p, err, sequence, pending)
	}
	if !pending && p.Database != p.Confirmed {
		t.Fatal("unconfirmed successful mutation")
	}
	return p
}

func TestPositionStorageCoversEveryMutationAndNoop(t *testing.T) {
	f := newPositionFixture(t, 5)
	previous := requirePosition(t, f.chain, 5, false)
	for _, kind := range []string{"block", "checkpoint", "fork-prune", "canonical-prune"} {
		action := positionAction(t, f, kind)
		before, err := f.chain.StorageProtection()
		if err != nil {
			t.Fatal(err)
		}
		if err := action(); err != nil {
			t.Fatal(kind, err)
		}
		after := requirePosition(t, f.chain, before.Database.Sequence+1, false)
		if after.Database.CommitID == previous.Database.CommitID || after.PairID != previous.PairID {
			t.Fatal("position token not fresh or pair changed")
		}
		previous = after
	}
	before := requirePosition(t, f.chain, 10, false)
	if _, err := f.chain.PruneStaleForks(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.chain.CreateReplayCheckpoint(); err != nil {
		t.Fatal(err)
	}
	commit, err := f.chain.PruneCanonicalPrefixOnce(f.operation(), func() (uint64, error) { t.Error("retained effect reauthorized"); return 0, nil })
	if err != nil || commit.Applied {
		t.Fatal("exact retry applied", err)
	}
	if after := requirePosition(t, f.chain, 10, false); after.Database != before.Database {
		t.Fatal("no-op advanced position")
	}
	want := positionDatabaseSummary(t, f.chain)
	f.reopen(t)
	if requirePosition(t, f.chain, 10, false).Database != before.Database || positionDatabaseSummary(t, f.chain) != want {
		t.Fatal("recovery changed state")
	}
	if err := f.chain.ResumeStorageConfirmation(); err != nil {
		t.Fatal(err)
	}
}

func TestPositionStorageRootsModesAndOwnership(t *testing.T) {
	f := newPositionFixture(t, 0)
	open := func(path, pins string, id types.Hash) (*Store, error) {
		return OpenPositionPinnedWithPolicy(path, pins, f.base, f.parameters, f.policy, id)
	}
	if s, err := open(f.path, f.pins, testStorageID()); s != nil || !errors.Is(err, ErrStoragePinBusy) {
		t.Fatal("second owner", err)
	}
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	for _, bound := range []bool{false, true} {
		var s *Store
		var err error
		if bound {
			s, err = OpenBoundWithPolicy(f.path, f.base, f.parameters, f.policy, testStorageID())
		} else {
			s, err = OpenWithPolicy(f.path, f.base, f.parameters, f.policy)
		}
		if s != nil || !errors.Is(err, ErrStoragePosition) {
			t.Fatal("downgrade reopened protected data", err)
		}
	}
	for _, id := range []types.Hash{{}, types.DomainHash("wrong-position-storage")} {
		if s, err := open(f.path, f.pins, id); s != nil || err == nil {
			t.Fatal("wrong external ID accepted")
		}
	}
	other := newPositionFixture(t, 0)
	_ = other.chain.Close()
	if s, err := open(f.path, other.pins, testStorageID()); s != nil || !errors.Is(err, ErrStoragePosition) {
		t.Fatal("foreign pair accepted", err)
	}
	if s, err := CreatePositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID()); s != nil || err == nil {
		t.Fatal("existing pair recreated")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if s, err := open(f.path, missing, testStorageID()); s != nil || err == nil {
		t.Fatal("missing pins recreated")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("open created pins")
	}
	for _, pins := range []string{f.path, filepath.Join(f.path, "nested")} {
		if s, err := open(f.path, pins, testStorageID()); s != nil || err == nil {
			t.Fatal("overlapping roots")
		}
	}
	link := filepath.Join(t.TempDir(), "pins-link")
	if err := os.Symlink(f.pins, link); err != nil {
		t.Fatal(err)
	}
	if s, err := open(f.path, link, testStorageID()); s != nil || err == nil {
		t.Fatal("symlink root accepted")
	}
	var err error
	f.chain, err = open(f.path, f.pins, testStorageID())
	if err != nil {
		t.Fatal("failed opens retained ownership", err)
	}
}

func TestPositionStorageRejectsDatabaseOnlyRollbackAndDocumentsCopies(t *testing.T) {
	f := newPositionFixture(t, 0)
	old := filepath.Join(t.TempDir(), "old-database")
	if err := f.chain.persistence.db.Checkpoint(old); err != nil {
		t.Fatal(err)
	}
	if err := positionAction(t, f, "block")(); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(t.TempDir(), "current-database")
	if err := f.chain.persistence.db.Checkpoint(current); err != nil {
		t.Fatal(err)
	}
	want := requirePosition(t, f.chain, 1, false)
	_ = f.chain.Close()
	if s, err := OpenPositionPinnedWithPolicy(old, f.pins, f.base, f.parameters, f.policy, testStorageID()); s != nil || !errors.Is(err, ErrStoragePosition) {
		t.Fatal("database rollback accepted", err)
	}
	// A current copy carries the same token. This layer does NOT fence copies.
	s, err := OpenPositionPinnedWithPolicy(current, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	if requirePosition(t, s, 1, false).Database != want.Database {
		t.Fatal("copy changed token")
	}
	_ = s.Close()
	clonePins := filepath.Join(t.TempDir(), "copied-pins")
	if err := os.CopyFS(clonePins, os.DirFS(f.pins)); err != nil {
		t.Fatal(err)
	}
	// Both roots copied together remain indistinguishable without an external
	// physical/monotonic service. Two independent root locks cannot fix that.
	s, err = OpenPositionPinnedWithPolicy(current, clonePins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	if err := positionAction(t, snapshotPositionFixture(f, s), "block")(); err != nil {
		t.Fatal(err)
	}
	if err := positionAction(t, f, "block")(); err != nil {
		t.Fatal(err)
	}
	left, _ := s.StorageProtection()
	right, _ := f.chain.StorageProtection()
	if left.Database.Sequence != right.Database.Sequence || left.Database.CommitID == right.Database.CommitID {
		t.Fatal("independent commits should have distinct tokens")
	}
}

func snapshotPositionFixture(f *positionFixture, s *Store) *positionFixture {
	copy := *f
	copy.chain = s
	return &copy
}

func positionFaultStages() []string {
	var stages []string
	for _, phase := range []string{"intent", "confirmation"} {
		for _, suffix := range []string{"before-temp", "temp-created", "before-file-sync", "file-synced", "linked", "directory-synced"} {
			stages = append(stages, phase+"-"+suffix)
		}
		if phase == "intent" {
			stages = append(stages, "database-before", "database-after")
		}
	}
	return stages
}

func positionFaultOutcome(stage string) (intent, committed, confirmed bool) {
	intent = stage == "intent-linked" || stage == "intent-directory-synced" || strings.HasPrefix(stage, "database-") || strings.HasPrefix(stage, "confirmation-")
	committed = stage == "database-after" || strings.HasPrefix(stage, "confirmation-")
	confirmed = stage == "confirmation-linked" || stage == "confirmation-directory-synced"
	return
}

func TestPositionStorageFaultsKeepExactStateOrPending(t *testing.T) {
	for _, kind := range []string{"block", "checkpoint", "fork-prune", "canonical-prune"} {
		expected := newPositionFixture(t, 5)
		if err := positionAction(t, expected, kind)(); err != nil {
			t.Fatal(err)
		}
		after := positionDatabaseSummary(t, expected.chain)
		_ = expected.chain.Close()
		for _, stage := range positionFaultStages() {
			t.Run(kind+"/"+stage, func(t *testing.T) {
				f := newPositionFixture(t, 5)
				action := positionAction(t, f, kind)
				before := positionDatabaseSummary(t, f.chain)
				old, _ := f.chain.StorageProtection()
				injected := errors.New("position boundary fault")
				f.chain.persistence.pins.hook = func(at string) error {
					if at == stage {
						return injected
					}
					return nil
				}
				if err := action(); !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
					t.Fatal("lost uncertain fault", err)
				}
				if _, err := f.chain.Tip(); !errors.Is(err, ErrUncertain) {
					t.Fatal("uncertain memory usable", err)
				}
				if _, err := f.chain.StorageProtection(); !errors.Is(err, ErrUncertain) {
					t.Fatal("uncertain diagnostics", err)
				}
				f.reopen(t)
				intent, committed, confirmed := positionFaultOutcome(stage)
				sequence := old.Database.Sequence
				want := before
				if committed {
					sequence++
					want = after
				}
				protection := requirePosition(t, f.chain, sequence, intent && !confirmed)
				if positionDatabaseSummary(t, f.chain) != want {
					t.Fatal("partial or wrong logical batch recovered")
				}
				if intent && !confirmed {
					if _, err := f.chain.Tip(); !errors.Is(err, ErrStoragePinPending) {
						t.Fatal("pending chain readable", err)
					}
					if err := f.chain.VerifyStorageID(testStorageID()); !errors.Is(err, ErrStoragePinPending) {
						t.Fatal("pending chain passed executor preflight")
					}
					if _, err := f.chain.PruneCanonicalPrefixOnce(f.operation(), func() (uint64, error) { t.Error("pending reauthorized"); return 200, nil }); !errors.Is(err, ErrStoragePinPending) {
						t.Fatal("pending prune allowed", err)
					}
					protection.Pending.CommitID = types.Hash{}
					if current, _ := f.chain.StorageProtection(); current.Pending.CommitID.IsZero() {
						t.Fatal("diagnostic aliases live pin")
					}
					resumeErr := f.chain.ResumeStorageConfirmation()
					if committed {
						if resumeErr != nil {
							t.Fatal(resumeErr)
						}
						requirePosition(t, f.chain, sequence, false)
					} else if !errors.Is(resumeErr, ErrStoragePinPending) {
						t.Fatal("absent mutation treated as no-effect permission", resumeErr)
					}
					if positionDatabaseSummary(t, f.chain) != want {
						t.Fatal("resume executed database work")
					}
				}
			})
		}
	}
}

func TestPositionStorageFinalAuthorizationFollowsIntent(t *testing.T) {
	f := newPositionFixture(t, 5)
	before := positionDatabaseSummary(t, f.chain)
	intentSynced := false
	f.chain.persistence.pins.hook = func(stage string) error {
		if stage == "intent-directory-synced" {
			intentSynced = true
		}
		return nil
	}
	_, err := f.chain.PruneCanonicalPrefixOnce(f.operation(), func() (uint64, error) {
		if !intentSynced {
			t.Error("authorization preceded independent I/O")
		}
		return f.boundary.RetainUntil, nil
	})
	if !errors.Is(err, ErrCanonicalPrune) || !errors.Is(err, ErrUncertain) {
		t.Fatal("expired authorization committed", err)
	}
	f.reopen(t)
	requirePosition(t, f.chain, 5, true)
	if positionDatabaseSummary(t, f.chain) != before {
		t.Fatal("denial changed database")
	}
	if err := f.chain.ResumeStorageConfirmation(); !errors.Is(err, ErrStoragePinPending) {
		t.Fatal("denied pending intent discarded", err)
	}
}

func TestPositionStorageConcurrentHistoricalRetries(t *testing.T) {
	f := newPositionFixture(t, 5)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := f.chain.PruneCanonicalPrefixOnce(f.operation(), func() (uint64, error) { return 200, nil }); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	requirePosition(t, f.chain, 6, false)
}

func TestPositionStorageInitializerDoesNotRepairPartialRoots(t *testing.T) {
	stages := []string{"initialize-before", "initialize-after"}
	for _, phase := range []string{"identity", "ready"} {
		for _, suffix := range []string{"before-temp", "temp-created", "before-file-sync", "file-synced", "linked", "directory-synced"} {
			stages = append(stages, phase+"-"+suffix)
		}
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			p := testParameters()
			b := testBase(t, p)
			policy := DefaultPolicy()
			path, pins := filepath.Join(t.TempDir(), "chain"), filepath.Join(t.TempDir(), "pins")
			fault := errors.New("initialize boundary")
			s, err := createPositionPinnedWithPolicy(path, pins, b, p, policy, testStorageID(), func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			})
			if s != nil || !errors.Is(err, fault) {
				t.Fatal("creation missed fault", err)
			}
			s, err = OpenPositionPinnedWithPolicy(path, pins, b, p, policy, testStorageID())
			ready := stage == "ready-linked" || stage == "ready-directory-synced"
			if ready {
				if err != nil {
					t.Fatal(err)
				}
				requirePosition(t, s, 0, false)
				_ = s.Close()
			} else if s != nil || err == nil {
				t.Fatal("partial pair reconstructed")
			}
			if s, err := CreatePositionPinnedWithPolicy(path, pins, b, p, policy, testStorageID()); s != nil || err == nil {
				t.Fatal("partial creation reset")
			}
		})
	}
}

func TestPositionStorageRejectsDamagedMetadataAndJournal(t *testing.T) {
	for _, mode := range []string{"missing-position", "bad-position", "future-position", "wrong-token", "missing-pair", "wrong-pair", "schema-downgrade", "missing-intent", "missing-confirmation", "changed-intent", "changed-confirmation", "extra-intent", "extra-confirmation", "missing-ready", "changed-ready", "extra-root", "symlink-intents", "unexpected-pending"} {
		t.Run(mode, func(t *testing.T) {
			f := newPositionFixture(t, 2)
			p, _ := f.chain.StorageProtection()
			_ = f.chain.Close()
			db, err := pebble.Open(f.path, &pebble.Options{ErrorIfNotExists: true})
			if err != nil {
				t.Fatal(err)
			}
			set := func(key, value []byte) {
				t.Helper()
				if err := db.Set(key, value, pebble.Sync); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path string, value []byte) {
				t.Helper()
				if err := os.WriteFile(path, value, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing-position":
				err = db.Delete(workKeyPosition, pebble.Sync)
			case "bad-position":
				set(workKeyPosition, []byte{1})
			case "future-position":
				p.Database.Sequence++
				set(workKeyPosition, encodeStoragePosition(p.Database))
			case "wrong-token":
				p.Database.CommitID[0] ^= 1
				set(workKeyPosition, encodeStoragePosition(p.Database))
			case "missing-pair":
				err = db.Delete(workKeyPositionPair, pebble.Sync)
			case "wrong-pair":
				set(workKeyPositionPair, make([]byte, 32))
			case "schema-downgrade":
				set(workKeySchema, []byte{0, byte(workBoundSchemaVersion)})
			case "missing-intent":
				remove(filepath.Join(f.pins, "intents", positionName(1)))
			case "missing-confirmation":
				remove(filepath.Join(f.pins, "confirmed", positionName(1)))
			case "changed-intent":
				write(filepath.Join(f.pins, "intents", positionName(1)), []byte{1})
			case "changed-confirmation":
				write(filepath.Join(f.pins, "confirmed", positionName(1)), []byte{1})
			case "extra-intent":
				write(filepath.Join(f.pins, "intents", positionName(4)), []byte{1})
			case "extra-confirmation":
				write(filepath.Join(f.pins, "confirmed", positionName(3)), []byte{1})
			case "missing-ready":
				remove(filepath.Join(f.pins, "ready"))
			case "changed-ready":
				write(filepath.Join(f.pins, "ready"), []byte{1})
			case "extra-root":
				write(filepath.Join(f.pins, "extra"), nil)
			case "symlink-intents":
				moved := filepath.Join(t.TempDir(), "moved")
				if err := os.Rename(filepath.Join(f.pins, "intents"), moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, filepath.Join(f.pins, "intents")); err != nil {
					t.Fatal(err)
				}
			case "unexpected-pending":
				write(filepath.Join(f.pins, "pending", "not-an-entry"), nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if s, err := OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID()); s != nil || err == nil {
				t.Fatal("damaged pair opened")
			}
		})
	}
}

func TestPositionStorageLiveRootReplacementStopsWrites(t *testing.T) {
	f := newPositionFixture(t, 1)
	action := positionAction(t, f, "block")
	before := positionDatabaseSummary(t, f.chain)
	moved := filepath.Join(t.TempDir(), "retained-pins")
	if err := os.Rename(f.pins, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(f.pins, os.DirFS(moved)); err != nil {
		t.Fatal(err)
	}
	if err := action(); !errors.Is(err, ErrUncertain) || !errors.Is(err, ErrStoragePosition) {
		t.Fatal("replacement accepted", err)
	}
	if positionDatabaseSummary(t, f.chain) != before {
		t.Fatal("write reached replaced root")
	}
}

func FuzzDecodeStoragePositionRecord(f *testing.F) {
	identity := positionIdentity(types.Hash{1}, types.Hash{2}, types.Hash{3})
	previous := StoragePosition{CommitID: types.Hash{4}}
	next := StoragePosition{Sequence: 1, CommitID: types.Hash{5}}
	f.Add(encodePositionRecord(identity, previous, next, false), false)
	f.Add(encodePositionRecord(identity, previous, next, true), true)
	f.Add(encodeStoragePosition(previous), false)
	f.Add(encodeStoragePosition(next), false)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, input []byte, confirmation bool) {
		previous, next, err := decodePositionRecord(input, identity, confirmation)
		if err == nil && !bytes.Equal(input, encodePositionRecord(identity, previous, next, confirmation)) {
			t.Fatal("noncanonical record accepted")
		}
		if p, err := decodeStoragePosition(input); err == nil && !bytes.Equal(input, encodeStoragePosition(p)) {
			t.Fatal("noncanonical position accepted")
		}
	})
}

func TestPositionStorageClosedAndUnprotectedDiagnostics(t *testing.T) {
	var absent *Store
	if _, err := absent.StorageProtection(); !errors.Is(err, ErrStoragePosition) {
		t.Fatal(err)
	}
	if err := absent.ResumeStorageConfirmation(); !errors.Is(err, ErrStoragePosition) {
		t.Fatal(err)
	}
	f := newPositionFixture(t, 0)
	_ = f.chain.Close()
	if _, err := f.chain.StorageProtection(); !errors.Is(err, storage.ErrClosed) {
		t.Fatal(err)
	}
	if err := f.chain.ResumeStorageConfirmation(); !errors.Is(err, storage.ErrClosed) {
		t.Fatal(err)
	}
	raw, err := New(f.base, f.parameters)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.StorageProtection(); !errors.Is(err, ErrStoragePosition) {
		t.Fatal(err)
	}
}

func TestPositionStoragePendingCommitDoesNotMakeOldCopySafe(t *testing.T) {
	f := newPositionFixture(t, 5)
	old := filepath.Join(t.TempDir(), "before-prune")
	if err := f.chain.persistence.db.Checkpoint(old); err != nil {
		t.Fatal(err)
	}
	f.chain.persistence.pins.hook = func(stage string) error {
		if stage == "database-after" {
			return errors.New("lost confirmation")
		}
		return nil
	}
	if err := positionAction(t, f, "canonical-prune")(); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	_ = f.chain.Close()
	s, err := OpenPositionPinnedWithPolicy(old, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	requirePosition(t, s, 5, true)
	if err := s.ResumeStorageConfirmation(); !errors.Is(err, ErrStoragePinPending) {
		t.Fatal("rolled-back copy resolved the actually committed effect", err)
	}
	if _, _, err := s.CanonicalPruneEffect(f.operation().TicketID); !errors.Is(err, ErrStoragePinPending) {
		t.Fatal("old copy exposed absence as usable evidence", err)
	}
	_ = s.Close()
	f.chain, err = OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID())
	if err != nil {
		t.Fatal(err)
	}
	requirePosition(t, f.chain, 6, true)
	if err := f.chain.ResumeStorageConfirmation(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.chain.CanonicalPruneEffect(f.operation().TicketID); err != nil || !found {
		t.Fatal("real effect missing", err)
	}
}

func TestPositionStorageRefusesDatabaseAheadOfPins(t *testing.T) {
	f := newPositionFixture(t, 0)
	oldPins := filepath.Join(t.TempDir(), "old-pins")
	if err := os.CopyFS(oldPins, os.DirFS(f.pins)); err != nil {
		t.Fatal(err)
	}
	if err := positionAction(t, f, "block")(); err != nil {
		t.Fatal(err)
	}
	_ = f.chain.Close()
	if s, err := OpenPositionPinnedWithPolicy(f.path, oldPins, f.base, f.parameters, f.policy, testStorageID()); s != nil || !errors.Is(err, ErrStoragePosition) {
		t.Fatal("unexplained database extension accepted", err)
	}
}

func TestPositionStorageJournalBounds(t *testing.T) {
	t.Run("staging", func(t *testing.T) {
		f := newPositionFixture(t, 0)
		action := positionAction(t, f, "block")
		for i := 0; i < maximumPositionPending; i++ {
			if err := os.WriteFile(filepath.Join(f.pins, "pending", fmt.Sprintf("entry-%d", i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := action(); !errors.Is(err, ErrStoragePinLimit) {
			t.Fatal("staging bound ignored", err)
		}
		f.reopen(t)
		requirePosition(t, f.chain, 0, false)
		if err := os.WriteFile(filepath.Join(f.pins, "pending", "entry-999"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = f.chain.Close()
		if s, err := OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, f.parameters, f.policy, testStorageID()); s != nil || !errors.Is(err, ErrStoragePinLimit) {
			t.Fatal("oversized staging reopened", err)
		}
	})
	t.Run("position-ceiling", func(t *testing.T) {
		f := newPositionFixture(t, 0)
		p := f.chain.persistence.pins
		previous := StoragePosition{Sequence: MaximumStoragePositions - 1, CommitID: types.Hash{1}}
		next := StoragePosition{Sequence: MaximumStoragePositions, CommitID: types.Hash{2}}
		// Exercise the final bound without manufacturing 65,536 filesystem
		// transactions. The journal's complete prefix is tested on normal open.
		for dir, encoded := range map[string][]byte{
			"intents":   encodePositionRecord(p.encodedIdentity, previous, next, false),
			"confirmed": encodePositionRecord(p.encodedIdentity, StoragePosition{}, next, true),
		} {
			if err := os.WriteFile(filepath.Join(f.pins, dir, positionName(next.Sequence)), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		p.confirmed = next
		if _, err := p.begin(); !errors.Is(err, ErrStoragePinLimit) {
			t.Fatal("sequence retention bound ignored", err)
		}
		if p.pending != nil {
			t.Fatal("limit published an intent")
		}
		if _, err := positionNames(filepath.Join(f.pins, "intents"), 0); !errors.Is(err, ErrStoragePinLimit) {
			t.Fatal("bounded enumeration ignored", err)
		}
	})
}

func TestPositionStorageCodec(t *testing.T) {
	identity := positionIdentity(types.Hash{1}, types.Hash{2}, types.Hash{3})
	previous := StoragePosition{CommitID: types.Hash{4}}
	next := StoragePosition{Sequence: 1, CommitID: types.Hash{5}}
	for _, confirmation := range []bool{false, true} {
		encoded := encodePositionRecord(identity, previous, next, confirmation)
		wantLength := 150
		if confirmation {
			wantLength = 110
		}
		if len(encoded) != wantLength {
			t.Fatal("record width changed", len(encoded))
		}
		id := types.DomainHash("test/workchain/storage-position/vector", encoded)
		wantID := "ee959aa50341ff9107208f32a6a860d6fdd035da92aaa5dfc4e37d32fae343ba"
		if confirmation {
			wantID = "5c9bd11bb5887be0263c2c689b85cbddf329bd2fac6adba98a80b04cc7722d53"
		}
		if id.String() != wantID {
			t.Fatalf("storage-position vector changed: confirmation=%v id=%s", confirmation, id)
		}
		left, right, err := decodePositionRecord(encoded, identity, confirmation)
		if err != nil || right != next || (!confirmation && left != previous) {
			t.Fatal("record roundtrip", err)
		}
		for n := 0; n < len(encoded); n++ {
			if _, _, err := decodePositionRecord(encoded[:n], identity, confirmation); err == nil {
				t.Fatal("truncated record accepted", n)
			}
			changed := bytes.Clone(encoded)
			changed[n] ^= 1
			if _, _, err := decodePositionRecord(changed, identity, confirmation); err == nil {
				t.Fatal("changed record accepted", n)
			}
		}
		if _, _, err := decodePositionRecord(append(bytes.Clone(encoded), 0), identity, confirmation); err == nil {
			t.Fatal("trailing byte accepted")
		}
		if _, _, err := decodePositionRecord(encoded, positionIdentity(types.Hash{9}, types.Hash{2}, types.Hash{3}), confirmation); err == nil {
			t.Fatal("foreign identity accepted")
		}
	}
	for _, p := range []StoragePosition{{Sequence: 1}, {Sequence: MaximumStoragePositions + 1, CommitID: types.Hash{1}}} {
		if _, err := decodeStoragePosition(encodeStoragePosition(p)); err == nil {
			t.Fatal("invalid position accepted")
		}
	}
}

func TestPositionStorageResumeErrorsPoisonMemoryWithoutReexecution(t *testing.T) {
	stages := []string{"resume-before-flush", "resume-after-flush"}
	for _, stage := range positionFaultStages() {
		if strings.HasPrefix(stage, "confirmation-") {
			stages = append(stages, stage)
		}
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := newPositionFixture(t, 5)
			injected := errors.New("confirmation interrupted")
			f.chain.persistence.pins.hook = func(at string) error {
				if at == "database-after" {
					return injected
				}
				return nil
			}
			if err := positionAction(t, f, "canonical-prune")(); !errors.Is(err, injected) {
				t.Fatal(err)
			}
			want := positionDatabaseSummary(t, f.chain)
			f.reopen(t)
			f.chain.persistence.pins.hook = func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}
			if err := f.chain.ResumeStorageConfirmation(); !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
				t.Fatal("lost resume uncertainty", err)
			}
			if _, err := f.chain.StorageProtection(); !errors.Is(err, ErrUncertain) {
				t.Fatal("failed resume left usable memory", err)
			}
			f.reopen(t)
			confirmed := stage == "confirmation-linked" || stage == "confirmation-directory-synced"
			requirePosition(t, f.chain, 6, !confirmed)
			if err := f.chain.ResumeStorageConfirmation(); err != nil {
				t.Fatal(err)
			}
			requirePosition(t, f.chain, 6, false)
			if positionDatabaseSummary(t, f.chain) != want {
				t.Fatal("confirmation replayed database work")
			}
		})
	}
}
