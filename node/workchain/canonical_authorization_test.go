package workchain

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
)

func canonicalAuthorizationFixture(t testing.TB) (*Store, string, Base, workblock.Parameters, Policy, CanonicalFloor) {
	return canonicalAuthorizationFixtureWithStorageID(t, types.Hash{})
}

func canonicalAuthorizationFixtureWithStorageID(t testing.TB, storageID types.Hash) (*Store, string, Base, workblock.Parameters, Policy, CanonicalFloor) {
	t.Helper()
	parameters := testParameters()
	base := testBase(t, parameters)
	path := filepath.Join(t.TempDir(), "chain")
	policy := DefaultPolicy()
	policy.CanonicalRetention = 1
	var store *Store
	var err error
	if storageID.IsZero() {
		store, err = OpenWithPolicy(path, base, parameters, policy)
	} else {
		store, err = CreateBoundWithPolicy(path, base, parameters, policy, storageID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	parent, timestamp := base.Tip.ID, base.Tip.Timestamp
	var anchorID types.Hash
	for height := range 5 {
		timestamp += parameters.TargetSpacing
		block, _ := mineChild(t, store, parent, timestamp, "authorized-prune-"+string(rune('a'+height)))
		if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		parent, _ = block.Header.ID()
		if height == 2 {
			anchorID = parent
		}
	}
	anchor, err := store.TipByID(anchorID)
	if err != nil {
		t.Fatal(err)
	}
	root, count, err := store.SelectedAncestryCommitment(anchorID)
	if err != nil {
		t.Fatal(err)
	}
	return store, path, base, parameters, policy, canonicalTestFloor(base.Tip.ID, anchor, root, count, "authorized")
}

func TestCanonicalPruneAuthorizationRunsAfterBatchPreparation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		at          uint64
		deny        error
		nilCallback bool
		want        error
	}{
		{name: "success", at: 200},
		{name: "same-time", at: 100},
		{name: "cancel", deny: context.Canceled, want: context.Canceled},
		{name: "rollback", at: 99, want: ErrCanonicalPrune},
		{name: "zero", at: 0, want: ErrCanonicalPrune},
		{name: "expired", at: 1_000, want: ErrCanonicalPrune},
		{name: "nil", nilCallback: true, want: ErrCanonicalPrune},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, path, base, parameters, policy, boundary := canonicalAuthorizationFixture(t)
			before, _, err := store.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			beforeNodes, err := store.NodeIDs()
			if err != nil {
				t.Fatal(err)
			}
			prepared, calls := false, 0
			store.persistence.commitHook = func() error { prepared = true; return nil }
			authorize := func() (uint64, error) {
				calls++
				if !prepared {
					t.Error("authorization ran before all batch preparation")
				}
				if store.floor.Pruned || store.persistence.historyBytes != before || len(store.nodes) != len(beforeNodes) {
					t.Error("uncommitted batch changed live state")
				}
				return tc.at, tc.deny
			}
			if tc.nilCallback {
				authorize = nil
			}
			report, err := store.PruneCanonicalPrefixAuthorized(boundary, authorize)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if calls != 1 && !tc.nilCallback {
				t.Fatalf("authorization calls=%d", calls)
			}
			if tc.nilCallback && prepared {
				t.Fatal("nil authorization prepared a deletion")
			}
			floor, err := store.CanonicalFloor()
			if err != nil || floor.Pruned != (tc.want == nil) {
				t.Fatalf("floor=%+v err=%v", floor, err)
			}
			if tc.want == nil {
				if floor.VerifiedAt != tc.at || report.RemovedNodes == 0 {
					t.Fatal("final authorization time not persisted")
				}
			} else {
				after, _, err := store.HistoryUsage()
				if err != nil || after != before || len(store.nodes) != len(beforeNodes) {
					t.Fatal("denial changed memory")
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenWithPolicy(path, base, parameters, policy)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			recovered, err := reopened.CanonicalFloor()
			if err != nil || !equalCanonicalTestFloor(floor, recovered) {
				t.Fatalf("reopen floor=%+v want=%+v err=%v", recovered, floor, err)
			}
			if tc.want != nil {
				after, _, err := reopened.HistoryUsage()
				if err != nil || after != before {
					t.Fatal("denial changed disk accounting", err)
				}
				for _, id := range beforeNodes {
					if _, err := reopened.TipByID(id); err != nil {
						t.Fatal("denial lost persisted node", err)
					}
				}
			}
		})
	}
}

func TestCanonicalPruneAuthorizationWaitsForChainLock(t *testing.T) {
	store, _, _, _, _, boundary := canonicalAuthorizationFixture(t)
	store.mu.Lock()
	started, checked := make(chan struct{}), make(chan struct{}, 1)
	result := make(chan error, 1)
	denied := false // protected by store.mu, also held while authorize runs
	go func() {
		close(started)
		_, err := store.PruneCanonicalPrefixAuthorized(boundary, func() (uint64, error) {
			checked <- struct{}{}
			if denied {
				return 0, context.Canceled
			}
			return 200, nil
		})
		result <- err
	}()
	<-started
	select {
	case <-checked:
		store.mu.Unlock()
		t.Fatal("authorization escaped the chain lock")
	default:
	}
	denied = true
	store.mu.Unlock()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("accepted before observing changed decision", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prune did not release its lock after denial")
	}
	if floor, err := store.CanonicalFloor(); err != nil || floor.Pruned {
		t.Fatal("denied operation pruned", err)
	}
}

func TestCanonicalPruneAuthorizationSeesLastPreparationDelay(t *testing.T) {
	store, _, _, _, _, boundary := canonicalAuthorizationFixture(t)
	at := uint64(100)
	store.persistence.commitHook = func() error { at = boundary.RetainUntil; return nil }
	if _, err := store.PruneCanonicalPrefixAuthorized(boundary, func() (uint64, error) { return at, nil }); !errors.Is(err, ErrCanonicalPrune) {
		t.Fatal("accepted stale pre-preparation time", err)
	}
	if floor, err := store.CanonicalFloor(); err != nil || floor.Pruned {
		t.Fatal("expired authorization pruned", err)
	}
}
