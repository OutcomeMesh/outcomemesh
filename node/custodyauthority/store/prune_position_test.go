package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestPositionPinnedPruneRejectsRollbackAndRecoversOnlyExistingEffect(t *testing.T) {
	f := newPruneFixtureWithStoragePositions(t, testHash(91), true)
	f.admit(t, true)
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(t.TempDir(), "old-database")
	if err := os.CopyFS(old, os.DirFS(f.chainPath)); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	fault := errors.New("lost executor result after confirmed database effect")
	f.executor.hooks.at = func(stage string) error {
		if stage == "prune-after-effect" {
			return fault
		}
		return nil
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if protection, err := f.chain.StorageProtection(); err != nil || protection.Database.Sequence != 6 || protection.Pending != nil {
		t.Fatal("database result not position-confirmed", err)
	}
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := workchain.OpenPositionPinnedWithPolicy(old, f.chainPositionPinsPath, f.base, f.parameters, f.policy, f.request.StorageID); s != nil || !errors.Is(err, workchain.ErrStoragePosition) {
		t.Fatal("rolled-back database admitted to recovery", err)
	}
	f.reopen(t)
	result, err := f.executor.Recover(t.Context(), f.chain)
	if err != nil || result.Applied {
		t.Fatal("positive recovery reexecuted work", err)
	}
	if protection, err := f.chain.StorageProtection(); err != nil || protection.Database.Sequence != 6 {
		t.Fatal("recovery changed database position", err)
	}
	if testCoordination(t, f.coordinator).Authority.Pending != 1 {
		t.Fatal("storage recovery signed authority completion")
	}
	f.complete(t, result.Effect)
}

func TestPositionPinnedPruneMissingDatabaseCommitStaysPending(t *testing.T) {
	f := newPruneFixtureWithStoragePositions(t, testHash(91), true)
	f.admit(t, true)
	// Final permission is evaluated after the independent database intent. A
	// denied attempt has no committed effect, but that absence is not a recovery
	// certificate and must never be used to clear either pending journal.
	denied := errors.New("permission withdrawn at final commit boundary")
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 0, denied }); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	f.reopen(t)
	protection, err := f.chain.StorageProtection()
	if err != nil || protection.Pending == nil || protection.Database.Sequence != 5 {
		t.Fatal("unresolved database intent lost", err)
	}
	if err := f.chain.ResumeStorageConfirmation(); !errors.Is(err, workchain.ErrStoragePinPending) {
		t.Fatal("missing database effect confirmed", err)
	}
	if _, err := f.executor.Recover(t.Context(), f.chain); !errors.Is(err, workchain.ErrStoragePinPending) {
		t.Fatal("gated database used to resolve start", err)
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("started deletion retried"); return 200, nil }); err == nil {
		t.Fatal("unresolved execution succeeded")
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneStarted || s.Protection.Confirmed.Stage != PruneStarted || testCoordination(t, f.coordinator).Authority.Pending != 1 {
		t.Fatal("unknown result cleared pending authority")
	}
	// A different request must also refuse the gated database before publishing
	// its own start, even though incarnation and consensus context still match.
	other := newPruneFixtureWithStoragePositions(t, testHash(91), true)
	other.admit(t, true)
	if _, err := other.executor.Execute(t.Context(), other.coordinator, f.chain, func() (uint64, error) { t.Error("pending database authorized"); return 200, nil }); !errors.Is(err, workchain.ErrStoragePinPending) {
		t.Fatal("pending database passed preflight", err)
	}
	if s := pruneSnapshot(t, other.executor); s.Stage != PruneAdmitted {
		t.Fatal("pending database published another start")
	}
}
