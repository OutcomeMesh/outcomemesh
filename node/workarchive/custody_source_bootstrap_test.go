package workarchive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCustodySourceBootstrapRequiresNewRootAndRetainsPartialFailure(t *testing.T) {
	f := newCustodyRecordFixture(t)
	limits := DefaultCustodyJournalLimits()
	root := filepath.Join(t.TempDir(), "journal")
	j, state, err := CreateCustodyJournalWithLimits(t.Context(), root, f.manifest, f.receipt, f.policy, limits)
	if err != nil || state.Sequence != 0 || state.InitialReceipt != f.receipt {
		t.Fatal(state, err)
	}
	if _, _, err := CreateCustodyJournalWithLimits(t.Context(), root, f.manifest, f.receipt, f.policy, limits); !errors.Is(err, os.ErrExist) {
		t.Fatal("opened an existing root", err)
	}
	if _, created, err := j.Append(f.record); err != nil || !created {
		t.Fatal(err)
	}
	if _, _, err := CreateCustodyJournalWithLimits(t.Context(), root, f.manifest, f.receipt, f.policy, limits); !errors.Is(err, os.ErrExist) {
		t.Fatal("reset a used source", err)
	}
	_, state, err = OpenExistingCustodyJournalWithLimits(t.Context(), root, f.manifest, f.receipt, f.policy, limits)
	if err != nil || state.Sequence != 1 {
		t.Fatal("source history was changed", state, err)
	}
	partial := filepath.Join(t.TempDir(), "partial")
	tiny := limits
	tiny.MaximumBytes = 1
	if _, _, err := CreateCustodyJournalWithLimits(t.Context(), partial, f.manifest, f.receipt, f.policy, tiny); err == nil {
		t.Fatal("tiny budget succeeded")
	}
	if _, err := os.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid limits mutated root", err)
	}
	// Model an interrupted creator's retained root/lock without a header.
	if err := os.Mkdir(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, custodyJournalLockName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(partial); err != nil || !info.IsDir() {
		t.Fatal("partial root missing", err)
	}
	if _, _, err := CreateCustodyJournalWithLimits(t.Context(), partial, f.manifest, f.receipt, f.policy, limits); !errors.Is(err, os.ErrExist) {
		t.Fatal("partial source repaired", err)
	}
	if _, _, err := OpenExistingCustodyJournalWithLimits(t.Context(), partial, f.manifest, f.receipt, f.policy, limits); err == nil {
		t.Fatal("partial source accepted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	absent := filepath.Join(t.TempDir(), "cancelled")
	if _, _, err := CreateCustodyJournalWithLimits(cancelled, absent, f.manifest, f.receipt, f.policy, limits); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled creation wrote a root", err)
	}
}

func TestCustodyArtifactsBootstrapNeverRepairsOrCreatesOnInspect(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts")
	if lock, err := OpenExistingCustodyArtifacts(t.Context(), root); err == nil {
		_ = lock.Close()
		t.Fatal("inspection created root")
	}
	lock, err := CreateCustodyArtifacts(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if lock, err := CreateCustodyArtifacts(t.Context(), root); !errors.Is(err, os.ErrExist) {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatal("existing artifacts repaired", err)
	}
	if err := os.Remove(filepath.Join(root, custodyArtifactsLockName)); err != nil {
		t.Fatal(err)
	}
	if lock, err := OpenExistingCustodyArtifacts(t.Context(), root); err == nil {
		_ = lock.Close()
		t.Fatal("inspection repaired missing lock")
	}
}
