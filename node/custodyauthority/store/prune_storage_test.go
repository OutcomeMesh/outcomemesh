package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestStorageBoundPruneRefusesAnotherIncarnationBeforeStart(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	foreign := newPruneFixtureWithStorageID(t, testHash(92))
	f.admit(t, true)
	// Same logical chain is insufficient: both stores pass the old context check.
	if err := foreign.chain.VerifyContext(f.parameters.NetworkID, f.parameters.ActivationHeight, f.base.Tip.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, foreign.chain, func() (uint64, error) {
		t.Error("wrong incarnation reached final authorization")
		return 200, nil
	}); !errors.Is(err, workchain.ErrStorageBinding) {
		t.Fatal("foreign database accepted", err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneAdmitted || s.Protection.Pending != nil {
		t.Fatal("rejected storage published a start", s.Stage)
	}
	path := filepath.Join(t.TempDir(), "raw")
	if raw, err := CreatePruneExecutor(path, testAssignment(), f.request, f.id); raw != nil || !errors.Is(err, ErrPruneRequest) {
		t.Fatal("bound request allowed without stage pins", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected raw constructor created a root", err)
	}
	f.reopen(t)
	var calls, applied atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			result, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) {
				calls.Add(1)
				return 200, nil
			})
			if err != nil || result.Effect.Operation.StorageID != f.request.StorageID {
				t.Error("bound execution result", err)
			} else if result.Applied {
				applied.Add(1)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || applied.Load() != 1 {
		t.Fatal("bound operation executed more than once", calls.Load(), applied.Load())
	}
	finished := pruneSnapshot(t, f.executor)
	if finished.Protection.Confirmed.Stage != PruneSucceeded || finished.Protection.Pending != nil {
		t.Fatal("result returned before independent confirmation")
	}
	f.complete(t, *finished.Effect)
	f.reopen(t)
	// Historical success remains evidence even without a live database handle.
	retained, err := f.executor.Recover(t.Context(), nil)
	if err != nil || retained.Applied || !samePruneEffect(retained.Effect, *finished.Effect) {
		t.Fatal("historical bound result lost after retirement", err)
	}
}

func TestStorageBoundPruneRecoveryDoesNotInferNoEffectFromOldCopy(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	foreign := newPruneFixtureWithStorageID(t, testHash(92))
	f.admit(t, true)
	if err := f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "old-copy")
	if err := os.CopyFS(copyPath, os.DirFS(f.chainPath)); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	old, err := workchain.OpenBoundWithPolicy(copyPath, f.base, f.parameters, f.policy, f.request.StorageID)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	injected := errors.New("lost reply after concrete effect")
	f.executor.hooks.at = func(stage string) error {
		if stage == "prune-after-effect" {
			return injected
		}
		return nil
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); !errors.Is(err, injected) {
		t.Fatal("effect interruption", err)
	}
	f.reopen(t)
	if _, err := f.executor.Recover(t.Context(), foreign.chain); !errors.Is(err, workchain.ErrStorageBinding) {
		t.Fatal("foreign database resolved recovery", err)
	}
	if _, err := f.executor.Recover(t.Context(), old); !errors.Is(err, ErrPruneOutcome) {
		t.Fatal("old copy fabricated a no-effect disposition", err)
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, old, func() (uint64, error) {
		t.Error("unknown effect repeated against old copy")
		return 200, nil
	}); !errors.Is(err, ErrPruneOutcome) {
		t.Fatal(err)
	}
	if s := pruneSnapshot(t, f.executor); s.Stage != PruneStarted || s.Protection.Confirmed.Stage != PruneStarted ||
		testCoordination(t, f.coordinator).Authority.Pending != 1 {
		t.Fatal("uncertain operation advanced or completed")
	}
	resolved, err := f.executor.Recover(t.Context(), f.chain)
	if err != nil || resolved.Applied || resolved.Effect.Operation.StorageID != f.request.StorageID {
		t.Fatal("exact database did not resolve its effect", err)
	}
	f.complete(t, resolved.Effect)
}

func TestStorageBoundPruneRequestCodec(t *testing.T) {
	r := purePruneRequest(t)
	r.StorageID = testHash(91)
	encoded, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := r.ID()
	if len(encoded) != 409 || id.String() != "200f79ab68e679511d7732e45db5a642c660ec47ec146e8c5011583deceaba70" {
		t.Fatalf("bound request vector changed: bytes=%d id=%s", len(encoded), id)
	}
	decoded, err := DecodePruneRequest(encoded)
	if err != nil || decoded.StorageID != r.StorageID {
		t.Fatal("bound request roundtrip", err)
	}
	again, _ := decoded.CanonicalBytes()
	if !bytes.Equal(again, encoded) {
		t.Fatal("noncanonical bound request")
	}
	for length := 0; length < len(encoded); length++ {
		if _, err := DecodePruneRequest(encoded[:length]); err == nil {
			t.Fatal("accepted truncated bound request", length)
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
		if _, err := DecodePruneRequest(bad); err == nil {
			t.Fatal("accepted malformed bound request", mode)
		}
	}
	changed := r
	changed.StorageID = testHash(92)
	if changedID, _ := changed.ID(); changedID == id {
		t.Fatal("storage incarnation absent from request ID")
	}
}
