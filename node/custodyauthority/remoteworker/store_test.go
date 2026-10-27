package remoteworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func newWorker(t testing.TB) (*Journal, string, Config) {
	t.Helper()
	c := workerConfig(t)
	path := filepath.Join(t.TempDir(), "worker")
	j, err := Create(t.Context(), path, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path, c
}

func TestWorkerJournalIrreversibleBranchesAndUnsignedDraft(t *testing.T) {
	for _, disposition := range []Disposition{Unseen, NoResult, RetainedResult} {
		t.Run(string(rune('0'+disposition)), func(t *testing.T) {
			j, path, c := newWorker(t)
			if _, err := Open(t.Context(), path, c); !errors.Is(err, ErrBusy) {
				t.Fatal("duplicate original owner", err)
			}
			state, err := j.Snapshot(t.Context())
			if err != nil || state.Stage != Prepared || state.Pending != 0 {
				t.Fatal(state, err)
			}
			if _, err := j.Start(t.Context(), workerHash(99)); err == nil {
				t.Fatal("accepted another Begin pin")
			}
			if _, err := j.CommitSeal(t.Context(), Unseen, types.Hash{}); err == nil {
				t.Fatal("sealed without irreversible sealing record")
			}
			if disposition != Unseen {
				for range 2 {
					state, err = j.Start(t.Context(), c.BeginID)
					if err != nil || state.Stage != Started || !state.Started {
						t.Fatal(state, err)
					}
				}
			}
			for range 2 {
				state, err = j.BeginSeal(t.Context())
				if err != nil || state.Stage != Sealing || state.Pending != 0 {
					t.Fatal(state, err)
				}
			}
			if _, err := j.Start(t.Context(), c.BeginID); !errors.Is(err, ErrTransition) {
				t.Fatal("Start after sealing", err)
			}
			wrong := Unseen
			if disposition == Unseen {
				wrong = NoResult
			}
			if _, err := j.CommitSeal(t.Context(), wrong, types.Hash{}); err == nil {
				t.Fatal("mixed unseen/started disposition")
			}
			var result types.Hash
			if disposition == RetainedResult {
				result = workerHash(71)
			}
			seal, err := j.CommitSeal(t.Context(), disposition, result)
			if err != nil {
				t.Fatal(err)
			}
			sealID, _ := seal.ID()
			for range 2 {
				again, err := j.CommitSeal(t.Context(), disposition, result)
				if err != nil || again != seal {
					t.Fatal("exact seal retry", err)
				}
			}
			if _, err := j.CommitSeal(t.Context(), RetainedResult, workerHash(99)); err == nil {
				t.Fatal("replaced tombstone")
			}
			position := custodyauthority.Position{Sequence: c.Begin.Command.ExpectedSequence + 1, HeadID: c.BeginID}
			if _, err := j.DrainedDraft(t.Context(), workerHash(99), position); err == nil {
				t.Fatal("draft accepted another tombstone")
			}
			draft, err := j.DrainedDraft(t.Context(), sealID, position)
			if err != nil || draft.Signature != [64]byte{} || draft.Kind != custodyauthority.RemoteDrained || draft.EvidenceID != sealID || draft.OperationID != c.BeginID || draft.TicketID != c.Begin.Command.TicketID {
				t.Fatal("static draft lost its exact binding", err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			j, err = Open(t.Context(), path, c)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			state, err = j.Snapshot(t.Context())
			if err != nil || state.Stage != Sealed || state.SealID != sealID || state.Started != (disposition != Unseen) {
				t.Fatal("replay changed tombstone branch", state, err)
			}
			if _, err := j.Start(t.Context(), c.BeginID); !errors.Is(err, ErrTransition) {
				t.Fatal("delayed Start survived unseen/started tombstone", err)
			}
			state.Seal.ResultID = workerHash(222)
			fresh, _ := j.Snapshot(t.Context())
			if fresh.Seal.ResultID != result {
				t.Fatal("snapshot alias changed retained seal")
			}
		})
	}
}

func TestWorkerJournalPendingSealingAndSealRequireExplicitExactRetry(t *testing.T) {
	j, path, c := newWorker(t)
	failure := errors.New("lost after sealing record")
	j.hooks.at = func(stage string) error {
		if stage == sealingName+"-record-durable" {
			return failure
		}
		return nil
	}
	if _, err := j.BeginSeal(t.Context()); !errors.Is(err, ErrUncertain) || !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := j.Start(t.Context(), c.BeginID); !errors.Is(err, ErrUncertain) {
		t.Fatal("uncertain owner remained usable", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := Open(t.Context(), path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err := j.Snapshot(t.Context())
	if err != nil || state.Stage != Sealing || state.Pending != Sealing {
		t.Fatal("open promoted or forgot pending sealing", state, err)
	}
	if _, err := os.Lstat(filepath.Join(path, confirmName(Sealing))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Open created a missing confirmation", err)
	}
	if _, err := j.Start(t.Context(), c.BeginID); !errors.Is(err, ErrTransition) {
		t.Fatal("pending sealing allowed Start", err)
	}
	if _, err := j.CommitSeal(t.Context(), Unseen, types.Hash{}); err == nil {
		t.Fatal("seal skipped unconfirmed transition")
	}
	if _, err := j.BeginSeal(t.Context()); err != nil {
		t.Fatal(err)
	}
	j.hooks.at = func(stage string) error {
		if stage == sealName+"-record-durable" {
			return failure
		}
		return nil
	}
	if _, err := j.CommitSeal(t.Context(), Unseen, types.Hash{}); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(t.Context(), path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err = j.Snapshot(t.Context())
	if err != nil || state.Stage != Sealed || state.Pending != Sealed {
		t.Fatal(state, err)
	}
	position := custodyauthority.Position{Sequence: c.Begin.Command.ExpectedSequence + 1, HeadID: c.BeginID}
	if _, err := j.DrainedDraft(t.Context(), state.SealID, position); err == nil {
		t.Fatal("unconfirmed tombstone produced draft")
	}
	if _, err := j.CommitSeal(t.Context(), Unseen, types.Hash{}); err != nil {
		t.Fatal("exact tombstone retry", err)
	}
	if _, err := j.DrainedDraft(t.Context(), state.SealID, position); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerPendingStartAndCancelledSealingStayConservative(t *testing.T) {
	j, path, c := newWorker(t)
	failure := errors.New("lost start confirmation")
	j.hooks.at = func(stage string) error {
		if stage == startName+"-record-durable" {
			return failure
		}
		return nil
	}
	if _, err := j.Start(t.Context(), c.BeginID); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := Open(t.Context(), path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err := j.Snapshot(t.Context())
	if err != nil || state.Stage != Started || state.Pending != Started || !state.Started {
		t.Fatal(state, err)
	}
	if _, err := j.BeginSeal(t.Context()); !errors.Is(err, ErrUncertain) {
		t.Fatal("silently confirmed a prior transition", err)
	}
	if _, err := j.Start(t.Context(), c.BeginID); err != nil {
		t.Fatal("exact record-only start retry", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	j.hooks.at = func(stage string) error {
		if stage == sealingName+"-record-durable" {
			cancel()
		}
		return nil
	}
	if _, err := j.BeginSeal(ctx); !errors.Is(err, ErrUncertain) || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation hid the retained transition", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(t.Context(), path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state, err = j.Snapshot(t.Context())
	if err != nil || state.Stage != Sealing || state.Pending != Sealing || !state.Started {
		t.Fatal(state, err)
	}
	if _, err := j.Start(t.Context(), c.BeginID); !errors.Is(err, ErrTransition) {
		t.Fatal("cancellation made sealing executable", err)
	}
	if _, err := j.BeginSeal(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CommitSeal(t.Context(), Unseen, types.Hash{}); !errors.Is(err, ErrSeal) {
		t.Fatal("started branch became unseen", err)
	}
	if seal, err := j.CommitSeal(t.Context(), NoResult, types.Hash{}); err != nil || seal.Disposition != NoResult || !seal.ResultID.IsZero() {
		t.Fatal("unknown result was changed into acceptance", err)
	}
}

func TestWorkerJournalNoRepairAndLiveFileReplacement(t *testing.T) {
	for _, mutation := range []string{"extra", "plan", "lock", "missing-sealing", "partial"} {
		t.Run(mutation, func(t *testing.T) {
			j, path, c := newWorker(t)
			if _, err := j.BeginSeal(t.Context()); err != nil {
				t.Fatal(err)
			}
			if mutation == "extra" {
				if err := os.WriteFile(filepath.Join(path, "unexpected"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "plan" {
				planPath := filepath.Join(path, planName)
				b, err := os.ReadFile(planPath)
				if err != nil {
					t.Fatal(err)
				}
				// Keep the old inode allocated outside the journal. Unlinking
				// first lets Linux reuse it and defeats the intended replacement.
				if err := os.Rename(planPath, filepath.Join(t.TempDir(), "original-plan")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(planPath, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "lock" {
				if err := os.Remove(filepath.Join(path, lockName)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, lockName), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "missing-sealing" {
				if err := os.Remove(filepath.Join(path, sealingName)); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "partial" {
				if err := os.WriteFile(filepath.Join(path, sealingName), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := j.Snapshot(t.Context()); !errors.Is(err, ErrUncertain) {
				t.Fatal("live replacement was not fail closed", err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if mutation != "plan" && mutation != "lock" {
				if opened, err := Open(t.Context(), path, c); err == nil {
					_ = opened.Close()
					t.Fatal("opened corrupt journal")
				}
			}
			if _, err := Create(t.Context(), path, c); err == nil {
				t.Fatal("reinitialized retained root")
			}
		})
	}
}

func TestWorkerJournalMissingPinsCancellationAndReadOnlyRetry(t *testing.T) {
	c := workerConfig(t)
	missing := filepath.Join(t.TempDir(), "missing", "worker")
	if _, err := Create(t.Context(), missing, c); err == nil {
		t.Fatal("initialized missing parent")
	}
	if _, err := Open(t.Context(), missing, c); err == nil {
		t.Fatal("initialized missing root")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	path := filepath.Join(t.TempDir(), "worker")
	if _, err := Create(ctx, path, c); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled Create wrote files", err)
	}
	bad := c
	bad.PlanID = types.Hash{}
	if _, err := Create(t.Context(), path, bad); err == nil {
		t.Fatal("created without Plan pin")
	}
	bad = c
	bad.BeginID = types.Hash{}
	if _, err := Create(t.Context(), path, bad); err == nil {
		t.Fatal("created without Begin proposal pin")
	}
	j, path, c := newWorker(t)
	if _, err := j.BeginSeal(t.Context()); err != nil {
		t.Fatal(err)
	}
	seal, err := j.CommitSeal(t.Context(), Unseen, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, sealName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0700) })
	probe, err := os.CreateTemp(path, ".probe-*")
	if err == nil {
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
		t.Skip("filesystem does not enforce owner write removal")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if again, err := j.CommitSeal(t.Context(), Unseen, types.Hash{}); err != nil || again != seal {
		t.Fatal("exact seal retry allocated or rewrote a file", err)
	}
	after, err := os.ReadFile(filepath.Join(path, sealName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("exact seal retry changed retained bytes", err)
	}
}
