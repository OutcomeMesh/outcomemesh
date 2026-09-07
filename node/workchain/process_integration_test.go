//go:build integration

package workchain

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	crashModeEnvironment   = "OUTCOMEMESH_WORKCHAIN_CRASH_MODE"
	crashPathEnvironment   = "OUTCOMEMESH_WORKCHAIN_CRASH_PATH"
	crashMarkerEnvironment = "OUTCOMEMESH_WORKCHAIN_CRASH_MARKER"
)

func TestPebbleProcessCrashAtomicity(t *testing.T) {
	for _, fixture := range []struct {
		operation string
		boundary  string
	}{
		{operation: "commit", boundary: "before"},
		{operation: "commit", boundary: "after"},
		{operation: "checkpoint", boundary: "before"},
		{operation: "checkpoint", boundary: "after"},
		{operation: "prune", boundary: "before"},
		{operation: "prune", boundary: "after"},
		{operation: "canonical", boundary: "before"},
		{operation: "canonical", boundary: "after"},
		{operation: "authorized", boundary: "before"},
		{operation: "authorized", boundary: "decision"},
		{operation: "authorized", boundary: "after"},
		{operation: "ticketed", boundary: "before"},
		{operation: "ticketed", boundary: "decision"},
		{operation: "ticketed", boundary: "after"},
		{operation: "ticketed", boundary: "unsynced"},
	} {
		name := fixture.operation + "-" + fixture.boundary
		t.Run(name, func(t *testing.T) {
			parameters := testParameters()
			base := testBase(t, parameters)
			policy := crashPolicy(fixture.operation)
			path := filepath.Join(t.TempDir(), "chain")
			expectedPath := filepath.Join(t.TempDir(), "expected")
			marker := filepath.Join(t.TempDir(), "reached")
			prepareCrashStore(t, path, fixture.operation, base, parameters, policy)
			prepareCrashStore(t, expectedPath, fixture.operation, base, parameters, policy)
			before := reopenCrashSummary(t, path, base, parameters, policy)
			expectedStore, err := OpenWithPolicy(expectedPath, base, parameters, policy)
			if err != nil {
				t.Fatal(err)
			}
			runCrashOperation(t, expectedStore, fixture.operation, parameters)
			after := crashStoreSummary(t, expectedStore)
			var expectedEffect CanonicalPruneEffect
			if fixture.operation == "ticketed" {
				var found bool
				expectedEffect, found, err = expectedStore.CanonicalPruneEffect(pruneOperation(CanonicalFloor{}, "process").TicketID)
				if err != nil || !found {
					t.Fatal("missing expected prune result", err)
				}
			}
			if err := expectedStore.Close(); err != nil {
				t.Fatal(err)
			}
			if equalCrashSummary(before, after) {
				t.Fatalf("%s fixture operation made no observable change", fixture.operation)
			}

			command := exec.Command(os.Args[0], "-test.run=^TestWorkChainCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				crashModeEnvironment+"="+name,
				crashPathEnvironment+"="+path,
				crashMarkerEnvironment+"="+marker,
			)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()

			reopened, err := OpenWithPolicy(path, base, parameters, policy)
			if err != nil {
				t.Fatal(err)
			}
			actual := crashStoreSummary(t, reopened)
			want := before
			if fixture.boundary == "after" || (fixture.boundary == "unsynced" && equalCrashSummary(actual, after)) {
				want = after
			}
			if !equalCrashSummary(actual, want) {
				t.Fatalf("%s recovery mismatch\nactual: %+v\nwant:   %+v", name, actual, want)
			}
			if fixture.operation == "ticketed" {
				// NoSync can still be in Pebble's userspace WAL buffer at death.
				// Either complete transaction is legal; a hybrid is never legal.
				persisted := actual.FloorPruned
				observed, found, err := reopened.CanonicalPruneEffect(expectedEffect.Operation.TicketID)
				if err != nil || found != persisted || (found && !equalPruneEffect(observed, expectedEffect)) {
					t.Fatal("reopen did not preserve exact result", err)
				}
				calls := 0
				retry, err := reopened.PruneCanonicalPrefixOnce(expectedEffect.Operation, func() (uint64, error) { calls++; return 200, nil })
				if err != nil || retry.Applied == persisted || !equalPruneEffect(retry.Effect, expectedEffect) ||
					calls != map[bool]int{false: 1, true: 0}[persisted] {
					t.Fatal("lost response repeated or changed the effect", retry, calls, err)
				}
				if !equalCrashSummary(crashStoreSummary(t, reopened), after) {
					t.Fatal("retry changed accounting or retained evidence")
				}
			}
			tip, err := reopened.Tip()
			if err != nil {
				t.Fatal(err)
			}
			extension, _ := mineChild(
				t, reopened, tip.ID, tip.Timestamp+parameters.TargetSpacing, "post-crash-"+name,
			)
			if _, _, err := reopened.Commit(extension, extension.Header.Seal.Timestamp); err != nil {
				t.Fatalf("%s recovered store cannot extend: %v", name, err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkChainCrashHelper(t *testing.T) {
	mode := os.Getenv(crashModeEnvironment)
	if mode == "" {
		t.Skip("subprocess helper")
	}
	path := os.Getenv(crashPathEnvironment)
	marker := os.Getenv(crashMarkerEnvironment)
	parameters := testParameters()
	base := testBase(t, parameters)
	parts := strings.Split(mode, "-")
	if len(parts) != 2 || (parts[1] != "before" && parts[1] != "after" && parts[1] != "decision" && parts[1] != "unsynced") {
		t.Fatalf("unknown crash mode %q", mode)
	}
	operation, boundary := parts[0], parts[1]
	store, err := OpenWithPolicy(path, base, parameters, crashPolicy(operation))
	if err != nil {
		t.Fatal(err)
	}
	stop := func() { blockAtCrashMarker(marker) }
	switch boundary {
	case "before":
		store.persistence.commitHook = func() error {
			stop()
			return storage.ErrCorrupt
		}
	case "after":
		store.persistence.afterCommitHook = stop
	case "unsynced":
		store.persistence.pruneCommitHook = func(batch *pebble.Batch) error {
			if err := batch.Commit(pebble.NoSync); err != nil {
				return err
			}
			stop()
			return errors.New("unreachable crash hook")
		}
	}
	runCrashOperation(t, store, operation, parameters)
	t.Fatal("crash hook returned")
}

type processCrashSummary struct {
	TipID        types.Hash
	StateRoot    types.Hash
	Height       uint64
	Timestamp    uint64
	Work         []byte
	History      uint64
	Nodes        []types.Hash
	Checkpoints  []types.Hash
	FloorID      types.Hash
	FloorPruned  bool
	VerifiedAt   uint64
	Archived     []types.Hash
	PruneTicket  types.Hash
	EffectIDs    []types.Hash
	EffectSchema bool
}

func crashPolicy(operation string) Policy {
	policy := DefaultPolicy()
	switch operation {
	case "commit":
	case "checkpoint":
		policy.CheckpointEvery = 2
		policy.CheckpointKeep = 2
	case "prune":
		policy.ForkRetention = 1
	case "canonical", "authorized", "ticketed":
		policy.ForkRetention = 1
		policy.CanonicalRetention = 1
	default:
		return Policy{}
	}
	return policy
}

func prepareCrashStore(
	t testing.TB,
	path string,
	operation string,
	base Base,
	parameters workblock.Parameters,
	policy Policy,
) {
	t.Helper()
	store, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	switch operation {
	case "commit":
	case "checkpoint", "canonical", "authorized", "ticketed":
		parentID := base.Tip.ID
		timestamp := base.Tip.Timestamp
		blocks := 2
		if operation == "canonical" || operation == "authorized" || operation == "ticketed" {
			blocks = 5
		}
		for height := 1; height <= blocks; height++ {
			timestamp += parameters.TargetSpacing
			block, _ := mineChild(t, store, parentID, timestamp, "process-checkpoint-"+string(rune('0'+height)))
			if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
				t.Fatal(err)
			}
			parentID, _ = block.Header.ID()
		}
	case "prune":
		stale, _ := mineChild(t, store, base.Tip.ID, base.Tip.Timestamp+parameters.TargetSpacing, "process-prune-stale")
		if _, _, err := store.Commit(stale, stale.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		staleID, _ := stale.Header.ID()
		staleChild, _ := mineChild(t, store, staleID, stale.Header.Seal.Timestamp+parameters.TargetSpacing, "process-prune-stale-child")
		if _, _, err := store.Commit(staleChild, staleChild.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
		parentID := base.Tip.ID
		timestamp := base.Tip.Timestamp
		for height := 1; height <= 4; height++ {
			timestamp += parameters.TargetSpacing
			block, _ := mineChild(t, store, parentID, timestamp, "process-prune-winner-"+string(rune('0'+height)))
			if _, _, err := store.Commit(block, block.Header.Seal.Timestamp); err != nil {
				t.Fatal(err)
			}
			parentID, _ = block.Header.ID()
		}
	default:
		t.Fatalf("unknown crash operation %q", operation)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func runCrashOperation(t testing.TB, store *Store, operation string, parameters workblock.Parameters) {
	t.Helper()
	switch operation {
	case "commit":
		tip, err := store.Tip()
		if err != nil {
			t.Fatal(err)
		}
		candidate, _ := mineChild(t, store, tip.ID, tip.Timestamp+parameters.TargetSpacing, "process-crash")
		if _, _, err := store.Commit(candidate, candidate.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
	case "checkpoint":
		if report, err := store.CreateReplayCheckpoint(); err != nil || !report.Created {
			t.Fatalf("checkpoint operation report=%+v err=%v", report, err)
		}
	case "prune":
		if report, err := store.PruneStaleForks(); err != nil || report.RemovedNodes == 0 {
			t.Fatalf("prune operation report=%+v err=%v", report, err)
		}
	case "canonical", "authorized", "ticketed":
		tip, err := store.Tip()
		if err != nil {
			t.Fatal(err)
		}
		anchorID := tip.ID
		for steps := 0; steps < 2; steps++ {
			node := store.nodes[anchorID]
			if node == nil || node.block == nil {
				t.Fatal("canonical crash fixture lost anchor ancestry")
			}
			anchorID = node.block.Header.Seal.AnchorParent
		}
		anchor, err := store.TipByID(anchorID)
		if err != nil {
			t.Fatal(err)
		}
		root, count, err := store.SelectedAncestryCommitment(anchorID)
		if err != nil {
			t.Fatal(err)
		}
		boundary := canonicalTestFloor(store.baseID, anchor, root, count, "process-crash")
		var report CanonicalPruneReport
		authorize := func() (uint64, error) {
			if os.Getenv(crashModeEnvironment) == operation+"-decision" {
				blockAtCrashMarker(os.Getenv(crashMarkerEnvironment))
			}
			return 200, nil
		}
		if operation == "ticketed" {
			var commit CanonicalPruneCommit
			commit, err = store.PruneCanonicalPrefixOnce(pruneOperation(boundary, "process"), authorize)
			report = commit.Effect.Report
		} else if operation == "authorized" {
			report, err = store.PruneCanonicalPrefixAuthorized(boundary, authorize)
		} else {
			report, err = store.PruneCanonicalPrefix(boundary)
		}
		if err != nil || report.RemovedNodes == 0 {
			t.Fatalf("canonical prune operation report=%+v err=%v", report, err)
		}
	default:
		t.Fatalf("unknown crash operation %q", operation)
	}
}

func reopenCrashSummary(
	t testing.TB,
	path string,
	base Base,
	parameters workblock.Parameters,
	policy Policy,
) processCrashSummary {
	t.Helper()
	store, err := OpenWithPolicy(path, base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	result := crashStoreSummary(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return result
}

func crashStoreSummary(t testing.TB, store *Store) processCrashSummary {
	t.Helper()
	tip, err := store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	history, limit, err := store.HistoryUsage()
	if err != nil || history == 0 || history > limit {
		t.Fatalf("history=%d/%d err=%v", history, limit, err)
	}
	nodes, err := store.NodeIDs()
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := make([]types.Hash, 0, len(store.persistence.checkpoints))
	for id := range store.persistence.checkpoints {
		checkpoints = append(checkpoints, id)
	}
	sort.Slice(checkpoints, func(left, right int) bool {
		return types.CompareHash(checkpoints[left], checkpoints[right]) < 0
	})
	floor, err := store.CanonicalFloor()
	if err != nil {
		t.Fatal(err)
	}
	archived := make([]types.Hash, len(store.archivedHeaders))
	for index, header := range store.archivedHeaders {
		archived[index], err = header.ID()
		if err != nil {
			t.Fatal(err)
		}
	}
	var effectIDs []types.Hash
	iterator, err := store.persistence.db.NewIter(&pebble.IterOptions{LowerBound: []byte{workPruneEffectPrefix}, UpperBound: []byte{workPruneEffectPrefix + 1}})
	if err != nil {
		t.Fatal(err)
	}
	for valid := iterator.First(); valid; valid = iterator.Next() {
		effect, err := DecodeCanonicalPruneEffect(iterator.Value())
		if err != nil {
			t.Fatal(err)
		}
		id, err := effect.ID()
		if err != nil {
			t.Fatal(err)
		}
		effectIDs = append(effectIDs, id)
	}
	if err := iterator.Error(); err != nil {
		t.Fatal(err)
	}
	if err := iterator.Close(); err != nil {
		t.Fatal(err)
	}
	return processCrashSummary{
		TipID: tip.ID, StateRoot: state.Root(), Height: tip.Height, Timestamp: tip.Timestamp,
		Work: append([]byte(nil), tip.CumulativeWork...), History: history,
		Nodes: append([]types.Hash(nil), nodes...), Checkpoints: checkpoints,
		FloorID: floor.Anchor.ID, FloorPruned: floor.Pruned, VerifiedAt: floor.VerifiedAt, Archived: archived,
		PruneTicket: floor.PruneTicketID, EffectIDs: effectIDs, EffectSchema: store.persistence.effectSchema,
	}
}

func equalCrashSummary(left, right processCrashSummary) bool {
	return left.TipID == right.TipID && left.StateRoot == right.StateRoot &&
		left.Height == right.Height && left.Timestamp == right.Timestamp && left.History == right.History &&
		bytes.Equal(left.Work, right.Work) && hashSlicesEqual(left.Nodes, right.Nodes) &&
		hashSlicesEqual(left.Checkpoints, right.Checkpoints) && left.FloorID == right.FloorID &&
		left.FloorPruned == right.FloorPruned && left.VerifiedAt == right.VerifiedAt && hashSlicesEqual(left.Archived, right.Archived) &&
		left.PruneTicket == right.PruneTicket && left.EffectSchema == right.EffectSchema && hashSlicesEqual(left.EffectIDs, right.EffectIDs)
}

func hashSlicesEqual(left, right []types.Hash) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func blockAtCrashMarker(path string) {
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		panic(err)
	}
	select {}
}

func waitForCrashMarker(t testing.TB, path string, command *exec.Cmd) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if command.ProcessState != nil && command.ProcessState.Exited() {
			t.Fatal("crash helper exited before reaching durability boundary")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	t.Fatal("crash helper did not reach durability boundary")
}
