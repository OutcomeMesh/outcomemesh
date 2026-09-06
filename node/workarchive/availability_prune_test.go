package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// Fixed times are confined to tests. The public destructive API has no time
// parameter; historical verifiers still accept explicit observation times.
func pruneArchiveAt(chain *workchain.Store, replicas []Replica, path string,
	checkpoint Checkpoint, policy Policy, replicaPolicy ReplicaPolicy,
	base workchain.Base, parameters workblock.Parameters, limits Limits, at uint64,
) (CanonicalPruneResult, error) {
	return pruneCanonicalPrefix(context.Background(), chain, replicas, path, checkpoint,
		policy, replicaPolicy, base, parameters, limits, func() time.Time { return time.Unix(int64(at), 0) })
}

func prepareAvailabilityPrune(t testing.TB) (archiveFixture, []Replica, ReplicaPolicy) {
	t.Helper()
	f := newArchiveFixture(t)
	replicas, policy := archiveReplicaFixture(t, f, 1_000, 20_000)
	block, _ := mineArchiveChild(t, f.source, f.manifest.Anchor.ID,
		f.manifest.Anchor.Timestamp+f.parameters.TargetSpacing, "availability-live-gate")
	if _, _, err := f.source.Commit(block, block.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.source.PruneStaleForks(); err != nil {
		t.Fatal(err)
	}
	return f, replicas, policy
}

func TestCanonicalPruneRechecksTimeAtEveryBoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		step       int
		at         time.Time
		cancel     bool
		remaining  uint64
		maximumAge uint64
		want       error
	}{
		{name: "fresh", step: 4, at: time.Unix(1_004, 0)},
		{name: "age-boundary-inclusive", step: 4, at: time.Unix(1_100, 0)},
		{name: "remaining-boundary-inclusive", step: 4, at: time.Unix(19_000, 0), maximumAge: 30_000},
		{name: "expires-during-replay", step: 2, at: time.Unix(1_101, 0), want: ErrAvailability},
		{name: "expires-during-publication", step: 3, at: time.Unix(1_101, 0), want: ErrAvailability},
		{name: "expires-during-batch-preparation", step: 4, at: time.Unix(1_101, 0), want: ErrAvailability},
		{name: "remaining-term-runs-out", step: 4, at: time.Unix(1_003, 0), remaining: 18_998, want: ErrAvailability},
		{name: "retention-expiry-exclusive", step: 4, at: time.Unix(20_000, 0), maximumAge: 30_000, want: ErrAvailability},
		{name: "clock-backwards-after-replay", step: 2, at: time.Unix(1_000, 0), want: ErrAvailabilityClock},
		{name: "clock-backwards-before-commit", step: 4, at: time.Unix(1_000, 0), want: ErrAvailabilityClock},
		{name: "subsecond-clock-backwards", step: 4, at: time.Unix(1_001, 400_000_000), want: ErrAvailabilityClock},
		{name: "zero-clock", step: 1, at: time.Unix(0, 0), want: ErrAvailabilityClock},
		{name: "negative-clock", step: 1, at: time.Unix(-1, 0), want: ErrAvailabilityClock},
		{name: "cancel-after-replay", step: 2, cancel: true, want: context.Canceled},
		{name: "cancel-after-publication", step: 3, cancel: true, want: context.Canceled},
		{name: "cancel-before-commit", step: 4, cancel: true, want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, replicas, policy := prepareAvailabilityPrune(t)
			if tc.remaining != 0 {
				policy.MinimumRemainingTerm = tc.remaining
			}
			if tc.maximumAge != 0 {
				policy.MaximumReceiptAge = tc.maximumAge
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			clock := func() time.Time {
				calls++
				if calls == tc.step {
					if tc.cancel {
						cancel()
					} else {
						return tc.at
					}
				}
				return time.Unix(1_001, 500_000_000)
			}
			before, _, err := f.source.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			anchorBlock, err := f.source.BlockByID(f.manifest.Anchor.ID)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "availability.omav")
			result, err := pruneCanonicalPrefix(ctx, f.source, replicas, path, f.checkpoint,
				f.policy, policy, f.base, f.parameters, DefaultLimits(), clock)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if calls != tc.step {
				t.Fatalf("clock samples=%d want=%d", calls, tc.step)
			}
			_, statErr := os.Lstat(path)
			if tc.step < 3 && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("failed pre-publication check wrote evidence", statErr)
			}
			if tc.step >= 3 && statErr != nil {
				t.Fatal("published evidence lost", statErr)
			}
			floor, err := f.source.CanonicalFloor()
			if err != nil || floor.Pruned != (tc.want == nil) {
				t.Fatalf("floor=%+v err=%v", floor, err)
			}
			if tc.want != nil {
				after, _, err := f.source.HistoryUsage()
				if err != nil || after != before {
					t.Fatalf("rejected prune changed logical bytes %d -> %d: %v", before, after, err)
				}
			} else {
				if floor.VerifiedAt != uint64(tc.at.Unix()) || result.Report.RemovedNodes == 0 {
					t.Fatalf("wrong authorization timestamp/result: %+v %+v", floor, result.Report)
				}
			}
			if err := f.source.Close(); err != nil {
				t.Fatal(err)
			}
			workPolicy := workchain.DefaultPolicy()
			workPolicy.ForkRetention, workPolicy.CanonicalRetention = 1, 1
			reopened, err := workchain.OpenWithPolicy(f.sourcePath, f.base, f.parameters, workPolicy)
			if err != nil {
				t.Fatal("reopen", err)
			}
			defer reopened.Close()
			recovered, err := reopened.CanonicalFloor()
			if err != nil || recovered.Pruned != floor.Pruned || recovered.VerifiedAt != floor.VerifiedAt {
				t.Fatalf("reopened floor=%+v want=%+v err=%v", recovered, floor, err)
			}
			if tc.want != nil {
				if _, err := reopened.BlockByID(anchorBlock.Header.Seal.AnchorParent); err != nil {
					t.Fatal("rejected prune lost pre-anchor history", err)
				}
			}
		})
	}
}

func TestCanonicalPruneLiveAPIRejectsHistoricalTimeAndCanceledContext(t *testing.T) {
	f, replicas, policy := prepareAvailabilityPrune(t)
	for _, mode := range []string{"historical", "canceled", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			want := ErrAvailability
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			} else if mode == "nil-context" {
				ctx = nil
			}
			path := filepath.Join(t.TempDir(), "availability.omav")
			_, err := PruneCanonicalPrefix(ctx, f.source, replicas, path, f.checkpoint,
				f.policy, policy, f.base, f.parameters, DefaultLimits())
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected public call wrote evidence", err)
			}
		})
	}
	started := uint64(time.Now().Unix())
	fresh, freshPolicy := archiveReplicaFixture(t, f, started, started+20_000)
	if _, err := PruneCanonicalPrefix(context.Background(), f.source, fresh, filepath.Join(t.TempDir(), "live.omav"),
		f.checkpoint, f.policy, freshPolicy, f.base, f.parameters, DefaultLimits()); err != nil {
		t.Fatal("live public API rejected current receipts", err)
	}
	floor, err := f.source.CanonicalFloor()
	if err != nil || !floor.Pruned || floor.VerifiedAt < started || floor.VerifiedAt > uint64(time.Now().Unix()) {
		t.Fatalf("public API did not persist a live authorization time: %+v %v", floor, err)
	}
}

func TestAvailabilityPublicationNeverReplacesEvidence(t *testing.T) {
	f := newArchiveFixture(t)
	replicas, policy := archiveReplicaFixture(t, f, 1_000, 20_000)
	bundle, err := VerifyReplicaSet(replicas, f.checkpoint, f.policy, policy, f.base, f.parameters, DefaultLimits(), 1_001)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := bundle.ID()
	encoded, _ := bundle.CanonicalBytes()
	save := func(path string) error {
		return SaveAvailabilityBundleFile(path, bundle, f.checkpoint, f.policy, policy, 1_001, id)
	}
	for _, mode := range []string{"identical", "corrupt", "directory", "symlink", "dangling-symlink"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "availability.omav")
			switch mode {
			case "identical":
				if err := save(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, bytes.Repeat([]byte{1}, len(encoded)), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			default:
				target := filepath.Join(t.TempDir(), "target")
				if mode == "symlink" {
					if err := os.WriteFile(target, encoded, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			err = save(path)
			if (err == nil) != (mode == "identical") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("existing evidence replaced", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "concurrent.omav")
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- save(path) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("identical concurrent publish", err)
		}
	}
	if got := mustReadArchiveFile(t, path); !bytes.Equal(got, encoded) {
		t.Fatal("concurrent publication differs")
	}
	otherReplicas, _ := archiveReplicaFixture(t, f, 1_001, 20_001)
	other, err := VerifyReplicaSet(otherReplicas, f.checkpoint, f.policy, policy, f.base, f.parameters, DefaultLimits(), 1_002)
	if err != nil {
		t.Fatal(err)
	}
	otherID, _ := other.ID()
	if err := SaveAvailabilityBundleFile(path, other, f.checkpoint, f.policy, policy, 1_002, otherID); !errors.Is(err, ErrAvailability) {
		t.Fatal("another valid bundle replaced earlier evidence", err)
	}
	if got := mustReadArchiveFile(t, path); !bytes.Equal(got, encoded) {
		t.Fatal("conflict changed bytes")
	}
	conflictPath := filepath.Join(t.TempDir(), "contested.omav")
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- save(conflictPath) }()
	go func() {
		<-start
		results <- SaveAvailabilityBundleFile(conflictPath, other, f.checkpoint, f.policy, policy, 1_002, otherID)
	}()
	close(start)
	first, second := <-results, <-results
	if !((first == nil && errors.Is(second, ErrAvailability)) || (second == nil && errors.Is(first, ErrAvailability))) {
		t.Fatalf("conflicting publishers must have one winner: %v / %v", first, second)
	}
	winner, err := DecodeAvailabilityBundle(mustReadArchiveFile(t, conflictPath))
	if err != nil {
		t.Fatal(err)
	}
	winnerID, _ := winner.ID()
	if winnerID != id && winnerID != otherID {
		t.Fatal("concurrent winner is neither complete bundle")
	}
}

func TestCanonicalPruneRetriesPublishedEvidenceAfterCancellation(t *testing.T) {
	f, replicas, policy := prepareAvailabilityPrune(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 4 {
			cancel()
		}
		return time.Unix(1_001, 0)
	}
	path := filepath.Join(t.TempDir(), "availability.omav")
	if _, err := pruneCanonicalPrefix(ctx, f.source, replicas, path, f.checkpoint, f.policy, policy,
		f.base, f.parameters, DefaultLimits(), clock); !errors.Is(err, context.Canceled) {
		t.Fatal("did not cancel at final gate", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded := mustReadArchiveFile(t, path)
	if _, err := pruneArchiveAt(f.source, replicas, path, f.checkpoint, f.policy, policy,
		f.base, f.parameters, DefaultLimits(), 1_005); err != nil {
		t.Fatal("exact evidence retry", err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || !bytes.Equal(encoded, mustReadArchiveFile(t, path)) {
		t.Fatal("retry replaced evidence", err)
	}
	if floor, err := f.source.CanonicalFloor(); err != nil || floor.VerifiedAt != 1_005 {
		t.Fatalf("retry did not use a fresh decision: %+v %v", floor, err)
	}
}

func TestReplicaAvailabilityTimeRejectsUnsignedWraparound(t *testing.T) {
	policy := ReplicaPolicy{MaximumReceiptAge: 10, MinimumRemainingTerm: 2}
	receipt := ReplicaReceipt{StoredAt: ^uint64(0) - 5, RetainUntil: ^uint64(0)}
	for _, tc := range []struct {
		at    uint64
		valid bool
	}{
		{0, false}, {1, false}, {^uint64(0) - 6, false}, {^uint64(0) - 5, true},
		{^uint64(0) - 2, true}, {^uint64(0) - 1, false}, {^uint64(0), false},
	} {
		if err := receipt.verifyAvailabilityTime(policy, tc.at); (err == nil) != tc.valid {
			t.Fatalf("at=%d valid=%t err=%v", tc.at, tc.valid, err)
		}
	}
}
