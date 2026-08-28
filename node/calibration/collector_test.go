package calibration

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCollectorPersistsDeduplicatesAndRollsIntervals(t *testing.T) {
	collector, config := testCollector(t, testStartedAt)
	clusterA := types.DomainHash("test/calibration/collector-cluster-a")
	clusterB := types.DomainHash("test/calibration/collector-cluster-b")
	workA := types.DomainHash("test/calibration/collector-work-a")
	workB := types.DomainHash("test/calibration/collector-work-b")
	tieA := types.DomainHash("test/calibration/collector-tie-a")
	tieB := types.DomainHash("test/calibration/collector-tie-b")

	if added, err := collector.ObserveWork(testStartedAt+10, workB, clusterB); err != nil || !added {
		t.Fatalf("observe work B added=%t err=%v", added, err)
	}
	if added, err := collector.ObserveWork(testStartedAt+11, workA, clusterA); err != nil || !added {
		t.Fatalf("observe work A added=%t err=%v", added, err)
	}
	if added, err := collector.ObserveWork(testStartedAt+12, workA, clusterA); err != nil || added {
		t.Fatalf("duplicate work added=%t err=%v", added, err)
	}
	if _, err := collector.ObserveWork(testStartedAt+12, workA, clusterB); !errors.Is(err, ErrObservation) {
		t.Fatalf("conflicting work error=%v", err)
	}
	if added, err := collector.ObserveTie(testStartedAt+20, tieB, false); err != nil || !added {
		t.Fatalf("observe tie B added=%t err=%v", added, err)
	}
	if added, err := collector.ObserveTie(testStartedAt+21, tieA, true); err != nil || !added {
		t.Fatalf("observe tie A added=%t err=%v", added, err)
	}
	if added, err := collector.ObserveTie(testStartedAt+22, tieA, true); err != nil || added {
		t.Fatalf("duplicate tie added=%t err=%v", added, err)
	}
	if _, err := collector.ObserveTie(testStartedAt+22, tieA, false); !errors.Is(err, ErrObservation) {
		t.Fatalf("conflicting tie error=%v", err)
	}
	status, err := collector.Status()
	if err != nil || status.Records != 0 || status.PendingWork != 2 || status.PendingTieTrials != 2 {
		t.Fatalf("pending status=%+v err=%v", status, err)
	}
	if err := collector.Advance(testStartedAt + MaximumIntervalSeconds - 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.ManifestPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("premature manifest stat error=%v", err)
	}
	if err := collector.Advance(testStartedAt + MaximumIntervalSeconds); err != nil {
		t.Fatal(err)
	}
	records, aggregate, err := LoadFile(config.ManifestPath, config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ObservedWork != 2 || records[0].ControlledTieTrials != 2 ||
		records[0].ControlledTieAdoptions != 1 || aggregate.LargestCoordinatedWork != 1 {
		t.Fatalf("first interval records=%+v aggregate=%+v", records, aggregate)
	}
	workC := types.DomainHash("test/calibration/collector-work-c")
	if added, err := collector.ObserveWork(testStartedAt+MaximumIntervalSeconds, workC, clusterA); err != nil || !added {
		t.Fatalf("second interval work added=%t err=%v", added, err)
	}
	if err := collector.Advance(testStartedAt + 2*MaximumIntervalSeconds); err != nil {
		t.Fatal(err)
	}
	_, aggregate, err = LoadFile(config.ManifestPath, config.Binding)
	if err != nil || aggregate.RecordCount != 2 || aggregate.ObservedWork != 3 || aggregate.LargestCoordinatedWork != 2 {
		t.Fatalf("second aggregate=%+v err=%v", aggregate, err)
	}
	if err := collector.Close(testStartedAt + 2*MaximumIntervalSeconds); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Status(); !errors.Is(err, ErrCollectorClosed) {
		t.Fatalf("closed status error=%v", err)
	}
}

func TestCollectorRestartsPendingAndReconcilesCommittedManifest(t *testing.T) {
	collector, config := testCollector(t, testStartedAt)
	cluster := types.DomainHash("test/calibration/restart-cluster")
	work := types.DomainHash("test/calibration/restart-work")
	if _, err := collector.ObserveWork(testStartedAt+1, work, cluster); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenCollector(config, testStartedAt+2)
	if err != nil {
		t.Fatal(err)
	}
	if added, err := restarted.ObserveWork(testStartedAt+3, work, cluster); err != nil || added {
		t.Fatalf("restart duplicate added=%t err=%v", added, err)
	}
	oldPending, err := os.ReadFile(config.PendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Advance(testStartedAt + MaximumIntervalSeconds); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.PendingPath, oldPending, 0o600); err != nil {
		t.Fatal(err)
	}
	reconciled, err := OpenCollector(config, testStartedAt+MaximumIntervalSeconds+1)
	if err != nil {
		t.Fatal(err)
	}
	status, err := reconciled.Status()
	if err != nil || status.Records != 1 || status.PendingStartedAt != testStartedAt+MaximumIntervalSeconds ||
		status.PendingWork != 0 {
		t.Fatalf("reconciled status=%+v err=%v", status, err)
	}
	pending, err := loadPending(config.PendingPath, config.Binding)
	if err != nil || pending.Sequence != 2 || pending.PreviousID != status.LastRecordID {
		t.Fatalf("reconciled pending=%+v err=%v", pending, err)
	}
}

func TestCollectorFillsEmptyIntervalsAndRejectsClockRollback(t *testing.T) {
	collector, config := testCollector(t, testStartedAt)
	if err := collector.Advance(testStartedAt - 1); !errors.Is(err, ErrClock) {
		t.Fatalf("rollback error=%v", err)
	}
	if err := collector.Advance(testStartedAt + 3*MaximumIntervalSeconds); err != nil {
		t.Fatal(err)
	}
	records, aggregate, err := LoadFile(config.ManifestPath, config.Binding)
	if err != nil || len(records) != 3 || aggregate.RecordCount != 3 || aggregate.ObservedWork != 0 ||
		aggregate.EndedAt != testStartedAt+3*MaximumIntervalSeconds {
		t.Fatalf("empty rollover records=%d aggregate=%+v err=%v", len(records), aggregate, err)
	}
}

func TestCollectorEnforcesClusterBudgetAndPoisonsPersistenceFailure(t *testing.T) {
	key := testKey()
	binding := testBinding(key)
	binding.ClusterComparisonBudget = 1
	root := t.TempDir()
	config := CollectorConfig{
		Binding: binding, PrivateKey: key,
		ManifestPath: filepath.Join(root, "manifest.bin"), PendingPath: filepath.Join(root, "pending.bin"),
	}
	collector, err := OpenCollector(config, testStartedAt)
	if err != nil {
		t.Fatal(err)
	}
	clusterA := types.DomainHash("test/calibration/budget-a")
	clusterB := types.DomainHash("test/calibration/budget-b")
	if _, err := collector.ObserveWork(testStartedAt+1, types.DomainHash("test/calibration/budget-work-a"), clusterA); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.ObserveWork(testStartedAt+2, types.DomainHash("test/calibration/budget-work-b"), clusterB); !errors.Is(err, ErrClusters) {
		t.Fatalf("cluster budget error=%v", err)
	}
	if err := os.Remove(config.PendingPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(config.PendingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.ObserveTie(testStartedAt+3, types.DomainHash("test/calibration/failing-tie"), true); !errors.Is(err, ErrCollectorFailed) {
		t.Fatalf("persistence failure error=%v", err)
	}
	if _, err := collector.ObserveTie(testStartedAt+4, types.DomainHash("test/calibration/after-failure"), false); !errors.Is(err, ErrCollectorFailed) {
		t.Fatalf("poisoned collector error=%v", err)
	}
	if _, err := OpenCollector(config, testStartedAt+5); !errors.Is(err, ErrCollectorFailed) {
		t.Fatalf("persistent failure marker error=%v", err)
	}
}

func TestCollectorExplicitFailureInvalidatesEvidenceWindow(t *testing.T) {
	collector, config := testCollector(t, testStartedAt)
	cause := errors.New("post-commit observation could not be classified")
	if err := collector.Fail(cause); !errors.Is(err, ErrCollectorFailed) || !errors.Is(err, cause) {
		t.Fatalf("explicit failure error=%v", err)
	}
	if _, err := os.Stat(config.PendingPath + ".failed"); err != nil {
		t.Fatalf("failure marker stat error=%v", err)
	}
	if _, err := OpenCollector(config, testStartedAt+1); !errors.Is(err, ErrCollectorFailed) {
		t.Fatalf("reopened invalid evidence window error=%v", err)
	}
}

func TestCollectorSerializesConcurrentObservations(t *testing.T) {
	collector, _ := testCollector(t, testStartedAt)
	cluster := types.DomainHash("test/calibration/concurrent-cluster")
	const observations = 24
	var wait sync.WaitGroup
	errorsSeen := make(chan error, observations)
	for index := range observations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			identifier := types.DomainHash("test/calibration/concurrent-work", []byte{byte(index)})
			_, err := collector.ObserveWork(testStartedAt+1, identifier, cluster)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	status, err := collector.Status()
	if err != nil || status.PendingWork != observations {
		t.Fatalf("concurrent status=%+v err=%v", status, err)
	}
}

func TestPendingCanonicalRoundTripAndFuzzSeed(t *testing.T) {
	collector, config := testCollector(t, testStartedAt)
	if _, err := collector.ObserveTie(testStartedAt+1, types.DomainHash("test/calibration/pending-tie"), true); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(config.PendingPath)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := decodePending(encoded, config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := pending.canonicalBytes()
	if err != nil || string(roundTrip) != string(encoded) {
		t.Fatalf("pending round trip error=%v", err)
	}
	if _, err := decodePending(append(encoded, 0), config.Binding); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("pending trailing error=%v", err)
	}
}

func FuzzDecodePendingNeverPanics(f *testing.F) {
	key := testKey()
	binding := testBinding(key)
	pending := newPending(binding, 1, testStartedAt, types.Hash{})
	encoded, err := pending.canonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decodePending(input, binding)
	})
}

func testCollector(t testing.TB, now uint64) (*Collector, CollectorConfig) {
	t.Helper()
	key := testKey()
	root := t.TempDir()
	config := CollectorConfig{
		Binding: testBinding(key), PrivateKey: key,
		ManifestPath: filepath.Join(root, "telemetry.omtm"),
		PendingPath:  filepath.Join(root, "telemetry.pending"),
	}
	collector, err := OpenCollector(config, now)
	if err != nil {
		t.Fatal(err)
	}
	return collector, config
}
