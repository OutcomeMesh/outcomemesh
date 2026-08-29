package calibration

import (
	"crypto/ed25519"
	"errors"
	"os"
	"sort"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrPending         = errors.New("invalid calibration pending state")
	ErrObservation     = errors.New("invalid calibration observation")
	ErrCollectorConfig = errors.New("invalid calibration collector configuration")
	ErrCollectorClosed = errors.New("calibration collector is closed")
	ErrCollectorFailed = errors.New("calibration collector requires restart")
	ErrClock           = errors.New("calibration collector clock moved backward")
	ErrEventCapacity   = errors.New("calibration interval event capacity reached")
)

type CollectorConfig struct {
	Binding      Binding
	PrivateKey   ed25519.PrivateKey
	ManifestPath string
	PendingPath  string
}

type CollectorStatus struct {
	Records          uint64
	StartedAt        uint64
	CompletedThrough uint64
	PendingStartedAt uint64
	PendingWork      uint64
	PendingTieTrials uint64
	LastRecordID     types.Hash
	Failed           bool
}

// Collector owns one local observer chain. Observation methods synchronously
// persist the current-hour event journal before returning success. A failure
// poisons the instance so the caller cannot accidentally continue an
// incomplete evidence window; OpenCollector reconciles a manifest commit that
// raced a crash before the next empty pending state was persisted.
type Collector struct {
	mu           sync.Mutex
	binding      Binding
	privateKey   ed25519.PrivateKey
	manifestPath string
	pendingPath  string
	failurePath  string
	records      []Record
	aggregate    Aggregate
	pending      pendingState
	clusterIDs   map[types.Hash]struct{}
	failed       error
	closed       bool
}

func OpenCollector(config CollectorConfig, now uint64) (*Collector, error) {
	if len(config.PrivateKey) != ed25519.PrivateKeySize || config.ManifestPath == "" ||
		config.PendingPath == "" || config.ManifestPath == config.PendingPath || !validBinding(config.Binding) || now == 0 {
		return nil, ErrCollectorConfig
	}
	publicKey := config.PrivateKey.Public().(ed25519.PublicKey)
	if string(publicKey) != string(config.Binding.ObserverPublicKey[:]) {
		return nil, ErrCollectorConfig
	}
	collector := &Collector{
		binding: config.Binding, privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...),
		manifestPath: config.ManifestPath, pendingPath: config.PendingPath,
		failurePath: config.PendingPath + ".failed",
		clusterIDs:  make(map[types.Hash]struct{}),
	}
	if _, err := os.Stat(collector.failurePath); err == nil {
		return nil, ErrCollectorFailed
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	records, aggregate, manifestErr := LoadFile(config.ManifestPath, config.Binding)
	if manifestErr == nil {
		collector.records = records
		collector.aggregate = aggregate
		for _, cluster := range aggregate.Clusters {
			collector.clusterIDs[cluster.ID] = struct{}{}
		}
	} else if !errors.Is(manifestErr, os.ErrNotExist) {
		return nil, manifestErr
	}
	pending, pendingErr := loadPending(config.PendingPath, config.Binding)
	switch {
	case pendingErr == nil:
		collector.pending = pending
	case errors.Is(pendingErr, os.ErrNotExist) && manifestErr != nil:
		collector.pending = newPending(config.Binding, 1, alignedIntervalStart(now), types.Hash{})
		if err := savePending(config.PendingPath, collector.pending); err != nil {
			return nil, err
		}
	case errors.Is(pendingErr, os.ErrNotExist):
		return nil, ErrPending
	default:
		return nil, pendingErr
	}
	if manifestErr != nil && collector.pending.Sequence != 1 {
		return nil, ErrPending
	}
	if manifestErr == nil {
		nextSequence := aggregate.RecordCount + 1
		if collector.pending.Sequence <= aggregate.RecordCount {
			collector.pending = newPending(config.Binding, nextSequence, aggregate.EndedAt, aggregate.LastRecordID)
			if err := savePending(config.PendingPath, collector.pending); err != nil {
				return nil, err
			}
		} else if collector.pending.Sequence != nextSequence ||
			collector.pending.PreviousID != aggregate.LastRecordID || collector.pending.StartedAt != aggregate.EndedAt {
			return nil, ErrPending
		}
	}
	if err := collector.advanceLocked(now); err != nil {
		return nil, err
	}
	return collector, nil
}

func (collector *Collector) ObserveWork(now uint64, eventID, clusterID types.Hash) (bool, error) {
	if collector == nil || eventID.IsZero() || clusterID.IsZero() {
		return false, ErrObservation
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if err := collector.readyLocked(); err != nil {
		return false, err
	}
	if err := collector.advanceLocked(now); err != nil {
		return false, err
	}
	index := sort.Search(len(collector.pending.Work), func(index int) bool {
		return types.CompareHash(collector.pending.Work[index].ID, eventID) >= 0
	})
	if index < len(collector.pending.Work) && collector.pending.Work[index].ID == eventID {
		if collector.pending.Work[index].ClusterID != clusterID {
			return false, ErrObservation
		}
		return false, nil
	}
	if len(collector.pending.Work) >= MaximumWorkEventsPerInterval {
		return false, ErrEventCapacity
	}
	if _, known := collector.clusterIDs[clusterID]; !known {
		pendingKnown := false
		for _, observation := range collector.pending.Work {
			if observation.ClusterID == clusterID {
				pendingKnown = true
				break
			}
		}
		if !pendingKnown && collector.clusterCountLocked() >=
			int(collector.binding.ClusterComparisonBudget) {
			return false, ErrClusters
		}
	}
	next := clonePending(collector.pending)
	next.Work = append(next.Work, WorkObservation{})
	copy(next.Work[index+1:], next.Work[index:])
	next.Work[index] = WorkObservation{ID: eventID, ClusterID: clusterID}
	if err := savePending(collector.pendingPath, next); err != nil {
		return false, collector.poisonLocked(err)
	}
	collector.pending = next
	return true, nil
}

// ObserveTie is retained for version-0 journal compatibility and arithmetic
// exploration. ValidateEvidenceBundle rejects every hourly chain containing
// these manually classified counters; ER-5 accepts only complete raw receipts.
func (collector *Collector) ObserveTie(now uint64, eventID types.Hash, adopted bool) (bool, error) {
	if collector == nil || eventID.IsZero() {
		return false, ErrObservation
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if err := collector.readyLocked(); err != nil {
		return false, err
	}
	if err := collector.advanceLocked(now); err != nil {
		return false, err
	}
	index := sort.Search(len(collector.pending.Ties), func(index int) bool {
		return types.CompareHash(collector.pending.Ties[index].ID, eventID) >= 0
	})
	if index < len(collector.pending.Ties) && collector.pending.Ties[index].ID == eventID {
		if collector.pending.Ties[index].Adopted != adopted {
			return false, ErrObservation
		}
		return false, nil
	}
	if len(collector.pending.Ties) >= MaximumTieEventsPerInterval {
		return false, ErrEventCapacity
	}
	next := clonePending(collector.pending)
	next.Ties = append(next.Ties, TieObservation{})
	copy(next.Ties[index+1:], next.Ties[index:])
	next.Ties[index] = TieObservation{ID: eventID, Adopted: adopted}
	if err := savePending(collector.pendingPath, next); err != nil {
		return false, collector.poisonLocked(err)
	}
	collector.pending = next
	return true, nil
}

func (collector *Collector) Advance(now uint64) error {
	if collector == nil {
		return ErrCollectorConfig
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if err := collector.readyLocked(); err != nil {
		return err
	}
	return collector.advanceLocked(now)
}

// Fail permanently invalidates the current local evidence window. Live
// adapters call it whenever a post-commit event cannot be represented or
// persisted, because continuing after one missed event would make otherwise
// valid signatures overstate the completeness of the observation window.
func (collector *Collector) Fail(cause error) error {
	if collector == nil || cause == nil {
		return ErrCollectorConfig
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return ErrCollectorClosed
	}
	if collector.failed != nil {
		return errors.Join(ErrCollectorFailed, collector.failed, cause)
	}
	return collector.poisonLocked(cause)
}

func (collector *Collector) Status() (CollectorStatus, error) {
	if collector == nil {
		return CollectorStatus{}, ErrCollectorConfig
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return CollectorStatus{}, ErrCollectorClosed
	}
	return CollectorStatus{
		Records: collector.aggregate.RecordCount, StartedAt: collector.aggregate.StartedAt,
		CompletedThrough: collector.aggregate.EndedAt, PendingStartedAt: collector.pending.StartedAt,
		PendingWork: uint64(len(collector.pending.Work)), PendingTieTrials: uint64(len(collector.pending.Ties)),
		LastRecordID: collector.aggregate.LastRecordID, Failed: collector.failed != nil,
	}, nil
}

func (collector *Collector) Close(now uint64) error {
	if collector == nil {
		return ErrCollectorConfig
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.closed {
		return ErrCollectorClosed
	}
	var err error
	if collector.failed != nil {
		err = errors.Join(ErrCollectorFailed, collector.failed)
	} else {
		err = collector.advanceLocked(now)
	}
	collector.closed = true
	return err
}

func (collector *Collector) advanceLocked(now uint64) error {
	if now < collector.pending.StartedAt {
		return ErrClock
	}
	for now >= collector.pending.EndedAt {
		unsigned, err := collector.pending.record()
		if err != nil {
			return collector.poisonLocked(err)
		}
		record, err := Sign(collector.privateKey, unsigned)
		if err != nil {
			return collector.poisonLocked(err)
		}
		nextRecords := append(append([]Record(nil), collector.records...), record)
		aggregate, err := SaveFile(collector.manifestPath, nextRecords, collector.binding)
		if err != nil {
			return collector.poisonLocked(err)
		}
		collector.records = nextRecords
		collector.aggregate = aggregate
		for _, cluster := range record.Clusters {
			collector.clusterIDs[cluster.ID] = struct{}{}
		}
		collector.pending = newPending(
			collector.binding, record.Sequence+1, record.EndedAt, aggregate.LastRecordID,
		)
		if err := savePending(collector.pendingPath, collector.pending); err != nil {
			return collector.poisonLocked(err)
		}
	}
	return nil
}

func (collector *Collector) poisonLocked(cause error) error {
	collector.failed = cause
	markerErr := savePrivateFile(
		collector.failurePath,
		".outcomemesh-telemetry-failed-*",
		[]byte("OMESH/testnet/calibration/collector-failed/v0\n"),
	)
	return errors.Join(ErrCollectorFailed, cause, markerErr)
}

func (collector *Collector) readyLocked() error {
	if collector.closed {
		return ErrCollectorClosed
	}
	if collector.failed != nil {
		return errors.Join(ErrCollectorFailed, collector.failed)
	}
	return nil
}

func newPending(binding Binding, sequence, startedAt uint64, previous types.Hash) pendingState {
	return pendingState{
		Binding: binding, Sequence: sequence, StartedAt: startedAt,
		EndedAt: startedAt + MaximumIntervalSeconds, PreviousID: previous,
	}
}

func alignedIntervalStart(now uint64) uint64 {
	return now - now%MaximumIntervalSeconds
}

func clonePending(source pendingState) pendingState {
	result := source
	result.Work = append([]WorkObservation(nil), source.Work...)
	result.Ties = append([]TieObservation(nil), source.Ties...)
	return result
}

func (collector *Collector) clusterCountLocked() int {
	clusters := make(map[types.Hash]struct{}, len(collector.clusterIDs))
	for identifier := range collector.clusterIDs {
		clusters[identifier] = struct{}{}
	}
	for _, observation := range collector.pending.Work {
		clusters[observation.ClusterID] = struct{}{}
	}
	return len(clusters)
}

func sortClusterWork(clusters []ClusterWork) {
	sort.Slice(clusters, func(left, right int) bool {
		return types.CompareHash(clusters[left].ID, clusters[right].ID) < 0
	})
}
