package calibration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const testStartedAt uint64 = 1_800_000_000

func TestRecordCanonicalRoundTripAndGoldenID(t *testing.T) {
	records, binding := testChain(t)
	first := records[0]
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRecord(first.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.CanonicalBytes(), first.CanonicalBytes()) {
		t.Fatal("record changed during canonical round trip")
	}
	if decoded.Binding() != binding {
		t.Fatalf("decoded binding = %+v, want %+v", decoded.Binding(), binding)
	}
	identifier, err := decoded.ID()
	if err != nil {
		t.Fatal(err)
	}
	const wantID = "446f5625a105483b837caeebe112d5e926930e2ca72a582e285203cb2b6d036a"
	if identifier.String() != wantID {
		t.Fatalf("record ID = %s, want %s", identifier, wantID)
	}
}

func TestManifestAggregatesContinuousIntervals(t *testing.T) {
	records, binding := testChain(t)
	aggregate, err := ValidateManifest(records, binding)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.RecordCount != 2 || aggregate.StartedAt != testStartedAt ||
		aggregate.EndedAt != testStartedAt+2*MaximumIntervalSeconds ||
		aggregate.ControlledTieAdoptions != 3 || aggregate.ControlledTieTrials != 10 ||
		aggregate.ObservedWork != 20 || aggregate.LargestCoordinatedWork != 15 ||
		len(aggregate.Clusters) != 2 || aggregate.FirstRecordID.IsZero() || aggregate.LastRecordID.IsZero() {
		t.Fatalf("aggregate = %+v", aggregate)
	}
	if aggregate.Clusters[0].Work+aggregate.Clusters[1].Work != aggregate.ObservedWork {
		t.Fatalf("cluster totals = %+v", aggregate.Clusters)
	}
	if types.CompareHash(aggregate.Clusters[0].ID, aggregate.Clusters[1].ID) >= 0 {
		t.Fatalf("aggregate cluster order = %+v", aggregate.Clusters)
	}
}

func TestRecordRejectsMutationAndMalformedCounters(t *testing.T) {
	records, _ := testChain(t)
	mutated := records[0]
	mutated.Clusters = append([]ClusterWork(nil), mutated.Clusters...)
	mutated.Clusters[0].Work++
	mutated.ObservedWork++
	if err := mutated.Validate(); !errors.Is(err, ErrSignature) {
		t.Fatalf("signed mutation error = %v, want ErrSignature", err)
	}

	base := unsignedTestRecord(testKey(), testBinding(testKey()), 1, testStartedAt, types.Hash{})
	base.EndedAt = base.StartedAt + MaximumIntervalSeconds + 1
	if _, err := Sign(testKey(), base); !errors.Is(err, ErrInterval) {
		t.Fatalf("long interval error = %v", err)
	}
	base = unsignedTestRecord(testKey(), testBinding(testKey()), 1, testStartedAt, types.Hash{})
	base.ControlledTieAdoptions = base.ControlledTieTrials + 1
	if _, err := Sign(testKey(), base); !errors.Is(err, ErrCounters) {
		t.Fatalf("tie counters error = %v", err)
	}
	base = unsignedTestRecord(testKey(), testBinding(testKey()), 1, testStartedAt, types.Hash{})
	base.ObservedWork++
	if _, err := Sign(testKey(), base); !errors.Is(err, ErrCounters) {
		t.Fatalf("work accounting error = %v", err)
	}
	base = unsignedTestRecord(testKey(), testBinding(testKey()), 1, testStartedAt, types.Hash{})
	base.Clusters[0], base.Clusters[1] = base.Clusters[1], base.Clusters[0]
	if _, err := Sign(testKey(), base); !errors.Is(err, ErrClusters) {
		t.Fatalf("cluster order error = %v", err)
	}
}

func TestRecordDecodeRejectsVersionTrailingAndLimit(t *testing.T) {
	records, _ := testChain(t)
	encoded := records[0].CanonicalBytes()
	unknown := append([]byte(nil), encoded...)
	unknown[1] = 1
	if _, err := DecodeRecord(unknown); !errors.Is(err, ErrVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
	if _, err := DecodeRecord(append(encoded, 0)); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing record error = %v", err)
	}
	if _, err := DecodeRecord(make([]byte, MaximumRecordBytes+1)); !errors.Is(err, ErrRecordLimit) {
		t.Fatalf("oversize record error = %v", err)
	}
}

func TestManifestRejectsBrokenChainAndBinding(t *testing.T) {
	records, binding := testChain(t)
	foreign := binding
	foreign.NetworkID++
	if _, err := ValidateManifest(records, foreign); !errors.Is(err, ErrBinding) {
		t.Fatalf("foreign binding error = %v", err)
	}

	broken := append([]Record(nil), records...)
	broken[1].StartedAt++
	broken[1].EndedAt++
	broken[1], _ = Sign(testKey(), broken[1])
	if _, err := ValidateManifest(broken, binding); !errors.Is(err, ErrInterval) {
		t.Fatalf("interval gap error = %v", err)
	}

	broken = append([]Record(nil), records...)
	broken[1].PreviousID = types.DomainHash("test/calibration/wrong-previous")
	broken[1], _ = Sign(testKey(), broken[1])
	if _, err := ValidateManifest(broken, binding); !errors.Is(err, ErrPrevious) {
		t.Fatalf("previous link error = %v", err)
	}

	broken = append([]Record(nil), records...)
	broken[1].Sequence++
	broken[1], _ = Sign(testKey(), broken[1])
	if _, err := ValidateManifest(broken, binding); !errors.Is(err, ErrSequence) {
		t.Fatalf("sequence gap error = %v", err)
	}
}

func TestManifestRejectsClusterBudgetExpansionAndOverflow(t *testing.T) {
	key := testKey()
	binding := testBinding(key)
	binding.ClusterComparisonBudget = 1
	first := unsignedTestRecord(key, binding, 1, testStartedAt, types.Hash{})
	first.Clusters = first.Clusters[:1]
	first.ObservedWork = first.Clusters[0].Work
	first, err := Sign(key, first)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := first.ID()
	second := unsignedTestRecord(key, binding, 2, first.EndedAt, firstID)
	second.Clusters = []ClusterWork{{ID: types.DomainHash("test/calibration/cluster-c"), Work: 1}}
	second.ObservedWork = 1
	second, err = Sign(key, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateManifest([]Record{first, second}, binding); !errors.Is(err, ErrClusters) {
		t.Fatalf("expanded cluster family error = %v", err)
	}

	overflowFirst := unsignedTestRecord(key, binding, 1, testStartedAt, types.Hash{})
	overflowFirst.Clusters = []ClusterWork{{ID: first.Clusters[0].ID, Work: ^uint64(0)}}
	overflowFirst.ObservedWork = ^uint64(0)
	overflowFirst, err = Sign(key, overflowFirst)
	if err != nil {
		t.Fatal(err)
	}
	overflowID, _ := overflowFirst.ID()
	overflowSecond := unsignedTestRecord(key, binding, 2, overflowFirst.EndedAt, overflowID)
	overflowSecond.Clusters = []ClusterWork{{ID: first.Clusters[0].ID, Work: 1}}
	overflowSecond.ObservedWork = 1
	overflowSecond, err = Sign(key, overflowSecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateManifest([]Record{overflowFirst, overflowSecond}, binding); !errors.Is(err, ErrCounters) {
		t.Fatalf("aggregate overflow error = %v", err)
	}
}

func FuzzDecodeRecordNeverPanics(f *testing.F) {
	records, _ := testChain(f)
	f.Add(records[0].CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		record, err := DecodeRecord(input)
		if err == nil {
			_ = record.Validate()
		}
	})
}

func testChain(t testing.TB) ([]Record, Binding) {
	t.Helper()
	key := testKey()
	binding := testBinding(key)
	first, err := Sign(key, unsignedTestRecord(key, binding, 1, testStartedAt, types.Hash{}))
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := first.ID()
	if err != nil {
		t.Fatal(err)
	}
	secondUnsigned := unsignedTestRecord(key, binding, 2, first.EndedAt, firstID)
	secondUnsigned.ControlledTieAdoptions = 2
	secondUnsigned.ControlledTieTrials = 6
	secondUnsigned.Clusters[0].Work = 2
	secondUnsigned.Clusters[1].Work = 8
	second, err := Sign(key, secondUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	return []Record{first, second}, binding
}

func unsignedTestRecord(_ ed25519.PrivateKey, binding Binding, sequence, startedAt uint64, previous types.Hash) Record {
	clusters := []ClusterWork{
		{ID: types.DomainHash("test/calibration/cluster-a"), Work: 7},
		{ID: types.DomainHash("test/calibration/cluster-b"), Work: 3},
	}
	slices.SortFunc(clusters, func(left, right ClusterWork) int { return types.CompareHash(left.ID, right.ID) })
	return Record{
		Version: Version0, NetworkID: binding.NetworkID, GenesisID: binding.GenesisID,
		ActivationHeight: binding.ActivationHeight, ClusterPolicyID: binding.ClusterPolicyID,
		ClusterComparisonBudget: binding.ClusterComparisonBudget,
		Sequence:                sequence, StartedAt: startedAt, EndedAt: startedAt + MaximumIntervalSeconds,
		PreviousID: previous, ControlledTieAdoptions: 1, ControlledTieTrials: 4,
		ObservedWork: 10, Clusters: clusters,
	}
}

func testKey() ed25519.PrivateKey {
	seed := types.DomainHash("test/calibration/observer-key/v0")
	return ed25519.NewKeyFromSeed(seed[:])
}

func testBinding(key ed25519.PrivateKey) Binding {
	result := Binding{
		NetworkID: 91, GenesisID: types.DomainHash("test/calibration/genesis"),
		ActivationHeight: 25, ClusterPolicyID: types.DomainHash("test/calibration/cluster-policy/v0"),
		ClusterComparisonBudget: 8,
	}
	copy(result.ObserverPublicKey[:], key.Public().(ed25519.PublicKey))
	return result
}
