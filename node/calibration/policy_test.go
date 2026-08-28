package calibration

import (
	"bytes"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestClusterPolicyCanonicalMappingAndGoldenID(t *testing.T) {
	unknown := types.DomainHash("test/calibration/policy/unknown")
	minerA := types.Address(types.DomainHash("test/calibration/policy/miner-a"))
	minerB := types.Address(types.DomainHash("test/calibration/policy/miner-b"))
	clusterA := types.DomainHash("test/calibration/policy/cluster-a")
	clusterB := types.DomainHash("test/calibration/policy/cluster-b")
	policy, err := NewClusterPolicy(8, unknown, []MinerClusterAssignment{
		{Miner: minerB, ClusterID: clusterB},
		{Miner: minerA, ClusterID: clusterA},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := policy.Cluster(minerA); got != clusterA {
		t.Fatalf("miner A cluster=%s", got)
	}
	if got, _ := policy.Cluster(types.Address(types.DomainHash("test/calibration/policy/new-miner"))); got != unknown {
		t.Fatalf("unknown cluster=%s", got)
	}
	reordered, err := NewClusterPolicy(8, unknown, []MinerClusterAssignment{
		{Miner: minerA, ClusterID: clusterA},
		{Miner: minerB, ClusterID: clusterB},
	})
	if err != nil {
		t.Fatal(err)
	}
	left, _ := policy.CanonicalBytes()
	right, _ := reordered.CanonicalBytes()
	if !bytes.Equal(left, right) {
		t.Fatal("policy input order changed canonical bytes")
	}
	identifier, err := policy.ID()
	if err != nil {
		t.Fatal(err)
	}
	const wantID = "be78271d3afa7ac6898167adf64fb020c1d137008c22a2d7e3a7dd79e96cc8de"
	if identifier.String() != wantID {
		t.Fatalf("policy ID=%s, want %s", identifier, wantID)
	}
}

func TestClusterPolicyRejectsAmbiguityAndBudgetOverflow(t *testing.T) {
	unknown := types.DomainHash("test/calibration/policy/reject-unknown")
	miner := types.Address(types.DomainHash("test/calibration/policy/reject-miner"))
	clusterA := types.DomainHash("test/calibration/policy/reject-a")
	clusterB := types.DomainHash("test/calibration/policy/reject-b")
	tests := [][]MinerClusterAssignment{
		{{Miner: miner, ClusterID: clusterA}, {Miner: miner, ClusterID: clusterA}},
		{{Miner: types.Address{}, ClusterID: clusterA}},
		{{Miner: miner, ClusterID: types.Hash{}}},
	}
	for index, assignments := range tests {
		if _, err := NewClusterPolicy(8, unknown, assignments); !errors.Is(err, ErrClusterPolicy) {
			t.Fatalf("case %d error=%v", index, err)
		}
	}
	if _, err := NewClusterPolicy(1, unknown, []MinerClusterAssignment{{Miner: miner, ClusterID: clusterB}}); !errors.Is(err, ErrClusterPolicy) {
		t.Fatalf("budget overflow error=%v", err)
	}
}
