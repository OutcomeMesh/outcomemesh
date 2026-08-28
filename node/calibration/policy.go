package calibration

import (
	"errors"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	ClusterPolicyVersion0     uint16 = 0
	MaximumPolicyAssignments         = 65_536
	MaximumClusterPolicyBytes        = 5 * 1024 * 1024
	clusterPolicyIDDomain            = "OMESH/testnet/calibration/cluster-policy/id/v0"
)

var ErrClusterPolicy = errors.New("invalid calibration cluster policy")

type MinerClusterAssignment struct {
	Miner     types.Address
	ClusterID types.Hash
}

// ClusterPolicy maps known payout addresses to coordination clusters and puts
// every unknown address into one explicit conservative catch-all cluster.
// Changing any assignment, catch-all, or comparison budget changes the ID and
// therefore requires a new observation window.
type ClusterPolicy struct {
	comparisonBudget uint32
	unknownCluster   types.Hash
	assignments      []MinerClusterAssignment
}

func NewClusterPolicy(
	comparisonBudget uint32,
	unknownCluster types.Hash,
	assignments []MinerClusterAssignment,
) (*ClusterPolicy, error) {
	if comparisonBudget == 0 || comparisonBudget > MaximumClusters || unknownCluster.IsZero() ||
		len(assignments) > MaximumPolicyAssignments {
		return nil, ErrClusterPolicy
	}
	canonical := append([]MinerClusterAssignment(nil), assignments...)
	sort.Slice(canonical, func(left, right int) bool {
		return types.CompareAddress(canonical[left].Miner, canonical[right].Miner) < 0
	})
	clusters := map[types.Hash]struct{}{unknownCluster: {}}
	for index, assignment := range canonical {
		if assignment.Miner.IsZero() || assignment.ClusterID.IsZero() ||
			(index > 0 && canonical[index-1].Miner == assignment.Miner) {
			return nil, ErrClusterPolicy
		}
		clusters[assignment.ClusterID] = struct{}{}
	}
	if len(clusters) > int(comparisonBudget) {
		return nil, ErrClusterPolicy
	}
	return &ClusterPolicy{
		comparisonBudget: comparisonBudget,
		unknownCluster:   unknownCluster,
		assignments:      canonical,
	}, nil
}

func (policy *ClusterPolicy) ID() (types.Hash, error) {
	encoded, err := policy.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(clusterPolicyIDDomain, encoded), nil
}

func (policy *ClusterPolicy) Cluster(miner types.Address) (types.Hash, error) {
	if policy == nil || miner.IsZero() {
		return types.Hash{}, ErrClusterPolicy
	}
	index := sort.Search(len(policy.assignments), func(index int) bool {
		return types.CompareAddress(policy.assignments[index].Miner, miner) >= 0
	})
	if index < len(policy.assignments) && policy.assignments[index].Miner == miner {
		return policy.assignments[index].ClusterID, nil
	}
	return policy.unknownCluster, nil
}

func (policy *ClusterPolicy) ComparisonBudget() uint32 {
	if policy == nil {
		return 0
	}
	return policy.comparisonBudget
}

func (policy *ClusterPolicy) CanonicalBytes() ([]byte, error) {
	if policy == nil || policy.comparisonBudget == 0 || policy.comparisonBudget > MaximumClusters ||
		policy.unknownCluster.IsZero() || len(policy.assignments) > MaximumPolicyAssignments {
		return nil, ErrClusterPolicy
	}
	encoder := codec.NewEncoder(48 + len(policy.assignments)*64)
	encoder.U16(ClusterPolicyVersion0)
	encoder.U32(policy.comparisonBudget)
	encoder.Fixed(policy.unknownCluster[:])
	encoder.Uvarint(uint64(len(policy.assignments)))
	for index, assignment := range policy.assignments {
		if assignment.Miner.IsZero() || assignment.ClusterID.IsZero() ||
			(index > 0 && types.CompareAddress(policy.assignments[index-1].Miner, assignment.Miner) >= 0) {
			return nil, ErrClusterPolicy
		}
		encoder.Fixed(assignment.Miner[:])
		encoder.Fixed(assignment.ClusterID[:])
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumClusterPolicyBytes {
		return nil, ErrClusterPolicy
	}
	return encoded, nil
}
