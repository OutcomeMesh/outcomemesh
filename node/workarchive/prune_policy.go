package workarchive

import (
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

// PrunePolicyID identifies exact checkpoint, trust/quorum and receipt-time policy
// for independently pinned local configuration. It is not a live authority grant.
// Trusted key sets must already be in canonical order; no quorum is inferred.
func PrunePolicyID(checkpoint Checkpoint, policy Policy, replicas ReplicaPolicy) (types.Hash, error) {
	if err := checkpoint.Verify(policy); err != nil {
		return types.Hash{}, err
	}
	if err := replicas.validate(); err != nil {
		return types.Hash{}, err
	}
	encoded, err := checkpoint.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	e := codec.NewEncoder(MaximumCheckpointBytes + 2*MaximumReplicas*32 + 64)
	e.U16(0)
	e.BytesField(encoded) // the statement already includes the exact policy binding
	e.U16(policy.RequiredAttestations)
	e.U16(uint16(len(policy.TrustedAttestors)))
	for _, key := range policy.TrustedAttestors {
		e.Fixed(key[:])
	}
	e.U16(replicas.RequiredReplicas)
	e.U64(replicas.MaximumReceiptAge)
	e.U64(replicas.MinimumRemainingTerm)
	e.U16(uint16(len(replicas.TrustedReplicas)))
	for _, key := range replicas.TrustedReplicas {
		e.Fixed(key[:])
	}
	return types.DomainHash("OMESH/workgraph/archive/prune-policy/v0", e.Bytes()), nil
}
