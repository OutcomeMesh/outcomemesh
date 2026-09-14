package store

import (
	"bytes"
	"context"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// LineageID explicitly opts the protected configuration into complete renewal
// verification. The initial-only ID is never silently reinterpreted. The request
// pins the selected availability bundle, whose receipts hash-link their proofs
// and predecessors; assignments already commit the initial receipts and policy.
func (policy ArchivePrunePolicy) LineageID() (types.Hash, error) {
	id, err := policy.ID()
	if err != nil {
		return types.Hash{}, err
	}
	e := codec.NewEncoder(64)
	e.U16(0)
	e.Fixed(id[:])
	e.U32(workarchive.MaximumReceiptLineageEntries)
	e.U64(workarchive.MaximumReceiptLineageBytes)
	return types.DomainHash("OMESH/custody-prune/archive-lineage-policy/v0", e.Bytes()), nil
}

// ExecuteArchiveWithLineage has ExecuteArchive's ownership and failure rules,
// but requires a separate LineageID pin and one complete historical prefix per
// selected assignment (including an empty prefix for an initial receipt).
// It holds all current authority guards while verifying lineage, replaying the
// replicas and committing the effect/result. Historical evidence never grants
// live authority, establishes a latest journal head or completes any ticket.
func (executor *PruneExecutor) ExecuteArchiveWithLineage(ctx context.Context, chain *workchain.Store,
	policy ArchivePrunePolicy, expectedPolicyID types.Hash, operations []RequiredOperation,
	replicas []workarchive.Replica, lineages []workarchive.CustodyReceiptLineage,
	availabilityPath string, base workchain.Base, parameters workblock.Parameters, limits workarchive.Limits,
) (workchain.CanonicalPruneCommit, error) {
	return executor.executeArchive(ctx, chain, policy, expectedPolicyID, operations, replicas, lineages, true, availabilityPath, base, parameters, limits, nil)
}

// Check a single aggregate budget before copying any large caller buffers.
// Reorder by the already pinned assignment list, never by a mutable owner head.
func detachArchiveLineages(ctx context.Context, lineages []workarchive.CustodyReceiptLineage, assignments []custodyauthority.Assignment) ([]workarchive.CustodyReceiptLineage, error) {
	if len(lineages) != len(assignments) || len(lineages) > workarchive.MaximumReplicas {
		return nil, workarchive.ErrReceiptLineage
	}
	remainingBytes, remainingEntries := workarchive.MaximumReceiptLineageBytes, workarchive.MaximumReceiptLineageEntries
	byID := make(map[types.Hash]workarchive.CustodyReceiptLineage, len(lineages))
	for _, lineage := range lineages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, exists := byID[lineage.AssignmentID]; exists || lineage.AssignmentID.IsZero() ||
			len(lineage.Policy.TrustedAuditors) > custodyauthority.MaximumMembers || len(lineage.Manifest) == 0 ||
			len(lineage.Manifest) > workarchive.MaximumManifestBytes || len(lineage.Manifest) > remainingBytes || len(lineage.Entries) > remainingEntries {
			return nil, workarchive.ErrReceiptLineage
		}
		remainingEntries -= len(lineage.Entries)
		remainingBytes -= len(lineage.Manifest)
		for _, encoded := range lineage.Entries {
			if len(encoded) == 0 || len(encoded) > workarchive.MaximumCustodyJournalEntryBytes || len(encoded) > remainingBytes {
				return nil, workarchive.ErrReceiptLineage
			}
			remainingBytes -= len(encoded)
		}
		byID[lineage.AssignmentID] = lineage
	}
	result := make([]workarchive.CustodyReceiptLineage, len(assignments))
	for i, assignment := range assignments {
		id, _ := assignment.ID()
		lineage, found := byID[id]
		if !found {
			return nil, workarchive.ErrReceiptLineage
		}
		lineage.Manifest = bytes.Clone(lineage.Manifest)
		lineage.Policy.TrustedAuditors = append([][32]byte(nil), lineage.Policy.TrustedAuditors...)
		entries := make([][]byte, len(lineage.Entries))
		for j, encoded := range lineage.Entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			entries[j] = bytes.Clone(encoded)
		}
		lineage.Entries = entries
		result[i] = lineage
	}
	return result, ctx.Err()
}
