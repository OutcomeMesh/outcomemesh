package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// ArchivePruneLineageSource selects an existing journal and the independently
// reviewed journal-only checkpoint. AssignmentID selects its pinned inventory
// entry; callers cannot substitute an assignment or selected terminal receipt.
// Manifest, initial receipt and custody policy must reconstruct that assignment.
type ArchivePruneLineageSource struct {
	AssignmentID   types.Hash
	JournalPath    string
	Checkpoint     workarchive.CustodyCheckpoint
	CheckpointID   types.Hash
	Manifest       []byte
	InitialReceipt workarchive.ReplicaReceipt
	Policy         workarchive.CustodyPolicy
}

// ExtractArchivePruneLineageEvidence reads one exact historical prefix per
// independently pinned LINEAGE inventory assignment, in inventory order. All
// source journals remain locked through source verification and copying; missing or
// changed sources are never created, repaired or resumed. The aggregate budget
// applies before output body copies, including empty initial-receipt prefixes.
//
// The result uses the existing evidence format and independent ID. This neither
// opens an executor/authority/database nor grants current Audit/Prune permission,
// attests a unique latest head or binds the evidence ID into a start record.
// Inputs and source directories must not be mutated outside their owner locks.
func ExtractArchivePruneLineageEvidence(ctx context.Context, inventory ArchivePruneInventory,
	expectedInventoryID, expectedPolicyID types.Hash, sources []ArchivePruneLineageSource,
) (ArchivePruneLineageEvidence, error) {
	if err := checkLineageEvidenceInventory(ctx, inventory, expectedInventoryID, expectedPolicyID); err != nil {
		return ArchivePruneLineageEvidence{}, err
	}
	if len(sources) != len(inventory.Policy.Assignments) || len(sources) > workarchive.MaximumReplicas {
		return ArchivePruneLineageEvidence{}, ErrPruneLineageEvidence
	}
	byID := make(map[types.Hash]ArchivePruneLineageSource, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return ArchivePruneLineageEvidence{}, err
		}
		if _, exists := byID[source.AssignmentID]; exists || source.AssignmentID.IsZero() {
			return ArchivePruneLineageEvidence{}, ErrPruneLineageEvidence
		}
		byID[source.AssignmentID] = source
	}
	ordered := make([]workarchive.CustodyReceiptLineageSource, len(sources))
	for i, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID() // inventory verification checked every assignment
		source, found := byID[id]
		if !found {
			return ArchivePruneLineageEvidence{}, ErrPruneLineageEvidence
		}
		ordered[i] = workarchive.CustodyReceiptLineageSource{
			JournalPath: source.JournalPath, Checkpoint: source.Checkpoint, CheckpointID: source.CheckpointID,
			Assignment: assignment, AssignmentID: id, Manifest: source.Manifest,
			InitialReceipt: source.InitialReceipt, Policy: source.Policy,
			SelectedReceipt: inventory.Availability.Receipts[i],
		}
	}
	lineages, err := workarchive.ExtractCustodyReceiptLineages(ctx, ordered)
	if err != nil {
		return ArchivePruneLineageEvidence{}, errors.Join(ErrPruneLineageEvidence, err)
	}
	// Extraction owns and verified these detached buffers in the pinned order.
	// Transfer them directly to the opaque result rather than clone another full
	// body budget; no intermediate output is exposed to the caller.
	return verifiedLineageEvidence(ctx, inventory, expectedInventoryID, expectedPolicyID, lineages)
}
