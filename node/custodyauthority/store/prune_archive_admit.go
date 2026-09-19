package store

import (
	"context"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// AdmitPreparedArchiveSecondary explicitly submits ONE exact, already co-signed
// secondary admission from a retained, independently pinned inventory. The
// primary request/admission must already be independently confirmed in this
// storage-bound executor. It never signs, chooses a head, rewrites the primary
// request for another assignment, admits a whole set, or starts/completes work.
//
// A FIRST secondary intent requires PruneAdmitted and a live pending primary
// ticket. The executor and both original coordinators stay locked through the
// secondary intent, decision and confirmation. Coordinators are locked in their
// immutable assignment-ID order, as in archive execution. Stopping primary work
// may drain; the secondary's own machine must still permit the signed admission.
//
// Exact retained secondary intents and historical decisions remain explicitly
// recoverable after the primary drains or the executor reaches a terminal state.
// This only resumes the old signed attempt or observes history; it cannot grant
// execution permission or prove prior API use. Pending executor transitions and
// unrelated secondary intents must be recovered separately.
// Errors may leave a retained intent/decision; do not replace it or infer absence.
// Commit.Appended can be true when a retained intent had not reached authority;
// it refers only to that decision, not execution authority.
//
// The inventory parent must be dedicated and disjoint from these six owner roots.
// All inputs/roots remain operator-controlled, with no raw/copied concurrent owner.
// This colocated library method neither owns the other secondary coordinators nor
// opens/checks WorkChain, replicas or lineage bodies. Execution still checks the
// entire required set, storage pins, placement, live policy and archive evidence.
func (executor *PruneExecutor) AdmitPreparedArchiveSecondary(ctx context.Context, primary, secondary *Coordinator,
	inventoryPath string, expectedInventoryID, expectedPolicyID types.Hash, entry custodyauthority.Entry,
) (Commit, error) {
	if executor == nil || primary == nil || secondary == nil {
		return Commit{}, ErrClosed
	}
	if ctx == nil {
		return Commit{}, ErrPruneInventory
	}
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	path, err := storePath(inventoryPath)
	if err != nil {
		return Commit{}, err
	}
	inventory, err := LoadArchivePruneInventoryFile(path, expectedInventoryID, expectedPolicyID)
	if err != nil {
		return Commit{}, err
	}
	encoded, err := inventory.CanonicalBytes()
	if err != nil {
		return Commit{}, err
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return Commit{}, err
	}
	if executor.pins == nil || executor.request.StorageID.IsZero() || executor.admission == nil ||
		inventory.Policy.RequestID != executor.id || inventory.Policy.ExecutorBindingID != executor.pins.binding ||
		(!executor.archiveInventoryID.IsZero() && executor.archiveInventoryID != expectedInventoryID) {
		return Commit{}, ErrPruneInventory
	}
	if primary == secondary || primary.assignmentID != executor.request.AssignmentID || secondary.assignmentID != entry.Command.AssignmentID ||
		secondary.assignmentID == primary.assignmentID {
		return Commit{}, custodyauthority.ErrAssignment
	}
	primaryMatch, secondaryMatch := false, false
	for _, admission := range inventory.Admissions {
		primaryMatch = primaryMatch || admission == *executor.admission
		secondaryMatch = secondaryMatch || admission == entry
	}
	if !primaryMatch || !secondaryMatch {
		return Commit{}, ErrPruneInventory
	}
	binding, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil {
		return Commit{}, err
	}
	ordered := [2]*Coordinator{primary, secondary}
	if types.CompareHash(ordered[0].assignmentID, ordered[1].assignmentID) > 0 {
		ordered[0], ordered[1] = ordered[1], ordered[0]
	}
	for _, owner := range ordered {
		if err := ctx.Err(); err != nil {
			return Commit{}, err
		}
		owner.mu.Lock()
		defer owner.mu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	// Both owners must be healthy. The primary may have a separately retained
	// attempt during historical retry; no such state can authorize a FIRST intent.
	if _, err := primary.snapshot(); err != nil {
		return Commit{}, err
	}
	current, err := secondary.snapshot()
	if err != nil {
		return Commit{}, err
	}
	roots := []string{executor.path, executor.pins.path, primary.authority.path, primary.journal.path,
		secondary.authority.path, secondary.journal.path, filepath.Dir(path)}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return Commit{}, err
			}
		}
	}
	if current.Pending != nil && *current.Pending != entry {
		return Commit{}, ErrPendingAttempt
	}
	retry := current.Pending != nil || entry.Command.ExpectedSequence < current.Confirmed.Sequence
	if !retry {
		if executor.stage == PruneStarted {
			return Commit{}, ErrPruneOutcome
		}
		if executor.stage != PruneAdmitted {
			return Commit{}, ErrPruneStage
		}
		if err := primary.checkOperation(binding); err != nil {
			return Commit{}, err
		}
	}
	if err := executor.hooks.reach("archive-secondary-before-inventory-sync"); err != nil {
		return Commit{}, err
	}
	// Re-read and sync the exact retained package under all three guards before
	// any secondary write. A missing or changed package is never reconstructed.
	if err := syncArchivePruneInventory(path, encoded, storeHooks{}); err != nil {
		return Commit{}, err
	}
	if err := executor.hooks.reach("archive-secondary-inventory-synced"); err != nil {
		return Commit{}, err
	}
	result, err := secondary.append(ctx, entry)
	if err != nil {
		return Commit{}, err // no partial result can acknowledge admission
	}
	return result, nil
}
