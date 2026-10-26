package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// These values are detached from a bounded file load, not caller-owned slices.
type archiveInventoryInput struct {
	path     string
	id       types.Hash
	encoded  []byte
	prepared ArchivePruneInventory
	// Owned effect runtimes compare a detached local review while the executor
	// and every original coordinator are held. These callbacks are private,
	// synchronous and may not re-enter any owner.
	reviewCheck      func() error
	beforeStartCheck func() error
}

func requireNoInventoryEffect(chain *workchain.Store, ticketID types.Hash) error {
	_, found, err := chain.CanonicalPruneEffect(ticketID)
	if err != nil || found {
		return errors.Join(ErrPruneInventory, err)
	}
	return nil
}

// ExecutePreparedArchive is opt-in colocated library execution of one previously
// retained, independently pinned inventory. Its mode chooses the existing full
// archive/lineage verifier; every EXACT historical ticket must still be pending
// under its original owner. A matching package is not itself live authority.
// The package parent must be dedicated and disjoint from all owned/evidence/
// replica roots. Preserve the package, external pins and owner roots for review.
// A version-1 Started record binds the inventory in both executor journals before
// the effect; Started still cannot be retried or reclassified as no-effect.
func (executor *PruneExecutor) ExecutePreparedArchive(ctx context.Context, chain *workchain.Store,
	inventoryPath string, expectedInventoryID, expectedPolicyID types.Hash, operations []RequiredOperation,
	replicas []workarchive.Replica, lineages []workarchive.CustodyReceiptLineage,
	availabilityPath string, base workchain.Base, parameters workblock.Parameters, limits workarchive.Limits,
) (workchain.CanonicalPruneCommit, error) {
	if executor == nil {
		return workchain.CanonicalPruneCommit{}, ErrClosed
	}
	if ctx == nil {
		return workchain.CanonicalPruneCommit{}, ErrPruneInventory
	}
	if err := ctx.Err(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	path, err := storePath(inventoryPath)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	prepared, err := LoadArchivePruneInventoryFile(path, expectedInventoryID, expectedPolicyID)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if prepared.Mode == ArchivePruneInitial && len(lineages) != 0 {
		return workchain.CanonicalPruneCommit{}, ErrPruneInventory
	}
	encoded, err := prepared.CanonicalBytes()
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	input := &archiveInventoryInput{path: path, id: expectedInventoryID, encoded: encoded, prepared: prepared}
	return executor.executeArchive(ctx, chain, prepared.Policy, expectedPolicyID, operations, replicas, lineages,
		prepared.Mode == ArchivePruneLineage, availabilityPath, base, parameters, limits, input)
}

// Called under the executor lock before lineage copying or archive I/O. Never
// obtain secondary operation IDs by rewriting the original primary request.
func (input *archiveInventoryInput) checkOperations(executor *PruneExecutor, operations []RequiredOperation, replicas []workarchive.Replica) error {
	p := input.prepared
	if p.Policy.RequestID != executor.id || len(operations) != len(p.Admissions) || len(replicas) != len(p.Availability.Receipts) {
		return ErrPruneInventory
	}
	for i, entry := range p.Admissions {
		ticket, _ := entry.ID()
		c := entry.Command
		want := OperationBinding{AssignmentID: c.AssignmentID, TicketID: ticket, ConsumerPublicKey: c.ActorPublicKey,
			OperationID: c.OperationID, Purpose: custodyauthority.Prune}
		matches, receiptMatches := 0, 0
		for _, operation := range operations {
			if operation.Binding == want {
				matches++
			}
		}
		for _, replica := range replicas {
			if replica.Receipt == p.Availability.Receipts[i] {
				receiptMatches++
			}
		}
		if matches != 1 || receiptMatches != 1 || (c.AssignmentID == executor.request.AssignmentID &&
			(executor.admission == nil || *executor.admission != entry)) {
			return ErrPruneInventory
		}
	}
	return nil
}

// InspectArchiveInventory reads historical LOCAL provenance from this owner and
// the externally pinned retained package. It neither executes nor resolves work,
// replays replicas, verifies lineage bodies or authorizes completion. Pending
// transitions must be explicitly recovered first. Started is not success; only
// Succeeded includes the independently confirmed exact executor effect record.
// An old unbound start/result can never be upgraded by supplying a package later.
func (executor *PruneExecutor) InspectArchiveInventory(inventoryPath string, expectedInventoryID, expectedPolicyID types.Hash) (PruneExecution, error) {
	if executor == nil {
		return PruneExecution{}, ErrClosed
	}
	prepared, err := LoadArchivePruneInventoryFile(inventoryPath, expectedInventoryID, expectedPolicyID)
	if err != nil {
		return PruneExecution{}, err
	}
	state, err := executor.Snapshot()
	if err != nil {
		return PruneExecution{}, err
	}
	if state.Protection == nil {
		return PruneExecution{}, ErrPruneInventory
	}
	if state.Protection.Pending != nil {
		return PruneExecution{}, ErrPrunePinPending
	}
	if state.ArchiveInventoryID != expectedInventoryID || state.RequestID != prepared.Policy.RequestID ||
		state.Protection.BindingID != prepared.Policy.ExecutorBindingID || state.Protection.Confirmed.Stage != state.Stage ||
		(state.Stage != PruneStarted && state.Stage != PruneSucceeded) || state.Admission == nil {
		return PruneExecution{}, ErrPruneInventory
	}
	for _, admission := range prepared.Admissions {
		if admission.Command.AssignmentID == state.Request.AssignmentID {
			if admission != *state.Admission {
				return PruneExecution{}, ErrPruneInventory
			}
			return state, nil
		}
	}
	return PruneExecution{}, errors.Join(ErrPruneInventory, custodyauthority.ErrAssignment)
}
