package store

import (
	"context"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// CompletePreparedArchiveSecondary explicitly submits one externally signed and
// co-signed secondary Complete entry using this executor's confirmed outcome.
// Success requires the exact inventory-bound start and retained effect. A
// pre-start cancellation uses its original request, primary ticket and executor
// binding; it does not acquire an inventory binding retroactively.
//
// The inventory must match both independent pins and contain the exact primary
// admission plus the target's actually admitted secondary ticket. EvidenceID is
// the existing effect/cancellation ID. Started and unconfirmed transitions cannot
// complete. The executor and target coordinator guards stay held through package
// re-sync and authority intent, decision and independent confirmation.
//
// Call separately for each secondary. Exact retries reconcile retained attempts
// or return history after completion/retirement. An unrelated pending attempt
// blocks this call. It neither signs, refreshes a head, changes executor history,
// queries WorkChain, replays replicas nor executes pruning. The primary owner and
// other secondaries need not be open; each keeps its own explicit completion.
// Preserve the inventory, pins and independently protected owner roots under the
// trusted exclusive-owner contract. This local adapter is not a remote outcome
// certificate or proof that copied owners have drained.
func (executor *PruneExecutor) CompletePreparedArchiveSecondary(ctx context.Context, secondary *Coordinator,
	inventoryPath string, expectedInventoryID, expectedPolicyID types.Hash, entry custodyauthority.Entry,
) (Commit, error) {
	if executor == nil || secondary == nil {
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
	binding, err := executor.archiveSecondaryCompletion(inventory, expectedInventoryID, entry)
	if err != nil {
		return Commit{}, err
	}
	if secondary.assignmentID != binding.AssignmentID {
		return Commit{}, custodyauthority.ErrAssignment
	}
	secondary.mu.Lock()
	defer secondary.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	current, err := secondary.snapshot()
	if err != nil {
		return Commit{}, err
	}
	if current.Pending != nil && *current.Pending != entry {
		return Commit{}, ErrPendingAttempt
	}
	// A packaged co-signature alone does not prove admission. The same full
	// operation must exist in the actual local history, even during exact retry.
	found := false
	completionID, _ := entry.ID() // signature and shape checked above
	for _, operation := range current.Authority.Operations {
		if operation.TicketID == binding.TicketID && operation.OperationID == binding.OperationID &&
			operation.ConsumerPublicKey == binding.ConsumerPublicKey && operation.Purpose == binding.Purpose {
			if !operation.CompletionID.IsZero() && (operation.CompletionID != completionID || operation.EvidenceID != entry.Command.EvidenceID) {
				return Commit{}, ErrPruneCompletion
			}
			found = true
			break
		}
	}
	if !found {
		return Commit{}, custodyauthority.ErrOperation
	}
	roots := []string{executor.path, executor.pins.path, secondary.authority.path, secondary.journal.path, filepath.Dir(path)}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return Commit{}, err
			}
		}
	}
	if err := executor.hooks.reach("archive-secondary-complete-before-inventory-sync"); err != nil {
		return Commit{}, err
	}
	if err := syncArchivePruneInventory(path, encoded, storeHooks{}); err != nil {
		return Commit{}, err
	}
	if err := executor.hooks.reach("archive-secondary-complete-inventory-synced"); err != nil {
		return Commit{}, err
	}
	result, err := secondary.append(ctx, entry)
	if err != nil {
		return Commit{}, err
	}
	return result, nil
}

// Requires the healthy, fully confirmed executor lock. No state is submitted.
func (executor *PruneExecutor) archiveSecondaryCompletion(inventory ArchivePruneInventory, inventoryID types.Hash,
	entry custodyauthority.Entry,
) (OperationBinding, error) {
	if executor.pins == nil {
		return OperationBinding{}, ErrPrunePin
	}
	if executor.request.StorageID.IsZero() || executor.admission == nil ||
		inventory.Policy.RequestID != executor.id || inventory.Policy.ExecutorBindingID != executor.pins.binding {
		return OperationBinding{}, ErrPruneInventory
	}
	var evidence types.Hash
	var err error
	switch executor.stage {
	case PruneSucceeded:
		if executor.archiveInventoryID != inventoryID || executor.effect == nil ||
			!pruneEffectMatches(executor.request, *executor.admission, *executor.effect) {
			return OperationBinding{}, ErrPruneInventory
		}
		evidence, err = executor.effect.ID()
	case PruneCancelled:
		if executor.cancellation == nil || !executor.archiveInventoryID.IsZero() ||
			!cancellationMatches(executor.execution(), *executor.cancellation) ||
			executor.cancellation.BindingID != executor.pins.binding {
			return OperationBinding{}, ErrPruneCompletion
		}
		evidence, err = executor.cancellation.ID()
	case PruneStarted:
		return OperationBinding{}, ErrPruneOutcome
	default:
		return OperationBinding{}, ErrPruneStage
	}
	if err != nil {
		return OperationBinding{}, err
	}
	if _, err := entry.CanonicalBytes(); err != nil {
		return OperationBinding{}, err
	}
	command := entry.Command
	if command.Kind != custodyauthority.Complete || command.AssignmentID == executor.request.AssignmentID || command.EvidenceID != evidence {
		return OperationBinding{}, ErrPruneCompletion
	}
	primaryFound, secondaryFound := false, false
	var binding OperationBinding
	for _, admission := range inventory.Admissions {
		if admission == *executor.admission {
			primaryFound = true
		}
		c := admission.Command
		if c.AssignmentID == command.AssignmentID {
			ticket, _ := admission.ID() // independently pinned inventory is validated
			if command.TicketID != ticket || command.ActorPublicKey != c.ActorPublicKey || entry.AuthorityPublicKey != admission.AuthorityPublicKey {
				return OperationBinding{}, ErrPruneCompletion
			}
			binding = OperationBinding{AssignmentID: c.AssignmentID, TicketID: ticket, ConsumerPublicKey: c.ActorPublicKey,
				OperationID: c.OperationID, Purpose: c.Purpose}
			secondaryFound = true
		}
	}
	if !primaryFound || !secondaryFound {
		return OperationBinding{}, ErrPruneInventory
	}
	return binding, nil
}
