package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

var ErrPruneArchivePolicy = errors.New("prune requires exact independently pinned archive policy, assignments and storage pairs")

// ArchivePrunePolicy is protected local configuration, not a signed grant. Every
// selected replica must have exactly one independently pinned assignment; IDs
// cannot be discovered from peers or a mutable authority snapshot. Assignments
// are ordered by replica key. ExecuteArchive accepts exact INITIAL receipts only;
// the separate lineage mode requires its own policy pin and complete evidence.
type ArchivePrunePolicy struct {
	RequestID, ExecutorBindingID, StoragePairID types.Hash
	Checkpoint                                  workarchive.Checkpoint
	CheckpointPolicy                            workarchive.Policy
	ReplicaPolicy                               workarchive.ReplicaPolicy
	Assignments                                 []custodyauthority.Assignment
}

func (policy ArchivePrunePolicy) ID() (types.Hash, error) {
	archiveID, err := workarchive.PrunePolicyID(policy.Checkpoint, policy.CheckpointPolicy, policy.ReplicaPolicy)
	if err != nil || policy.RequestID.IsZero() || policy.ExecutorBindingID.IsZero() || policy.StoragePairID.IsZero() ||
		len(policy.Assignments) < int(policy.ReplicaPolicy.RequiredReplicas) || len(policy.Assignments) > workarchive.MaximumReplicas {
		return types.Hash{}, errors.Join(ErrPruneArchivePolicy, err)
	}
	e := codec.NewEncoder(256 + workarchive.MaximumReplicas*types.HashSize)
	e.U16(0)
	for _, id := range []types.Hash{policy.RequestID, policy.ExecutorBindingID, policy.StoragePairID, archiveID} {
		e.Fixed(id[:])
	}
	e.U16(uint16(len(policy.Assignments)))
	statementID, _ := policy.Checkpoint.Statement.ID()
	b := policy.CheckpointPolicy.Binding
	for i, a := range policy.Assignments {
		id, err := a.ID()
		if err != nil || a.NetworkID != b.NetworkID || a.GenesisID != b.GenesisID || a.ActivationHeight != b.ActivationHeight || a.BaseID != b.BaseID ||
			a.StatementID != statementID || a.ManifestID != policy.Checkpoint.Statement.ArchiveManifestID ||
			(i > 0 && bytes.Compare(policy.Assignments[i-1].ReplicaPublicKey[:], a.ReplicaPublicKey[:]) >= 0) {
			return types.Hash{}, ErrPruneArchivePolicy
		}
		trusted := false
		for _, key := range policy.ReplicaPolicy.TrustedReplicas {
			trusted = trusted || key == a.ReplicaPublicKey
		}
		if !trusted {
			return types.Hash{}, ErrPruneArchivePolicy
		}
		e.Fixed(id[:])
	}
	return types.DomainHash("OMESH/custody-prune/archive-acceptance-policy/v0", e.Bytes()), nil
}

// ExecuteArchive is opt-in, colocated library acceptance, not a CLI/remote effect
// API. It verifies the independently pinned policy and both storage pair pins,
// acquires EVERY required assignment guard, replays every selected replica,
// publishes exact evidence and executes the original retained request once.
// Lock order: executor -> coordinators sorted by assignment ID -> WorkChain.
// Inputs/replica directories must remain immutable for this synchronous call.
// No raw owner may be used concurrently outside the guarded runtime. No new
// admission, recovery, completion or successor assignment is inferred here.
func (executor *PruneExecutor) ExecuteArchive(ctx context.Context, chain *workchain.Store,
	policy ArchivePrunePolicy, expectedPolicyID types.Hash, operations []RequiredOperation,
	replicas []workarchive.Replica, availabilityPath string, base workchain.Base, parameters workblock.Parameters, limits workarchive.Limits,
) (workchain.CanonicalPruneCommit, error) {
	return executor.executeArchive(ctx, chain, policy, expectedPolicyID, operations, replicas, nil, false, availabilityPath, base, parameters, limits, nil)
}

func (executor *PruneExecutor) executeArchive(ctx context.Context, chain *workchain.Store,
	policy ArchivePrunePolicy, expectedPolicyID types.Hash, operations []RequiredOperation,
	replicas []workarchive.Replica, lineages []workarchive.CustodyReceiptLineage, requireLineage bool,
	availabilityPath string, base workchain.Base, parameters workblock.Parameters, limits workarchive.Limits,
	inventory *archiveInventoryInput,
) (workchain.CanonicalPruneCommit, error) {
	if executor == nil {
		return workchain.CanonicalPruneCommit{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if !executor.request.ScheduleID.IsZero() {
		return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
	}
	if ctx == nil {
		return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
	}
	if err := ctx.Err(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if len(operations) > workarchive.MaximumReplicas || len(replicas) > workarchive.MaximumReplicas {
		return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
	}
	// Detach bounded caller-owned slices before checking the pin or waiting for
	// other owners; later caller edits cannot change accepted trust policy.
	var err error
	policy, err = cloneArchivePrunePolicy(policy)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	operations = append([]RequiredOperation(nil), operations...)
	replicas = append([]workarchive.Replica(nil), replicas...)
	id, err := policy.ID()
	if requireLineage {
		id, err = policy.LineageID()
	}
	if err != nil || expectedPolicyID.IsZero() || id != expectedPolicyID || policy.RequestID != executor.id || executor.pins == nil ||
		executor.request.StorageID.IsZero() || policy.ExecutorBindingID != executor.pins.binding {
		return workchain.CanonicalPruneCommit{}, errors.Join(ErrPruneArchivePolicy, err)
	}
	// Repeated execution is not a historical query. Existing Recover/Snapshot
	// report terminal evidence separately; this path never relabels it as live.
	if executor.stage == PruneStarted {
		return workchain.CanonicalPruneCommit{}, ErrPruneOutcome
	}
	if executor.stage != PruneAdmitted {
		return workchain.CanonicalPruneCommit{}, ErrPruneStage
	}
	if inventory != nil {
		if err := inventory.checkOperations(executor, operations, replicas); err != nil {
			return workchain.CanonicalPruneCommit{}, err
		}
	}
	if requireLineage {
		lineages, err = detachArchiveLineages(ctx, lineages, policy.Assignments)
		if err != nil {
			return workchain.CanonicalPruneCommit{}, err
		}
	}
	primary, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil || len(operations) != len(policy.Assignments) || len(replicas) != len(policy.Assignments) {
		return workchain.CanonicalPruneCommit{}, errors.Join(ErrPruneArchivePolicy, err)
	}
	needed := make(map[types.Hash]bool, len(policy.Assignments))
	for _, assignment := range policy.Assignments {
		assignmentID, _ := assignment.ID()
		needed[assignmentID] = true
		matches := 0
		for _, replica := range replicas {
			receiptID, err := replica.Receipt.ID()
			initial := replica.Receipt.Version == workarchive.ReplicaReceiptVersion0 && receiptID == assignment.InitialReceiptID
			if err == nil && (initial || requireLineage) && replica.Receipt.ReplicaPublicKey == assignment.ReplicaPublicKey {
				matches++
			}
		}
		if matches != 1 {
			return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
		}
	}
	var primaryOwner *Coordinator
	for _, operation := range operations {
		b := operation.Binding
		if !needed[b.AssignmentID] || b.OperationID != executor.id || b.ConsumerPublicKey != executor.request.ConsumerPublicKey || b.Purpose != custodyauthority.Prune {
			return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
		}
		delete(needed, b.AssignmentID)
		if b.AssignmentID == primary.AssignmentID {
			if b != primary {
				return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
			}
			primaryOwner = operation.Coordinator
		}
	}
	if primaryOwner == nil {
		return workchain.CanonicalPruneCommit{}, ErrPruneArchivePolicy
	}
	var result workchain.CanonicalPruneCommit
	err = withRequiredOperations(ctx, operations, func() error {
		databasePath, storagePinsPath, err := chain.StorageRoots()
		if err != nil {
			return err
		}
		// Evidence has a dedicated existing directory, disjoint from every
		// owned root and replica. No publication can mutate a journal/DB layout.
		if info, err := os.Lstat(filepath.Dir(availabilityPath)); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(ErrPruneArchivePolicy, err)
		}
		roots := []string{executor.path, executor.pins.path, databasePath, storagePinsPath, filepath.Dir(availabilityPath)}
		if inventory != nil {
			roots = append(roots, filepath.Dir(inventory.path))
		}
		for _, operation := range operations {
			roots = append(roots, operation.Coordinator.authority.path, operation.Coordinator.journal.path)
		}
		for _, replica := range replicas {
			roots = append(roots, replica.Directory)
		}
		for i := range roots {
			for j := i + 1; j < len(roots); j++ {
				if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
					return err
				}
			}
		}
		protection, err := chain.StorageProtection()
		if err != nil || protection.PairID != policy.StoragePairID || protection.StorageID != executor.request.StorageID ||
			protection.Pending != nil || protection.Database != protection.Confirmed {
			return errors.Join(ErrPruneArchivePolicy, err)
		}
		if err := chain.VerifyContext(executor.assignment.NetworkID, executor.assignment.ActivationHeight, executor.assignment.BaseID); err != nil {
			return err
		}
		if inventory != nil {
			if err := requireNoInventoryEffect(chain, primary.TicketID); err != nil {
				return err
			}
			if inventory.reviewCheck != nil {
				if err := inventory.reviewCheck(); err != nil {
					return err
				}
			}
		}
		if err := executor.hooks.reach("archive-before-verification"); err != nil {
			return err
		}
		if requireLineage {
			for i, assignment := range policy.Assignments {
				for _, replica := range replicas {
					if replica.Receipt.ReplicaPublicKey == assignment.ReplicaPublicKey {
						if err := workarchive.VerifyCustodyReceiptLineage(ctx, lineages[i], assignment, lineages[i].AssignmentID, replica.Receipt); err != nil {
							return err
						}
					}
				}
			}
			if err := executor.hooks.reach("archive-after-lineage"); err != nil {
				return err
			}
		}
		verified, err := workarchive.VerifyCanonicalPruneRequest(ctx, chain, replicas, availabilityPath,
			policy.Checkpoint, policy.CheckpointPolicy, policy.ReplicaPolicy, base, parameters, limits, executor.request.Boundary)
		if err != nil {
			return err
		}
		if err := executor.hooks.reach("archive-before-start"); err != nil {
			return err
		}
		var inventoryID types.Hash
		if inventory != nil {
			if err := requireNoInventoryEffect(chain, primary.TicketID); err != nil {
				return err
			}
			// Re-sync the already retained exact package under every owner guard.
			// A missing file is not reconstructed from cached bytes. Final live
			// freshness is checked AFTER this potentially slow publication fence.
			if err := syncArchivePruneInventory(inventory.path, inventory.encoded, storeHooks{}); err != nil {
				return err
			}
			if err := executor.hooks.reach("archive-inventory-synced"); err != nil {
				return err
			}
			inventoryID = inventory.id
			if inventory.beforeStartCheck != nil {
				if err := inventory.beforeStartCheck(); err != nil {
					return err
				}
			}
		}
		if _, err := verified.Authorize(); err != nil {
			return err
		}
		result, err = executor.executeGuardedInventory(ctx, chain, primary, verified.Authorize, inventoryID)
		return err
	})
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	return result, nil
}

func cloneArchivePrunePolicy(policy ArchivePrunePolicy) (ArchivePrunePolicy, error) {
	if _, err := policy.ID(); err != nil {
		return ArchivePrunePolicy{}, err
	}
	encoded, _ := policy.Checkpoint.CanonicalBytes()
	checkpoint, err := workarchive.DecodeCheckpoint(encoded)
	if err != nil {
		return ArchivePrunePolicy{}, err
	}
	policy.Checkpoint = checkpoint
	policy.CheckpointPolicy.TrustedAttestors = append([][32]byte(nil), policy.CheckpointPolicy.TrustedAttestors...)
	policy.ReplicaPolicy.TrustedReplicas = append([][32]byte(nil), policy.ReplicaPolicy.TrustedReplicas...)
	assignments := make([]custodyauthority.Assignment, len(policy.Assignments))
	for i, assignment := range policy.Assignments {
		encoded, err := assignment.CanonicalBytes()
		if err != nil {
			return ArchivePrunePolicy{}, err
		}
		assignments[i], err = custodyauthority.DecodeAssignment(encoded)
		if err != nil {
			return ArchivePrunePolicy{}, err
		}
	}
	policy.Assignments = assignments
	return policy, nil
}
