package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type ScheduledPruneSource struct {
	AssignmentID           types.Hash
	Directory, JournalPath string
	CustodyPolicy          workarchive.CustodyPolicy
	JournalLimits          workarchive.CustodyJournalLimits
}

// ExecuteScheduledArchive holds the pinned executor, every original authority,
// every original journal and protected WorkChain through the atomic deletion and
// durable result. A retained Started attempt is resolved only by Recover; absence
// of an effect never authorizes another attempt. No obligation completes here.
func (executor *PruneExecutor) ExecuteScheduledArchive(ctx context.Context, chain *workchain.Store, inventoryPath string, inventoryID types.Hash,
	operations []RequiredOperation, sources []ScheduledPruneSource, base workchain.Base, parameters workblock.Parameters, limits workarchive.Limits) (workchain.CanonicalPruneCommit, error) {
	if executor == nil || chain == nil {
		return workchain.CanonicalPruneCommit{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if ctx == nil {
		return workchain.CanonicalPruneCommit{}, ErrScheduledPrune
	}
	if err := ctx.Err(); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	inventory, err := LoadScheduledPruneInventory(inventoryPath, inventoryID)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	requestID, _ := inventory.Request.ID()
	if executor.pins == nil || executor.request.ScheduleID.IsZero() || requestID != executor.id || inventory.ExecutorBindingID != executor.pins.binding || len(operations) != len(inventory.Replicas) || len(sources) != len(inventory.Replicas) {
		return workchain.CanonicalPruneCommit{}, ErrScheduledPrune
	}
	if executor.stage == PruneStarted {
		return workchain.CanonicalPruneCommit{}, ErrPruneOutcome
	}
	if executor.stage != PruneAdmitted {
		return workchain.CanonicalPruneCommit{}, ErrPruneStage
	}
	encoded, _ := inventory.CanonicalBytes()
	operations = append([]RequiredOperation(nil), operations...)
	sources = append([]ScheduledPruneSource(nil), sources...)
	for i := range sources {
		sources[i].CustodyPolicy.TrustedAuditors = append([][32]byte(nil), sources[i].CustodyPolicy.TrustedAuditors...)
	}
	primary, err := pruneAdmissionBinding(executor.assignment, executor.request, *executor.admission)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	needed := make(map[types.Hash]OperationBinding)
	for _, s := range inventory.Replicas {
		aid, _ := s.Assignment.ID()
		ticket, _ := s.Admission.ID()
		sid, _ := s.Proof.ID()
		needed[aid] = OperationBinding{ScheduleID: sid, AssignmentID: aid, TicketID: ticket, ConsumerPublicKey: inventory.Request.ConsumerPublicKey, OperationID: requestID, Purpose: custodyauthority.Prune}
	}
	if needed[primary.AssignmentID] != primary {
		return workchain.CanonicalPruneCommit{}, ErrScheduledPrune
	}
	for _, op := range operations {
		want, ok := needed[op.Binding.AssignmentID]
		if !ok || op.Binding != want {
			return workchain.CanonicalPruneCommit{}, ErrScheduledPrune
		}
		delete(needed, op.Binding.AssignmentID)
	}
	paths := make(map[types.Hash]ScheduledPruneSource)
	for _, s := range sources {
		if _, ok := paths[s.AssignmentID]; ok || s.JournalLimits.Validate() != nil {
			return workchain.CanonicalPruneCommit{}, ErrScheduledPrune
		}
		paths[s.AssignmentID] = s
	}
	var result workchain.CanonicalPruneCommit
	err = withRequiredOperations(ctx, operations, func() (returnErr error) {
		database, pins, err := chain.StorageRoots()
		if err != nil {
			return err
		}
		protection, err := chain.StorageProtection()
		if err != nil || protection.PairID != inventory.StoragePairID || protection.StorageID != executor.request.StorageID || protection.Pending != nil || protection.Database != protection.Confirmed {
			return errors.Join(ErrScheduledPrune, err)
		}
		if err := chain.VerifyContext(executor.assignment.NetworkID, executor.assignment.ActivationHeight, executor.assignment.BaseID); err != nil {
			return err
		}
		roots := []string{executor.path, executor.pins.path, database, pins, filepath.Dir(inventoryPath)}
		for _, op := range operations {
			roots = append(roots, op.Coordinator.authority.path, op.Coordinator.journal.path)
		}
		for _, s := range sources {
			roots = append(roots, s.Directory, s.JournalPath)
		}
		for i := range roots {
			for j := i + 1; j < len(roots); j++ {
				if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
					return err
				}
			}
		}
		type identity struct {
			path string
			info os.FileInfo
		}
		var identities []identity
		for _, path := range roots {
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.Join(ErrScheduledPrune, err)
			}
			identities = append(identities, identity{path, info})
		}
		fileInfo, err := os.Lstat(inventoryPath)
		if err != nil || !fileInfo.Mode().IsRegular() {
			return errors.Join(ErrScheduledPrune, err)
		}
		identities = append(identities, identity{inventoryPath, fileInfo})
		checkIdentities := func() error {
			for _, v := range identities {
				now, err := os.Lstat(v.path)
				if err != nil || !os.SameFile(v.info, now) {
					return errors.Join(ErrScheduledPrune, err)
				}
			}
			return ctx.Err()
		}
		var decisions []*workarchive.CustodyJournalDecision
		defer func() {
			for i := len(decisions) - 1; i >= 0; i-- {
				returnErr = errors.Join(returnErr, decisions[i].Close())
			}
		}()
		var assignments []custodyauthority.Assignment
		var evidence []workarchive.ScheduledReplicaEvidence
		var directories []string
		remaining := workarchive.MaximumReceiptLineageBytes
		for _, s := range inventory.Replicas {
			aid, _ := s.Assignment.ID()
			source, ok := paths[aid]
			if !ok {
				return ErrScheduledPrune
			}
			journal, _, err := workarchive.OpenScheduledCustodyJournal(ctx, source.JournalPath, s.Proof, s.Assignment, inventory.OriginalPolicy, source.CustodyPolicy, source.JournalLimits)
			if err != nil {
				return err
			}
			d, err := journal.AcquireDecision()
			if err != nil {
				return err
			}
			decisions = append(decisions, d)
			lineage, selected, err := d.ScheduleLineage(ctx, s.Proof, s.Assignment, inventory.OriginalPolicy)
			if err != nil || selected != s.Receipt.Original {
				return errors.Join(ErrScheduledPrune, err)
			}
			for _, raw := range [][]byte{s.Proof.OriginalManifest, s.Proof.TargetManifest, lineage.Manifest} {
				if len(raw) > remaining {
					return ErrScheduledPrune
				}
				remaining -= len(raw)
			}
			for _, raw := range lineage.Entries {
				if len(raw) > remaining {
					return ErrScheduledPrune
				}
				remaining -= len(raw)
			}
			assignments = append(assignments, s.Assignment)
			evidence = append(evidence, workarchive.ScheduledReplicaEvidence{Proof: s.Proof, Lineage: lineage})
			directories = append(directories, source.Directory)
		}
		if err := executor.hooks.reach("scheduled-prune-before-verification"); err != nil {
			return err
		}
		bundle, err := inventory.Bundle()
		if err != nil {
			return err
		}
		verified, err := workarchive.VerifyScheduledCanonicalPruneRequest(ctx, chain, directories, bundle, inventory.Checkpoint, inventory.OriginalPolicy, inventory.ReplicaPolicy, assignments, evidence, base, parameters, limits, executor.request.Boundary)
		if err != nil {
			return err
		}
		if err := requireNoInventoryEffect(chain, primary.TicketID); err != nil {
			return err
		}
		retained, err := readRegular(inventoryPath, MaximumScheduledPruneInventoryBytes)
		if err != nil || !bytes.Equal(retained, encoded) {
			return errors.Join(ErrScheduledPrune, err)
		}
		if err := publishCustodyArtifactBytes(ctx, inventoryPath, encoded); err != nil {
			return err
		}
		authorize := func() (uint64, error) {
			if err := checkIdentities(); err != nil {
				return 0, err
			}
			for _, d := range decisions {
				if err := d.CheckAccess(); err != nil {
					return 0, err
				}
			}
			return verified.Authorize()
		}
		if err := executor.hooks.reach("scheduled-prune-before-start"); err != nil {
			return err
		}
		if _, err := authorize(); err != nil {
			return err
		}
		result, err = executor.executeGuardedInventory(ctx, chain, primary, authorize, inventoryID)
		return err
	})
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	return result, nil
}

// CompleteScheduledArchiveReplica drains one original ticket only after the
// executor has retained the matching storage effect under this exact inventory.
// It cannot turn an unconfirmed or missing storage outcome into completion.
func (executor *PruneExecutor) CompleteScheduledArchiveReplica(ctx context.Context, owner *Coordinator, path string, id types.Hash, entry custodyauthority.Entry) (Commit, error) {
	if executor == nil || owner == nil {
		return Commit{}, ErrClosed
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.operationCheck(); err != nil {
		return Commit{}, err
	}
	if ctx == nil {
		return Commit{}, ErrScheduledPrune
	}
	v, err := LoadScheduledPruneInventory(path, id)
	if err != nil {
		return Commit{}, err
	}
	if executor.stage != PruneSucceeded || executor.effect == nil || executor.archiveInventoryID != id || executor.pins == nil || executor.pins.binding != v.ExecutorBindingID {
		return Commit{}, ErrPruneOutcome
	}
	rid, _ := v.Request.ID()
	if rid != executor.id || !pruneEffectMatches(executor.request, *executor.admission, *executor.effect) {
		return Commit{}, ErrScheduledPrune
	}
	evidence, _ := executor.effect.ID()
	if _, err := entry.ID(); err != nil {
		return Commit{}, err
	}
	matched := false
	for _, s := range v.Replicas {
		aid, _ := s.Assignment.ID()
		if aid != owner.assignmentID {
			continue
		}
		ticket, _ := s.Admission.ID()
		sid, _ := s.Proof.ID()
		c := entry.Command
		if c.Version != custodyauthority.ScheduleVersion2 || c.ScheduleID != sid || c.Kind != custodyauthority.Complete || c.AssignmentID != aid || c.TicketID != ticket || c.ActorPublicKey != v.Request.ConsumerPublicKey || c.EvidenceID != evidence || entry.AuthorityPublicKey != s.Assignment.AuthorityPublicKey {
			return Commit{}, ErrPruneCompletion
		}
		matched = true
	}
	if !matched {
		return Commit{}, ErrScheduledPrune
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	current, err := owner.snapshot()
	if err != nil {
		return Commit{}, err
	}
	if current.Pending != nil && *current.Pending != entry {
		return Commit{}, ErrPendingAttempt
	}
	completionID, _ := entry.ID()
	found := false
	for _, operation := range current.Authority.Operations {
		if operation.TicketID == entry.Command.TicketID && operation.OperationID == rid && operation.ConsumerPublicKey == v.Request.ConsumerPublicKey && operation.Purpose == custodyauthority.Prune {
			if !operation.CompletionID.IsZero() && (operation.CompletionID != completionID || operation.EvidenceID != evidence) {
				return Commit{}, ErrPruneCompletion
			}
			found = true
		}
	}
	if !found {
		return Commit{}, custodyauthority.ErrOperation
	}
	roots := []string{executor.path, executor.pins.path, owner.authority.path, owner.journal.path, filepath.Dir(path)}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return Commit{}, err
			}
		}
	}
	encoded, err := v.CanonicalBytes()
	if err != nil {
		return Commit{}, err
	}
	if err := publishCustodyArtifactBytes(ctx, path, encoded); err != nil {
		return Commit{}, err
	}
	return owner.append(ctx, entry)
}
