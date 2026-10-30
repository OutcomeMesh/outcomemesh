package store

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type ScheduledPruneRuntimeConfig struct {
	InventoryPath                                            string
	InventoryID, StorageMigrationID                          types.Hash
	ExecutorPath, ExecutorPinsPath, ChainPath, ChainPinsPath string
	Authorities                                              []PruneArchiveAuthorityRoots
	Sources                                                  []ScheduledPruneSource
	Base                                                     workchain.Base
	Parameters                                               workblock.Parameters
	StoragePolicy                                            workchain.Policy
	Limits                                                   workarchive.Limits
}

type ScheduledPruneReview struct {
	ScopeID, InventoryID, ReviewID types.Hash
	Executor                       PruneExecution
	Storage                        workchain.StorageProtection
	Authorities                    []Coordination
	Journals                       []workarchive.CustodyJournalState
}
type ScheduledPruneRuntimeResult struct {
	Review ScheduledPruneReview
	Commit *workchain.CanonicalPruneCommit
}

// RunScheduledPrune owns all original roots for one explicitly selected action.
// Review is read-only. Execute and recover require the exact preceding review;
// recovery only reads a matching committed effect. All owners close before the
// caller receives output, including on errors and cancellation.
func RunScheduledPrune(ctx context.Context, config ScheduledPruneRuntimeConfig, mode string, expectedReviewID types.Hash) (ScheduledPruneRuntimeResult, error) {
	return runScheduledPrune(ctx, config, mode, expectedReviewID, storeHooks{})
}
func runScheduledPrune(ctx context.Context, config ScheduledPruneRuntimeConfig, mode string, expectedReviewID types.Hash, hooks storeHooks) (_ ScheduledPruneRuntimeResult, returnErr error) {
	var result ScheduledPruneRuntimeResult
	if ctx == nil || (mode != "review" && mode != "execute" && mode != "recover") || (mode == "review" && !expectedReviewID.IsZero()) || (mode != "review" && expectedReviewID.IsZero()) || config.StorageMigrationID.IsZero() || config.Base.State == nil {
		return result, ErrScheduledPrune
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	v, err := LoadScheduledPruneInventory(config.InventoryPath, config.InventoryID)
	if err != nil {
		return result, err
	}
	if len(config.Authorities) != len(v.Replicas) || len(config.Sources) != len(v.Replicas) || config.Limits.Validate() != nil || config.Parameters.RadixActivationHeight != v.Request.Boundary.RadixActivationHeight {
		return result, ErrScheduledPrune
	}
	config.Authorities = append([]PruneArchiveAuthorityRoots(nil), config.Authorities...)
	config.Sources = append([]ScheduledPruneSource(nil), config.Sources...)
	for _, p := range []*string{&config.InventoryPath, &config.ExecutorPath, &config.ExecutorPinsPath, &config.ChainPath, &config.ChainPinsPath} {
		path, err := storePath(*p)
		if err != nil {
			return result, err
		}
		*p = path
	}
	roots := []string{config.ExecutorPath, config.ExecutorPinsPath, config.ChainPath, config.ChainPinsPath, filepath.Dir(config.InventoryPath)}
	for i := range config.Authorities {
		for _, p := range []*string{&config.Authorities[i].AuthorityPath, &config.Authorities[i].AuthorityPinsPath} {
			path, err := storePath(*p)
			if err != nil {
				return result, err
			}
			*p = path
			roots = append(roots, path)
		}
	}
	for i := range config.Sources {
		s := &config.Sources[i]
		for _, p := range []*string{&s.Directory, &s.JournalPath} {
			path, err := storePath(*p)
			if err != nil {
				return result, err
			}
			*p = path
			roots = append(roots, path)
		}
		s.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), s.CustodyPolicy.TrustedAuditors...)
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return result, err
			}
		}
	}
	var primary custodyauthority.Assignment
	byID := make(map[types.Hash]ScheduledPruneReplica)
	for _, s := range v.Replicas {
		id, _ := s.Assignment.ID()
		byID[id] = s
		if id == v.Request.AssignmentID {
			primary = s.Assignment
		}
	}
	requestID, _ := v.Request.ID()
	executor, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, primary, requestID)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, executor.Close()) }()
	executor.hooks = hooks
	executor.pins.hooks = hooks
	if executor.pins == nil || executor.pins.binding != v.ExecutorBindingID {
		return result, ErrScheduledPrune
	}
	var owners []*Coordinator
	defer func() {
		for i := len(owners) - 1; i >= 0; i-- {
			returnErr = errors.Join(returnErr, owners[i].Close())
		}
	}()
	var operations []RequiredOperation
	seen := make(map[types.Hash]bool)
	for _, root := range config.Authorities {
		s, ok := byID[root.AssignmentID]
		if !ok || seen[root.AssignmentID] {
			return result, ErrScheduledPrune
		}
		seen[root.AssignmentID] = true
		owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, s.Assignment, root.AssignmentID)
		if err != nil {
			return result, err
		}
		owners = append(owners, owner)
		ticket, _ := s.Admission.ID()
		sid, _ := s.Proof.ID()
		operations = append(operations, RequiredOperation{Coordinator: owner, Binding: OperationBinding{AssignmentID: root.AssignmentID, ScheduleID: sid, TicketID: ticket, ConsumerPublicKey: v.Request.ConsumerPublicKey, OperationID: requestID, Purpose: custodyauthority.Prune}})
		snap, err := owner.Snapshot()
		if err != nil || snap.Pending != nil || snap.Authority.ScheduleID != sid {
			return result, errors.Join(ErrScheduledPrune, err)
		}
		result.Review.Authorities = append(result.Review.Authorities, snap)
	}
	chain, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath, config.Base, config.Parameters, config.StoragePolicy, v.Request.StorageID, config.StorageMigrationID)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, chain.Close()) }()
	storage, err := chain.StorageProtection()
	if err != nil || storage.PairID != v.StoragePairID || storage.Pending != nil || storage.Database != storage.Confirmed {
		return result, errors.Join(ErrScheduledPrune, err)
	}
	result.Review.Storage = storage
	result.Review.Executor, err = executor.Snapshot()
	if err != nil {
		return result, err
	}
	seen = make(map[types.Hash]bool)
	for _, source := range config.Sources {
		s, ok := byID[source.AssignmentID]
		if !ok || seen[source.AssignmentID] {
			return result, ErrScheduledPrune
		}
		seen[source.AssignmentID] = true
		_, state, err := workarchive.OpenScheduledCustodyJournal(ctx, source.JournalPath, s.Proof, s.Assignment, v.OriginalPolicy, source.CustodyPolicy, source.JournalLimits)
		if err != nil {
			return result, err
		}
		result.Review.Journals = append(result.Review.Journals, state)
	}
	legacyConfig := PruneArchiveEffectServiceConfig{InventoryPath: config.InventoryPath, InventoryID: config.InventoryID, ExecutorPath: config.ExecutorPath, ExecutorPinsPath: config.ExecutorPinsPath, ChainPath: config.ChainPath, ChainPinsPath: config.ChainPinsPath, Authorities: config.Authorities, Base: config.Base, Parameters: config.Parameters, StoragePolicy: config.StoragePolicy, Limits: config.Limits}
	for _, s := range config.Sources {
		legacyConfig.Replicas = append(legacyConfig.Replicas, PruneArchiveReplicaPath{AssignmentID: s.AssignmentID, Directory: s.Directory})
	}
	legacyID := archiveEffectScopeID(legacyConfig)
	e := codec.NewEncoder(2048)
	e.Fixed(legacyID[:])
	e.Fixed(config.StorageMigrationID[:])
	e.U64(config.Parameters.RadixActivationHeight)
	for _, s := range config.Sources {
		e.Fixed(s.AssignmentID[:])
		e.BytesField([]byte(s.JournalPath))
		pid := byID[s.AssignmentID].Assignment.CustodyPolicyID
		e.Fixed(pid[:])
		e.U64(s.JournalLimits.MaximumBytes)
		e.U64(s.JournalLimits.MaximumPaths)
	}
	scopeID := types.DomainHash("OMESH/custody-prune/scheduled-runtime/scope/v0", e.Bytes())
	result.Review.ScopeID = scopeID
	result.Review.InventoryID = config.InventoryID
	e = codec.NewEncoder(2048)
	e.Fixed(scopeID[:])
	e.U16(uint16(result.Review.Executor.Stage))
	e.Fixed(result.Review.Executor.Protection.Confirmed.HeadID[:])
	e.U64(storage.Confirmed.Sequence)
	e.Fixed(storage.Confirmed.CommitID[:])
	for _, snap := range result.Review.Authorities {
		e.Fixed(snap.Authority.AssignmentID[:])
		e.U64(snap.Confirmed.Sequence)
		e.Fixed(snap.Confirmed.HeadID[:])
	}
	for _, state := range result.Review.Journals {
		e.U64(state.Sequence)
		e.Fixed(state.HeadEntryID[:])
		id, err := state.CurrentReceipt.ID()
		if err != nil {
			return result, err
		}
		e.Fixed(id[:])
	}
	result.Review.ReviewID = types.DomainHash("OMESH/custody-prune/scheduled-runtime/review/v0", e.Bytes())
	if mode == "review" {
		return result, ctx.Err()
	}
	if expectedReviewID != result.Review.ReviewID {
		return result, ErrPruneArchiveEffectReview
	}
	var commit workchain.CanonicalPruneCommit
	if mode == "execute" {
		commit, err = executor.ExecuteScheduledArchive(ctx, chain, config.InventoryPath, config.InventoryID, operations, config.Sources, config.Base, config.Parameters, config.Limits)
	} else {
		commit, err = executor.Recover(ctx, chain)
	}
	if err != nil {
		return result, err
	}
	result.Commit = &commit
	return result, nil
}
