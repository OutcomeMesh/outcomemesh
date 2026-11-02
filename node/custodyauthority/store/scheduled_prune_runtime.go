package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type ScheduledPruneRuntimeConfig struct {
	// ServiceIdentity is trusted local owner configuration, never decoded from a peer.
	ServiceIdentity                                          *prunefence.ServiceIdentity `json:"-"`
	CollectPruneClaim                                        PruneClaimCollector         `json:"-"`
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
	FenceResult     *prunefence.Result
	FenceSettlement *PruneSettlement
	Review          ScheduledPruneReview
	Commit          *workchain.CanonicalPruneCommit
}

// RunScheduledPrune owns all original roots for one explicitly selected action.
// The shared effect service closes before the caller receives output, including
// on errors. Recovery never executes deletion or resumes an unconfirmed write.
func RunScheduledPrune(ctx context.Context, config ScheduledPruneRuntimeConfig, mode string, expectedReviewID types.Hash) (ScheduledPruneRuntimeResult, error) {
	return runScheduledPrune(ctx, config, mode, expectedReviewID, storeHooks{})
}
func runScheduledPrune(ctx context.Context, config ScheduledPruneRuntimeConfig, mode string, expectedReviewID types.Hash, hooks storeHooks) (_ ScheduledPruneRuntimeResult, returnErr error) {
	if !validScheduledPruneAction(mode, expectedReviewID) {
		return ScheduledPruneRuntimeResult{}, ErrScheduledPrune
	}
	service, err := openScheduledPruneEffectService(ctx, config, hooks)
	if err != nil {
		return ScheduledPruneRuntimeResult{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
	return service.run(ctx, mode, expectedReviewID)
}
