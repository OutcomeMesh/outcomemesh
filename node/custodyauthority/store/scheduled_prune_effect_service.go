package store

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// ScheduledPruneEffectService owns one original scheduled execution placement.
// All journal decisions remain locked until Close, including between calls.
// No owner, storage handle or session capability is exposed to the caller.
// This local lifetime is a prerequisite for an isolated executor, not a remote
// execution grant or proof of current authority on independently copied hosts.
type ScheduledPruneEffectService struct {
	mu                sync.Mutex
	config            ScheduledPruneRuntimeConfig
	inventory         ScheduledPruneInventory
	executor          *PruneExecutor
	owners            []*Coordinator // configuration order, used by the existing review ID
	acquired          []*Coordinator // assignment-ID acquisition order
	operations        []RequiredOperation
	chain             *workchain.Store
	decisions         map[types.Hash]*workarchive.CustodyJournalDecision
	acquiredDecisions []*workarchive.CustodyJournalDecision
	closed            bool
	failure, closeErr error
	hooks             storeHooks
}

// OpenScheduledPruneEffectService opens existing original owners only. It never
// initializes a root, resumes a pending write or collects an execution claim.
// The caller must Close even after context cancellation or a failed action.
func OpenScheduledPruneEffectService(ctx context.Context, config ScheduledPruneRuntimeConfig) (*ScheduledPruneEffectService, error) {
	return openScheduledPruneEffectService(ctx, config, storeHooks{})
}

func openScheduledPruneEffectService(ctx context.Context, config ScheduledPruneRuntimeConfig, hooks storeHooks) (_ *ScheduledPruneEffectService, returnErr error) {
	if ctx == nil {
		return nil, ErrScheduledPrune
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, v, err := prepareScheduledPruneRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	s := &ScheduledPruneEffectService{config: config, inventory: v, decisions: make(map[types.Hash]*workarchive.CustodyJournalDecision), hooks: hooks}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, s.closeOwners())
		}
	}()
	byID := make(map[types.Hash]ScheduledPruneReplica)
	var primary custodyauthority.Assignment
	for _, replica := range v.Replicas {
		id, _ := replica.Assignment.ID()
		byID[id] = replica
		if id == v.Request.AssignmentID {
			primary = replica.Assignment
		}
	}
	rid, _ := v.Request.ID()
	s.executor, err = OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, primary, rid)
	if err != nil {
		return nil, err
	}
	if s.executor.pins == nil || s.executor.pins.binding != v.ExecutorBindingID {
		return nil, ErrScheduledPrune
	}
	s.executor.hooks, s.executor.pins.hooks = hooks, hooks
	s.owners = make([]*Coordinator, len(config.Authorities))
	s.operations = make([]RequiredOperation, len(config.Authorities))
	indices := make([]int, len(config.Authorities))
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool {
		return types.CompareHash(config.Authorities[indices[i]].AssignmentID, config.Authorities[indices[j]].AssignmentID) < 0
	})
	for _, i := range indices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		root := config.Authorities[i]
		replica := byID[root.AssignmentID]
		owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, replica.Assignment, root.AssignmentID)
		if err != nil {
			return nil, err
		}
		s.owners[i] = owner
		s.acquired = append(s.acquired, owner)
		ticket, _ := replica.Admission.ID()
		sid, _ := replica.Proof.ID()
		s.operations[i] = RequiredOperation{Coordinator: owner, Binding: OperationBinding{AssignmentID: root.AssignmentID, ScheduleID: sid, TicketID: ticket, ConsumerPublicKey: v.Request.ConsumerPublicKey, OperationID: rid, Purpose: custodyauthority.Prune}}
	}
	s.chain, err = workchain.OpenRadixMigratedPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath, config.Base, config.Parameters, config.StoragePolicy, v.Request.StorageID, config.StorageMigrationID)
	if err != nil {
		return nil, err
	}
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool {
		return types.CompareHash(config.Sources[indices[i]].AssignmentID, config.Sources[indices[j]].AssignmentID) < 0
	})
	for _, i := range indices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		source := config.Sources[i]
		replica := byID[source.AssignmentID]
		journal, _, err := workarchive.OpenScheduledCustodyJournal(ctx, source.JournalPath, replica.Proof, replica.Assignment, v.OriginalPolicy, source.CustodyPolicy, source.JournalLimits)
		if err != nil {
			return nil, err
		}
		d, err := journal.AcquireDecision()
		if err != nil {
			return nil, err
		}
		s.decisions[source.AssignmentID] = d
		s.acquiredDecisions = append(s.acquiredDecisions, d)
	}
	if _, err := s.reviewLocked(ctx); err != nil {
		return nil, err
	}
	if err := hooks.reach("scheduled-runtime-opened"); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

func validScheduledPruneAction(mode string, expected types.Hash) bool {
	return (mode == "review" && expected.IsZero()) || ((mode == "execute" || mode == "recover") && !expected.IsZero())
}

// Review returns detached diagnostic state. It neither authorizes execution nor
// changes a held unknown outcome. Execute always computes the comparison again.
func (s *ScheduledPruneEffectService) Review(ctx context.Context) (ScheduledPruneReview, error) {
	r, err := s.run(ctx, "review", types.Hash{})
	return r.Review, err
}

func (s *ScheduledPruneEffectService) Execute(ctx context.Context, expected types.Hash) (ScheduledPruneRuntimeResult, error) {
	return s.run(ctx, "execute", expected)
}

// Recover only reads the original exact retained outcome. It cannot reconstruct
// a lost live session, perform deletion or resume an unconfirmed owner history.
func (s *ScheduledPruneEffectService) Recover(ctx context.Context, expected types.Hash) (ScheduledPruneRuntimeResult, error) {
	return s.run(ctx, "recover", expected)
}

func (s *ScheduledPruneEffectService) run(ctx context.Context, mode string, expected types.Hash) (result ScheduledPruneRuntimeResult, returnErr error) {
	if s == nil {
		return result, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if !s.closed && s.failure == nil && (errors.Is(returnErr, ErrUncertain) || errors.Is(returnErr, workchain.ErrUncertain) || errors.Is(returnErr, ErrClosed)) {
			s.failure = returnErr
		}
	}()
	if s.closed {
		return result, errors.Join(ErrClosed, s.closeErr)
	}
	if s.failure != nil {
		return result, s.failure
	}
	if ctx == nil || !validScheduledPruneAction(mode, expected) {
		return result, ErrScheduledPrune
	}
	var err error
	result.Review, err = s.reviewLocked(ctx)
	if err != nil || mode == "review" {
		return result, err
	}
	if result.Review.ReviewID != expected {
		return result, ErrPruneArchiveEffectReview
	}
	if err := s.hooks.reach("scheduled-runtime-before-action"); err != nil {
		return result, err
	}
	c := s.config
	var commit workchain.CanonicalPruneCommit
	if mode == "execute" {
		if s.inventory.Request.FencePolicyID.IsZero() && (c.CollectPruneClaim != nil || c.CollectPruneCandidate != nil) {
			return result, prunefence.ErrFence
		}
		commit, err = s.executor.executeScheduledArchive(ctx, s.chain, c.InventoryPath, c.InventoryID, s.operations, c.Sources, c.Base, c.Parameters, c.Limits, c.CollectPruneClaim, s.decisions, c.ServiceIdentity, c.CollectPruneCandidate)
	} else {
		commit, err = s.executor.Recover(ctx, s.chain)
	}
	if err != nil {
		return result, err
	}
	snapshot, err := s.executor.Snapshot()
	if err != nil {
		return result, err
	}
	result.Commit = &commit
	result.FenceResult, result.FenceSettlement = snapshot.FenceResult, snapshot.FenceSettlement
	return result, nil
}

func (s *ScheduledPruneEffectService) reviewLocked(ctx context.Context) (ScheduledPruneReview, error) {
	var review ScheduledPruneReview
	if err := ctx.Err(); err != nil {
		return review, err
	}
	if _, err := LoadScheduledPruneInventory(s.config.InventoryPath, s.config.InventoryID); err != nil {
		return review, err
	}
	var err error
	review.Storage, err = s.chain.StorageProtection()
	if err != nil || review.Storage.PairID != s.inventory.StoragePairID || review.Storage.Pending != nil || review.Storage.Database != review.Storage.Confirmed {
		return review, errors.Join(ErrScheduledPrune, err)
	}
	review.Executor, err = s.executor.Snapshot()
	if err != nil {
		return review, err
	}
	for i, owner := range s.owners {
		snapshot, err := owner.Snapshot()
		if err != nil || snapshot.Pending != nil || snapshot.Authority.ScheduleID != s.operations[i].Binding.ScheduleID {
			return review, errors.Join(ErrScheduledPrune, err)
		}
		review.Authorities = append(review.Authorities, snapshot)
	}
	for _, source := range s.config.Sources {
		state, err := s.decisions[source.AssignmentID].State()
		if err != nil {
			return review, err
		}
		review.Journals = append(review.Journals, state)
	}
	if err := ctx.Err(); err != nil {
		return review, err
	}
	return scheduledPruneRuntimeReview(s.config, s.inventory, review)
}

func (s *ScheduledPruneEffectService) closeOwners() (err error) {
	for i := len(s.acquiredDecisions) - 1; i >= 0; i-- {
		err = errors.Join(err, s.acquiredDecisions[i].Close())
	}
	if s.chain != nil {
		err = errors.Join(err, s.chain.Close())
	}
	for i := len(s.acquired) - 1; i >= 0; i-- {
		err = errors.Join(err, s.acquired[i].Close())
	}
	if s.executor != nil {
		err = errors.Join(err, s.executor.Close())
	}
	return err
}

// Close drains the synchronous accepted action before releasing any owner. A
// failed service stays failed; closing it never resolves its retained outcome.
func (s *ScheduledPruneEffectService) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closeErr = errors.Join(s.failure, s.closeOwners())
		s.closed = true
	}
	return s.closeErr
}

func prepareScheduledPruneRuntimeConfig(c ScheduledPruneRuntimeConfig) (ScheduledPruneRuntimeConfig, ScheduledPruneInventory, error) {
	bad := func(err error) (ScheduledPruneRuntimeConfig, ScheduledPruneInventory, error) {
		return ScheduledPruneRuntimeConfig{}, ScheduledPruneInventory{}, errors.Join(ErrScheduledPrune, err)
	}
	if c.StorageMigrationID.IsZero() || c.Base.State == nil {
		return bad(nil)
	}
	v, err := LoadScheduledPruneInventory(c.InventoryPath, c.InventoryID)
	if err != nil {
		return bad(err)
	}
	if (c.CollectPruneClaim != nil && c.CollectPruneCandidate != nil) || (c.CollectPruneCandidate != nil && (c.ServiceIdentity == nil || v.Request.ServiceEnrollmentID.IsZero())) {
		return bad(prunefence.ErrFence)
	}
	if len(c.Authorities) != len(v.Replicas) || len(c.Sources) != len(v.Replicas) || c.Limits.Validate() != nil || c.Parameters.RadixActivationHeight != v.Request.Boundary.RadixActivationHeight {
		return bad(nil)
	}
	c.Authorities = append([]PruneArchiveAuthorityRoots(nil), c.Authorities...)
	c.Sources = append([]ScheduledPruneSource(nil), c.Sources...)
	for _, p := range []*string{&c.InventoryPath, &c.ExecutorPath, &c.ExecutorPinsPath, &c.ChainPath, &c.ChainPinsPath} {
		*p, err = storePath(*p)
		if err != nil {
			return bad(err)
		}
	}
	roots := []string{c.ExecutorPath, c.ExecutorPinsPath, c.ChainPath, c.ChainPinsPath, filepath.Dir(c.InventoryPath)}
	selected := make(map[types.Hash]bool)
	for _, replica := range v.Replicas {
		id, _ := replica.Assignment.ID()
		selected[id] = true
	}
	seen := make(map[types.Hash]bool)
	for i := range c.Authorities {
		r := &c.Authorities[i]
		if !selected[r.AssignmentID] || seen[r.AssignmentID] {
			return bad(nil)
		}
		seen[r.AssignmentID] = true
		for _, p := range []*string{&r.AuthorityPath, &r.AuthorityPinsPath} {
			*p, err = storePath(*p)
			if err != nil {
				return bad(err)
			}
			roots = append(roots, *p)
		}
	}
	seen = make(map[types.Hash]bool)
	for i := range c.Sources {
		s := &c.Sources[i]
		if !selected[s.AssignmentID] || seen[s.AssignmentID] || s.JournalLimits.Validate() != nil {
			return bad(nil)
		}
		seen[s.AssignmentID] = true
		for _, p := range []*string{&s.Directory, &s.JournalPath} {
			*p, err = storePath(*p)
			if err != nil {
				return bad(err)
			}
			roots = append(roots, *p)
		}
		s.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), s.CustodyPolicy.TrustedAuditors...)
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return bad(err)
			}
		}
	}
	c.Base.RecentTimestamps = append([]uint64(nil), c.Base.RecentTimestamps...)
	c.Base.Tip.CumulativeWork = append([]byte(nil), c.Base.Tip.CumulativeWork...)
	c.Base.State, err = state.NewVersion(c.Base.State.Resources(), c.Base.State.CommitmentVersion())
	if err != nil {
		return bad(err)
	}
	return c, v, nil
}

// Preserve the existing local comparison domains and configured order. These
// IDs describe a reviewed local scope; they are not portable execution grants.
func scheduledPruneRuntimeReview(config ScheduledPruneRuntimeConfig, v ScheduledPruneInventory, review ScheduledPruneReview) (ScheduledPruneReview, error) {
	byID := make(map[types.Hash]ScheduledPruneReplica)
	for _, s := range v.Replicas {
		id, _ := s.Assignment.ID()
		byID[id] = s
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
	review.ScopeID = scopeID
	review.InventoryID = config.InventoryID
	e = codec.NewEncoder(2048)
	e.Fixed(scopeID[:])
	e.U16(uint16(review.Executor.Stage))
	e.Fixed(review.Executor.Protection.Confirmed.HeadID[:])
	e.U64(review.Storage.Confirmed.Sequence)
	e.Fixed(review.Storage.Confirmed.CommitID[:])
	for _, snap := range review.Authorities {
		e.Fixed(snap.Authority.AssignmentID[:])
		e.U64(snap.Confirmed.Sequence)
		e.Fixed(snap.Confirmed.HeadID[:])
	}
	for _, state := range review.Journals {
		e.U64(state.Sequence)
		e.Fixed(state.HeadEntryID[:])
		id, err := state.CurrentReceipt.ID()
		if err != nil {
			return ScheduledPruneReview{}, err
		}
		e.Fixed(id[:])
	}
	reviewDomain := "OMESH/custody-prune/scheduled-runtime/review/v0"
	if !v.Request.FencePolicyID.IsZero() {
		reviewDomain = "OMESH/custody-prune/scheduled-runtime/review/v1"
		e.Fixed(v.Request.FencePolicyID[:])
		var candidate []byte
		if review.Executor.FenceCandidate != nil {
			candidate, _ = review.Executor.FenceCandidate.CanonicalBytes()
		}
		e.BytesField(candidate)
	}
	if !v.Request.ServiceEnrollmentID.IsZero() {
		reviewDomain = "OMESH/custody-prune/scheduled-runtime/review/v2"
	}
	review.ReviewID = types.DomainHash(reviewDomain, e.Bytes())
	return review, nil
}
