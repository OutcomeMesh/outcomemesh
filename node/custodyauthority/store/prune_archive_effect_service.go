package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

var ErrPruneArchiveEffectReview = errors.New("archive effect review does not match the exact owned scope and retained state")

// PruneArchiveAuthorityRoots selects an ORIGINAL retained coordinator pair.
// The assignment itself is derived only from the independently pinned inventory.
type PruneArchiveAuthorityRoots struct {
	AssignmentID                     types.Hash
	AuthorityPath, AuthorityPinsPath string
}

// PruneArchiveReplicaPath names a selected replica's existing immutable archive.
// Its receipt is taken from the inventory, never supplied or discovered here.
type PruneArchiveReplicaPath struct {
	AssignmentID types.Hash
	Directory    string
}

// PruneArchiveEffectServiceConfig is explicit local protected configuration.
// Every root already exists. The preceding command services must stop, drain and
// close before this separate owner acquires their roots. Open never bootstraps,
// resumes, signs, completes, activates or creates a network endpoint.
type PruneArchiveEffectServiceConfig struct {
	InventoryPath                  string
	InventoryID, PolicyID          types.Hash
	ExecutorPath, ExecutorPinsPath string
	Authorities                    []PruneArchiveAuthorityRoots
	ChainPath, ChainPinsPath       string
	Base                           workchain.Base
	Parameters                     workblock.Parameters
	StoragePolicy                  workchain.Policy
	Replicas                       []PruneArchiveReplicaPath
	AvailabilityPath               string
	LineagePath                    string
	LineageID                      types.Hash
	Limits                         workarchive.Limits
}

type PruneArchiveAuthorityReview struct {
	AssignmentID types.Hash
	Position     custodyauthority.Position
	Phase        custodyauthority.Phase
	TicketID     types.Hash
}

// PruneArchiveEffectReview is detached historical LOCAL state. ID is a local
// compare token, not a portable permission, signature or current-authority grant.
// Its ScopeID commits every configured path, content pin and execution control.
type PruneArchiveEffectReview struct {
	Mode                                                   ArchivePruneMode
	ScopeID, InventoryID, PolicyID, LineageEvidenceID      types.Hash
	RequestID, StorageID, ExecutorBindingID, StoragePairID types.Hash
	Executor                                               PrunePosition
	Storage                                                workchain.StoragePosition
	Authorities                                            []PruneArchiveAuthorityReview // strict assignment-ID order
}

func (review PruneArchiveEffectReview) ID() (types.Hash, error) {
	if review.Mode > ArchivePruneLineage || (review.Mode == ArchivePruneInitial) != review.LineageEvidenceID.IsZero() ||
		review.ScopeID.IsZero() || review.InventoryID.IsZero() || review.PolicyID.IsZero() || review.RequestID.IsZero() ||
		review.StorageID.IsZero() || review.ExecutorBindingID.IsZero() || review.StoragePairID.IsZero() ||
		review.Executor.Stage != PruneAdmitted || review.Executor.HeadID.IsZero() || review.Storage.CommitID.IsZero() ||
		len(review.Authorities) == 0 || len(review.Authorities) > workarchive.MaximumReplicas {
		return types.Hash{}, ErrPruneArchiveEffectReview
	}
	e := codec.NewEncoder(512 + len(review.Authorities)*110)
	e.U16(0)
	e.U16(uint16(review.Mode))
	for _, id := range []types.Hash{review.ScopeID, review.InventoryID, review.PolicyID, review.LineageEvidenceID,
		review.RequestID, review.StorageID, review.ExecutorBindingID, review.StoragePairID, review.Executor.HeadID} {
		e.Fixed(id[:])
	}
	e.U16(uint16(review.Executor.Stage))
	e.U64(review.Storage.Sequence)
	e.Fixed(review.Storage.CommitID[:])
	e.U16(uint16(len(review.Authorities)))
	for i, authority := range review.Authorities {
		if authority.AssignmentID.IsZero() || authority.Position.HeadID.IsZero() || authority.TicketID.IsZero() ||
			(authority.Phase != custodyauthority.Accepting && authority.Phase != custodyauthority.Stopping) ||
			(i > 0 && types.CompareHash(review.Authorities[i-1].AssignmentID, authority.AssignmentID) >= 0) {
			return types.Hash{}, ErrPruneArchiveEffectReview
		}
		e.Fixed(authority.AssignmentID[:])
		e.U64(authority.Position.Sequence)
		e.Fixed(authority.Position.HeadID[:])
		e.U16(uint16(authority.Phase))
		e.Fixed(authority.TicketID[:])
	}
	return types.DomainHash("OMESH/custody-prune/archive-effect/review/v0", e.Bytes()), nil
}

// PruneArchiveEffectService exclusively owns all original journal pairs and one
// position-pinned WorkChain. Lifecycle ownership spans Review, Execute and Close;
// no raw handle or arbitrary callback can escape. It is a colocated library
// runtime, not managed Audit/Serve acceptance, copy fencing or activation.
type PruneArchiveEffectService struct {
	mu                sync.Mutex
	config            PruneArchiveEffectServiceConfig
	inventory         ArchivePruneInventory
	scopeID           types.Hash
	executor          *PruneExecutor
	coordinators      []*Coordinator // acquisition order, released in reverse
	operations        []RequiredOperation
	replicas          []workarchive.Replica
	chain             *workchain.Store
	closed            bool
	failure, closeErr error
	hooks             storeHooks
}

// OpenPruneArchiveEffectService acquires existing owners only after complete
// pairwise placement validation. Pins are opened before writers, coordinator
// pairs in assignment-ID order and WorkChain last. A partial failure releases
// only the acquired owners, in reverse. No missing root is reconstructed.
func OpenPruneArchiveEffectService(config PruneArchiveEffectServiceConfig) (_ *PruneArchiveEffectService, err error) {
	config, inventory, err := prepareArchiveEffectConfig(config)
	if err != nil {
		return nil, err
	}
	service := &PruneArchiveEffectService{config: config, inventory: inventory}
	service.scopeID = archiveEffectScopeID(config)
	defer func() {
		if err != nil {
			err = errors.Join(err, service.closeOwners())
		}
	}()
	var primary custodyauthority.Assignment
	assignments := make(map[types.Hash]custodyauthority.Assignment, len(inventory.Policy.Assignments))
	admissions := make(map[types.Hash]custodyauthority.Entry, len(inventory.Admissions))
	for i, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID()
		assignments[id], admissions[id] = assignment, inventory.Admissions[i]
		if id == inventory.Request.AssignmentID {
			primary = assignment
		}
	}
	service.executor, err = OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, primary, inventory.Policy.RequestID)
	if err != nil {
		return nil, err
	}
	for _, roots := range config.Authorities {
		assignment := assignments[roots.AssignmentID]
		owner, openErr := OpenCoordinator(roots.AuthorityPath, roots.AuthorityPinsPath, assignment, roots.AssignmentID)
		if openErr != nil {
			return nil, openErr
		}
		service.coordinators = append(service.coordinators, owner)
		entry := admissions[roots.AssignmentID]
		ticket, _ := entry.ID()
		service.operations = append(service.operations, RequiredOperation{Coordinator: owner, Binding: OperationBinding{
			AssignmentID: roots.AssignmentID, TicketID: ticket, ConsumerPublicKey: entry.Command.ActorPublicKey,
			OperationID: inventory.Policy.RequestID, Purpose: custodyauthority.Prune}})
	}
	service.chain, err = workchain.OpenPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath,
		config.Base, config.Parameters, config.StoragePolicy, inventory.Request.StorageID)
	if err != nil {
		return nil, err
	}
	protection, err := service.chain.StorageProtection()
	if err != nil || protection.PairID != inventory.Policy.StoragePairID || protection.Pending != nil || protection.Database != protection.Confirmed {
		return nil, errors.Join(ErrPruneArchivePolicy, err)
	}
	for i, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID()
		for _, replica := range config.Replicas {
			if replica.AssignmentID == id {
				service.replicas = append(service.replicas, workarchive.Replica{Directory: replica.Directory, Receipt: inventory.Availability.Receipts[i]})
			}
		}
	}
	if err := service.hooks.reach("effect-opened"); err != nil {
		return nil, err
	}
	return service, nil
}

// Review verifies retained files and captures all confirmed original owners
// under executor -> sorted coordinator guards. It does not replay replicas,
// publish availability, execute, recover or complete a ticket.
func (service *PruneArchiveEffectService) Review(ctx context.Context) (PruneArchiveEffectReview, error) {
	if service == nil {
		return PruneArchiveEffectReview{}, ErrClosed
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.check(ctx); err != nil {
		return PruneArchiveEffectReview{}, err
	}
	service.executor.mu.Lock()
	defer service.executor.mu.Unlock()
	var review PruneArchiveEffectReview
	err := withRequiredOperations(ctx, service.operations, func() error {
		// Verify complete historical prefixes on every explicit review; a cached
		// open-time value cannot replace a lost retained evidence file.
		if _, err := service.loadLineages(ctx); err != nil {
			return err
		}
		var err error
		review, err = service.reviewLocked(ctx)
		if err != nil {
			return err
		}
		return service.hooks.reach("effect-review-checked")
	})
	service.rememberFailure(err)
	if err != nil {
		return PruneArchiveEffectReview{}, err
	}
	return review, nil
}

// Execute compares the supplied review inside the SAME original owner guards
// used by the concrete archive verifier and effect. It never refreshes a review,
// retries a retained start, signs completion or infers non-execution from absence.
// Close waits for this complete synchronous call, including retained result.
func (service *PruneArchiveEffectService) Execute(ctx context.Context, expectedReviewID types.Hash) (workchain.CanonicalPruneCommit, error) {
	if service == nil {
		return workchain.CanonicalPruneCommit{}, ErrClosed
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.check(ctx); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	if expectedReviewID.IsZero() {
		return workchain.CanonicalPruneCommit{}, ErrPruneArchiveEffectReview
	}
	prepared, err := LoadArchivePruneInventoryFile(service.config.InventoryPath, service.config.InventoryID, service.config.PolicyID)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	lineages, err := service.loadLineages(ctx)
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	encoded, err := prepared.CanonicalBytes()
	if err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	checkReview := func() error {
		review, err := service.reviewLocked(ctx)
		if err != nil {
			return err
		}
		id, err := review.ID()
		if err != nil || id != expectedReviewID {
			return errors.Join(ErrPruneArchiveEffectReview, err)
		}
		return service.hooks.reach("effect-review-checked")
	}
	input := &archiveInventoryInput{path: service.config.InventoryPath, id: service.config.InventoryID, encoded: encoded,
		prepared: prepared, reviewCheck: checkReview, beforeStartCheck: func() error {
			if prepared.Mode == ArchivePruneLineage {
				if err := syncLineageEvidenceFile(ctx, service.config.LineagePath, service.config.LineageID, storeHooks{}); err != nil {
					return err
				}
			}
			return checkReview()
		}}
	if err := service.hooks.reach("effect-before-execute"); err != nil {
		return workchain.CanonicalPruneCommit{}, err
	}
	result, err := service.executor.executeArchive(ctx, service.chain, prepared.Policy, service.config.PolicyID,
		service.operations, service.replicas, lineages, prepared.Mode == ArchivePruneLineage, service.config.AvailabilityPath,
		service.config.Base, service.config.Parameters, service.config.Limits, input)
	if err == nil {
		if hookErr := service.hooks.reach("effect-after-execute"); hookErr != nil {
			err = errors.Join(ErrUncertain, hookErr)
		}
	}
	service.rememberFailure(err)
	return result, err
}

func (service *PruneArchiveEffectService) loadLineages(ctx context.Context) ([]workarchive.CustodyReceiptLineage, error) {
	if service.inventory.Mode == ArchivePruneInitial {
		return nil, ctx.Err()
	}
	evidence, err := LoadArchivePruneLineageEvidenceFile(ctx, service.config.LineagePath, service.inventory,
		service.config.InventoryID, service.config.PolicyID, service.config.LineageID)
	if err != nil {
		return nil, err
	}
	// The loader owns these immutable detached bodies. executeArchive performs
	// its usual bounded detach before any original coordinator is locked.
	return evidence.lineages, nil
}

// Caller holds the lifecycle, executor and EVERY original coordinator mutex.
func (service *PruneArchiveEffectService) reviewLocked(ctx context.Context) (PruneArchiveEffectReview, error) {
	if err := service.executor.operationCheck(); err != nil {
		return PruneArchiveEffectReview{}, err
	}
	if service.executor.stage == PruneStarted {
		return PruneArchiveEffectReview{}, ErrPruneOutcome
	}
	if service.executor.stage != PruneAdmitted {
		return PruneArchiveEffectReview{}, ErrPruneStage
	}
	if _, err := LoadArchivePruneInventoryFile(service.config.InventoryPath, service.config.InventoryID, service.config.PolicyID); err != nil {
		return PruneArchiveEffectReview{}, err
	}
	if service.inventory.Mode == ArchivePruneLineage {
		if err := verifyArchiveEffectLineageFile(ctx, service.config.LineagePath, service.config.LineageID); err != nil {
			return PruneArchiveEffectReview{}, err
		}
	}
	protection := service.executor.pins.protection()
	if protection.Pending != nil || protection.BindingID != service.inventory.Policy.ExecutorBindingID ||
		protection.Confirmed.Stage != service.executor.stage || service.executor.admission == nil {
		return PruneArchiveEffectReview{}, ErrPrunePinPending
	}
	storage, err := service.chain.StorageProtection()
	if err != nil || storage.Pending != nil || storage.Database != storage.Confirmed || storage.StorageID != service.inventory.Request.StorageID ||
		storage.PairID != service.inventory.Policy.StoragePairID {
		return PruneArchiveEffectReview{}, errors.Join(ErrPruneArchivePolicy, err)
	}
	if err := service.chain.VerifyContext(service.inventory.Policy.CheckpointPolicy.Binding.NetworkID, service.inventory.Policy.Checkpoint.Statement.ActivationHeight,
		service.inventory.Policy.Checkpoint.Statement.BaseID); err != nil {
		return PruneArchiveEffectReview{}, err
	}
	review := PruneArchiveEffectReview{Mode: service.inventory.Mode, ScopeID: service.scopeID,
		InventoryID: service.config.InventoryID, PolicyID: service.config.PolicyID, LineageEvidenceID: service.config.LineageID,
		RequestID: service.inventory.Policy.RequestID, StorageID: storage.StorageID, ExecutorBindingID: protection.BindingID,
		StoragePairID: storage.PairID, Executor: protection.Confirmed, Storage: storage.Confirmed,
		Authorities: make([]PruneArchiveAuthorityReview, len(service.operations))}
	for i, operation := range service.operations {
		current, err := operation.Coordinator.snapshot()
		if err != nil {
			return PruneArchiveEffectReview{}, err
		}
		if current.Pending != nil {
			return PruneArchiveEffectReview{}, ErrPendingAttempt
		}
		if err := operation.Coordinator.checkOperation(operation.Binding); err != nil {
			return PruneArchiveEffectReview{}, err
		}
		review.Authorities[i] = PruneArchiveAuthorityReview{AssignmentID: operation.Binding.AssignmentID,
			Position: current.Confirmed, Phase: current.Authority.Phase, TicketID: operation.Binding.TicketID}
		if operation.Binding.AssignmentID == service.inventory.Request.AssignmentID {
			ticket, _ := service.executor.admission.ID()
			if ticket != operation.Binding.TicketID {
				return PruneArchiveEffectReview{}, ErrPruneInventory
			}
			if err := requireNoInventoryEffect(service.chain, ticket); err != nil {
				return PruneArchiveEffectReview{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return PruneArchiveEffectReview{}, err
	}
	_, err = review.ID()
	return review, err
}

func verifyArchiveEffectLineageFile(ctx context.Context, path string, id types.Hash) (err error) {
	input, err := openLineageEvidenceFile(path, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.file.Close()) }()
	return input.verifyHash(ctx, id)
}

func (service *PruneArchiveEffectService) check(ctx context.Context) error {
	if service.closed {
		return errors.Join(ErrClosed, service.closeErr)
	}
	if service.failure != nil {
		return service.failure
	}
	if ctx == nil {
		return ErrPruneRuntime
	}
	return ctx.Err()
}

func (service *PruneArchiveEffectService) rememberFailure(err error) {
	if errors.Is(err, ErrUncertain) || errors.Is(err, workchain.ErrUncertain) || errors.Is(err, ErrClosed) {
		service.failure = errors.Join(service.failure, err)
	}
}

func (service *PruneArchiveEffectService) closeOwners() (err error) {
	if service.chain != nil {
		err = errors.Join(err, service.chain.Close())
	}
	for i := len(service.coordinators) - 1; i >= 0; i-- {
		err = errors.Join(err, service.coordinators[i].Close())
	}
	if service.executor != nil {
		err = errors.Join(err, service.executor.Close())
	}
	return err
}

func (service *PruneArchiveEffectService) Close() error {
	if service == nil {
		return nil
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if !service.closed {
		service.closeErr = errors.Join(service.failure, service.closeOwners())
		service.closed = true
	}
	return service.closeErr
}

func prepareArchiveEffectConfig(config PruneArchiveEffectServiceConfig) (PruneArchiveEffectServiceConfig, ArchivePruneInventory, error) {
	invalid := func(err error) (PruneArchiveEffectServiceConfig, ArchivePruneInventory, error) {
		return PruneArchiveEffectServiceConfig{}, ArchivePruneInventory{}, errors.Join(ErrPruneRuntime, err)
	}
	if config.InventoryID.IsZero() || config.PolicyID.IsZero() || config.Base.State == nil || config.StoragePolicy.MaxHistoryBytes == 0 ||
		config.StoragePolicy.CanonicalRetention == 0 || len(config.Authorities) == 0 || len(config.Authorities) > workarchive.MaximumReplicas ||
		len(config.Replicas) != len(config.Authorities) {
		return invalid(nil)
	}
	if err := config.Limits.Validate(); err != nil {
		return invalid(err)
	}
	var err error
	config.InventoryPath, err = canonicalArchiveEffectFile(config.InventoryPath, true)
	if err != nil {
		return invalid(err)
	}
	inventory, err := LoadArchivePruneInventoryFile(config.InventoryPath, config.InventoryID, config.PolicyID)
	if err != nil {
		return invalid(err)
	}
	if len(config.Authorities) != len(inventory.Policy.Assignments) {
		return invalid(ErrPruneInventory)
	}
	if inventory.Mode == ArchivePruneInitial {
		if config.LineagePath != "" || !config.LineageID.IsZero() {
			return invalid(ErrPruneLineageEvidence)
		}
	} else {
		if config.LineageID.IsZero() {
			return invalid(ErrPruneLineageEvidence)
		}
		config.LineagePath, err = canonicalArchiveEffectFile(config.LineagePath, true)
		if err != nil {
			return invalid(err)
		}
		// Match the separately retained content pin before acquiring any owner.
		// Full prefix verification remains an explicit context-bound Review or
		// Execute operation; opening never caches substitute historical bodies.
		if err := verifyArchiveEffectLineageFile(context.Background(), config.LineagePath, config.LineageID); err != nil {
			return invalid(err)
		}
	}
	config.AvailabilityPath, err = canonicalArchiveEffectFile(config.AvailabilityPath, false)
	if err != nil {
		return invalid(err)
	}
	config.Authorities = append([]PruneArchiveAuthorityRoots(nil), config.Authorities...)
	config.Replicas = append([]PruneArchiveReplicaPath(nil), config.Replicas...)
	sort.Slice(config.Authorities, func(i, j int) bool {
		return types.CompareHash(config.Authorities[i].AssignmentID, config.Authorities[j].AssignmentID) < 0
	})
	sort.Slice(config.Replicas, func(i, j int) bool {
		return types.CompareHash(config.Replicas[i].AssignmentID, config.Replicas[j].AssignmentID) < 0
	})
	selected := make(map[types.Hash]bool, len(inventory.Policy.Assignments))
	for _, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID()
		selected[id] = true
	}
	for i, roots := range config.Authorities {
		if !selected[roots.AssignmentID] || (i > 0 && config.Authorities[i-1].AssignmentID == roots.AssignmentID) ||
			config.Replicas[i].AssignmentID != roots.AssignmentID {
			return invalid(ErrPruneInventory)
		}
	}
	roots := []*string{&config.ExecutorPath, &config.ExecutorPinsPath, &config.ChainPath, &config.ChainPinsPath}
	for i := range config.Authorities {
		roots = append(roots, &config.Authorities[i].AuthorityPath, &config.Authorities[i].AuthorityPinsPath)
	}
	for i := range config.Replicas {
		roots = append(roots, &config.Replicas[i].Directory)
	}
	parents := []string{filepath.Dir(config.InventoryPath), filepath.Dir(config.AvailabilityPath)}
	if config.LineagePath != "" {
		parents = append(parents, filepath.Dir(config.LineagePath))
	}
	for i := range parents {
		roots = append(roots, &parents[i])
	}
	// Canonicalize existing directories first, then compare every pair before
	// any lifetime owner is acquired. This also rejects symlink directory roots.
	for _, root := range roots {
		path, err := storePath(*root)
		if err != nil {
			return invalid(err)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return invalid(errors.Join(ErrStore, err))
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			return invalid(err)
		}
		*root = path
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(*roots[i], *roots[j]); err != nil {
				return invalid(err)
			}
		}
	}
	config.Base.RecentTimestamps = append([]uint64(nil), config.Base.RecentTimestamps...)
	config.Base.Tip.CumulativeWork = append([]byte(nil), config.Base.Tip.CumulativeWork...)
	config.Base.State, err = state.NewVersion(config.Base.State.Resources(), config.Base.State.CommitmentVersion())
	if err != nil {
		return invalid(err)
	}
	validation, err := workchain.New(config.Base, config.Parameters)
	if err != nil {
		return invalid(err)
	}
	if err := validation.Close(); err != nil {
		return invalid(err)
	}
	return config, inventory, nil
}

func canonicalArchiveEffectFile(path string, required bool) (string, error) {
	path, err := storePath(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	path = filepath.Join(parent, filepath.Base(path))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return path, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.Join(ErrStore, err)
	}
	return path, nil
}

func archiveEffectScopeID(config PruneArchiveEffectServiceConfig) types.Hash {
	e := codec.NewEncoder(2048)
	e.U16(0)
	for _, id := range []types.Hash{config.InventoryID, config.PolicyID, config.LineageID} {
		e.Fixed(id[:])
	}
	for _, path := range []string{config.InventoryPath, config.ExecutorPath, config.ExecutorPinsPath, config.ChainPath, config.ChainPinsPath, config.AvailabilityPath, config.LineagePath} {
		e.BytesField([]byte(path))
	}
	e.U16(uint16(len(config.Authorities)))
	for _, owner := range config.Authorities {
		e.Fixed(owner.AssignmentID[:])
		e.BytesField([]byte(owner.AuthorityPath))
		e.BytesField([]byte(owner.AuthorityPinsPath))
	}
	e.U16(uint16(len(config.Replicas)))
	for _, replica := range config.Replicas {
		e.Fixed(replica.AssignmentID[:])
		e.BytesField([]byte(replica.Directory))
	}
	e.BytesField(config.Base.Tip.CanonicalBytes())
	root := config.Base.State.Root()
	e.Fixed(root[:])
	e.U16(uint16(len(config.Base.RecentTimestamps)))
	for _, timestamp := range config.Base.RecentTimestamps {
		e.U64(timestamp)
	}
	p := config.Parameters
	e.U32(p.NetworkID)
	e.U64(p.BlockSubsidy)
	e.U64(p.RewardMaturity)
	e.U64(p.ActivationHeight)
	e.U64(p.DifficultyAnchorTimestamp)
	e.Fixed(p.DifficultyAnchorTarget[:])
	e.U64(p.TargetSpacing)
	e.U64(p.ASERTHalfLife)
	e.U16(p.FeeDelay)
	s := config.StoragePolicy
	e.U64(s.MaxHistoryBytes)
	e.U64(s.ForkRetention)
	e.U64(s.CheckpointEvery)
	e.U32(s.CheckpointKeep)
	e.U64(s.CanonicalRetention)
	e.U64(config.Limits.MaximumBlocks)
	e.U32(config.Limits.MaximumChunks)
	e.U64(config.Limits.MaximumBytes)
	return types.DomainHash("OMESH/custody-prune/archive-effect/scope/v0", e.Bytes())
}
