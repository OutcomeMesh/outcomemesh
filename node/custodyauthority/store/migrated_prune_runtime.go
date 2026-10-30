package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type MigratedPruneStorage struct {
	ChainPath, ChainPinsPath string
	MigrationID              types.Hash
	Base                     workchain.Base
	Parameters               workblock.Parameters
	Policy                   workchain.Policy
}
type MigratedPruneConfig struct {
	InventoryPath, ProofPath                                         string
	InventoryID, PolicyID, ScheduleID                                types.Hash
	AuthorityPath, AuthorityPinsPath, ExecutorPath, ExecutorPinsPath string
	EntryPath, OutcomePath, OutcomeKind                              string
	EntryID, OutcomeID                                               types.Hash
	Storage                                                          *MigratedPruneStorage
}
type MigratedPruneReview struct {
	ReviewID       types.Hash
	Authority      Coordination
	Executor       PruneExecution
	Storage        *workchain.StorageProtection
	Outcome        MigratedPruneOutcome
	AlreadyApplied bool
}
type MigratedPruneResult struct {
	Review      MigratedPruneReview
	Commit      *Commit
	Executor    PruneExecution
	Recovered   *workchain.CanonicalPruneCommit
	Observation *MigratedPruneObservation `json:",omitempty"`
}

func LoadMigratedPruneContext(c MigratedPruneConfig) (MigratedPruneContext, error) {
	var v MigratedPruneContext
	var err error
	v.Inventory, err = LoadArchivePruneInventoryFile(c.InventoryPath, c.InventoryID, c.PolicyID)
	if err != nil {
		return v, err
	}
	raw, err := readRegular(c.ProofPath, workarchive.MaximumCustodyScheduleBytes)
	if err != nil {
		return v, err
	}
	v.Proof, err = workarchive.DecodeCustodyScheduleProof(raw)
	if err != nil {
		return v, err
	}
	v.InventoryID, v.PolicyID, v.ScheduleID = c.InventoryID, c.PolicyID, c.ScheduleID
	_, err = v.bindings()
	return v, err
}

// RunMigratedPrune owns the original executor and selected migrated authority for
// one action. It never admits work, executes deletion, infers absence or creates
// replacement stores. Recovery may only retain a matching old storage effect.
func RunMigratedPrune(ctx context.Context, c MigratedPruneConfig, mode string, expected types.Hash) (MigratedPruneResult, error) {
	return runMigratedPrune(ctx, c, mode, expected, storeHooks{})
}
func runMigratedPrune(ctx context.Context, c MigratedPruneConfig, mode string, expected types.Hash, hooks storeHooks) (_ MigratedPruneResult, returnErr error) {
	return runMigratedPruneOwned(ctx, c, mode, expected, hooks, false)
}

// InspectMigratedPrune captures a historical observation while holding the
// original primary owner, confirmed Started executor and migrated storage pair.
// It never resolves the executor, even when a matching committed effect is found.
func InspectMigratedPrune(ctx context.Context, c MigratedPruneConfig) (MigratedPruneResult, error) {
	return runMigratedPruneOwned(ctx, c, "review", types.Hash{}, storeHooks{}, true)
}

func runMigratedPruneOwned(ctx context.Context, c MigratedPruneConfig, mode string, expected types.Hash, hooks storeHooks, inspect bool) (_ MigratedPruneResult, returnErr error) {
	var result MigratedPruneResult
	if inspect && (mode != "review" || c.Storage == nil || c.EntryPath != "" || c.OutcomePath != "") {
		return result, ErrPruneObservation
	}
	if ctx == nil || (mode != "review" && mode != "apply" && mode != "resume" && mode != "resume-executor" && mode != "recover-effect" && mode != "cancel-before-start") || (mode == "review") != expected.IsZero() {
		return result, ErrMigratedPrune
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if c.Storage != nil {
		copy := *c.Storage
		c.Storage = &copy
		if mode != "review" && mode != "recover-effect" {
			return result, ErrMigratedPrune
		}
	}
	if mode == "recover-effect" && c.Storage == nil {
		return result, ErrMigratedPrune
	}
	for _, p := range []*string{&c.InventoryPath, &c.ProofPath, &c.AuthorityPath, &c.AuthorityPinsPath, &c.ExecutorPath, &c.ExecutorPinsPath, &c.EntryPath, &c.OutcomePath} {
		if *p != "" {
			path, err := storePath(*p)
			if err != nil {
				return result, err
			}
			*p = path
		}
	}
	v, err := LoadMigratedPruneContext(c)
	if err != nil {
		return result, err
	}
	b, _ := v.bindings()
	roots := []string{c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath}
	if c.Storage != nil {
		roots = append(roots, c.Storage.ChainPath, c.Storage.ChainPinsPath)
	}
	if err := scheduledPrunePlacement(roots, []string{c.InventoryPath, c.ProofPath, c.EntryPath, c.OutcomePath}, ""); err != nil {
		return result, err
	}
	var entry custodyauthority.Entry
	if c.EntryPath != "" {
		if mode == "resume-executor" || mode == "recover-effect" || mode == "cancel-before-start" || c.Storage != nil {
			return result, ErrMigratedPrune
		}
		raw, err := readRegular(c.EntryPath, custodyauthority.MaximumEntryBytes)
		if err != nil {
			return result, err
		}
		entry, err = custodyauthority.DecodeEntry(raw)
		if err != nil {
			return result, err
		}
		id, _ := entry.ID()
		if c.EntryID.IsZero() || id != c.EntryID {
			return result, ErrMigratedPrune
		}
	} else if !c.EntryID.IsZero() || mode == "apply" || mode == "resume" {
		return result, ErrMigratedPrune
	}
	var supplied MigratedPruneOutcome
	if c.OutcomePath != "" {
		if c.EntryPath == "" {
			return result, ErrMigratedPrune
		}
		supplied, err = LoadMigratedPruneOutcome(c.OutcomePath, c.OutcomeKind, c.OutcomeID)
		if err != nil {
			return result, err
		}
	} else if !c.OutcomeID.IsZero() || c.OutcomeKind != "" || c.EntryPath != "" {
		return result, ErrMigratedPrune
	}
	e, err := OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, b.primary, v.Inventory.Policy.RequestID)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, e.Close()) }()
	e.hooks, e.pins.hooks = hooks, hooks
	owner, err := OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, b.selected, v.Proof.AssignmentID)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
	setCoordinatorRuntimeHooks(owner, hooks)
	authority, err := owner.Snapshot()
	if err != nil {
		return result, err
	}
	if authority.Authority.ScheduleID != v.ScheduleID {
		return result, ErrMigratedPrune
	}
	snapshot, err := e.Snapshot()
	if err != nil {
		return result, err
	}
	retained := snapshot
	if snapshot.Protection.Pending != nil {
		retained = e.pins.next
	}
	if snapshot.Protection.BindingID != v.Inventory.Policy.ExecutorBindingID || retained.Admission == nil || *retained.Admission != b.primaryEntry || !samePruneRequest(retained.Request, v.Inventory.Request) {
		return result, ErrMigratedPrune
	}
	// Even a signed inventory is insufficient: the original selected ticket must
	// exist in the actual owner history with its original operation and consumer.
	found := false
	for _, op := range authority.Authority.Operations {
		if op.TicketID == b.ticket && op.OperationID == v.Inventory.Policy.RequestID && op.ConsumerPublicKey == v.Inventory.Request.ConsumerPublicKey && op.Purpose == custodyauthority.Prune {
			if c.EntryPath != "" && !op.CompletionID.IsZero() && (op.CompletionID != c.EntryID || op.EvidenceID != c.OutcomeID) {
				return result, ErrPruneCompletion
			}
			found = true
		}
	}
	if !found {
		return result, custodyauthority.ErrOperation
	}
	outcome, outcomeErr := migratedPruneRetained(v, snapshot)
	already := false
	if c.EntryPath != "" {
		if outcomeErr != nil || !sameMigratedOutcome(outcome, supplied) {
			return result, ErrPruneOutcome
		}
		cmd := entry.Command
		draft, err := BuildMigratedPruneCompletion(v, supplied, custodyauthority.Position{Sequence: cmd.ExpectedSequence, HeadID: cmd.ExpectedHead})
		if err != nil {
			return result, err
		}
		draft.Signature = cmd.Signature
		if draft != cmd || entry.AuthorityPublicKey != b.selected.AuthorityPublicKey {
			return result, ErrPruneCompletion
		}
		if authority.Pending != nil && *authority.Pending != entry {
			return result, ErrPendingAttempt
		}
		if authority.Pending == nil && cmd.ExpectedSequence < authority.Confirmed.Sequence {
			if err := retainedCustodyCommand(owner, entry, false); err != nil {
				return result, err
			}
			already = true
		} else if authority.Pending == nil && (cmd.ExpectedSequence != authority.Confirmed.Sequence || cmd.ExpectedHead != authority.Confirmed.HeadID) {
			return result, custodyauthority.ErrHead
		}
	}
	var chain *workchain.Store
	var protection *workchain.StorageProtection
	if c.Storage != nil {
		s := c.Storage
		if s.Base.State == nil || s.MigrationID.IsZero() || s.Parameters.RadixActivationHeight != v.Proof.TargetCheckpoint.Statement.RadixActivationHeight {
			return result, ErrMigratedPrune
		}
		chain, err = workchain.OpenRadixMigratedPositionPinnedWithPolicy(s.ChainPath, s.ChainPinsPath, s.Base, s.Parameters, s.Policy, v.Inventory.Request.StorageID, s.MigrationID)
		if err != nil {
			return result, err
		}
		defer func() { returnErr = errors.Join(returnErr, chain.Close()) }()
		state, err := chain.StorageProtection()
		if err != nil {
			return result, err
		}
		if state.PairID != v.Inventory.Policy.StoragePairID {
			return result, ErrMigratedPrune
		}
		protection = &state
	}
	if inspect {
		if err := hooks.reach("prune-observation-before-read"); err != nil {
			return result, err
		}
		observation, err := inspectMigratedPruneOwned(ctx, v, c.Storage.MigrationID, e, owner, chain)
		if err != nil {
			return result, err
		}
		if err := hooks.reach("prune-observation-after-read"); err != nil {
			return result, err
		}
		// Recheck original identities and confirmed positions after the read. No
		// handle escapes this call, and all three process locks remain held.
		check, err := inspectMigratedPruneOwned(ctx, v, c.Storage.MigrationID, e, owner, chain)
		if err != nil {
			return result, err
		}
		id, _ := observation.ID()
		cid, _ := check.ID()
		if id != cid {
			return result, ErrPruneObservation
		}
		result.Observation = &observation
	}
	review := MigratedPruneReview{Authority: authority, Executor: snapshot, Storage: protection, AlreadyApplied: already}
	if outcomeErr == nil {
		review.Outcome = outcome
	}
	enc := codec.NewEncoder(4096)
	for _, h := range []types.Hash{c.InventoryID, c.PolicyID, c.ScheduleID, c.EntryID, c.OutcomeID, authority.Confirmed.HeadID, authority.Authority.HeadID, snapshot.Protection.BindingID, snapshot.Protection.Confirmed.HeadID, snapshot.ArchiveInventoryID} {
		enc.Fixed(h[:])
	}
	for _, n := range []uint64{authority.Confirmed.Sequence, authority.Authority.Sequence, uint64(snapshot.Stage), uint64(snapshot.Protection.Confirmed.Stage)} {
		enc.U64(n)
	}
	var pending types.Hash
	if authority.Pending != nil {
		pending, _ = authority.Pending.ID()
	}
	enc.Fixed(pending[:])
	if snapshot.Protection.Pending != nil {
		enc.U16(uint16(snapshot.Protection.Pending.Stage))
		enc.Fixed(snapshot.Protection.Pending.HeadID[:])
	} else {
		enc.U16(0)
	}
	for _, path := range []string{c.InventoryPath, c.ProofPath, c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath, c.EntryPath, c.OutcomePath, c.OutcomeKind} {
		enc.BytesField([]byte(path))
	}
	if protection != nil {
		enc.U16(1)
		enc.Fixed(c.Storage.MigrationID[:])
		enc.Fixed(protection.PairID[:])
		enc.Fixed(protection.Confirmed.CommitID[:])
		enc.U64(protection.Confirmed.Sequence)
		enc.Fixed(protection.Database.CommitID[:])
		enc.U64(protection.Database.Sequence)
		if protection.Pending != nil {
			enc.U16(1)
			enc.Fixed(protection.Pending.CommitID[:])
			enc.U64(protection.Pending.Sequence)
		} else {
			enc.U16(0)
		}
		p := c.Storage.Policy
		for _, n := range []uint64{p.MaxHistoryBytes, p.ForkRetention, p.CheckpointEvery, uint64(p.CheckpointKeep), p.CanonicalRetention} {
			enc.U64(n)
		}
		enc.BytesField([]byte(c.Storage.ChainPath))
		enc.BytesField([]byte(c.Storage.ChainPinsPath))
	} else {
		enc.U16(0)
	}
	if inspect {
		id, _ := result.Observation.ID()
		enc.Fixed(id[:])
		review.ReviewID = types.DomainHash("OMESH/local/migrated-prune-observation-review/v0", enc.Bytes())
	} else {
		review.ReviewID = types.DomainHash("OMESH/local/migrated-prune-review/v0", enc.Bytes())
	}
	result.Review, result.Executor = review, snapshot
	if mode == "review" {
		return result, ctx.Err()
	}
	if expected != review.ReviewID {
		return result, ErrPruneRecoveryReview
	}
	if mode == "cancel-before-start" {
		if authority.Pending != nil || v.Proof.AssignmentID != v.Inventory.Request.AssignmentID {
			return result, ErrMigratedPrune
		}
		if err := resyncMigratedPrune(ctx, c, v); err != nil {
			return result, err
		}
		if err := cancelMigratedPruneBeforeStart(ctx, e, owner, v, b); err != nil {
			return result, err
		}
	} else if mode == "resume-executor" {
		if authority.Pending != nil || snapshot.Protection.Pending == nil || v.Proof.AssignmentID != v.Inventory.Request.AssignmentID {
			return result, ErrPrunePinPending
		}
		next := e.pins.next
		switch next.Stage {
		case PruneStarted:
			if next.ArchiveInventoryID != v.InventoryID {
				return result, ErrMigratedPrune
			}
		case PruneSucceeded, PruneCancelled:
			next.Protection = &PruneProtection{BindingID: snapshot.Protection.BindingID}
			if _, err := migratedPruneRetained(v, next); err != nil {
				return result, err
			}
		default:
			return result, ErrPrunePinPending
		}
		if err := resyncMigratedPrune(ctx, c, v); err != nil {
			return result, err
		}
		if err := e.ResumePinnedTransition(ctx); err != nil {
			return result, err
		}
	} else if mode == "recover-effect" {
		if protection == nil || protection.Pending != nil || authority.Pending != nil || snapshot.Protection.Pending != nil || v.Proof.AssignmentID != v.Inventory.Request.AssignmentID || snapshot.ArchiveInventoryID != v.InventoryID || (snapshot.Stage != PruneStarted && snapshot.Stage != PruneSucceeded) {
			return result, ErrPruneOutcome
		}
		if err := resyncMigratedPrune(ctx, c, v); err != nil {
			return result, err
		}
		if err := hooks.reach("migrated-prune-before-recovery"); err != nil {
			return result, err
		}
		if _, err := owner.Snapshot(); err != nil {
			return result, err
		}
		commit, err := e.Recover(ctx, chain)
		if err != nil {
			return result, err
		}
		result.Recovered = &commit
	} else {
		if snapshot.Protection.Pending != nil {
			return result, ErrPrunePinPending
		}
		if mode == "apply" && authority.Pending != nil {
			return result, ErrPendingAttempt
		}
		if mode == "resume" && authority.Pending == nil {
			return result, ErrNoAttempt
		}
		if err := resyncMigratedPrune(ctx, c, v); err != nil {
			return result, err
		}
		raw, _ := entry.CanonicalBytes()
		if err := publishCustodyArtifactBytes(ctx, c.EntryPath, raw); err != nil {
			return result, err
		}
		raw, _ = supplied.Artifact()
		if err := publishCustodyArtifactBytes(ctx, c.OutcomePath, raw); err != nil {
			return result, err
		}
		if err := hooks.reach("migrated-prune-before-complete"); err != nil {
			return result, err
		}
		commit, err := owner.Append(ctx, entry)
		if err != nil {
			return result, err
		}
		result.Commit = &commit
	}
	result.Executor, err = e.Snapshot()
	return result, err
}
func resyncMigratedPrune(ctx context.Context, c MigratedPruneConfig, v MigratedPruneContext) error {
	inventory, err := v.Inventory.CanonicalBytes()
	if err != nil {
		return err
	}
	proof, err := v.Proof.CanonicalBytes()
	if err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		raw  []byte
	}{{c.InventoryPath, inventory}, {c.ProofPath, proof}} {
		if err := publishCustodyArtifactBytes(ctx, item.path, item.raw); err != nil {
			return err
		}
	}
	return nil
}

// The original pinned executor may choose cancellation only before any retained
// start. The migrated owner guard binds the unchanged original ticket to its
// current schedule; the cancellation record and request keep their old bytes.
func cancelMigratedPruneBeforeStart(ctx context.Context, e *PruneExecutor, owner *Coordinator, v MigratedPruneContext, b migratedPruneBindings) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.cancellationCheck(ctx); err != nil {
		return err
	}
	if e.stage == PruneCancelled {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := e.checkAuthorityRoots(owner); err != nil {
		return err
	}
	binding := OperationBinding{AssignmentID: v.Proof.AssignmentID, ScheduleID: v.ScheduleID, TicketID: b.ticket, ConsumerPublicKey: v.Inventory.Request.ConsumerPublicKey, OperationID: v.Inventory.Policy.RequestID, Purpose: custodyauthority.Prune}
	return owner.withOperation(ctx, binding, func() error {
		cancellation := PruneCancellation{AssignmentID: e.request.AssignmentID, RequestID: e.id, TicketID: b.ticket, BindingID: e.pins.binding}
		raw, err := cancellation.CanonicalBytes()
		if err != nil {
			return err
		}
		if err := e.publish(ctx, 1, raw, "prune-cancel"); err != nil {
			return err
		}
		e.stage, e.cancellation = PruneCancelled, &cancellation
		return e.applied("prune-cancel")
	})
}
