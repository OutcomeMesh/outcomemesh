package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type ScheduledPruneCommandConfig struct {
	PlanPath                                                         string
	PlanID, AssignmentID                                             types.Hash
	AuthorityPath, AuthorityPinsPath, ExecutorPath, ExecutorPinsPath string
	EntryPath                                                        string
	EntryID                                                          types.Hash
	InventoryPath                                                    string
	InventoryID                                                      types.Hash
	JournalPath                                                      string
	CustodyPolicy                                                    workarchive.CustodyPolicy
	JournalLimits                                                    workarchive.CustodyJournalLimits
}
type ScheduledPruneCommandReview struct {
	ReviewID, PlanID, EntryID types.Hash
	Authority                 Coordination
	Executor                  PruneExecution
	JournalSequence           uint64
	JournalHeadID, ReceiptID  types.Hash
	AlreadyApplied            bool
}
type ScheduledPruneCommandResult struct {
	Review   ScheduledPruneCommandReview
	Commit   *Commit
	Executor PruneExecution
}

func scheduledPrunePlacement(roots, files []string, out string) error {
	for i, root := range roots {
		for j := 0; j < i; j++ {
			if _, _, err := coordinatorPaths(root, roots[j]); err != nil {
				return err
			}
		}
		for _, file := range files {
			if file != "" && workarchive.CustodyEvidencePathsOverlap(root, file) {
				return ErrRootOverlap
			}
		}
		if out != "" && workarchive.CustodyEvidencePathsOverlap(root, filepath.Dir(out)) {
			return ErrRootOverlap
		}
	}
	if out != "" {
		for _, file := range files {
			if file != "" && workarchive.CustodyEvidencePathsOverlap(out, file) {
				return ErrRootOverlap
			}
		}
	}
	return nil
}

// RunScheduledPruneCommand opens original owners for one reviewed action. It
// never signs, creates owners, executes deletion or infers a missing result.
// Resume applies only the supplied exact pending command; resume-executor only
// confirms the existing inventory-bound start/result and cannot execute it.
func RunScheduledPruneCommand(ctx context.Context, c ScheduledPruneCommandConfig, mode string, expected types.Hash) (ScheduledPruneCommandResult, error) {
	return runScheduledPruneCommand(ctx, c, mode, expected, storeHooks{})
}
func runScheduledPruneCommand(ctx context.Context, c ScheduledPruneCommandConfig, mode string, expected types.Hash, hooks storeHooks) (_ ScheduledPruneCommandResult, returnErr error) {
	var result ScheduledPruneCommandResult
	if ctx == nil || (mode != "review" && mode != "apply" && mode != "resume" && mode != "resume-executor") || (mode == "review") != expected.IsZero() {
		return result, ErrScheduledPrune
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	for _, p := range []*string{&c.PlanPath, &c.AuthorityPath, &c.AuthorityPinsPath, &c.ExecutorPath, &c.ExecutorPinsPath, &c.EntryPath, &c.InventoryPath, &c.JournalPath} {
		if *p != "" {
			path, err := storePath(*p)
			if err != nil {
				return result, err
			}
			*p = path
		}
	}
	plan, err := LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
	if err != nil {
		return result, err
	}
	selected, err := plan.Replica(c.AssignmentID)
	if err != nil {
		return result, err
	}
	primary, err := plan.Replica(plan.Request.AssignmentID)
	if err != nil {
		return result, err
	}
	rid, _ := plan.Request.ID()
	var entry custodyauthority.Entry
	if c.EntryPath != "" {
		raw, err := readRegular(c.EntryPath, custodyauthority.MaximumEntryBytes)
		if err != nil {
			return result, err
		}
		entry, err = custodyauthority.DecodeEntry(raw)
		if err != nil {
			return result, err
		}
		id, _ := entry.ID()
		if c.EntryID.IsZero() || id != c.EntryID || entry.Command.AssignmentID != c.AssignmentID || entry.AuthorityPublicKey != selected.Assignment.AuthorityPublicKey {
			return result, ErrScheduledPrune
		}
	} else if !c.EntryID.IsZero() || mode == "apply" || mode == "resume" {
		return result, ErrScheduledPrune
	}
	if c.JournalPath != "" && (c.EntryPath == "" || entry.Command.Kind != custodyauthority.Admit) {
		return result, ErrScheduledPrune
	}
	roots := []string{c.ExecutorPath, c.ExecutorPinsPath, c.AuthorityPath, c.AuthorityPinsPath}
	if c.JournalPath != "" {
		roots = append(roots, c.JournalPath)
	}
	files := []string{c.PlanPath, c.EntryPath, c.InventoryPath}
	if err := scheduledPrunePlacement(roots, files, ""); err != nil {
		return result, err
	}
	executor, err := OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, primary.Assignment, rid)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, executor.Close()) }()
	executor.hooks = hooks
	executor.pins.hooks = hooks
	owner, err := OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, selected.Assignment, c.AssignmentID)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
	setCoordinatorRuntimeHooks(owner, hooks)
	authority, err := owner.Snapshot()
	if err != nil {
		return result, err
	}
	scope, _ := selected.Proof.ID()
	if authority.Authority.ScheduleID != scope {
		return result, ErrScheduledPrune
	}
	snapshot, err := executor.Snapshot()
	if err != nil {
		return result, err
	}
	var inventory ScheduledPruneInventory
	if c.InventoryPath != "" {
		inventory, err = LoadScheduledPruneInventory(c.InventoryPath, c.InventoryID)
		if err != nil {
			return result, err
		}
		if err := plan.BindInventory(inventory); err != nil {
			return result, err
		}
		if inventory.ExecutorBindingID != snapshot.Protection.BindingID {
			return result, ErrScheduledPrune
		}
	} else if !c.InventoryID.IsZero() {
		return result, ErrScheduledPrune
	}
	already := false
	if c.EntryPath != "" {
		cmd := entry.Command
		pos := custodyauthority.Position{Sequence: cmd.ExpectedSequence, HeadID: cmd.ExpectedHead}
		var draft custodyauthority.Command
		switch cmd.Kind {
		case custodyauthority.Admit:
			if c.InventoryPath != "" {
				return result, ErrScheduledPrune
			}
			draft, err = BuildScheduledPruneAdmission(selected.Assignment, selected.Proof, plan.OriginalPolicy, plan.Request, pos)
		case custodyauthority.Complete:
			if c.InventoryPath == "" || snapshot.Stage != PruneSucceeded || snapshot.Effect == nil || snapshot.ArchiveInventoryID != c.InventoryID || snapshot.Protection.Pending != nil || c.JournalPath != "" {
				return result, ErrPruneOutcome
			}
			draft, err = BuildScheduledPruneCompletion(plan, inventory, *snapshot.Effect, c.AssignmentID, pos)
		default:
			return result, ErrScheduledPrune
		}
		if err != nil {
			return result, err
		}
		draft.Signature = cmd.Signature
		if draft != cmd {
			return result, ErrScheduledPrune
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
	var decision *workarchive.CustodyJournalDecision
	var journal workarchive.CustodyJournalState
	// A historical exact retry has no authority to renew or require new evidence.
	freshAdmission := c.EntryPath != "" && entry.Command.Kind == custodyauthority.Admit && !already && authority.Pending == nil
	if freshAdmission {
		if c.JournalPath == "" || c.JournalLimits.Validate() != nil {
			return result, ErrScheduledPrune
		}
		j, _, err := workarchive.OpenScheduledCustodyJournal(ctx, c.JournalPath, selected.Proof, selected.Assignment, plan.OriginalPolicy, c.CustodyPolicy, c.JournalLimits)
		if err != nil {
			return result, err
		}
		decision, err = j.AcquireDecision()
		if err != nil {
			return result, err
		}
		defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
		lineage, receipt, err := decision.ScheduleLineage(ctx, selected.Proof, selected.Assignment, plan.OriginalPolicy)
		if err != nil || receipt != selected.Receipt.Original {
			return result, errors.Join(ErrScheduledPrune, err)
		}
		if err := selected.Receipt.Verify(ctx, selected.Proof, selected.Assignment, plan.OriginalPolicy, lineage); err != nil {
			return result, err
		}
		journal, err = decision.State()
		if err != nil {
			return result, err
		}
	}
	review := ScheduledPruneCommandReview{PlanID: c.PlanID, EntryID: c.EntryID, Authority: authority, Executor: snapshot, JournalSequence: journal.Sequence, JournalHeadID: journal.HeadEntryID, AlreadyApplied: already}
	if freshAdmission {
		review.ReceiptID, _ = journal.CurrentReceipt.ID()
	}
	e := codec.NewEncoder(2048)
	for _, h := range []types.Hash{c.PlanID, c.AssignmentID, c.EntryID, c.InventoryID, authority.Confirmed.HeadID, authority.Authority.HeadID, snapshot.Protection.BindingID, snapshot.Protection.Confirmed.HeadID, snapshot.ArchiveInventoryID, review.JournalHeadID, review.ReceiptID} {
		e.Fixed(h[:])
	}
	for _, n := range []uint64{authority.Confirmed.Sequence, authority.Authority.Sequence, uint64(snapshot.Stage), uint64(snapshot.Protection.Confirmed.Stage), review.JournalSequence, c.JournalLimits.MaximumBytes, c.JournalLimits.MaximumPaths} {
		e.U64(n)
	}
	var pending types.Hash
	if authority.Pending != nil {
		pending, _ = authority.Pending.ID()
	}
	e.Fixed(pending[:])
	if snapshot.Protection.Pending != nil {
		e.U16(uint16(snapshot.Protection.Pending.Stage))
		e.Fixed(snapshot.Protection.Pending.HeadID[:])
	} else {
		e.U16(0)
	}
	for _, path := range []string{c.PlanPath, c.EntryPath, c.InventoryPath, c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath, c.JournalPath} {
		e.BytesField([]byte(path))
	}
	review.ReviewID = types.DomainHash("OMESH/local/scheduled-prune-command-review/v0", e.Bytes())
	result.Review = review
	result.Executor = snapshot
	if mode == "review" {
		return result, ctx.Err()
	}
	if expected != review.ReviewID {
		return result, ErrPruneArchiveEffectReview
	}
	if mode == "resume-executor" {
		if c.EntryPath != "" || c.AssignmentID != plan.Request.AssignmentID || authority.Pending != nil || c.InventoryPath == "" || snapshot.Protection.Pending == nil {
			return result, ErrPrunePinPending
		}
		next := executor.pins.next
		if (next.Stage != PruneStarted && next.Stage != PruneSucceeded) || next.ArchiveInventoryID != c.InventoryID || next.Admission == nil {
			return result, ErrPrunePinPending
		}
		found := false
		for _, s := range inventory.Replicas {
			aid, _ := s.Assignment.ID()
			if aid == c.AssignmentID && s.Admission == *next.Admission {
				found = true
			}
		}
		if !found {
			return result, ErrScheduledPrune
		}
		if err := SaveScheduledPruneInventory(ctx, c.InventoryPath, inventory, c.InventoryID); err != nil {
			return result, err
		}
		if err := executor.ResumePinnedTransition(ctx); err != nil {
			return result, err
		}
		result.Executor, err = executor.Snapshot()
		return result, err
	}
	pendingAttempt := authority.Pending != nil || snapshot.Protection.Pending != nil
	if mode == "apply" && pendingAttempt {
		return result, ErrPendingAttempt
	}
	if mode == "resume" && !pendingAttempt {
		return result, ErrNoAttempt
	}
	if snapshot.Protection.Pending != nil && (entry.Command.Kind != custodyauthority.Admit || c.AssignmentID != plan.Request.AssignmentID || executor.pins.next.Stage != PruneAdmitted || !bytes.Equal(executor.pins.pending, mustScheduledEntryBytes(entry))) {
		return result, ErrPrunePinPending
	}
	for _, file := range []struct {
		path string
		raw  []byte
	}{{c.PlanPath, mustScheduledPlanBytes(plan)}, {c.EntryPath, mustScheduledEntryBytes(entry)}} {
		if err := publishCustodyArtifactBytes(ctx, file.path, file.raw); err != nil {
			return result, err
		}
	}
	if decision != nil {
		if err := decision.CheckAccess(); err != nil {
			return result, err
		}
	}
	if err := hooks.reach("scheduled-command-before-apply"); err != nil {
		return result, err
	}
	if decision != nil {
		if err := decision.CheckAccess(); err != nil {
			return result, err
		}
	}
	var commit Commit
	if entry.Command.Kind == custodyauthority.Complete {
		commit, err = executor.CompleteScheduledArchiveReplica(ctx, owner, c.InventoryPath, c.InventoryID, entry)
	} else if c.AssignmentID == plan.Request.AssignmentID {
		commit, err = executor.Admit(ctx, owner, entry)
	} else {
		if snapshot.Protection.Pending != nil {
			return result, ErrPrunePinPending
		}
		commit, err = owner.Append(ctx, entry)
	}
	if err != nil {
		return result, err
	}
	result.Commit = &commit
	result.Executor, err = executor.Snapshot()
	return result, err
}

func mustScheduledPlanBytes(p ScheduledPrunePlan) []byte      { b, _ := p.CanonicalBytes(); return b }
func mustScheduledEntryBytes(e custodyauthority.Entry) []byte { b, _ := e.CanonicalBytes(); return b }
func setCoordinatorRuntimeHooks(c *Coordinator, h storeHooks) {
	setAuthorityHooks(c.authority, h)
	c.journal.hooks = h
}
