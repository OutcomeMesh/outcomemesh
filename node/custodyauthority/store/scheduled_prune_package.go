package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

type ScheduledPruneAdmissionSource struct {
	AssignmentID                                types.Hash
	AuthorityPath, AuthorityPinsPath, EntryPath string
	EntryID                                     types.Hash
}
type ScheduledPrunePackageConfig struct {
	PlanPath                       string
	PlanID                         types.Hash
	ExecutorPath, ExecutorPinsPath string
	Sources                        []ScheduledPruneAdmissionSource
}

// PackageScheduledPruneInventory proves that every supplied admission exists as
// pending work under its original owner. The package is not an execution grant.
// Publication is immutable and remains inside all original operation guards.
func PackageScheduledPruneInventory(ctx context.Context, c ScheduledPrunePackageConfig, out string, expected types.Hash) (_ ScheduledPruneInventory, returnErr error) {
	var empty ScheduledPruneInventory
	if ctx == nil || (out == "") != expected.IsZero() {
		return empty, ErrScheduledPrune
	}
	plan, err := LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
	if err != nil {
		return empty, err
	}
	if len(c.Sources) != len(plan.Replicas) {
		return empty, ErrScheduledPrune
	}
	roots := []string{c.ExecutorPath, c.ExecutorPinsPath}
	files := []string{c.PlanPath}
	for _, s := range c.Sources {
		roots = append(roots, s.AuthorityPath, s.AuthorityPinsPath)
		files = append(files, s.EntryPath)
	}
	if err := scheduledPrunePlacement(roots, files, out); err != nil {
		return empty, err
	}
	primary, err := plan.Replica(plan.Request.AssignmentID)
	if err != nil {
		return empty, err
	}
	rid, _ := plan.Request.ID()
	executor, err := OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, primary.Assignment, rid)
	if err != nil {
		return empty, err
	}
	defer func() { returnErr = errors.Join(returnErr, executor.Close()) }()
	snapshot, err := executor.Snapshot()
	if err != nil {
		return empty, err
	}
	if snapshot.Stage != PruneAdmitted || snapshot.Protection.Pending != nil || snapshot.Admission == nil {
		return empty, ErrPruneStage
	}
	v := ScheduledPruneInventory(plan)
	v.Replicas = append([]ScheduledPruneReplica(nil), plan.Replicas...)
	v.ExecutorBindingID = snapshot.Protection.BindingID
	var owners []*Coordinator
	defer func() {
		for i := len(owners) - 1; i >= 0; i-- {
			returnErr = errors.Join(returnErr, owners[i].Close())
		}
	}()
	var operations []RequiredOperation
	seen := make(map[types.Hash]bool)
	for _, source := range c.Sources {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		s, err := plan.Replica(source.AssignmentID)
		if err != nil || seen[source.AssignmentID] {
			return empty, ErrScheduledPrune
		}
		seen[source.AssignmentID] = true
		raw, err := readRegular(source.EntryPath, custodyauthority.MaximumEntryBytes)
		if err != nil {
			return empty, err
		}
		entry, err := custodyauthority.DecodeEntry(raw)
		if err != nil {
			return empty, err
		}
		id, _ := entry.ID()
		if source.EntryID.IsZero() || id != source.EntryID {
			return empty, ErrScheduledPrune
		}
		command := entry.Command
		draft, err := BuildScheduledPruneAdmission(s.Assignment, s.Proof, plan.OriginalPolicy, plan.Request, custodyauthority.Position{Sequence: command.ExpectedSequence, HeadID: command.ExpectedHead})
		if err != nil {
			return empty, err
		}
		draft.Signature = command.Signature
		if draft != command || entry.AuthorityPublicKey != s.Assignment.AuthorityPublicKey {
			return empty, ErrScheduledPrune
		}
		if source.AssignmentID == plan.Request.AssignmentID && entry != *snapshot.Admission {
			return empty, ErrScheduledPrune
		}
		owner, err := OpenCoordinator(source.AuthorityPath, source.AuthorityPinsPath, s.Assignment, source.AssignmentID)
		if err != nil {
			return empty, err
		}
		owners = append(owners, owner)
		for i := range v.Replicas {
			aid, _ := v.Replicas[i].Assignment.ID()
			if aid == source.AssignmentID {
				v.Replicas[i].Admission = entry
			}
		}
		operations = append(operations, RequiredOperation{Coordinator: owner, Binding: OperationBinding{AssignmentID: source.AssignmentID, ScheduleID: command.ScheduleID, TicketID: id, ConsumerPublicKey: command.ActorPublicKey, OperationID: rid, Purpose: custodyauthority.Prune}})
	}
	err = withRequiredOperations(ctx, operations, func() error {
		id, err := v.ID()
		if err != nil {
			return err
		}
		if out != "" {
			if expected != id {
				return ErrPruneArchiveEffectReview
			}
			return SaveScheduledPruneInventory(ctx, out, v, expected)
		}
		return ctx.Err()
	})
	if err != nil {
		return empty, err
	}
	return v, nil
}
