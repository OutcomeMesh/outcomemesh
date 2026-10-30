package store

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// ScheduledCustodyReplicaSource identifies the original owners, assignment and
// currently selected receipt. All IDs and policies are operator-pinned inputs.
type ScheduledCustodyReplicaSource struct {
	AuthorityPath, AuthorityPinsPath, JournalPath string
	Assignment                                    custodyauthority.Assignment
	AssignmentID                                  types.Hash
	Schedule                                      CustodyScheduleContext
	Receipt                                       workarchive.ScheduledReplicaReceipt
	ReceiptID                                     types.Hash
	CustodyPolicy                                 workarchive.CustodyPolicy
	JournalLimits                                 workarchive.CustodyJournalLimits
}

// InspectScheduledCustodyQuorum holds every original owner and journal decision
// until the final freshness check. It returns historical inspection evidence;
// it never completes a ticket, grants pruning, changes accounting or publishes
// an archive. Contended, pending, stale and replaced sources fail closed.
func InspectScheduledCustodyQuorum(ctx context.Context, sources []ScheduledCustodyReplicaSource, target workarchive.Checkpoint,
	oldPolicy workarchive.Policy, policy workarchive.ReplicaPolicy, now func() uint64) (_ workarchive.ScheduledAvailabilityBundle, returnErr error) {
	if ctx == nil || now == nil || len(sources) < workarchive.MinimumReplicas || len(sources) > workarchive.MaximumReplicas {
		return workarchive.ScheduledAvailabilityBundle{}, workarchive.ErrAvailability
	}
	// Reject shared or nested roots before taking any source lock.
	var roots []string
	for _, source := range sources {
		for _, root := range []string{source.AuthorityPath, source.AuthorityPinsPath, source.JournalPath} {
			for _, prior := range roots {
				if _, _, err := coordinatorPaths(prior, root); err != nil {
					return workarchive.ScheduledAvailabilityBundle{}, err
				}
			}
			roots = append(roots, root)
		}
	}
	var owners []*Coordinator
	var decisions []*workarchive.CustodyJournalDecision
	defer func() {
		for i := len(decisions) - 1; i >= 0; i-- {
			returnErr = errors.Join(returnErr, decisions[i].Close())
		}
		for i := len(owners) - 1; i >= 0; i-- {
			returnErr = errors.Join(returnErr, owners[i].Close())
		}
	}()
	assignments := make([]custodyauthority.Assignment, 0, len(sources))
	evidence := make([]workarchive.ScheduledReplicaEvidence, 0, len(sources))
	receipts := make([]workarchive.ScheduledReplicaReceipt, 0, len(sources))
	remaining := workarchive.MaximumReceiptLineageBytes
	for _, s := range sources {
		if err := ctx.Err(); err != nil {
			return workarchive.ScheduledAvailabilityBundle{}, err
		}
		scope, _, err := s.Schedule.detached()
		if err != nil {
			return workarchive.ScheduledAvailabilityBundle{}, err
		}
		id, err := s.Receipt.ID()
		if err != nil || id != s.ReceiptID || s.Receipt.ScheduleID != scope.ExpectedID {
			return workarchive.ScheduledAvailabilityBundle{}, workarchive.ErrAvailability
		}
		owner, err := OpenCoordinator(s.AuthorityPath, s.AuthorityPinsPath, s.Assignment, s.AssignmentID)
		if err != nil {
			return workarchive.ScheduledAvailabilityBundle{}, err
		}
		owners = append(owners, owner)
		snapshot, err := owner.Snapshot()
		if err != nil || snapshot.Pending != nil || snapshot.Authority.ScheduleID != scope.ExpectedID || snapshot.Authority.Phase == custodyauthority.Retired {
			return workarchive.ScheduledAvailabilityBundle{}, errors.Join(workarchive.ErrAvailability, err)
		}
		for _, root := range []string{s.AuthorityPath, s.AuthorityPinsPath} {
			if _, _, err := coordinatorPaths(root, s.JournalPath); err != nil {
				return workarchive.ScheduledAvailabilityBundle{}, err
			}
		}
		journal, _, err := workarchive.OpenScheduledCustodyJournal(ctx, s.JournalPath, scope.Proof, s.Assignment, scope.Policy, s.CustodyPolicy, s.JournalLimits)
		if err != nil {
			return workarchive.ScheduledAvailabilityBundle{}, err
		}
		decision, err := journal.AcquireDecision()
		if err != nil {
			return workarchive.ScheduledAvailabilityBundle{}, err
		}
		decisions = append(decisions, decision)
		lineage, selected, err := decision.ScheduleLineage(ctx, scope.Proof, s.Assignment, scope.Policy)
		if err != nil || selected != s.Receipt.Original {
			return workarchive.ScheduledAvailabilityBundle{}, errors.Join(workarchive.ErrAvailability, err)
		}
		for _, raw := range [][]byte{scope.Proof.OriginalManifest, scope.Proof.TargetManifest, lineage.Manifest} {
			if len(raw) > remaining {
				return workarchive.ScheduledAvailabilityBundle{}, workarchive.ErrAvailability
			}
			remaining -= len(raw)
		}
		for _, raw := range lineage.Entries {
			if len(raw) > remaining {
				return workarchive.ScheduledAvailabilityBundle{}, workarchive.ErrAvailability
			}
			remaining -= len(raw)
		}
		assignments = append(assignments, s.Assignment)
		evidence = append(evidence, workarchive.ScheduledReplicaEvidence{Proof: scope.Proof, Lineage: lineage})
		receipts = append(receipts, s.Receipt)
	}
	bundle, err := workarchive.CreateScheduledAvailabilityBundle(ctx, target, oldPolicy, policy, assignments, evidence, receipts, now())
	if err != nil {
		return workarchive.ScheduledAvailabilityBundle{}, err
	}
	// Recheck the retained original paths after all potentially slow replay work.
	for i, owner := range owners {
		snapshot, err := owner.Snapshot()
		if err != nil || snapshot.Pending != nil || snapshot.Authority.ScheduleID != receipts[i].ScheduleID {
			return workarchive.ScheduledAvailabilityBundle{}, errors.Join(workarchive.ErrAvailability, err)
		}
		if err := decisions[i].CheckAccess(); err != nil {
			return workarchive.ScheduledAvailabilityBundle{}, err
		}
	}
	finalTime := now()
	for _, receipt := range receipts {
		if err := receipt.VerifyAvailabilityTime(policy, finalTime); err != nil {
			return workarchive.ScheduledAvailabilityBundle{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return workarchive.ScheduledAvailabilityBundle{}, err
	}
	return bundle, nil
}
