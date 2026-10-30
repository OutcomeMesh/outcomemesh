package store

import (
	"context"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func inspectMigratedPruneOwned(ctx context.Context, c MigratedPruneContext, migrationID types.Hash, e *PruneExecutor, owner *Coordinator, chain *workchain.Store) (MigratedPruneObservation, error) {
	var o MigratedPruneObservation
	if err := ctx.Err(); err != nil {
		return o, err
	}
	s, err := e.Snapshot()
	if err != nil {
		return o, err
	}
	a, err := owner.Snapshot()
	if err != nil {
		return o, err
	}
	if s.Stage != PruneStarted || s.Protection == nil || s.Protection.Pending != nil ||
		s.Protection.Confirmed.Stage != PruneStarted || s.Admission == nil || s.Effect != nil || s.Cancellation != nil ||
		s.ArchiveInventoryID != c.InventoryID || s.Protection.BindingID != c.Inventory.Policy.ExecutorBindingID ||
		a.Pending != nil || a.Confirmed != (custodyauthority.Position{Sequence: a.Authority.Sequence, HeadID: a.Authority.HeadID}) ||
		a.Authority.ScheduleID != c.ScheduleID || a.Authority.AssignmentID != s.Request.AssignmentID {
		return o, ErrPruneObservation
	}
	ticket, err := s.Admission.ID()
	if err != nil {
		return o, err
	}
	open := false
	for _, op := range a.Authority.Operations {
		if op.TicketID == ticket && op.OperationID == s.RequestID && op.ConsumerPublicKey == s.Request.ConsumerPublicKey && op.Purpose == custodyauthority.Prune && op.CompletionID.IsZero() && op.EvidenceID.IsZero() {
			open = true
		}
	}
	if !open {
		return o, ErrPruneObservation
	}
	if err := chain.VerifyContext(e.assignment.NetworkID, e.assignment.ActivationHeight, e.assignment.BaseID); err != nil {
		return o, err
	}
	inspection, err := chain.InspectCanonicalPrune(ticket)
	if err != nil {
		return o, err
	}
	o = MigratedPruneObservation{InventoryID: c.InventoryID, PolicyID: c.PolicyID, ScheduleID: c.ScheduleID,
		AssignmentID: s.Request.AssignmentID, RequestID: s.RequestID, TicketID: ticket,
		ExecutorBindingID: s.Protection.BindingID, ExecutorHeadID: s.Protection.Confirmed.HeadID,
		StorageID: inspection.Storage.StorageID, StoragePairID: inspection.Storage.PairID,
		StorageMigrationID: migrationID, StoragePosition: inspection.Storage.Confirmed,
		Authority: a.Confirmed, AuthorityPhase: a.Authority.Phase,
		RadixActivationHeight: c.Proof.TargetCheckpoint.Statement.RadixActivationHeight, Effect: inspection.Effect}
	if err := o.Verify(c, migrationID); err != nil {
		return MigratedPruneObservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return MigratedPruneObservation{}, err
	}
	return o, nil
}
