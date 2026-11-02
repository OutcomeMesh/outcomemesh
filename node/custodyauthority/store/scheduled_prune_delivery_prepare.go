package store

import (
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
)

// ValidateScheduledPruneDeliveryIntent checks offline artifacts and transport
// role separation. The receiver review and executor binding remain external
// pins. In particular, a completion's evidence ID is not proof that the outcome
// exists; only the receiving original-owner command path verifies that outcome.
func ValidateScheduledPruneDeliveryIntent(plan ScheduledPrunePlan, inventory *ScheduledPruneInventory, intent scheduledwire.Intent, expectedID types.Hash) error {
	pid, err := plan.ID()
	if err != nil || pid != intent.PlanID {
		return errors.Join(ErrScheduledPruneIntent, err)
	}
	rid, err := plan.Request.ID()
	if err != nil || rid != intent.RequestID {
		return errors.Join(ErrScheduledPruneIntent, err)
	}
	selected, err := plan.Replica(intent.Entry.Command.AssignmentID)
	if err != nil {
		return err
	}
	if err := validateScheduledPruneIntent(selected.Assignment, intent, expectedID); err != nil {
		return err
	}
	for _, replica := range plan.Replicas {
		if err := validatePruneRuntimePeers(replica.Assignment, intent.ClientPeerID, intent.ServerPeerID); err != nil {
			return err
		}
	}
	cmd := intent.Entry.Command
	position := custodyauthority.Position{Sequence: cmd.ExpectedSequence, HeadID: cmd.ExpectedHead}
	var draft custodyauthority.Command
	if cmd.Kind == custodyauthority.Admit {
		if inventory != nil {
			return ErrScheduledPruneIntent
		}
		draft, err = BuildScheduledPruneAdmission(selected.Assignment, selected.Proof, plan.OriginalPolicy, plan.Request, position)
	} else {
		if inventory == nil {
			return ErrScheduledPruneIntent
		}
		iid, e := inventory.ID()
		if e != nil || iid != intent.InventoryID || inventory.ExecutorBindingID != intent.ExecutorBindingID {
			return errors.Join(ErrScheduledPruneIntent, e)
		}
		if err := plan.BindInventory(*inventory); err != nil {
			return err
		}
		draft, err = buildScheduledPruneCompletion(*inventory, cmd.AssignmentID, position, cmd.EvidenceID)
	}
	if err != nil {
		return err
	}
	draft.Signature = cmd.Signature
	if draft != cmd {
		return ErrScheduledPruneIntent
	}
	return nil
}
