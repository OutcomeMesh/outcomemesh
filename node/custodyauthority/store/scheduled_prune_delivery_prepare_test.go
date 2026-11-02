package store

import (
	"testing"

	"github.com/outcomemesh/outcomemesh/node/transport"
)

func TestPruneScheduledDeliveryPreparationRejectsSubstitutions(t *testing.T) {
	f := newScheduledPruneOperatorFixture(t)
	host, client := completionHosts(t)
	i := scheduledDeliveryIntent(t, f.config[0], host, client)
	id, _ := i.ID()
	if err := ValidateScheduledPruneDeliveryIntent(f.plan, nil, i, id); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"plan", "request", "pin", "inventory", "ticket", "operation", "schedule", "signature", "entry-signature", "same-peer", "other-replica-role"} {
		t.Run(field, func(t *testing.T) {
			bad := i
			cmd := bad.Entry.Command
			switch field {
			case "plan":
				bad.PlanID = testHash(240)
			case "request":
				bad.RequestID = testHash(240)
			case "inventory":
				bad.InventoryID = testHash(240)
			case "ticket":
				bad.Entry.Command.TicketID = testHash(240)
			case "operation":
				cmd.OperationID = testHash(240)
			case "schedule":
				cmd.ScheduleID = testHash(240)
			case "signature":
				bad.Entry.Command.Signature[0] ^= 1
			case "entry-signature":
				bad.Entry.Signature[0] ^= 1
			case "same-peer":
				bad.ClientPeerID = bad.ServerPeerID
			case "other-replica-role":
				key := f.plan.Replicas[1].Assignment.ReplicaPublicKey
				bad.ClientPeerID, _ = transport.PeerIDFromPublicKey(key[:])
			}
			if field == "operation" || field == "schedule" {
				bad.Entry = managedCommandApplyTestSign(t, cmd)
			}
			expected, _ := bad.ID()
			if field == "pin" {
				expected = testHash(240)
			}
			if err := ValidateScheduledPruneDeliveryIntent(f.plan, nil, bad, expected); err == nil {
				t.Fatal("accepted substitution", field)
			}
		})
	}
	if err := ValidateScheduledPruneDeliveryIntent(f.plan, &ScheduledPruneInventory{}, i, id); err == nil {
		t.Fatal("admission accepted inventory")
	}
	// An offline preparation cannot attest either external receiver pin. The
	// original-owner preflight is separately tested to reject these mismatches.
	i.ReviewID, i.ExecutorBindingID = testHash(240), testHash(241)
	id, _ = i.ID()
	if err := ValidateScheduledPruneDeliveryIntent(f.plan, nil, i, id); err != nil {
		t.Fatal("offline preparation pretended to inspect current owners", err)
	}
}
