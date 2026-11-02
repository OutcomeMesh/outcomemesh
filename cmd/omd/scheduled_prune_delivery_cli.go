package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	scheduledDeliveryPrepareCommand = "work-prune-scheduled-delivery-prepare"
	scheduledDeliveryOutboxCommand  = "work-prune-scheduled-delivery-outbox"
	scheduledDeliveryCommand        = "work-prune-scheduled-deliver-quic"
	scheduledDeliveryServeCommand   = "work-prune-scheduled-serve-quic"
)

func runScheduledDeliveryCLI(args []string) error {
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runScheduledDelivery(ctx, args, os.Stdout)
}

func runScheduledDelivery(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || out == nil || len(args) == 0 {
		return store.ErrScheduledPruneIntent
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch args[0] {
	case scheduledDeliveryPrepareCommand:
		return runScheduledDeliveryPrepare(ctx, args[1:], out)
	case scheduledDeliveryOutboxCommand:
		return runScheduledDeliveryOutbox(ctx, args[1:], out)
	case scheduledDeliveryCommand, scheduledDeliveryServeCommand:
		return runScheduledDeliveryRuntime(ctx, args, out)
	}
	return store.ErrScheduledPruneIntent
}

func scheduledDeliveryView(i scheduledwire.Intent, id types.Hash) map[string]any {
	eid, _ := i.Entry.ID()
	c := i.Entry.Command
	return map[string]any{
		"intent_id": id.String(), "plan_id": i.PlanID.String(), "request_id": i.RequestID.String(),
		"executor_binding_id": i.ExecutorBindingID.String(), "inventory_id": i.InventoryID.String(),
		"receiver_review_id": i.ReviewID.String(), "assignment_id": c.AssignmentID.String(), "entry_id": eid.String(),
		"client_peer_id": i.ClientPeerID.String(), "server_peer_id": i.ServerPeerID.String(),
		"kind": c.Kind, "expected_sequence": c.ExpectedSequence, "expected_head": c.ExpectedHead.String(),
		"ticket_id": c.TicketID.String(), "evidence_id": c.EvidenceID.String(),
		"historical_only": true, "execution_authorized": false, "automatic_retry": false,
		"current_head_verified": false, "terminal_state_verified": false,
	}
}

func loadScheduledDeliveryIntent(path string, expected types.Hash) (scheduledwire.Intent, error) {
	raw, err := readRegularArtifact(path, scheduledwire.IntentBytes)
	if err != nil {
		return scheduledwire.Intent{}, err
	}
	i, err := scheduledwire.DecodeIntent(raw)
	if err != nil {
		return scheduledwire.Intent{}, err
	}
	id, err := i.ID()
	if err != nil || expected.IsZero() || id != expected {
		return scheduledwire.Intent{}, errors.Join(store.ErrScheduledPruneIntent, err)
	}
	return i, nil
}

func runScheduledDeliveryPrepare(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet(scheduledDeliveryPrepareCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review or publish a fixed canonical delivery intent")
	planPath := f.String("plan", "", "original canonical plan")
	planText := f.String("plan-id", "", "independently retained plan ID")
	assignmentText := f.String("assignment-id", "", "selected original assignment ID")
	entryPath := f.String("entry", "", "already co-signed scheduled entry")
	entryText := f.String("entry-id", "", "independently retained entry ID")
	requestText := f.String("request-id", "", "original request ID")
	bindingText := f.String("executor-binding-id", "", "original executor binding from receiver review")
	reviewText := f.String("receiver-review-id", "", "independently obtained receiver local command review ID")
	clientText := f.String("client-peer-id", "", "pinned client transport identity")
	serverText := f.String("server-peer-id", "", "pinned server transport identity")
	inventoryPath := f.String("inventory", "", "completion only: original inventory")
	inventoryText := f.String("inventory-id", "", "completion only: independently retained inventory ID")
	expectedText := f.String("intent-id", "", "publish only: previously reviewed intent ID")
	destination := f.String("out", "", "publish only: immutable intent file")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	if *mode != "review" && *mode != "publish" {
		return store.ErrScheduledPruneIntent
	}
	presence := custodyCommandPresence(f)
	if *mode == "review" {
		if err := custodyCommandForbid(presence, "intent-id", "out"); err != nil {
			return err
		}
	}
	var i scheduledwire.Intent
	var aid, eid types.Hash
	for _, field := range []struct {
		name, text string
		id         *types.Hash
	}{
		{"plan-id", *planText, &i.PlanID}, {"assignment-id", *assignmentText, &aid},
		{"entry-id", *entryText, &eid}, {"request-id", *requestText, &i.RequestID},
		{"executor-binding-id", *bindingText, &i.ExecutorBindingID}, {"receiver-review-id", *reviewText, &i.ReviewID},
		{"client-peer-id", *clientText, &i.ClientPeerID}, {"server-peer-id", *serverText, &i.ServerPeerID},
	} {
		id, err := pruneExternalID(field.name, field.text)
		if err != nil {
			return err
		}
		*field.id = id
	}
	p, err := store.LoadScheduledPrunePlan(*planPath, i.PlanID)
	if err != nil {
		return err
	}
	raw, err := readRegularArtifact(*entryPath, custodyauthority.MaximumEntryBytes)
	if err != nil {
		return err
	}
	i.Entry, err = custodyauthority.DecodeEntry(raw)
	if err != nil {
		return err
	}
	have, err := i.Entry.ID()
	if err != nil || have != eid || i.Entry.Command.AssignmentID != aid {
		return store.ErrScheduledPruneIntent
	}
	var inventory *store.ScheduledPruneInventory
	if i.Entry.Command.Kind == custodyauthority.Complete {
		i.InventoryID, err = pruneExternalID("inventory-id", *inventoryText)
		if err != nil {
			return err
		}
		v, err := store.LoadScheduledPruneInventory(*inventoryPath, i.InventoryID)
		if err != nil {
			return err
		}
		inventory = &v
	} else if presence["inventory"] || presence["inventory-id"] {
		return store.ErrScheduledPruneIntent
	}
	id, err := i.ID()
	if err != nil {
		return err
	}
	if err := store.ValidateScheduledPruneDeliveryIntent(p, inventory, i, id); err != nil {
		return err
	}
	if *mode == "publish" {
		expected, err := pruneExternalID("intent-id", *expectedText)
		if err != nil || expected != id {
			return errors.Join(store.ErrScheduledPruneIntent, err)
		}
		if err := scheduledOperatorOutput(*destination, []string{*planPath, *entryPath, *inventoryPath}, nil); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, _ := i.CanonicalBytes()
		if err := publishImmutableArtifact(*destination, raw); err != nil {
			return err
		}
	}
	report := scheduledDeliveryView(i, id)
	report["mode"], report["published"], report["sent"] = *mode, *mode == "publish", false
	return scheduledOperatorReport(ctx, out, report)
}

func runScheduledDeliveryOutbox(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet(scheduledDeliveryOutboxCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "inspect", "create a new typed outbox or inspect the original one without sending")
	assignmentPath := f.String("assignment", "", "original canonical assignment")
	assignmentText := f.String("assignment-id", "", "independently retained assignment ID")
	intentPath := f.String("intent", "", "create only: reviewed canonical intent")
	intentText := f.String("intent-id", "", "independently retained intent ID")
	path := f.String("outbox", "", "typed outbox root")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	if *mode != "create" && *mode != "inspect" {
		return store.ErrScheduledPruneIntent
	}
	if *mode == "inspect" {
		if err := custodyCommandForbid(custodyCommandPresence(f), "intent"); err != nil {
			return err
		}
	}
	aid, err := pruneExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	id, err := pruneExternalID("intent-id", *intentText)
	if err != nil {
		return err
	}
	a, err := loadPruneOfflineAssignment(*assignmentPath, aid)
	if err != nil {
		return err
	}
	if *path == "" {
		return store.ErrScheduledPruneIntent
	}
	for _, file := range []string{*assignmentPath, *intentPath} {
		if file != "" && workarchive.CustodyEvidencePathsOverlap(*path, file) {
			return store.ErrRootOverlap
		}
	}
	var box *store.ScheduledPruneOutbox
	if *mode == "create" {
		i, err := loadScheduledDeliveryIntent(*intentPath, id)
		if err != nil {
			return err
		}
		if err := validatePruneOfflinePeers(a, i.ClientPeerID, i.ServerPeerID); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		box, err = store.CreateScheduledPruneOutbox(*path, a, i, id)
		if err != nil {
			return err
		}
	} else {
		box, err = store.OpenScheduledPruneOutbox(*path, a, id)
		if err != nil {
			return err
		}
	}
	state, readErr := box.Snapshot()
	if err := errors.Join(readErr, box.Close()); err != nil {
		return err
	}
	if err := validatePruneOfflinePeers(a, state.Intent.ClientPeerID, state.Intent.ServerPeerID); err != nil {
		return err
	}
	report := scheduledDeliveryView(state.Intent, state.IntentID)
	report["mode"], report["created"], report["sent"] = *mode, *mode == "create", false
	report["receipt_present"] = state.Acknowledgement != nil
	if state.Acknowledgement != nil {
		report["receipt_nonce"] = state.Acknowledgement.Nonce.String()
	}
	return scheduledOperatorReport(ctx, out, report)
}
