package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/wallet/keystore"
)

func scheduledDeliveryKey(path string, roots ...string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, store.ErrPruneRuntime
	}
	for _, root := range roots {
		if root != "" && workarchive.CustodyEvidencePathsOverlap(path, root) {
			return nil, store.ErrRootOverlap
		}
	}
	seed, err := keystore.ReadPrivate(path, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, store.ErrPruneRuntime
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func runScheduledDeliveryRuntime(ctx context.Context, args []string, out io.Writer) (err error) {
	serving := args[0] == scheduledDeliveryServeCommand
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	keyPath := f.String("key", "", "existing private transport-only 32-byte Ed25519 seed")
	intentText := f.String("intent-id", "", "independently retained exact intent ID")
	assignmentText := f.String("assignment-id", "", "independently retained original assignment ID")
	timeout := f.Duration("timeout", 10*time.Second, "exchange deadline, 100ms..2m; never a filesystem deadline")
	var assignmentPath, outboxPath, address, intentPath, listen, clientText, serverText string
	var c store.ScheduledPruneCommandConfig
	var planText, entryText, inventoryText string
	var policy archiveCustodyPolicyFlags
	var limits archiveCustodyJournalLimitFlags
	if serving {
		f.StringVar(&intentPath, "intent", "", "reviewed fixed canonical intent")
		f.StringVar(&clientText, "client-peer-id", "", "independently pinned sender identity")
		f.StringVar(&serverText, "server-peer-id", "", "independently pinned receiving identity")
		f.StringVar(&listen, "listen", "/ip4/127.0.0.1/udp/0/quic-v1", "dedicated direct QUIC-v1 listen address")
		f.StringVar(&c.PlanPath, "plan", "", "original canonical plan")
		f.StringVar(&planText, "plan-id", "", "independently retained plan ID")
		f.StringVar(&c.EntryPath, "entry", "", "original co-signed command")
		f.StringVar(&entryText, "entry-id", "", "independently retained entry ID")
		f.StringVar(&c.AuthorityPath, "authority", "", "original authority root")
		f.StringVar(&c.AuthorityPinsPath, "authority-pins", "", "original independent authority pins")
		f.StringVar(&c.ExecutorPath, "executor", "", "original primary executor root")
		f.StringVar(&c.ExecutorPinsPath, "executor-pins", "", "original independent executor pins")
		f.StringVar(&c.JournalPath, "journal", "", "admission: original custody journal")
		f.StringVar(&c.InventoryPath, "inventory", "", "completion: original inventory")
		f.StringVar(&inventoryText, "inventory-id", "", "completion: independently retained inventory ID")
		policy, limits = addArchiveCustodyPolicyFlags(f), addArchiveCustodyJournalLimitFlags(f)
	} else {
		f.StringVar(&assignmentPath, "assignment", "", "original canonical assignment")
		f.StringVar(&outboxPath, "outbox", "", "original typed outbox; never created here")
		f.StringVar(&address, "peer", "", "explicit server route; not an identity pin")
	}
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if *keyPath == "" || *timeout < scheduledwire.MinimumTimeout || *timeout > scheduledwire.MaximumTimeout {
		return store.ErrPruneRuntime
	}
	id, err := pruneExternalID("intent-id", *intentText)
	if err != nil {
		return err
	}
	aid, err := pruneExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	config := libp2ptransport.DefaultConfig()
	if !serving {
		if outboxPath == "" || address == "" {
			return store.ErrPruneRuntime
		}
		a, err := loadPruneOfflineAssignment(assignmentPath, aid)
		if err != nil {
			return err
		}
		// Check the external intent pin and retained files before reading a seed.
		box, err := store.OpenScheduledPruneOutbox(outboxPath, a, id)
		if err != nil {
			return err
		}
		state, readErr := box.Snapshot()
		if err := errors.Join(readErr, box.Close()); err != nil {
			return err
		}
		if err := validatePruneOfflinePeers(a, state.Intent.ClientPeerID, state.Intent.ServerPeerID); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := scheduledDeliveryKey(*keyPath, outboxPath, assignmentPath)
		if err != nil {
			return err
		}
		defer clear(key)
		ack, err := store.DeliverScheduledPrune(ctx, key, store.PruneDeliveryConfig{Path: outboxPath, Assignment: a, IntentID: id, Address: address, Timeout: *timeout, Transport: config})
		if err != nil {
			return err
		}
		report := scheduledDeliveryView(state.Intent, id)
		report["mode"], report["delivery_confirmed"], report["receipt_nonce"] = "deliver", true, ack.Nonce.String()
		if err := scheduledOperatorReport(ctx, out, report); err != nil {
			return errors.Join(scheduledwire.ErrUnconfirmed, err)
		}
		return nil
	}
	i, err := loadScheduledDeliveryIntent(intentPath, id)
	if err != nil {
		return err
	}
	presence := custodyCommandPresence(f)
	if i.Entry.Command.Kind == custodyauthority.Admit {
		if err := custodyCommandForbid(presence, "inventory", "inventory-id"); err != nil {
			return err
		}
	} else if err := custodyCommandForbid(presence, "journal"); err != nil {
		return err
	}
	c.AssignmentID = aid
	for _, field := range []struct {
		name, text string
		id         *types.Hash
	}{
		{"plan-id", planText, &c.PlanID}, {"entry-id", entryText, &c.EntryID},
	} {
		v, err := pruneExternalID(field.name, field.text)
		if err != nil {
			return err
		}
		*field.id = v
	}
	client, err := pruneExternalID("client-peer-id", clientText)
	if err != nil {
		return err
	}
	server, err := pruneExternalID("server-peer-id", serverText)
	if err != nil {
		return err
	}
	if client != i.ClientPeerID || server != i.ServerPeerID || listen == "" {
		return store.ErrPruneRuntime
	}
	if c.InventoryPath != "" || inventoryText != "" {
		c.InventoryID, err = pruneExternalID("inventory-id", inventoryText)
		if err != nil {
			return err
		}
	}
	if err := limits.validate(f, c.JournalPath); err != nil {
		return err
	}
	c.JournalLimits = limits.limits()
	if c.JournalPath != "" {
		if err := policy.validate(); err != nil {
			return err
		}
		plan, err := store.LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
		if err != nil {
			return err
		}
		replica, err := plan.Replica(c.AssignmentID)
		if err != nil {
			return err
		}
		c.CustodyPolicy = workarchive.CustodyPolicy{TrustedAuditors: replica.Assignment.Auditors, MaximumChallengeLifetime: *policy.challengeLifetime, MaximumProofAge: *policy.proofAge, MaximumRenewalTerm: *policy.renewalTerm}
	} else if err := custodyCommandForbid(custodyCommandPresence(f), "max-challenge-lifetime-seconds", "max-proof-age-seconds", "max-renewal-term-seconds"); err != nil {
		return err
	}
	for _, root := range []string{c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath, c.JournalPath} {
		if root != "" && workarchive.CustodyEvidencePathsOverlap(root, intentPath) {
			return store.ErrRootOverlap
		}
	}
	service, err := store.PrepareScheduledPruneCommandService(ctx, c, i, id, *timeout)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, service.Close()) }()
	key, err := scheduledDeliveryKey(*keyPath, c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath, c.JournalPath, intentPath, c.PlanPath, c.EntryPath, c.InventoryPath)
	if err != nil {
		return err
	}
	defer clear(key)
	config.Listen = []string{listen}
	if err := service.Start(ctx, key, config); err != nil {
		return err
	}
	report := scheduledDeliveryView(i, id)
	report["mode"], report["ready"], report["listen"] = "serve", true, service.Addresses()
	report["automatic_resume"] = false
	if err := scheduledOperatorReport(ctx, out, report); err != nil {
		return err
	}
	<-service.Done()
	return nil
}
