package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const pruneSecondaryServeCommand = "work-prune-secondary-command-serve-quic"

// This lifetime owns only the selected command receivers and existing roots.
// Stop and drain it before using the separate offline maintenance commands.
func runPruneSecondaryCommand(ctx context.Context, arguments []string, output io.Writer) (err error) {
	if ctx == nil || output == nil || len(arguments) == 0 || arguments[0] != pruneSecondaryServeCommand {
		return errors.New("secondary prune command needs a context, output and explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet(pruneSecondaryServeCommand, flag.ContinueOnError)
	modeText := flags.String("mode", "", "explicit command scope: admit, complete or both (required)")
	inventoryPath := flags.String("inventory", "", "existing canonical inventory file (required)")
	inventoryText := flags.String("inventory-id", "", "independently retained inventory ID (required)")
	policyText := flags.String("policy-id", "", "independently retained inventory policy ID (required)")
	assignmentText := flags.String("assignment-id", "", "independently retained target secondary assignment ID (required)")
	executorPath := flags.String("executor", "", "existing original executor root (required)")
	executorPins := flags.String("executor-pins", "", "existing original executor pin root (required)")
	authorityPath := flags.String("authority", "", "existing target secondary authority root (required)")
	authorityPins := flags.String("authority-pins", "", "existing target secondary authority pin root (required)")
	primaryPath := flags.String("primary-authority", "", "existing primary authority root (admit/both only)")
	primaryPins := flags.String("primary-authority-pins", "", "existing primary authority pin root (admit/both only)")
	keyPath := flags.String("key", "", "existing transport-only 32-byte Ed25519 seed file (required)")
	serverText := flags.String("server-peer-id", "", "externally pinned server transport identity (required)")
	clientText := flags.String("client-peer-id", "", "externally pinned allowed client transport identity (required)")
	timeout := flags.Duration("timeout", 10*time.Second, "per-exchange timeout, 100ms..2m; not a filesystem deadline")
	listen := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "dedicated direct QUIC-v1 listen address")
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	var mode authoritystore.PruneSecondaryCommandMode
	switch *modeText {
	case "admit":
		mode = authoritystore.PruneSecondaryAdmission
	case "complete":
		mode = authoritystore.PruneSecondaryCompletion
	case "both":
		mode = authoritystore.PruneSecondaryBoth
	default:
		return errors.New("mode must be explicitly supplied as admit, complete or both")
	}
	primarySupplied := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "primary-authority" || f.Name == "primary-authority-pins" {
			primarySupplied = true
		}
	})
	if mode == authoritystore.PruneSecondaryCompletion && primarySupplied {
		return errors.New("complete mode does not accept primary authority flags")
	}
	if *inventoryPath == "" || *keyPath == "" || *executorPath == "" || *executorPins == "" ||
		*authorityPath == "" || *authorityPins == "" || *listen == "" ||
		*timeout < admissionwire.MinimumTimeout || *timeout > admissionwire.MaximumTimeout {
		return errors.New("inventory, key, all four existing target/executor roots, listen and a timeout within 100ms..2m are required")
	}
	if mode != authoritystore.PruneSecondaryCompletion && (*primaryPath == "" || *primaryPins == "") {
		return errors.New("admit and both modes require both existing primary authority roots")
	}
	scope := authoritystore.PreparedArchiveSecondaryCommandConfig{InventoryPath: *inventoryPath, Timeout: *timeout}
	if scope.InventoryID, err = pruneExternalID("inventory-id", *inventoryText); err != nil {
		return err
	}
	if scope.PolicyID, err = pruneExternalID("policy-id", *policyText); err != nil {
		return err
	}
	if scope.AssignmentID, err = pruneExternalID("assignment-id", *assignmentText); err != nil {
		return err
	}
	if scope.ServerPeerID, err = pruneExternalID("server-peer-id", *serverText); err != nil {
		return err
	}
	if scope.ClientPeerID, err = pruneExternalID("client-peer-id", *clientText); err != nil {
		return err
	}
	// Validate the package, independent pins and every owner path before reading
	// a secret seed. Opening never creates missing roots or starts a listener.
	service, err := authoritystore.OpenPruneSecondaryCommandService(authoritystore.PruneSecondaryCommandServiceConfig{
		Session: scope, Mode: mode, ExecutorPath: *executorPath, ExecutorPinsPath: *executorPins,
		AuthorityPath: *authorityPath, AuthorityPinsPath: *authorityPins,
		PrimaryAuthorityPath: *primaryPath, PrimaryAuthorityPinsPath: *primaryPins,
	})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, service.Close()) }()
	key, err := loadPruneOfflineKey(*keyPath)
	if err != nil {
		return err
	}
	transportConfig := libp2ptransport.DefaultConfig()
	transportConfig.Listen = []string{*listen}
	if err := service.Start(ctx, key, transportConfig); err != nil {
		return err
	}
	if err := writePruneOutputLine(output, fmt.Sprintf("serving_work_prune_secondary_commands mode=%s peer_id=%s client_peer_id=%s assignment_id=%s inventory_id=%s policy_id=%s listen=%s command_only=true execution_enabled=false automatic_resume=false\n",
		mode, scope.ServerPeerID, scope.ClientPeerID, scope.AssignmentID, scope.InventoryID, scope.PolicyID,
		strings.Join(service.Addresses(), ","))); err != nil {
		return err
	}
	<-service.Done()
	return nil
}
