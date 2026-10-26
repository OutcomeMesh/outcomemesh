package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

// Offline preparation/maintenance is explicit, never a delivery/startup fallback.
// Protect cleanup from broken stdout just as the transport command boundary does.
func runPruneOfflineCLI(arguments []string) error {
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runPruneOffline(ctx, arguments, os.Stdout)
}

func runPruneOffline(ctx context.Context, arguments []string, output io.Writer) error {
	if ctx == nil || output == nil || len(arguments) == 0 {
		return errors.New("offline prune command needs a context, output and explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch arguments[0] {
	case pruneAuthorityBootstrapCommand, pruneExecutorPrepareCommand:
		return runPruneBootstrap(ctx, arguments, output)
	case pruneSigningCommand, pruneCosigningCommand, pruneSecondarySigningCommand, pruneSecondaryCosigningCommand:
		return runPruneSigning(ctx, arguments, output)
	case pruneAdmissionPrepareCommand, pruneCompletionPrepareCommand:
		return runPruneOutboxPrepare(ctx, arguments, output)
	case pruneMaintenanceCommand:
		return runPruneMaintenance(ctx, arguments, output)
	case pruneLineageExtractCommand:
		return runPruneLineageExtract(ctx, arguments, output)
	default:
		return errors.New("unsupported offline prune command")
	}
}

func loadPruneOfflineAssignment(path string, expectedID types.Hash) (custodyauthority.Assignment, error) {
	if expectedID.IsZero() {
		return custodyauthority.Assignment{}, custodyauthority.ErrAssignment
	}
	encoded, err := readRegularArtifact(path, custodyauthority.MaximumAssignmentBytes)
	if err != nil {
		return custodyauthority.Assignment{}, fmt.Errorf("read assignment: %w", err)
	}
	assignment, err := custodyauthority.DecodeAssignment(encoded)
	if err != nil {
		return custodyauthority.Assignment{}, err
	}
	id, err := assignment.ID()
	if err != nil || id != expectedID {
		return custodyauthority.Assignment{}, errors.Join(custodyauthority.ErrAssignment, err)
	}
	return assignment, nil
}

func loadPruneOfflineKey(path string) (ed25519.PrivateKey, error) {
	seed, err := readRegularArtifact(path, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("read explicit seed file: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("key must contain exactly 32 seed bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func validatePruneOfflineRequest(assignment custodyauthority.Assignment, request authoritystore.PruneRequest, expectedID types.Hash) error {
	if request.StorageID.IsZero() {
		return authoritystore.ErrPruneRequest
	}
	return authoritystore.ValidatePruneRequest(assignment, request, expectedID)
}

func validatePruneOfflinePeers(assignment custodyauthority.Assignment, self, remote types.Hash) error {
	return authoritystore.ValidatePruneRuntimePeers(assignment, self, remote)
}
