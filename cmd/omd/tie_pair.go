package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
)

func runWorkTelemetryTiePairCreate(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("work-telemetry-tie-pair-create", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "coordinator WorkGraph node data directory")
	planPath := flags.String("plan", "", "published signed controlled-tie plan file")
	planIDText := flags.String("plan-id", "", "externally published controlled-tie plan ID")
	coordinatorKeyText := flags.String("coordinator-public-key", "", "trusted coordinator Ed25519 public key")
	observerKeyText := flags.String("observer-public-key", "", "trusted observer Ed25519 public key")
	sequence := flags.Uint64("sequence", 0, "one-based planned slot sequence")
	outputPath := flags.String("output", "", "new portable pair artifact path")
	wait := flags.Bool("wait", true, "wait for the signed slot start")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *planPath == "" || *planIDText == "" || *coordinatorKeyText == "" ||
		*observerKeyText == "" || *sequence == 0 || *outputPath == "" {
		return errors.New("plan, published plan ID, coordinator/observer public keys, sequence, and output are required")
	}
	observerKey, err := parseHash(*observerKeyText)
	if err != nil {
		return fmt.Errorf("observer-public-key: %w", err)
	}
	plan, binding, planID, err := loadPublishedTiePlan(
		*data, *planPath, *planIDText, *coordinatorKeyText, observerKey,
	)
	if err != nil {
		return err
	}
	if *sequence > uint64(len(plan.Slots)) {
		return errors.New("controlled-tie sequence exceeds the published plan")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := waitForTieSlot(ctx, plan.Slots[*sequence-1].StartedAt, *wait); err != nil {
		return err
	}
	_, store, router, _, err := openWorkNode(*data)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, router.Close()) }()
	pair, production, err := tieproducer.MinePair(ctx, router, tieproducer.Config{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: *sequence,
	})
	if err != nil {
		return err
	}
	encoded, err := pair.CanonicalBytes(plan, binding, planID)
	if err != nil {
		return err
	}
	pairID, err := pair.ID(plan, binding, planID)
	if err != nil {
		return err
	}
	if err := writeNewTiePairFile(*outputPath, encoded); err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_pair_created plan=%s sequence=%d pair=%s first_role=%s parent=%s height=%d tested=%s tested_nonce=%d control=%s control_nonce=%d bytes=%d output=%s\n",
		planID, production.Sequence, pairID, tieRoleText(production.FirstRole), production.ParentID,
		production.Height, production.Tested.ID, production.Tested.WinningNonce,
		production.Control.ID, production.Control.WinningNonce, len(encoded), *outputPath,
	)
	return nil
}

func runWorkTelemetryTiePairAdmit(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("work-telemetry-tie-pair-admit", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "independent observer WorkGraph node data directory")
	observerKeyPath := flags.String("observer-key", "", "independent observer Ed25519 seed file")
	planPath := flags.String("plan", "", "published signed controlled-tie plan file")
	planIDText := flags.String("plan-id", "", "externally published controlled-tie plan ID")
	coordinatorKeyText := flags.String("coordinator-public-key", "", "trusted coordinator Ed25519 public key")
	sequence := flags.Uint64("sequence", 0, "one-based planned slot sequence")
	inputPath := flags.String("input", "", "portable pair artifact path")
	expectedPairIDText := flags.String("pair-id", "", "externally published portable pair ID")
	receiptPath := flags.String("receipt-manifest", "", "signed raw tie receipt path (default under data)")
	pendingPath := flags.String("pending", "", "crash-safe partial tie state path (default under data)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *observerKeyPath == "" || *planPath == "" || *planIDText == "" ||
		*coordinatorKeyText == "" || *sequence == 0 || *inputPath == "" || *expectedPairIDText == "" {
		return errors.New("observer key, plan/pair IDs, coordinator public key, sequence, and input are required")
	}
	if *receiptPath == "" {
		*receiptPath = defaultTieReceiptPath(*data)
	}
	if *pendingPath == "" {
		*pendingPath = defaultTiePendingPath(*data)
	}
	observerKey, err := loadPrivateKey(*observerKeyPath)
	if err != nil {
		return err
	}
	var observerPublicKey types.Hash
	copy(observerPublicKey[:], observerKey.Public().(ed25519.PublicKey))
	plan, binding, planID, err := loadPublishedTiePlan(
		*data, *planPath, *planIDText, *coordinatorKeyText, observerPublicKey,
	)
	if err != nil {
		return err
	}
	if *sequence > uint64(len(plan.Slots)) {
		return errors.New("controlled-tie sequence exceeds the published plan")
	}
	encoded, err := readTiePairFile(*inputPath)
	if err != nil {
		return err
	}
	pair, err := tieproducer.DecodePair(encoded, plan, binding, planID)
	if err != nil {
		return err
	}
	if pair.Sequence != *sequence {
		return errors.New("portable pair sequence does not match requested sequence")
	}
	pairID, err := pair.ID(plan, binding, planID)
	if err != nil {
		return err
	}
	expectedPairID, err := parseHash(*expectedPairIDText)
	if err != nil {
		return fmt.Errorf("pair-id: %w", err)
	}
	if pairID != expectedPairID {
		return errors.New("portable pair does not match the published pair ID")
	}
	collector, err := calibration.OpenTieCollector(calibration.TieCollectorConfig{
		Plan: plan, Binding: binding, PrivateKey: observerKey,
		ReceiptPath: *receiptPath, PendingPath: *pendingPath,
	}, unixNow())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, collector.Close(unixNow())) }()
	status, err := collector.Status()
	if err != nil {
		return err
	}
	if status.NextSequence != *sequence {
		return fmt.Errorf("collector expects sequence %d, requested %d", status.NextSequence, *sequence)
	}
	observer := &tieHarnessObserver{collector: collector}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	_, store, router, _, err := openWorkNodeObserved(*data, observer.Observe)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, router.Close()) }()
	production, err := tieproducer.AdmitPair(ctx, router, tieproducer.Config{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: *sequence,
	}, pair)
	if err != nil {
		return err
	}
	if err := observer.Err(); err != nil {
		return fmt.Errorf("controlled-tie observer failed: %w", err)
	}
	status, err = collector.Status()
	if err != nil {
		return err
	}
	if status.NextSequence != *sequence+1 || status.InvalidCurrent {
		return errors.New("portable pair did not produce a completed signed receipt")
	}
	fmt.Printf(
		"work_tie_pair_admitted plan=%s sequence=%d pair=%s first_role=%s parent=%s height=%d tested=%s control=%s selected=%s receipt_tail=%s\n",
		planID, production.Sequence, pairID, tieRoleText(production.FirstRole), production.ParentID,
		production.Height, production.Tested.ID, production.Control.ID, production.FinalSelected,
		status.LastReceiptID,
	)
	return nil
}

func defaultTieReceiptPath(data string) string {
	return filepath.Join(data, "work-tie-receipts.omtr")
}

func defaultTiePendingPath(data string) string {
	return filepath.Join(data, "work-tie-receipts.pending")
}

func loadPublishedTiePlan(
	data string,
	planPath string,
	planIDText string,
	coordinatorKeyText string,
	observerPublicKey types.Hash,
) (calibration.TiePlan, calibration.TiePlanBinding, types.Hash, error) {
	document, err := loadGenesis(data)
	if err != nil {
		return calibration.TiePlan{}, calibration.TiePlanBinding{}, types.Hash{}, err
	}
	profile, err := loadWorkActivation(data, document)
	if err != nil {
		return calibration.TiePlan{}, calibration.TiePlanBinding{}, types.Hash{}, err
	}
	genesisID, err := document.ID()
	if err != nil {
		return calibration.TiePlan{}, calibration.TiePlanBinding{}, types.Hash{}, err
	}
	planID, err := parseHash(planIDText)
	if err != nil {
		return calibration.TiePlan{}, calibration.TiePlanBinding{}, types.Hash{}, fmt.Errorf("plan-id: %w", err)
	}
	coordinatorKey, err := parseHash(coordinatorKeyText)
	if err != nil {
		return calibration.TiePlan{}, calibration.TiePlanBinding{}, types.Hash{}, fmt.Errorf("coordinator-public-key: %w", err)
	}
	binding := calibration.TiePlanBinding{
		NetworkID: document.NetworkID, GenesisID: genesisID, ActivationHeight: profile.ActivationHeight,
	}
	copy(binding.ObserverPublicKey[:], observerPublicKey[:])
	copy(binding.CoordinatorPublicKey[:], coordinatorKey[:])
	plan, err := calibration.LoadTiePlanFile(planPath, binding)
	if err != nil {
		return calibration.TiePlan{}, calibration.TiePlanBinding{}, types.Hash{}, err
	}
	actualPlanID, err := plan.ID()
	if err != nil || actualPlanID != planID {
		return calibration.TiePlan{}, calibration.TiePlanBinding{}, types.Hash{}, errors.New("controlled-tie plan does not match the published plan ID")
	}
	return plan, binding, planID, nil
}

func readTiePairFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, tieproducer.MaximumPairArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > tieproducer.MaximumPairArtifactBytes {
		return nil, tieproducer.ErrPairArtifact
	}
	return encoded, nil
}

func writeNewTiePairFile(path string, encoded []byte) error {
	if path == "" || len(encoded) == 0 || len(encoded) > tieproducer.MaximumPairArtifactBytes {
		return tieproducer.ErrPairArtifact
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".outcomemesh-tie-pair-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	writeErr := writeCommandBytes(temporary, encoded)
	if writeErr == nil {
		writeErr = temporary.Sync()
	}
	closeErr := temporary.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	return syncCommandDirectory(directory)
}
