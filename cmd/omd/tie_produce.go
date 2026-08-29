package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
)

func runWorkTelemetryTieProduce(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("work-telemetry-tie-produce", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled harness node data directory")
	observerKeyPath := flags.String("observer-key", "", "independent observer Ed25519 seed file")
	planPath := flags.String("plan", "", "published signed controlled-tie plan file")
	planIDText := flags.String("plan-id", "", "externally published controlled-tie plan ID")
	coordinatorKeyText := flags.String("coordinator-public-key", "", "trusted coordinator Ed25519 public key")
	sequence := flags.Uint64("sequence", 0, "one-based planned slot sequence")
	receiptPath := flags.String("receipt-manifest", "", "signed raw tie receipt path (default under data)")
	pendingPath := flags.String("pending", "", "crash-safe partial tie state path (default under data)")
	testedStartNonce := flags.Uint64("tested-start-nonce", 0, "first tested-miner nonce")
	controlStartNonce := flags.Uint64("control-start-nonce", 0, "first control-miner nonce")
	wait := flags.Bool("wait", true, "wait for the signed slot start")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *observerKeyPath == "" || *planPath == "" || *planIDText == "" ||
		*coordinatorKeyText == "" || *sequence == 0 {
		return errors.New("observer key, plan, published plan ID, coordinator public key, and sequence are required")
	}
	if *receiptPath == "" {
		*receiptPath = filepath.Join(*data, "work-tie-receipts.omtr")
	}
	if *pendingPath == "" {
		*pendingPath = filepath.Join(*data, "work-tie-receipts.pending")
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	profile, err := loadWorkActivation(*data, document)
	if err != nil {
		return err
	}
	genesisID, err := document.ID()
	if err != nil {
		return err
	}
	observerKey, err := loadPrivateKey(*observerKeyPath)
	if err != nil {
		return err
	}
	expectedPlanID, err := parseHash(*planIDText)
	if err != nil {
		return fmt.Errorf("plan-id: %w", err)
	}
	coordinatorKey, err := parseHash(*coordinatorKeyText)
	if err != nil {
		return fmt.Errorf("coordinator-public-key: %w", err)
	}
	binding := calibration.TiePlanBinding{
		NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight: profile.ActivationHeight,
	}
	copy(binding.ObserverPublicKey[:], observerKey.Public().(ed25519.PublicKey))
	copy(binding.CoordinatorPublicKey[:], coordinatorKey[:])
	plan, err := calibration.LoadTiePlanFile(*planPath, binding)
	if err != nil {
		return err
	}
	planID, err := plan.ID()
	if err != nil || planID != expectedPlanID {
		return errors.New("controlled-tie plan does not match the published plan ID")
	}
	if *sequence > uint64(len(plan.Slots)) {
		return errors.New("controlled-tie sequence exceeds the published plan")
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	slot := plan.Slots[*sequence-1]
	if err := waitForTieSlot(ctx, slot.StartedAt, *wait); err != nil {
		return err
	}
	if err := collector.Advance(unixNow()); err != nil {
		return err
	}
	status, err = collector.Status()
	if err != nil {
		return err
	}
	if status.NextSequence != *sequence {
		return fmt.Errorf("collector advanced to sequence %d before production", status.NextSequence)
	}

	observer := &tieHarnessObserver{collector: collector}
	_, store, router, _, err := openWorkNodeObserved(*data, observer.Observe)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, router.Close()) }()
	production, err := tieproducer.Produce(ctx, router, tieproducer.Config{
		Plan: plan, Binding: binding, ExpectedPlanID: expectedPlanID, Sequence: *sequence,
		TestedStartNonce: *testedStartNonce, ControlStartNonce: *controlStartNonce,
	})
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
		return errors.New("controlled-tie pair did not produce a completed signed receipt")
	}
	fmt.Printf(
		"work_tie_produced plan=%s sequence=%d first_role=%s parent=%s height=%d tested=%s tested_nonce=%d control=%s control_nonce=%d selected=%s receipt_tail=%s\n",
		planID, production.Sequence, tieRoleText(production.FirstRole), production.ParentID, production.Height,
		production.Tested.ID, production.Tested.WinningNonce, production.Control.ID,
		production.Control.WinningNonce, production.FinalSelected, status.LastReceiptID,
	)
	return nil
}

type tieHarnessObserver struct {
	mu        sync.Mutex
	collector *calibration.TieCollector
	err       error
}

func (observer *tieHarnessObserver) Observe(event activation.WorkAdmission) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.err != nil {
		return
	}
	_, observer.err = observer.collector.Observe(calibration.TieAdmission{
		ID: event.ID, ParentID: event.ParentID, Height: event.Height,
		ObservedAt: event.ObservedAt, Miner: event.Miner, SelectedID: event.SelectedID,
	})
}

func (observer *tieHarnessObserver) Err() error {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.err
}

func waitForTieSlot(ctx context.Context, startedAt uint64, wait bool) error {
	for {
		now := unixNow()
		if now >= startedAt {
			return nil
		}
		if !wait {
			return tieproducer.ErrOutsideSlot
		}
		seconds := startedAt - now
		if seconds > 60 {
			seconds = 60
		}
		timer := time.NewTimer(time.Duration(seconds) * time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func tieRoleText(role calibration.TieTrialRole) string {
	if role == calibration.TieRoleControl {
		return "control"
	}
	return "tested"
}
