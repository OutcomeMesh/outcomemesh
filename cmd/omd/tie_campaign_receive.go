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
	"strings"
	"sync"
	"syscall"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieexchange"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// Set only by the integration helper process. The hooks give process tests
// exact request/admission crash boundaries without exposing production CLI
// fault switches.
var (
	tieCampaignBeforeRequest         func()
	tieCampaignAfterFirstObservation func()
)

func runWorkTelemetryTieCampaignReceiveQUIC(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("work-telemetry-tie-campaign-receive-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "independent observer WorkGraph node data directory")
	transportKeyPath := flags.String("key", "", "observer QUIC transport Ed25519 seed file")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "direct QUIC-v1 listen multiaddress")
	coordinatorPeerIDText := flags.String("coordinator-peer-id", "", "allowed coordinator OutcomeMesh transport peer ID")
	observerKeyPath := flags.String("observer-key", "", "independent receipt observer Ed25519 seed file")
	planPath := flags.String("plan", "", "published signed controlled-tie plan file")
	planIDText := flags.String("plan-id", "", "externally published controlled-tie plan ID")
	coordinatorKeyText := flags.String("coordinator-public-key", "", "trusted plan coordinator Ed25519 public key")
	publishedDirectory := flags.String("published", "", "external signed-checkpoint publication directory")
	confirmedDirectory := flags.String("confirmed", "", "durable coordinator-confirmation directory (default under data)")
	pollInterval := flags.Duration("poll", time.Second, "checkpoint and slot polling interval")
	receiptPath := flags.String("receipt-manifest", "", "signed raw tie receipt path (default under data)")
	pendingPath := flags.String("pending", "", "crash-safe partial tie state path (default under data)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *coordinatorPeerIDText == "" || *observerKeyPath == "" ||
		*planPath == "" || *planIDText == "" || *coordinatorKeyText == "" ||
		*publishedDirectory == "" || *pollInterval <= 0 || *pollInterval > time.Minute {
		return errors.New("transport/observer keys, coordinator identities, plan, publication directory, and bounded polling are required")
	}
	if *confirmedDirectory == "" {
		*confirmedDirectory = filepath.Join(*data, "work-tie-campaign-confirmed")
	}
	if *receiptPath == "" {
		*receiptPath = defaultTieReceiptPath(*data)
	}
	if *pendingPath == "" {
		*pendingPath = defaultTiePendingPath(*data)
	}
	publishedAbsolute, err := filepath.Abs(*publishedDirectory)
	if err != nil {
		return err
	}
	confirmedAbsolute, err := filepath.Abs(*confirmedDirectory)
	if err != nil {
		return err
	}
	if filepath.Clean(publishedAbsolute) == filepath.Clean(confirmedAbsolute) {
		return errors.New("external publication and local confirmation directories must differ")
	}
	transportKey, err := loadPrivateKey(*transportKeyPath)
	if err != nil {
		return err
	}
	coordinatorPeerID, err := parseHash(*coordinatorPeerIDText)
	if err != nil {
		return fmt.Errorf("coordinator-peer-id: %w", err)
	}
	observerKey, err := loadPrivateKey(*observerKeyPath)
	if err != nil {
		return err
	}
	observerPublicKey := hashFromPublicKey(observerKey.Public().(ed25519.PublicKey))
	plan, binding, planID, err := loadPublishedTiePlan(
		*data, *planPath, *planIDText, *coordinatorKeyText, observerPublicKey,
	)
	if err != nil {
		return err
	}
	transportPeerID := types.DomainHash("OMESH/p2p/ed25519/v0", transportKey.Public().(ed25519.PublicKey))
	observerKeyAsTransportID := types.DomainHash("OMESH/p2p/ed25519/v0", observerKey.Public().(ed25519.PublicKey))
	planCoordinatorAsTransportID := types.DomainHash("OMESH/p2p/ed25519/v0", plan.CoordinatorPublicKey[:])
	if transportPeerID == observerKeyAsTransportID || coordinatorPeerID == planCoordinatorAsTransportID {
		return errors.New("campaign transport, receipt observer, and plan coordinator must use separate Ed25519 keys")
	}
	files, err := tieproducer.NewFileObserverCampaign(
		*publishedDirectory, *confirmedDirectory, plan, binding, planID,
	)
	if err != nil {
		return err
	}
	collector, err := calibration.OpenTieCollector(calibration.TieCollectorConfig{
		Plan: plan, Binding: binding, PrivateKey: observerKey,
		ReceiptPath: *receiptPath, PendingPath: *pendingPath, FailOnPartialExpiry: true,
	}, unixNow())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, collector.Close(unixNow())) }()
	observer := &tieHarnessObserver{
		collector: collector, afterFirstObservation: tieCampaignAfterFirstObservation,
	}
	_, store, router, _, err := openWorkNodeObserved(*data, observer.Observe)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, router.Close()) }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{*listenAddress}
	host, err := libp2ptransport.New(ctx, transportKey, config, nil)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, host.Close()) }()
	addresses := host.Addresses()
	if len(addresses) == 0 {
		return errors.New("tie campaign receiver has no direct QUIC address")
	}
	status, err := collector.Status()
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_campaign_receiving transport_peer_id=%s coordinator_peer_id=%s plan=%s next_sequence=%d observer=%s listen=%s published=%s confirmed=%s\n",
		host.ID(), coordinatorPeerID, planID, status.NextSequence, observerPublicKey,
		strings.Join(addresses, ","), *publishedDirectory, *confirmedDirectory,
	)
	if err := driveObserverTieCampaign(
		ctx, host, coordinatorPeerID, observerPublicKey, plan, binding, planID,
		collector, observer, router, files, *receiptPath, *pollInterval,
	); err != nil {
		return err
	}
	status, err = collector.Status()
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_campaign_observer_complete plan=%s observer=%s slots=%d completed=%d no_pair=%d receipt_tail=%s\n",
		planID, observerPublicKey, status.ClosedSlots, status.CompletedTrials,
		status.NoPairSlots, status.LastReceiptID,
	)
	return nil
}

func driveObserverTieCampaign(
	ctx context.Context,
	host *libp2ptransport.Host,
	coordinatorPeerID types.Hash,
	observerPublicKey types.Hash,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	planID types.Hash,
	collector *calibration.TieCollector,
	observer *tieHarnessObserver,
	router tieproducer.Source,
	files *tieproducer.FileObserverCampaign,
	receiptPath string,
	pollInterval time.Duration,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := collector.Advance(unixNow()); err != nil {
			return err
		}
		status, err := collector.Status()
		if err != nil {
			return err
		}
		if status.InvalidCurrent || status.CurrentCandidates != 0 {
			return calibration.ErrPartialTiePair
		}
		recoverySequence, err := observerCampaignRecoverySequence(
			files, receiptPath, plan, binding,
		)
		if err != nil {
			return err
		}
		sequence := status.NextSequence
		recovered := false
		if recoverySequence != 0 {
			sequence = recoverySequence
			recovered = true
		} else if status.Complete {
			return nil
		}
		checkpoint, err := waitObserverCampaignCheckpoint(
			ctx, files, collector, sequence, recovered, pollInterval,
		)
		if errors.Is(err, errObserverCampaignSlotMissed) {
			fmt.Printf(
				"work_tie_campaign_slot_missed plan=%s sequence=%d observer=%s candidates=0\n",
				planID, sequence, observerPublicKey,
			)
			continue
		}
		if err != nil {
			return err
		}
		receiptTail, recoveredDelivery, err := serveObserverCampaignSlot(
			ctx, host, coordinatorPeerID, observerPublicKey, plan, binding, planID,
			checkpoint, collector, observer, router, files, receiptPath, pollInterval,
		)
		if errors.Is(err, errObserverCampaignSlotMissed) {
			fmt.Printf(
				"work_tie_campaign_slot_missed plan=%s sequence=%d observer=%s candidates=0\n",
				planID, sequence, observerPublicKey,
			)
			continue
		}
		if err != nil {
			return err
		}
		fmt.Printf(
			"work_tie_campaign_pair_received plan=%s sequence=%d pair=%s observer=%s receipt_tail=%s recovered=%t\n",
			planID, sequence, checkpoint.PairID, observerPublicKey, receiptTail,
			recovered || recoveredDelivery,
		)
	}
}

var errObserverCampaignSlotMissed = errors.New("controlled-tie campaign slot missed without candidates")

func waitObserverCampaignCheckpoint(
	ctx context.Context,
	files *tieproducer.FileObserverCampaign,
	collector *calibration.TieCollector,
	sequence uint64,
	recovered bool,
	pollInterval time.Duration,
) (calibration.TiePairCheckpoint, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		checkpoint, _, err := files.LoadPublishedCheckpoint(sequence)
		if err == nil {
			return checkpoint, nil
		}
		if !tieproducer.IsMissingObserverCampaignFile(err) {
			return calibration.TiePairCheckpoint{}, err
		}
		if !recovered {
			if err := collector.Advance(unixNow()); err != nil {
				return calibration.TiePairCheckpoint{}, err
			}
			status, err := collector.Status()
			if err != nil {
				return calibration.TiePairCheckpoint{}, err
			}
			if status.NextSequence > sequence {
				return calibration.TiePairCheckpoint{}, errObserverCampaignSlotMissed
			}
		}
		select {
		case <-ctx.Done():
			return calibration.TiePairCheckpoint{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

type observerCampaignSlotResult struct {
	receiptTail types.Hash
	recovered   bool
}

func serveObserverCampaignSlot(
	ctx context.Context,
	host *libp2ptransport.Host,
	coordinatorPeerID types.Hash,
	observerPublicKey types.Hash,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	planID types.Hash,
	checkpoint calibration.TiePairCheckpoint,
	collector *calibration.TieCollector,
	observer *tieHarnessObserver,
	router tieproducer.Source,
	files *tieproducer.FileObserverCampaign,
	receiptPath string,
	pollInterval time.Duration,
) (types.Hash, bool, error) {
	sequence := checkpoint.Sequence
	exchangeBinding := tieexchange.Binding{
		PlanID: planID, PairID: checkpoint.PairID, Sequence: sequence,
	}
	completed := make(chan observerCampaignSlotResult, 1)
	fatal := make(chan error, 1)
	var stateMu sync.Mutex
	active := true
	claimed := false
	claim := func() bool {
		stateMu.Lock()
		defer stateMu.Unlock()
		if !active || claimed {
			return false
		}
		claimed = true
		return true
	}
	release := func() {
		stateMu.Lock()
		claimed = false
		stateMu.Unlock()
	}
	deactivate := func() {
		stateMu.Lock()
		active = false
		stateMu.Unlock()
	}
	reportFatal := func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	reset := func(stream libp2pnetwork.Stream) { _ = stream.Reset() }
	err := host.SetTiePairHandler(
		coordinatorPeerID,
		func(handlerContext context.Context, remoteID types.Hash, stream libp2pnetwork.Stream) {
			if remoteID != coordinatorPeerID {
				reset(stream)
				return
			}
			if tieCampaignBeforeRequest != nil {
				tieCampaignBeforeRequest()
			}
			status, err := collector.Status()
			if err != nil {
				reset(stream)
				reportFatal(err)
				return
			}
			isCurrent := status.NextSequence == sequence
			isRecovery := status.NextSequence == sequence+1
			if !isCurrent && !isRecovery {
				reset(stream)
				return
			}
			deadline := time.Now().Add(30 * time.Second)
			if isCurrent {
				slot := plan.Slots[sequence-1]
				now := unixNow()
				if now < slot.StartedAt || now >= slot.EndedAt {
					reset(stream)
					return
				}
				deadline = time.Unix(int64(slot.EndedAt), 0)
			}
			if err := stream.SetDeadline(deadline); err != nil {
				reset(stream)
				return
			}
			request, err := tieexchange.ReadRequest(stream, exchangeBinding)
			if err != nil {
				reset(stream)
				return
			}
			actualPairID, err := tieproducer.ArtifactID(request.Artifact)
			if err != nil || actualPairID != checkpoint.PairID {
				reset(stream)
				return
			}
			pair, err := tieproducer.DecodePair(request.Artifact, plan, binding, planID)
			if err != nil || !claim() {
				reset(stream)
				return
			}
			defer release()

			var receiptTail types.Hash
			if isCurrent {
				attemptContext, attemptCancel := context.WithDeadline(handlerContext, deadline)
				_, err = tieproducer.AdmitPair(attemptContext, router, tieproducer.Config{
					Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: sequence,
				}, pair)
				attemptCancel()
				if err == nil {
					err = observer.Err()
				}
				var current calibration.TieCollectorStatus
				if err == nil {
					current, err = collector.Status()
				}
				if err == nil && (current.NextSequence != sequence+1 || current.InvalidCurrent ||
					current.LastReceiptID.IsZero()) {
					err = errors.New("portable pair did not produce a completed durable receipt")
				}
				receiptTail = current.LastReceiptID
			} else {
				receiptTail, err = persistedReceiptForPair(receiptPath, plan, binding, pair, sequence)
			}
			if err != nil {
				reset(stream)
				reportFatal(err)
				return
			}
			if err := tieexchange.WriteAcknowledgement(stream, tieexchange.Acknowledgement{
				Binding: exchangeBinding, ObserverPublicKey: observerPublicKey, ReceiptTail: receiptTail,
			}); err != nil {
				reset(stream)
				return
			}
			if _, err := tieexchange.ReadConfirmation(stream, exchangeBinding, receiptTail); err != nil {
				reset(stream)
				return
			}
			if err := files.Confirm(sequence, checkpoint.PairID, receiptTail); err != nil {
				reset(stream)
				reportFatal(err)
				return
			}
			deactivate()
			_ = stream.Close()
			completed <- observerCampaignSlotResult{receiptTail: receiptTail, recovered: isRecovery}
		},
	)
	if err != nil {
		return types.Hash{}, false, err
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	defer deactivate()
	for {
		select {
		case <-ctx.Done():
			return types.Hash{}, false, ctx.Err()
		case err := <-fatal:
			return types.Hash{}, false, err
		case result := <-completed:
			return result.receiptTail, result.recovered, nil
		case <-ticker.C:
			if err := collector.Advance(unixNow()); err != nil {
				return types.Hash{}, false, err
			}
			status, err := collector.Status()
			if err != nil {
				return types.Hash{}, false, err
			}
			if status.NextSequence > sequence && status.LastReceiptID.IsZero() {
				return types.Hash{}, false, errObserverCampaignSlotMissed
			}
			if status.NextSequence > sequence {
				_, receipts, _, err := calibration.LoadTieReceiptFile(receiptPath, binding)
				if err != nil {
					return types.Hash{}, false, err
				}
				if sequence <= uint64(len(receipts)) && receipts[sequence-1].Status == calibration.TieTrialNoPair {
					return types.Hash{}, false, errObserverCampaignSlotMissed
				}
			}
		}
	}
}

func observerCampaignRecoverySequence(
	files *tieproducer.FileObserverCampaign,
	receiptPath string,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
) (uint64, error) {
	_, receipts, _, err := calibration.LoadTieReceiptFile(receiptPath, binding)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	for _, receipt := range receipts {
		confirmation, confirmationErr := files.LoadConfirmation(receipt.Sequence)
		if receipt.Status == calibration.TieTrialNoPair {
			if confirmationErr == nil || !tieproducer.IsMissingObserverCampaignFile(confirmationErr) {
				return 0, tieproducer.ErrCampaignState
			}
			continue
		}
		receiptID, err := receipt.ID(plan)
		if err != nil {
			return 0, err
		}
		if tieproducer.IsMissingObserverCampaignFile(confirmationErr) {
			return receipt.Sequence, nil
		}
		if confirmationErr != nil {
			return 0, confirmationErr
		}
		if confirmation.ReceiptTail != receiptID {
			return 0, tieproducer.ErrCampaignState
		}
	}
	return 0, nil
}
