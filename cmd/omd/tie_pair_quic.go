package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
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

func runWorkTelemetryTiePairReceiveQUIC(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("work-telemetry-tie-pair-receive-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "independent observer WorkGraph node data directory")
	transportKeyPath := flags.String("key", "", "observer QUIC transport Ed25519 seed file")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "direct QUIC-v1 listen multiaddress")
	coordinatorPeerIDText := flags.String("coordinator-peer-id", "", "allowed coordinator OutcomeMesh transport peer ID")
	observerKeyPath := flags.String("observer-key", "", "independent receipt observer Ed25519 seed file")
	planPath := flags.String("plan", "", "published signed controlled-tie plan file")
	planIDText := flags.String("plan-id", "", "externally published controlled-tie plan ID")
	coordinatorKeyText := flags.String("coordinator-public-key", "", "trusted plan coordinator Ed25519 public key")
	sequence := flags.Uint64("sequence", 0, "one-based planned slot sequence")
	expectedPairIDText := flags.String("pair-id", "", "externally published portable pair ID")
	checkpointPath := flags.String("pair-checkpoint", "", "coordinator-signed pair checkpoint file")
	checkpointIDText := flags.String("pair-checkpoint-id", "", "externally published pair checkpoint ID")
	receiptPath := flags.String("receipt-manifest", "", "signed raw tie receipt path (default under data)")
	pendingPath := flags.String("pending", "", "crash-safe partial tie state path (default under data)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *coordinatorPeerIDText == "" || *observerKeyPath == "" ||
		*planPath == "" || *planIDText == "" || *coordinatorKeyText == "" ||
		*sequence == 0 || !validPairPublicationFlags(*expectedPairIDText, *checkpointPath, *checkpointIDText) {
		return errors.New("transport/observer keys, coordinator identities, plan, sequence, and one published pair binding are required")
	}
	if *receiptPath == "" {
		*receiptPath = defaultTieReceiptPath(*data)
	}
	if *pendingPath == "" {
		*pendingPath = defaultTiePendingPath(*data)
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
		return errors.New("tie-pair transport, receipt observer, and plan coordinator must use separate Ed25519 keys")
	}
	if *sequence > uint64(len(plan.Slots)) {
		return errors.New("controlled-tie sequence exceeds the published plan")
	}
	expectedPairID, err := resolvePublishedPairID(
		*expectedPairIDText, *checkpointPath, *checkpointIDText,
		plan, binding, planID, *sequence,
	)
	if err != nil {
		return err
	}
	exchangeBinding := tieexchange.Binding{PlanID: planID, PairID: expectedPairID, Sequence: *sequence}
	collector, err := calibration.OpenTieCollector(calibration.TieCollectorConfig{
		Plan: plan, Binding: binding, PrivateKey: observerKey,
		ReceiptPath: *receiptPath, PendingPath: *pendingPath,
	}, unixNow())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, collector.Close(unixNow())) }()
	initialStatus, err := collector.Status()
	if err != nil {
		return err
	}
	if initialStatus.NextSequence != *sequence && initialStatus.NextSequence != *sequence+1 {
		return fmt.Errorf("collector expects sequence %d, requested or recoverable sequence %d", initialStatus.NextSequence, *sequence)
	}
	observer := &tieHarnessObserver{collector: collector}
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

	type receiveResult struct {
		production tieproducer.Result
		receipt    types.Hash
		recovered  bool
		err        error
	}
	completed := make(chan receiveResult, 1)
	var reportOnce sync.Once
	report := func(result receiveResult) { reportOnce.Do(func() { completed <- result }) }
	var claimMu sync.Mutex
	claimed := false
	claim := func() bool {
		claimMu.Lock()
		defer claimMu.Unlock()
		if claimed {
			return false
		}
		claimed = true
		return true
	}
	fail := func(stream libp2pnetwork.Stream, err error) {
		_ = stream.Reset()
		report(receiveResult{err: err})
	}
	err = host.SetTiePairHandler(coordinatorPeerID, func(handlerContext context.Context, remoteID types.Hash, stream libp2pnetwork.Stream) {
		if remoteID != coordinatorPeerID {
			_ = stream.Reset()
			return
		}
		deadline := time.Now().Add(30 * time.Second)
		if initialStatus.NextSequence == *sequence {
			deadline = time.Unix(int64(plan.Slots[*sequence-1].EndedAt), 0)
		}
		if !deadline.After(time.Now()) {
			fail(stream, tieproducer.ErrOutsideSlot)
			return
		}
		if initialStatus.NextSequence == *sequence {
			now := unixNow()
			slot := plan.Slots[*sequence-1]
			if now < slot.StartedAt || now >= slot.EndedAt {
				fail(stream, tieproducer.ErrOutsideSlot)
				return
			}
		}
		if err := stream.SetDeadline(deadline); err != nil {
			fail(stream, err)
			return
		}
		request, err := tieexchange.ReadRequest(stream, exchangeBinding)
		if err != nil {
			fail(stream, err)
			return
		}
		actualPairID, err := tieproducer.ArtifactID(request.Artifact)
		if err != nil || actualPairID != expectedPairID {
			fail(stream, tieexchange.ErrBinding)
			return
		}
		pair, err := tieproducer.DecodePair(request.Artifact, plan, binding, planID)
		if err != nil {
			fail(stream, err)
			return
		}
		if !claim() {
			_ = stream.Reset()
			return
		}

		result := receiveResult{}
		if initialStatus.NextSequence == *sequence {
			attemptContext, attemptCancel := context.WithDeadline(handlerContext, deadline)
			result.production, result.err = tieproducer.AdmitPair(attemptContext, router, tieproducer.Config{
				Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: *sequence,
			}, pair)
			attemptCancel()
			if result.err == nil {
				result.err = observer.Err()
			}
			var status calibration.TieCollectorStatus
			if result.err == nil {
				status, result.err = collector.Status()
			}
			if result.err == nil && (status.NextSequence != *sequence+1 || status.InvalidCurrent || status.LastReceiptID.IsZero()) {
				result.err = errors.New("portable pair did not produce a completed durable receipt")
			}
			result.receipt = status.LastReceiptID
		} else {
			result.recovered = true
			result.receipt, result.err = persistedReceiptForPair(*receiptPath, plan, binding, pair, *sequence)
		}
		if result.err != nil {
			fail(stream, result.err)
			return
		}
		if err := tieexchange.WriteAcknowledgement(stream, tieexchange.Acknowledgement{
			Binding: exchangeBinding, ObserverPublicKey: observerPublicKey, ReceiptTail: result.receipt,
		}); err != nil {
			fail(stream, err)
			return
		}
		if _, err := tieexchange.ReadConfirmation(stream, exchangeBinding, result.receipt); err != nil {
			fail(stream, err)
			return
		}
		if err := tieexchange.WriteConfirmationAcknowledgement(
			stream,
			tieexchange.ConfirmationAcknowledgement{
				Binding: exchangeBinding, ReceiptTail: result.receipt,
			},
		); err != nil {
			fail(stream, err)
			return
		}
		if err := awaitTiePairCoordinatorClose(handlerContext, stream); err != nil {
			fail(stream, err)
			return
		}
		_ = stream.Close()
		report(result)
	})
	if err != nil {
		return err
	}
	addresses := host.Addresses()
	if len(addresses) == 0 {
		return errors.New("tie-pair receiver has no direct QUIC address")
	}
	fmt.Printf(
		"work_tie_pair_receiving transport_peer_id=%s coordinator_peer_id=%s plan=%s sequence=%d pair=%s observer=%s listen=%s\n",
		host.ID(), coordinatorPeerID, planID, *sequence, expectedPairID, observerPublicKey, strings.Join(addresses, ","),
	)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case result := <-completed:
		if result.err != nil {
			return result.err
		}
		fmt.Printf(
			"work_tie_pair_received plan=%s sequence=%d pair=%s observer=%s receipt_tail=%s recovered=%t\n",
			planID, *sequence, expectedPairID, observerPublicKey, result.receipt, result.recovered,
		)
		return nil
	}
}

func runWorkTelemetryTiePairSendQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-telemetry-tie-pair-send-quic", flag.ContinueOnError)
	transportKeyPath := flags.String("key", "", "coordinator QUIC transport Ed25519 seed file")
	peerAddress := flags.String("peer", "", "observer QUIC-v1 multiaddress including /p2p/<id>")
	observerPeerIDText := flags.String("observer-peer-id", "", "expected observer OutcomeMesh transport peer ID")
	observerPublicKeyText := flags.String("observer-public-key", "", "expected receipt observer Ed25519 public key")
	planIDText := flags.String("plan-id", "", "externally published controlled-tie plan ID")
	sequence := flags.Uint64("sequence", 0, "one-based planned slot sequence")
	pairIDText := flags.String("pair-id", "", "externally published portable pair ID")
	inputPath := flags.String("input", "", "portable pair artifact path")
	timeout := flags.Duration("timeout", 2*time.Minute, "connect, upload, replay, and acknowledgement timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *transportKeyPath == "" || *peerAddress == "" || *observerPeerIDText == "" ||
		*observerPublicKeyText == "" || *planIDText == "" || *sequence == 0 ||
		*pairIDText == "" || *inputPath == "" || *timeout < time.Second || *timeout > 10*time.Minute {
		return errors.New("key, pinned observer identities, peer, plan/pair IDs, sequence, input, and timeout 1s..10m are required")
	}
	transportKey, err := loadPrivateKey(*transportKeyPath)
	if err != nil {
		return err
	}
	observerPeerID, err := parseHash(*observerPeerIDText)
	if err != nil {
		return fmt.Errorf("observer-peer-id: %w", err)
	}
	observerPublicKey, err := parseHash(*observerPublicKeyText)
	if err != nil {
		return fmt.Errorf("observer-public-key: %w", err)
	}
	planID, err := parseHash(*planIDText)
	if err != nil {
		return fmt.Errorf("plan-id: %w", err)
	}
	pairID, err := parseHash(*pairIDText)
	if err != nil {
		return fmt.Errorf("pair-id: %w", err)
	}
	artifact, err := readTiePairFile(*inputPath)
	if err != nil {
		return err
	}
	actualPairID, err := tieproducer.ArtifactID(artifact)
	if err != nil || actualPairID != pairID {
		return errors.New("portable pair bytes do not match the published pair ID")
	}

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, *timeout)
	defer cancel()
	host, err := libp2ptransport.New(ctx, transportKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		return err
	}
	defer host.Close()
	exchangeBinding := tieexchange.Binding{PlanID: planID, PairID: pairID, Sequence: *sequence}
	acknowledgement, remoteID, err := exchangeTiePairQUIC(
		ctx, host, *peerAddress, observerPeerID, observerPublicKey,
		exchangeBinding, artifact, *timeout,
	)
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_tie_pair_sent transport_peer_id=%s observer_peer_id=%s plan=%s sequence=%d pair=%s observer=%s receipt_tail=%s bytes=%d\n",
		host.ID(), remoteID, planID, *sequence, pairID, observerPublicKey,
		acknowledgement.ReceiptTail, len(artifact),
	)
	return nil
}

func exchangeTiePairQUIC(
	ctx context.Context,
	host *libp2ptransport.Host,
	peerAddress string,
	observerPeerID types.Hash,
	observerPublicKey types.Hash,
	binding tieexchange.Binding,
	artifact []byte,
	timeout time.Duration,
) (tieexchange.Acknowledgement, types.Hash, error) {
	if ctx == nil || host == nil || peerAddress == "" || observerPeerID.IsZero() ||
		observerPublicKey.IsZero() || binding.Validate() != nil || len(artifact) == 0 ||
		timeout < time.Second || timeout > 10*time.Minute {
		return tieexchange.Acknowledgement{}, types.Hash{}, tieexchange.ErrProtocol
	}
	stream, remoteID, err := host.OpenTiePairStream(ctx, peerAddress, &observerPeerID)
	if err != nil {
		return tieexchange.Acknowledgement{}, types.Hash{}, err
	}
	defer stream.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if !deadline.After(time.Now()) {
		return tieexchange.Acknowledgement{}, types.Hash{}, context.DeadlineExceeded
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return tieexchange.Acknowledgement{}, types.Hash{}, err
	}
	if err := tieexchange.WriteRequest(stream, tieexchange.Request{Binding: binding, Artifact: artifact}); err != nil {
		return tieexchange.Acknowledgement{}, types.Hash{}, err
	}
	acknowledgement, err := tieexchange.ReadAcknowledgement(stream, binding, observerPublicKey)
	if err != nil {
		return tieexchange.Acknowledgement{}, types.Hash{}, err
	}
	if err := tieexchange.WriteConfirmation(stream, tieexchange.Confirmation{
		Binding: binding, ReceiptTail: acknowledgement.ReceiptTail,
	}); err != nil {
		return tieexchange.Acknowledgement{}, types.Hash{}, err
	}
	if _, err := tieexchange.ReadConfirmationAcknowledgement(
		stream, binding, acknowledgement.ReceiptTail,
	); err != nil {
		return tieexchange.Acknowledgement{}, types.Hash{}, err
	}
	retireTiePairCoordinatorStream(ctx, stream)
	return acknowledgement, remoteID, nil
}

func persistedReceiptForPair(
	path string,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	pair tieproducer.Pair,
	sequence uint64,
) (types.Hash, error) {
	_, receipts, _, err := calibration.LoadTieReceiptFile(path, binding)
	if err != nil || sequence == 0 || sequence > uint64(len(receipts)) {
		return types.Hash{}, errors.Join(errors.New("durable receipt recovery failed"), err)
	}
	receipt := receipts[sequence-1]
	testedID, testedErr := pair.Tested.Header.ID()
	controlID, controlErr := pair.Control.Header.ID()
	if testedErr != nil || controlErr != nil || receipt.Sequence != sequence ||
		receipt.Status != calibration.TieTrialCompleted || receipt.TestedAnchorID != testedID ||
		receipt.ControlAnchorID != controlID || receipt.ParentID != pair.Tested.Header.Seal.AnchorParent ||
		receipt.Height != pair.Tested.Header.Seal.Height {
		return types.Hash{}, errors.New("published pair does not match the durable receipt")
	}
	return receipt.ID(plan)
}

func hashFromPublicKey(publicKey ed25519.PublicKey) types.Hash {
	var result types.Hash
	copy(result[:], publicKey)
	return result
}
