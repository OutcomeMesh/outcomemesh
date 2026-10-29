package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/chainsession"
	"github.com/outcomemesh/outcomemesh/node/peers"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/node/workminer"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	workActivationFilename = "work-activation.bin"
	workActivationPending  = "work-activation.pending"
	workForestDirectory    = "work-forest"
	workActivationSize     = 64
)

var workActivationMagic = [8]byte{'O', 'M', 'W', 'O', 'R', 'K', 0, 1}

type workActivationProfile struct {
	NetworkID        uint32
	GenesisID        types.Hash
	ActivationHeight uint64
	FeeDelay         uint16
	MaxTrees         uint16
	MaxHistoryBytes  uint64
}

func runWorkEnable(arguments []string) error {
	flags := flag.NewFlagSet("work-enable", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "initialized node data directory")
	activationHeight := flags.Uint64("activation-height", 0, "first WorkGraph block height")
	feeDelay := flags.Uint("fee-delay", 3, "fork-local delayed-fee queue depth")
	maxTrees := flags.Uint("max-trees", activation.DefaultMaxWorkTrees, "maximum persisted activation-base trees")
	maxHistoryBytes := flags.Uint64("max-history-bytes", workchain.DefaultMaxHistoryBytes, "forest-wide logical v1 history budget")
	confirmGenesis := flags.String("confirm-genesis", "", "exact genesis ID required to enable the experimental path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *activationHeight == 0 || *feeDelay == 0 || *feeDelay > uint(workgraph.MaxFeeDelay) ||
		*maxTrees == 0 || *maxTrees > activation.MaxWorkTreesLimit || *maxTrees > uint(^uint16(0)) ||
		*maxHistoryBytes < minimumHistoryBytes || *confirmGenesis == "" {
		return fmt.Errorf(
			"activation-height and confirm-genesis are required; fee-delay must be 1..%d, max-trees 1..%d, and max-history-bytes at least %d",
			workgraph.MaxFeeDelay, activation.MaxWorkTreesLimit, minimumHistoryBytes,
		)
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	if document.Version != genesis.Version0 {
		return errors.New("WorkGraph requires protocol 0 genesis; protocol 2 activation is not defined")
	}
	if !workgraph.ExactShareRatio(document.Target) {
		return errors.New("genesis target cannot preserve the exact 512:1 WorkGraph threshold ratio; use at least 9 leading difficulty bits")
	}
	if _, _, err := workgraph.RewardRates(document.BlockSubsidy); err != nil {
		return fmt.Errorf("genesis subsidy is incompatible with bounded WorkGraph rewards: %w", err)
	}
	genesisID, err := document.ID()
	if err != nil {
		return err
	}
	confirmed, err := parseHash(*confirmGenesis)
	if err != nil || confirmed != genesisID {
		return fmt.Errorf("confirm-genesis does not match %s", genesisID)
	}
	if existing, err := loadWorkActivation(*data, document); err == nil {
		return fmt.Errorf("WorkGraph path is already enabled at height %d", existing.ActivationHeight)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	tip, err := store.Tip()
	if err != nil {
		return err
	}
	if tip.Height >= *activationHeight {
		return fmt.Errorf("activation height %d must be above current v0 height %d", *activationHeight, tip.Height)
	}
	profile := workActivationProfile{
		NetworkID: document.NetworkID, GenesisID: genesisID, ActivationHeight: *activationHeight,
		FeeDelay: uint16(*feeDelay), MaxTrees: uint16(*maxTrees), MaxHistoryBytes: *maxHistoryBytes,
	}
	router, err := openWorkRouter(store, document, profile, *data, nil)
	if err != nil {
		return fmt.Errorf("validate WorkGraph activation: %w", err)
	}
	if err := router.Close(); err != nil {
		return err
	}
	if err := writeWorkActivation(*data, profile); err != nil {
		return err
	}
	fmt.Printf(
		"work_enabled network=%d genesis=%s activation_height=%d fee_delay=%d max_trees=%d max_history_bytes=%d\n",
		profile.NetworkID, profile.GenesisID, profile.ActivationHeight, profile.FeeDelay,
		profile.MaxTrees, profile.MaxHistoryBytes,
	)
	return nil
}

func runWorkStatus(arguments []string) error {
	flags := flag.NewFlagSet("work-status", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	document, store, router, profile, err := openWorkNode(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	defer router.Close()
	tip, err := router.Tip()
	if err != nil {
		return err
	}
	state, err := router.Snapshot()
	if err != nil {
		return err
	}
	forest, err := router.WorkForestStatus()
	if err != nil {
		return err
	}
	fmt.Printf(
		"work_status network=%d activation_height=%d height=%d tip=%s state=%s resources=%d cumulative_work=%x trees=%d/%d nodes=%d history_bytes=%d history_limit=%d\n",
		document.NetworkID, profile.ActivationHeight, tip.Height, tip.ID, tip.StateRoot,
		state.Len(), tip.CumulativeWork, forest.Trees, forest.MaxTrees, forest.Nodes,
		forest.HistoryBytes, forest.MaxHistoryBytes,
	)
	return nil
}

func runWorkBalance(arguments []string) error {
	flags := flag.NewFlagSet("work-balance", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	addressText := flags.String("address", "", "address as 64 hex characters (default: first genesis owner)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	document, store, router, _, err := openWorkNode(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	defer router.Close()
	var address types.Address
	if *addressText == "" {
		if len(document.Allocations) == 0 {
			return errors.New("genesis has no default allocation owner")
		}
		address = document.Allocations[0].Owner
	} else {
		address, err = parseAddress(*addressText)
		if err != nil {
			return err
		}
	}
	state, err := router.Snapshot()
	if err != nil {
		return err
	}
	tip, err := router.Tip()
	if err != nil {
		return err
	}
	if tip.Height == ^uint64(0) {
		return errors.New("tip height overflow")
	}
	total, err := state.Balance(address, types.NativeAssetID())
	if err != nil {
		return err
	}
	spendable, err := state.SpendableBalance(address, types.NativeAssetID(), tip.Height+1)
	if err != nil {
		return err
	}
	locked, err := types.SubAmount(total, spendable)
	if err != nil {
		return err
	}
	fmt.Printf("work_balance address=%s asset=%s total=%d spendable_next_height=%d locked=%d height=%d\n",
		address, types.NativeAssetID(), total, spendable, locked, tip.Height)
	return nil
}

func runWorkVerify(arguments []string) error {
	flags := flag.NewFlagSet("work-verify", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	document, store, router, profile, err := openWorkNode(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	defer router.Close()
	legacyTip, err := verifyLegacyLedger(store, document)
	if err != nil {
		return err
	}
	tip, err := router.Tip()
	if err != nil {
		return err
	}
	genesisID, err := document.ID()
	if err != nil {
		return err
	}
	cursor := tip.ID
	for height := tip.Height; height > 0; height-- {
		candidate, err := router.BlockByID(cursor)
		if err != nil {
			return fmt.Errorf("load routed block %d: %w", height, err)
		}
		if candidate.Height() != height {
			return fmt.Errorf("invalid routed height %d: %w", height, storage.ErrCorrupt)
		}
		if err := candidate.Validate(profile.ActivationHeight); err != nil {
			return fmt.Errorf("validate routed block %d: %w", height, err)
		}
		id, err := candidate.ID()
		if err != nil || id != cursor {
			return storage.ErrCorrupt
		}
		cursor = candidate.ParentID()
	}
	if cursor != genesisID || legacyTip.Height >= profile.ActivationHeight {
		return storage.ErrCorrupt
	}
	state, err := router.Snapshot()
	if err != nil || state.Root() != tip.StateRoot {
		return storage.ErrCorrupt
	}
	forest, err := router.WorkForestStatus()
	if err != nil {
		return err
	}
	fmt.Printf("work_verified activation_height=%d height=%d tip=%s state=%s trees=%d nodes=%d history_bytes=%d\n",
		profile.ActivationHeight, tip.Height, tip.ID, tip.StateRoot, forest.Trees, forest.Nodes, forest.HistoryBytes)
	return nil
}

func runWorkMine(arguments []string) error {
	flags := flag.NewFlagSet("work-mine", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	minerText := flags.String("miner", defaultDevelopmentAddress().String(), "reward address as 64 hex characters")
	count := flags.Uint64("count", 1, "number of empty development blocks")
	startNonce := flags.Uint64("start-nonce", 0, "first WorkSeal nonce to test")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *count == 0 {
		return errors.New("count must be positive")
	}
	miner, err := parseAddress(*minerText)
	if err != nil {
		return fmt.Errorf("miner: %w", err)
	}
	_, store, router, profile, err := openWorkNode(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	defer router.Close()
	roundManager, err := workround.NewManager(router, unixNow, worksession.DefaultConfig())
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for index := uint64(0); index < *count; index++ {
		parent, err := router.Tip()
		if err != nil {
			return err
		}
		timestamp := workTimestamp(parent.Timestamp)
		started := time.Now()
		if parent.Height+1 < profile.ActivationHeight {
			prepared, err := router.PrepareLegacy(nil, miner, timestamp)
			if err != nil {
				return err
			}
			candidate, ok := prepared.LegacyBlock()
			if !ok {
				return storage.ErrCorrupt
			}
			candidate, _, err = legacyblock.Mine(ctx, candidate, *startNonce)
			if err != nil {
				return err
			}
			routed, err := activation.Legacy(candidate, profile.ActivationHeight)
			if err != nil {
				return err
			}
			tip, err := router.Submit(routed)
			if err != nil {
				return err
			}
			id, _ := routed.ID()
			fmt.Printf("work_mined version=0 height=%d id=%s nonce=%d elapsed=%s state=%s\n",
				tip.Height, id, candidate.Header.Nonce, time.Since(started).Round(time.Millisecond), tip.StateRoot)
			continue
		}
		inclusion, err := workgraph.InclusionRoot(nil)
		if err != nil {
			return err
		}
		round, err := roundManager.Current()
		if err != nil {
			return err
		}
		var mined workminer.Result
		var weakShares, capacityRejections uint64
		for {
			miningContext, err := round.Context()
			if err != nil {
				return err
			}
			mineContext, stopMining := context.WithTimeout(
				ctx, workRoundRolloverDelay(miningContext.AnchorTimestamp, unixNow()),
			)
			generation, mineErr := round.Mine(mineContext, miner, inclusion, *startNonce, nil)
			timedOut := errors.Is(mineContext.Err(), context.DeadlineExceeded) && ctx.Err() == nil
			stopMining()
			weakShares += generation.WeakShares
			capacityRejections += generation.CapacityRejections
			if !timedOut {
				if mineErr != nil {
					return mineErr
				}
				mined = generation
				mined.WeakShares = weakShares
				mined.CapacityRejections = capacityRejections
				break
			}
			next, err := roundManager.RollForward(round)
			if err != nil {
				return err
			}
			nextContext, err := next.Context()
			if err != nil {
				return err
			}
			status, _ := next.Status()
			fmt.Fprintf(os.Stderr, "work_round_rollover height=%d timestamp=%d->%d retained_shares=%d\n",
				nextContext.Height, miningContext.AnchorTimestamp, nextContext.AnchorTimestamp, status.Shares)
			round = next
		}
		routed, err := activation.Work(mined.Block, profile.ActivationHeight)
		if err != nil {
			return err
		}
		tip, err := router.Submit(routed)
		if err != nil {
			return err
		}
		if err := roundManager.Invalidate(); err != nil {
			return err
		}
		id, err := mined.Block.Header.ID()
		if err != nil {
			return err
		}
		fmt.Printf("work_mined version=1 height=%d id=%s nonce=%d weak_shares=%d included_shares=%d capacity_rejections=%d elapsed=%s state=%s\n",
			tip.Height, id, mined.WinningNonce, mined.WeakShares, len(mined.Block.Shares),
			mined.CapacityRejections, time.Since(started).Round(time.Millisecond), tip.StateRoot)
	}
	return nil
}

func runWorkServeQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-serve-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/9845/quic-v1", "QUIC-v1 libp2p listen multiaddress")
	maxConnections := flags.Int("max-connections", 64, "maximum authenticated QUIC connections")
	maxStreams := flags.Int("max-chain-streams", 4, "maximum concurrent versioned chain streams")
	maxStreamsPerPeer := flags.Int("max-chain-streams-per-peer", 1, "maximum concurrent versioned streams per peer")
	telemetryKeyPath := flags.String("telemetry-key", "", "independent Ed25519 observer seed; enables hard-anchor telemetry")
	telemetryPolicyPath := flags.String("telemetry-policy", "", "published miner-to-cluster policy text file")
	telemetryPolicyIDText := flags.String("telemetry-policy-id", "", "expected canonical cluster-policy ID")
	telemetryClusters := flags.Uint("telemetry-clusters", 0, "precommitted cluster comparison budget")
	telemetryManifestPath := flags.String("telemetry-manifest", "", "signed telemetry manifest path (default under data)")
	telemetryPendingPath := flags.String("telemetry-pending", "", "crash-safe current-hour journal path (default under data)")
	tiePlanPath := flags.String("telemetry-tie-plan", "", "published signed controlled-tie plan file")
	tiePlanIDText := flags.String("telemetry-tie-plan-id", "", "externally published controlled-tie plan ID")
	tieCoordinatorKeyText := flags.String("telemetry-tie-coordinator-key", "", "trusted controlled-tie coordinator public key")
	tieManifestPath := flags.String("telemetry-tie-manifest", "", "signed raw tie receipt path (default under data)")
	tiePendingPath := flags.String("telemetry-tie-pending", "", "crash-safe partial tie candidate path (default under data)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *keyPath == "" || *maxConnections <= 0 || *maxConnections > libp2ptransport.MaxConnectionLimit ||
		*maxStreams <= 0 || *maxStreams > libp2ptransport.MaxVersionedChainStreamsLimit ||
		*maxStreamsPerPeer <= 0 || *maxStreamsPerPeer > libp2ptransport.MaxVersionedChainStreamsPerPeerLimit ||
		*maxStreams < *maxStreamsPerPeer {
		return errors.New("key and coherent bounded connection/versioned-stream limits are required")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	tieEnabled := *tiePlanPath != "" || *tiePlanIDText != "" || *tieCoordinatorKeyText != "" ||
		*tieManifestPath != "" || *tiePendingPath != ""
	telemetryEnabled := tieEnabled || *telemetryKeyPath != "" || *telemetryPolicyPath != "" || *telemetryPolicyIDText != "" ||
		*telemetryClusters != 0 || *telemetryManifestPath != "" || *telemetryPendingPath != ""
	var liveTelemetry *liveWorkTelemetry
	var observer func(activation.WorkAdmission)
	telemetryClosed := false
	if telemetryEnabled {
		if *telemetryKeyPath == "" || *telemetryPolicyPath == "" || *telemetryPolicyIDText == "" ||
			*telemetryClusters == 0 || *telemetryClusters > calibration.MaximumClusters {
			return errors.New("telemetry requires key, policy, expected policy ID, and a bounded cluster budget")
		}
		expectedPolicyID, err := parseHash(*telemetryPolicyIDText)
		if err != nil {
			return fmt.Errorf("telemetry-policy-id: %w", err)
		}
		telemetryDocument, err := loadGenesis(*data)
		if err != nil {
			return err
		}
		telemetryProfile, err := loadWorkActivation(*data, telemetryDocument)
		if err != nil {
			return err
		}
		if *telemetryManifestPath == "" {
			*telemetryManifestPath = filepath.Join(*data, "work-telemetry.omtm")
		}
		if *telemetryPendingPath == "" {
			*telemetryPendingPath = filepath.Join(*data, "work-telemetry.pending")
		}
		var tieConfig *liveTieTelemetryConfig
		if tieEnabled {
			if *tiePlanPath == "" || *tiePlanIDText == "" || *tieCoordinatorKeyText == "" {
				return errors.New("controlled-tie telemetry requires plan, published plan ID, and coordinator public key")
			}
			expectedPlanID, err := parseHash(*tiePlanIDText)
			if err != nil {
				return fmt.Errorf("telemetry-tie-plan-id: %w", err)
			}
			coordinatorKey, err := parseHash(*tieCoordinatorKeyText)
			if err != nil {
				return fmt.Errorf("telemetry-tie-coordinator-key: %w", err)
			}
			if *tieManifestPath == "" {
				*tieManifestPath = filepath.Join(*data, "work-tie-receipts.omtr")
			}
			if *tiePendingPath == "" {
				*tiePendingPath = filepath.Join(*data, "work-tie-receipts.pending")
			}
			tieConfig = &liveTieTelemetryConfig{
				PlanPath: *tiePlanPath, ExpectedPlanID: expectedPlanID,
				ReceiptPath: *tieManifestPath, PendingPath: *tiePendingPath,
			}
			copy(tieConfig.CoordinatorPublicKey[:], coordinatorKey[:])
		}
		liveTelemetry, err = openLiveWorkTelemetry(
			telemetryDocument, telemetryProfile, *telemetryKeyPath, *telemetryPolicyPath,
			expectedPolicyID, uint32(*telemetryClusters), *telemetryManifestPath, *telemetryPendingPath, unixNow(), tieConfig,
		)
		if err != nil {
			return err
		}
		observer = liveTelemetry.Observe
		defer func() {
			if !telemetryClosed {
				_ = liveTelemetry.Close(unixNow())
			}
		}()
	}
	document, store, router, profile, err := openWorkNodeObserved(*data, observer)
	if err != nil {
		return err
	}
	defer store.Close()
	defer router.Close()
	chainSession, err := chainsession.NewNode(router, document, chainsession.DefaultSessionConfig())
	if err != nil {
		return err
	}
	roundManager, err := workround.NewManager(router, unixNow, worksession.DefaultConfig())
	if err != nil {
		return err
	}
	peerManager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var telemetryErrors <-chan error
	if liveTelemetry != nil {
		telemetryErrors = liveTelemetry.Start(ctx, unixNow)
		status, statusErr := liveTelemetry.Status()
		if statusErr != nil {
			return statusErr
		}
		fmt.Printf("work_telemetry_enabled policy=%s records=%d completed_through=%d pending_start=%d tail=%s\n",
			*telemetryPolicyIDText, status.Records, status.CompletedThrough, status.PendingStartedAt, status.LastRecordID)
		if tieEnabled {
			tieStatus, tieStatusErr := liveTelemetry.TieStatus()
			if tieStatusErr != nil {
				return tieStatusErr
			}
			fmt.Printf("work_tie_telemetry_enabled plan=%s closed=%d planned=%d completed=%d no_pair=%d tail=%s\n",
				tieStatus.PlanID, tieStatus.ClosedSlots, tieStatus.PlannedSlots,
				tieStatus.CompletedTrials, tieStatus.NoPairSlots, tieStatus.LastReceiptID)
		}
	}
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{*listenAddress}
	config.MaxConnections = *maxConnections
	config.MaxVersionedChainStreams = *maxStreams
	config.MaxVersionedChainStreamsPerPeer = *maxStreamsPerPeer
	config.MaxFileDescriptors = max(config.MaxFileDescriptors, 2*config.MaxConnections)
	host, err := libp2ptransport.New(ctx, privateKey, config, nil)
	if err != nil {
		return err
	}
	defer host.Close()
	now := unixNow()
	addressBook, err := openPeerBook(*data, document.NetworkID, now)
	if err != nil {
		return err
	}
	if _, err := publishWorkDiscoveryRecord(
		addressBook, privateKey, host.ID(), document.NetworkID, profile.ActivationHeight,
		host.Addresses(), now, workDiscoverySuggestedSequence(),
	); err != nil {
		return err
	}
	if err := savePeerBook(*data, addressBook, now); err != nil {
		return err
	}
	chainSession.AttachDiscovery(addressBook)
	if err := host.SetVersionedChainHandler(func(handlerContext context.Context, peerID types.Hash, stream libp2pnetwork.Stream) {
		if err := peerManager.Acquire(peerID); err != nil {
			_ = stream.Reset()
			return
		}
		defer peerManager.Release(peerID)
		limited := &peerLimitedStream{Stream: stream, manager: peerManager, peerID: peerID}
		sessionErr := chainSession.Serve(handlerContext, limited)
		recordPeerSession(peerManager, peerID, sessionErr)
		if sessionErr != nil && handlerContext.Err() == nil {
			fmt.Fprintf(os.Stderr, "versioned QUIC peer session %s: %v\n", peerID, sessionErr)
		}
	}); err != nil {
		return err
	}
	if err := host.SetWorkGraphHandler(func(handlerContext context.Context, peerID types.Hash, stream libp2pnetwork.Stream) {
		if err := peerManager.Acquire(peerID); err != nil {
			_ = stream.Reset()
			return
		}
		defer peerManager.Release(peerID)
		round, err := roundManager.Current()
		if err != nil {
			_ = stream.Reset()
			return
		}
		limited := &peerLimitedStream{Stream: stream, manager: peerManager, peerID: peerID}
		sessionErr := round.Serve(handlerContext, limited)
		recordWorkPeerSession(peerManager, peerID, sessionErr)
		if sessionErr != nil {
			if handlerContext.Err() == nil {
				fmt.Fprintf(os.Stderr, "WorkGraph QUIC peer session %s: %v\n", peerID, sessionErr)
			}
			return
		}
		status, err := round.Status()
		if err == nil {
			fmt.Fprintf(os.Stderr, "work_relay peer_id=%s accepted=%d pending=%d shares=%d\n",
				peerID, status.Accepted, status.Pending, status.Shares)
		}
	}); err != nil {
		return err
	}
	if err := host.SetChainNotifyHandler(func(handlerContext context.Context, peerID types.Hash, stream libp2pnetwork.Stream) {
		if err := peerManager.Acquire(peerID); err != nil {
			_ = stream.Reset()
			return
		}
		defer peerManager.Release(peerID)
		before, beforeErr := router.Tip()
		limited := &peerLimitedStream{Stream: stream, manager: peerManager, peerID: peerID}
		selected, sessionErr := chainSession.Synchronize(handlerContext, limited)
		recordPeerSession(peerManager, peerID, sessionErr)
		if sessionErr != nil {
			if handlerContext.Err() == nil {
				fmt.Fprintf(os.Stderr, "chain notification from %s: %v\n", peerID, sessionErr)
			}
			return
		}
		if beforeErr == nil && selected.ID != before.ID {
			_ = roundManager.Invalidate()
		}
		fmt.Fprintf(os.Stderr, "chain_notification peer_id=%s height=%d tip=%s\n", peerID, selected.Height, selected.ID)
	}); err != nil {
		return err
	}
	fmt.Printf("serving_work_quic peer_id=%s libp2p_id=%s network=%d activation_height=%d protocols=chain-v1,chain-notify-v1,workgraph-v1,peer-discovery-v1 listen=%s\n",
		host.ID(), host.Libp2pID(), document.NetworkID, profile.ActivationHeight, strings.Join(host.Addresses(), ","))
	renewalErrors := renewWorkDiscoveryRecords(
		ctx, *data, addressBook, privateKey, host.ID(), document.NetworkID,
		profile.ActivationHeight, host.Addresses(),
	)
	var serveErr error
	select {
	case <-ctx.Done():
		serveErr = nil
	case renewalErr, ok := <-renewalErrors:
		if !ok {
			serveErr = nil
		} else {
			serveErr = renewalErr
		}
	case telemetryErr := <-telemetryErrors:
		serveErr = fmt.Errorf("WorkGraph telemetry failed: %w", telemetryErr)
	}
	cancel()
	serveErr = errors.Join(serveErr, host.Close(), router.Close())
	if liveTelemetry != nil {
		telemetryClosed = true
		serveErr = errors.Join(serveErr, liveTelemetry.Close(unixNow()))
	}
	return serveErr
}

func recordWorkPeerSession(manager *peers.Manager, peerID types.Hash, sessionErr error) {
	if sessionErr == nil {
		_ = manager.Record(peerID, peers.EventValidMessage)
	} else if errors.Is(sessionErr, worksession.ErrContext) {
		_ = manager.Record(peerID, peers.EventStaleData)
	} else if networkError, ok := sessionErr.(interface{ Timeout() bool }); ok && networkError.Timeout() {
		_ = manager.Record(peerID, peers.EventTimeout)
	} else {
		_ = manager.Record(peerID, peers.EventInvalidMessage)
	}
}

func runWorkSyncQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-sync-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	peerAddress := flags.String("peer", "", "QUIC-v1 libp2p multiaddress including /p2p/<id>")
	peerIDText := flags.String("peer-id", "", "expected OutcomeMesh peer ID as 64 hex characters")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *keyPath == "" || *peerAddress == "" {
		return errors.New("key and peer are required")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	var expectedPeer *types.Hash
	if *peerIDText != "" {
		parsed, err := parseHash(*peerIDText)
		if err != nil {
			return fmt.Errorf("peer-id: %w", err)
		}
		expectedPeer = &parsed
	}
	document, store, router, profile, err := openWorkNode(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	defer router.Close()
	chainSession, err := chainsession.NewNode(router, document, chainsession.DefaultSessionConfig())
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	host, err := libp2ptransport.New(ctx, privateKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		return err
	}
	defer host.Close()
	stream, peerID, err := host.OpenVersionedChainStream(ctx, *peerAddress, expectedPeer)
	if err != nil {
		return err
	}
	tip, err := chainSession.Synchronize(ctx, stream)
	if err != nil {
		return err
	}
	fmt.Printf("work_synced_quic peer_id=%s activation_height=%d height=%d tip=%s state=%s cumulative_work=%x\n",
		peerID, profile.ActivationHeight, tip.Height, tip.ID, tip.StateRoot, tip.CumulativeWork)
	return nil
}

func openWorkNode(data string) (
	genesis.Document,
	storage.Ledger,
	*activation.Router,
	workActivationProfile,
	error,
) {
	return openWorkNodeObserved(data, nil)
}

func openWorkNodeObserved(
	data string,
	observer func(activation.WorkAdmission),
) (
	genesis.Document,
	storage.Ledger,
	*activation.Router,
	workActivationProfile,
	error,
) {
	document, err := loadGenesis(data)
	if err != nil {
		return genesis.Document{}, nil, nil, workActivationProfile{}, err
	}
	profile, err := loadWorkActivation(data, document)
	if err != nil {
		return genesis.Document{}, nil, nil, workActivationProfile{}, err
	}
	store, err := openStore(data, document)
	if err != nil {
		return genesis.Document{}, nil, nil, workActivationProfile{}, err
	}
	router, err := openWorkRouter(store, document, profile, data, observer)
	if err != nil {
		_ = store.Close()
		return genesis.Document{}, nil, nil, workActivationProfile{}, err
	}
	return document, store, router, profile, nil
}

func openWorkRouter(
	ledger storage.Ledger,
	document genesis.Document,
	profile workActivationProfile,
	data string,
	observer func(activation.WorkAdmission),
) (*activation.Router, error) {
	if err := validateWorkActivation(profile, document); err != nil {
		return nil, err
	}
	legacy := legacyblock.ParametersFromGenesis(document)
	forestRoot, err := filepath.Abs(filepath.Join(data, workForestDirectory))
	if err != nil {
		return nil, err
	}
	policy := workchain.DefaultPolicy()
	policy.MaxHistoryBytes = profile.MaxHistoryBytes
	return activation.New(ledger, activation.Config{
		Legacy: legacy,
		Work: workblock.Parameters{
			NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy,
			RewardMaturity: legacy.RewardMaturity, ActivationHeight: profile.ActivationHeight,
			DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
			TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife,
			FeeDelay: profile.FeeDelay,
		},
		Now: func() uint64 { return unixNow() }, WorkRoot: forestRoot,
		WorkPolicy: policy, MaxWorkTrees: int(profile.MaxTrees), ObserveWork: observer,
	})
}

func validateWorkActivation(profile workActivationProfile, document genesis.Document) error {
	if document.Version != genesis.Version0 {
		return errors.New("WorkGraph requires protocol 0 genesis; protocol 2 activation is not defined")
	}
	genesisID, err := document.ID()
	if err != nil {
		return err
	}
	if profile.NetworkID != document.NetworkID || profile.GenesisID != genesisID ||
		profile.ActivationHeight == 0 || profile.FeeDelay == 0 || profile.FeeDelay > workgraph.MaxFeeDelay ||
		profile.MaxTrees == 0 || profile.MaxTrees > activation.MaxWorkTreesLimit ||
		profile.MaxHistoryBytes < minimumHistoryBytes {
		return errors.New("invalid or mismatched WorkGraph activation profile")
	}
	return nil
}

func loadWorkActivation(data string, document genesis.Document) (workActivationProfile, error) {
	encoded, err := os.ReadFile(filepath.Join(data, workActivationFilename))
	if err != nil {
		return workActivationProfile{}, err
	}
	profile, err := decodeWorkActivation(encoded)
	if err != nil {
		return workActivationProfile{}, err
	}
	if err := validateWorkActivation(profile, document); err != nil {
		return workActivationProfile{}, err
	}
	return profile, nil
}

func (profile workActivationProfile) canonicalBytes() []byte {
	encoded := make([]byte, workActivationSize)
	copy(encoded[:8], workActivationMagic[:])
	binary.BigEndian.PutUint32(encoded[8:12], profile.NetworkID)
	copy(encoded[12:44], profile.GenesisID[:])
	binary.BigEndian.PutUint64(encoded[44:52], profile.ActivationHeight)
	binary.BigEndian.PutUint16(encoded[52:54], profile.FeeDelay)
	binary.BigEndian.PutUint16(encoded[54:56], profile.MaxTrees)
	binary.BigEndian.PutUint64(encoded[56:64], profile.MaxHistoryBytes)
	return encoded
}

func decodeWorkActivation(encoded []byte) (workActivationProfile, error) {
	if len(encoded) != workActivationSize || !bytes.Equal(encoded[:8], workActivationMagic[:]) {
		return workActivationProfile{}, errors.New("invalid WorkGraph activation profile encoding")
	}
	var result workActivationProfile
	result.NetworkID = binary.BigEndian.Uint32(encoded[8:12])
	copy(result.GenesisID[:], encoded[12:44])
	result.ActivationHeight = binary.BigEndian.Uint64(encoded[44:52])
	result.FeeDelay = binary.BigEndian.Uint16(encoded[52:54])
	result.MaxTrees = binary.BigEndian.Uint16(encoded[54:56])
	result.MaxHistoryBytes = binary.BigEndian.Uint64(encoded[56:64])
	if result.NetworkID == 0 || result.GenesisID.IsZero() || result.ActivationHeight == 0 ||
		result.FeeDelay == 0 || result.FeeDelay > workgraph.MaxFeeDelay || result.MaxTrees == 0 ||
		result.MaxTrees > activation.MaxWorkTreesLimit || result.MaxHistoryBytes < minimumHistoryBytes {
		return workActivationProfile{}, errors.New("invalid WorkGraph activation profile fields")
	}
	return result, nil
}

func writeWorkActivation(data string, profile workActivationProfile) error {
	finalPath := filepath.Join(data, workActivationFilename)
	pendingPath := filepath.Join(data, workActivationPending)
	if _, err := os.Lstat(finalPath); err == nil {
		return errors.New("WorkGraph activation profile already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	want := profile.canonicalBytes()
	if pending, err := os.ReadFile(pendingPath); err == nil {
		if !bytes.Equal(pending, want) {
			return errors.New("conflicting pending WorkGraph activation profile")
		}
		pendingFile, err := os.Open(pendingPath)
		if err != nil {
			return err
		}
		syncErr := pendingFile.Sync()
		closeErr := pendingFile.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Rename(pendingPath, finalPath); err != nil {
			return err
		}
		return syncCommandDirectory(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(pendingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeCommandBytes(file, want)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(pendingPath, finalPath); err != nil {
		return err
	}
	return syncCommandDirectory(data)
}

func rejectWorkActivation(data, command string) error {
	for _, name := range []string{workActivationFilename, workActivationPending} {
		if _, err := os.Lstat(filepath.Join(data, name)); err == nil {
			return fmt.Errorf("%s is disabled for a WorkGraph-enabled data directory; use the explicit work-* command", command)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func writeCommandBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func syncCommandDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func workTimestamp(parent uint64) uint64 {
	now := unixNow()
	if now <= parent {
		return parent + 1
	}
	return now
}

func unixNow() uint64 {
	now := time.Now().Unix()
	if now < 0 {
		return 0
	}
	return uint64(now)
}
