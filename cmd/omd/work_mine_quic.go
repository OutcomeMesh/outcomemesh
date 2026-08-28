package main

import (
	"context"
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
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/chainsession"
	"github.com/outcomemesh/outcomemesh/node/peers"
	"github.com/outcomemesh/outcomemesh/node/routing"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

func runWorkMineQUIC(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("work-mine-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "QUIC-v1 libp2p listen multiaddress")
	var peerAddresses repeatedStringFlag
	var peerIDs repeatedStringFlag
	flags.Var(&peerAddresses, "peer", "cooperating WorkGraph peer multiaddress; repeat for up to 8 peers")
	flags.Var(&peerIDs, "peer-id", "matching OutcomeMesh peer ID; omit all or repeat once per peer")
	autoPeers := flags.Int("auto-peers", 0, "compatible peers to select from the signed local peerbook")
	autoAttempts := flags.Int("auto-attempts", 16, "maximum ranked peerbook capability probes")
	asnMapPath := flags.String("asn-map", "", "required local CIDR,ASN table for automatic peer diversity")
	asnMaxAge := flags.Duration("asn-max-age", 24*time.Hour, "maximum accepted age of the local ASN table")
	maxPerASN := flags.Int("max-per-asn", 1, "maximum automatic peers attempted from one resolved ASN")
	minerText := flags.String("miner", defaultDevelopmentAddress().String(), "reward address as 64 hex characters")
	count := flags.Uint64("count", 1, "number of version-1 anchors")
	startNonce := flags.Uint64("start-nonce", 0, "first WorkSeal nonce to test per round")
	relayEvery := flags.Int("relay-every", 128, "unpublished weak shares collected before a relay attempt")
	relayInterval := flags.Duration("relay-interval", defaultWorkRelayInterval, "maximum wait before relaying a partial weak-share batch")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *keyPath == "" || *count == 0 || *relayEvery <= 0 || *relayEvery > wire.MaxShareInventoryIDs ||
		*relayInterval < defaultWorkRelayInterval || *relayInterval > maxWorkRelayInterval {
		return fmt.Errorf("key is required; count must be positive, relay-every must be 1..%d, and relay-interval must be %s..%s",
			wire.MaxShareInventoryIDs, defaultWorkRelayInterval, maxWorkRelayInterval)
	}
	targets, err := parseWorkPeerTargets(peerAddresses, peerIDs)
	if err != nil {
		return err
	}
	if *autoPeers < 0 || *autoPeers > maxWorkMiningPeers || len(targets)+*autoPeers == 0 ||
		len(targets)+*autoPeers > maxWorkMiningPeers {
		return fmt.Errorf("explicit plus automatic peers must total 1..%d", maxWorkMiningPeers)
	}
	if *autoPeers > 0 && (*asnMapPath == "" || *autoAttempts < *autoPeers || *autoAttempts > wire.MaxPeerRecords ||
		*asnMaxAge <= 0 || *asnMaxAge > routing.MaxASNTableAge || *maxPerASN <= 0 || *maxPerASN > wire.MaxPeerRecords) {
		return fmt.Errorf("automatic peers require an ASN map, attempts %d..%d, max-per-asn 1..%d, and asn-max-age up to %s",
			*autoPeers, wire.MaxPeerRecords, wire.MaxPeerRecords, routing.MaxASNTableAge)
	}
	miner, err := parseAddress(*minerText)
	if err != nil {
		return fmt.Errorf("miner: %w", err)
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
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
	if tip.Height == ^uint64(0) || tip.Height+1 < profile.ActivationHeight {
		return fmt.Errorf("mine the version-0 prefix through height %d with work-mine before cooperative mining", profile.ActivationHeight-1)
	}
	roundManager, err := workround.NewManager(router, unixNow, worksession.DefaultConfig())
	if err != nil {
		return err
	}
	chainSession, err := chainsession.NewNode(router, document, chainsession.DefaultSessionConfig())
	if err != nil {
		return err
	}
	peerManager, err := openPeerManager(*data)
	if err != nil {
		return err
	}
	defer func() {
		if saveErr := peers.SaveFile(filepath.Join(*data, reputationFilename), peerManager); resultErr == nil && saveErr != nil {
			resultErr = saveErr
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{*listenAddress}
	host, err := libp2ptransport.New(ctx, privateKey, config, nil)
	if err != nil {
		return err
	}
	defer host.Close()
	for _, target := range targets {
		if target.id == host.ID() {
			return errors.New("cooperative peer list contains this miner's identity")
		}
	}
	roundControl := new(workMiningRoundControl)
	if err := installWorkMiningHandlers(host, chainSession, roundManager, peerManager, roundControl); err != nil {
		return err
	}
	if *autoPeers > 0 {
		probeRound, err := roundManager.Current()
		if err != nil {
			return err
		}
		automatic, results, err := selectAutomaticWorkPeers(
			ctx, *data, document.NetworkID, host, probeRound, peerManager, targets,
			workAutoPeerConfig{
				Count: *autoPeers, AttemptLimit: *autoAttempts, ASNMapPath: *asnMapPath,
				ASNMaxAge: *asnMaxAge, MaxPerASN: *maxPerASN,
			},
		)
		for _, result := range results {
			if result.Err == nil {
				fmt.Printf("work_auto_probe peer_id=%s result=compatible\n", result.PeerID)
			} else {
				fmt.Printf("work_auto_probe peer_id=%s result=failed error=%q\n", result.PeerID, result.Err)
			}
		}
		if err != nil {
			return err
		}
		for _, target := range automatic {
			fmt.Printf("work_auto_peer peer_id=%s address=%s\n", target.id, target.address)
		}
		targets = append(targets, automatic...)
	}
	notifier, err := newWorkAnchorNotifier(ctx, targets, func(notifyContext context.Context, target workPeerTarget) error {
		return notifyWorkAnchor(notifyContext, host, chainSession, peerManager, target)
	})
	if err != nil {
		return err
	}
	defer notifier.Close()
	fmt.Printf("mining_work_quic peer_id=%s libp2p_id=%s network=%d activation_height=%d peers=%d auto_peers=%d relay_every=%d relay_interval=%s listen=%s\n",
		host.ID(), host.Libp2pID(), document.NetworkID, profile.ActivationHeight, len(targets), *autoPeers, *relayEvery, *relayInterval,
		strings.Join(host.Addresses(), ","))
anchorLoop:
	for minedCount := uint64(0); minedCount < *count; {
		started := time.Now()
		var totalWeakShares, totalCapacityRejections uint64
		var totalGossip workMiningGossipStats
		var totalRelay workShareFanoutStats
		for {
			round, err := roundManager.Current()
			if err != nil {
				return err
			}
			inclusion, err := workgraph.InclusionRoot(nil)
			if err != nil {
				return err
			}
			miningContext, err := round.Context()
			if err != nil {
				return err
			}
			roundContext, generation, finishRound := roundControl.Begin(ctx, miningContext)
			mineContext, stopMining := context.WithTimeout(
				roundContext, workRoundRolloverDelay(miningContext.AnchorTimestamp, unixNow()),
			)
			publisher, err := newWorkSharePublisher(
				mineContext, targets, *relayEvery, *relayInterval,
				func(relayContext context.Context, target workPeerTarget, ids []types.Hash) (worksession.Stats, error) {
					return relayWorkShares(relayContext, round, host, peerManager, target, ids)
				},
			)
			if err != nil {
				stopMining()
				_ = finishRound()
				return err
			}
			if !roundControl.Attach(generation, publisher) {
				stopMining()
				_ = finishRound()
				publisher.Close()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			retained, err := round.IDs()
			if err != nil {
				stopMining()
				_ = finishRound()
				publisher.Close()
				return err
			}
			if _, err := publisher.Seed(retained); err != nil {
				stopMining()
				_ = finishRound()
				publisher.Close()
				return err
			}
			mined, err := round.Mine(mineContext, miner, inclusion, *startNonce, publisher.Publish)
			timedOut := errors.Is(mineContext.Err(), context.DeadlineExceeded) && ctx.Err() == nil
			stopMining()
			gossipStats := finishRound()
			relayStats := publisher.Close()
			totalWeakShares += mined.WeakShares
			totalCapacityRejections += mined.CapacityRejections
			totalGossip.Shares += gossipStats.Shares
			totalGossip.Copies += gossipStats.Copies
			totalRelay.merge(relayStats)
			if err != nil {
				if timedOut {
					next, rolloverErr := roundManager.RollForward(round)
					if errors.Is(rolloverErr, workround.ErrRoundChanged) || errors.Is(rolloverErr, workround.ErrUnstableChain) {
						next, rolloverErr = roundManager.Current()
					}
					if rolloverErr != nil {
						return rolloverErr
					}
					nextContext, contextErr := next.Context()
					if contextErr != nil {
						return contextErr
					}
					if !sameWorkRoundContext(miningContext, nextContext) {
						fmt.Fprintln(os.Stderr, "restart WorkGraph mining on advanced chain tip")
						continue anchorLoop
					}
					status, _ := next.Status()
					fmt.Fprintf(os.Stderr, "work_round_rollover height=%d timestamp=%d->%d retained_shares=%d relayed=%d pending=%d\n",
						nextContext.Height, miningContext.AnchorTimestamp, nextContext.AnchorTimestamp,
						status.Shares, relayStats.Relayed, relayStats.Pending)
					continue
				}
				if errors.Is(err, context.Canceled) && ctx.Err() == nil {
					current, currentErr := roundManager.Current()
					if currentErr != nil {
						return currentErr
					}
					currentContext, currentErr := current.Context()
					if currentErr != nil {
						return currentErr
					}
					if sameWorkRoundContext(miningContext, currentContext) {
						fmt.Fprintf(os.Stderr, "continue WorkGraph mining after timestamp rollover %d->%d\n",
							miningContext.AnchorTimestamp, currentContext.AnchorTimestamp)
						continue
					}
					fmt.Fprintln(os.Stderr, "restart WorkGraph mining on notified chain tip")
					continue anchorLoop
				}
				return err
			}
			mined.WeakShares = totalWeakShares
			mined.CapacityRejections = totalCapacityRejections
			routed, err := activation.Work(mined.Block, profile.ActivationHeight)
			if err != nil {
				return err
			}
			selected, err := router.Submit(routed)
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
			notifyQueued := 0
			if selected.ID == id {
				notifyQueued = notifier.Notify()
			}
			fmt.Printf("work_mined_quic height=%d id=%s nonce=%d weak_shares=%d included_shares=%d gossip_shares=%d gossip_copies=%d relay_peers=%d/%d relay_failed_peers=%d relayed_shares=%d relay_rejected=%d relay_failures=%d relay_dropped=%d pending_relay=%d anchor_notify_queued=%d elapsed=%s state=%s\n",
				selected.Height, id, mined.WinningNonce, mined.WeakShares, len(mined.Block.Shares),
				totalGossip.Shares, totalGossip.Copies,
				totalRelay.ReachedPeers, totalRelay.Peers, totalRelay.FailedPeers, totalRelay.Relayed, totalRelay.Rejected,
				totalRelay.Failures, totalRelay.Dropped, totalRelay.Pending, notifyQueued,
				time.Since(started).Round(time.Millisecond), selected.StateRoot)
			minedCount++
			continue anchorLoop
		}
	}
	notifyStats := notifier.Close()
	fmt.Printf("work_mining_quic_done peers=%d notifications=%d/%d notification_failures=%d notification_coalesced=%d\n",
		notifyStats.Peers, notifyStats.Succeeded, notifyStats.Attempts,
		notifyStats.Failed, notifyStats.Coalesced)
	return nil
}

func installWorkMiningHandlers(
	host *libp2ptransport.Host,
	chainSession *chainsession.Node,
	roundManager *workround.Manager,
	peerManager *peers.Manager,
	roundControl *workMiningRoundControl,
) error {
	if host == nil || chainSession == nil || roundManager == nil || peerManager == nil || roundControl == nil {
		return errors.New("invalid cooperative mining handlers")
	}
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
		miningContext, err := round.Context()
		if err != nil {
			_ = stream.Reset()
			return
		}
		sessionErr := round.ServeAccepted(handlerContext, limited, func(share workgraph.Share, _ types.Hash) {
			roundControl.Forward(miningContext, peerID, share)
		})
		recordWorkPeerSession(peerManager, peerID, sessionErr)
		if sessionErr != nil && handlerContext.Err() == nil {
			fmt.Fprintf(os.Stderr, "WorkGraph QUIC peer session %s: %v\n", peerID, sessionErr)
		}
	}); err != nil {
		return err
	}
	return host.SetChainNotifyHandler(func(handlerContext context.Context, peerID types.Hash, stream libp2pnetwork.Stream) {
		if err := peerManager.Acquire(peerID); err != nil {
			_ = stream.Reset()
			return
		}
		defer peerManager.Release(peerID)
		limited := &peerLimitedStream{Stream: stream, manager: peerManager, peerID: peerID}
		selected, sessionErr := chainSession.Synchronize(handlerContext, limited)
		recordPeerSession(peerManager, peerID, sessionErr)
		if sessionErr != nil {
			if handlerContext.Err() == nil {
				fmt.Fprintf(os.Stderr, "chain notification from %s: %v\n", peerID, sessionErr)
			}
			return
		}
		_ = roundManager.Invalidate()
		roundControl.Advance(selected.ID)
	})
}

func notifyWorkAnchor(
	ctx context.Context,
	host *libp2ptransport.Host,
	chainSession *chainsession.Node,
	peerManager *peers.Manager,
	target workPeerTarget,
) error {
	stream, peerID, err := host.OpenChainNotifyStream(ctx, target.address, &target.id)
	if err != nil {
		return err
	}
	stopReset := context.AfterFunc(ctx, func() { _ = stream.Reset() })
	defer stopReset()
	if err := peerManager.Acquire(peerID); err != nil {
		_ = stream.Reset()
		return err
	}
	limited := &peerLimitedStream{Stream: stream, manager: peerManager, peerID: peerID}
	sessionErr := chainSession.Serve(ctx, limited)
	peerManager.Release(peerID)
	recordPeerSession(peerManager, peerID, sessionErr)
	if sessionErr != nil {
		return sessionErr
	}
	return nil
}

func relayWorkShares(
	ctx context.Context,
	round *workround.Round,
	host *libp2ptransport.Host,
	peerManager *peers.Manager,
	target workPeerTarget,
	ids []types.Hash,
) (worksession.Stats, error) {
	stream, peerID, err := host.OpenWorkGraphStream(ctx, target.address, &target.id)
	if err != nil {
		return worksession.Stats{}, err
	}
	stopReset := context.AfterFunc(ctx, func() { _ = stream.Reset() })
	defer stopReset()
	if err := peerManager.Acquire(peerID); err != nil {
		_ = stream.Reset()
		return worksession.Stats{}, err
	}
	limited := &peerLimitedStream{Stream: stream, manager: peerManager, peerID: peerID}
	stats, sessionErr := round.RelayInventory(ctx, limited, ids)
	peerManager.Release(peerID)
	recordWorkRelayAttempt(peerManager, peerID, sessionErr)
	return stats, sessionErr
}

type workMiningRoundControl struct {
	mu            sync.Mutex
	generation    uint64
	miningContext workgraph.Context
	active        bool
	cancel        context.CancelFunc
	publisher     *workSharePublisher
	pending       []workPendingForward
	gossip        workMiningGossipStats
}

type workMiningGossipStats struct {
	Shares uint64
	Copies uint64
}

type workPendingForward struct {
	source types.Hash
	share  workgraph.Share
}

func (control *workMiningRoundControl) Begin(
	parent context.Context,
	miningContext workgraph.Context,
) (context.Context, uint64, func() workMiningGossipStats) {
	control.mu.Lock()
	if control.cancel != nil {
		control.cancel()
	}
	control.generation++
	generation := control.generation
	result, cancel := context.WithCancel(parent)
	control.miningContext = miningContext
	control.active = true
	control.cancel = cancel
	control.publisher = nil
	control.pending = nil
	control.gossip = workMiningGossipStats{}
	control.mu.Unlock()
	return result, generation, func() workMiningGossipStats {
		control.mu.Lock()
		stats := workMiningGossipStats{}
		if control.generation == generation {
			stats = control.gossip
			control.active = false
			control.miningContext = workgraph.Context{}
			control.cancel = nil
			control.publisher = nil
			control.pending = nil
		}
		control.mu.Unlock()
		cancel()
		return stats
	}
}

func (control *workMiningRoundControl) Attach(generation uint64, publisher *workSharePublisher) bool {
	control.mu.Lock()
	defer control.mu.Unlock()
	if publisher == nil || !control.active || control.generation != generation {
		return false
	}
	control.publisher = publisher
	for _, pending := range control.pending {
		control.forwardLocked(pending.source, pending.share)
	}
	control.pending = nil
	return true
}

func (control *workMiningRoundControl) Forward(
	miningContext workgraph.Context,
	source types.Hash,
	share workgraph.Share,
) bool {
	control.mu.Lock()
	defer control.mu.Unlock()
	if !control.active || !sameWorkRoundContext(control.miningContext, miningContext) || source.IsZero() {
		return false
	}
	if control.publisher == nil {
		if len(control.pending) >= workgraph.MaxShares {
			return false
		}
		share.Parents = append([]types.Hash(nil), share.Parents...)
		control.pending = append(control.pending, workPendingForward{source: source, share: share})
		return true
	}
	return control.forwardLocked(source, share)
}

func sameWorkRoundContext(left, right workgraph.Context) bool {
	left.AnchorMiner = types.Address{}
	right.AnchorMiner = types.Address{}
	left.AnchorTimestamp = 0
	right.AnchorTimestamp = 0
	return left == right
}

func (control *workMiningRoundControl) forwardLocked(source types.Hash, share workgraph.Share) bool {
	copies, err := control.publisher.Forward(source, share)
	if err != nil || copies == 0 {
		return false
	}
	control.gossip.Shares++
	control.gossip.Copies += uint64(copies)
	return true
}

func (control *workMiningRoundControl) Advance(parentID types.Hash) {
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.cancel != nil && control.miningContext.AnchorParent != parentID {
		control.active = false
		control.publisher = nil
		control.pending = nil
		control.cancel()
	}
}

func recordWorkRelayAttempt(manager *peers.Manager, peerID types.Hash, sessionErr error) {
	if sessionErr == nil {
		_ = manager.Record(peerID, peers.EventValidMessage)
	} else if errors.Is(sessionErr, worksession.ErrContext) {
		_ = manager.Record(peerID, peers.EventStaleData)
	} else if networkError, ok := sessionErr.(interface{ Timeout() bool }); ok && networkError.Timeout() {
		_ = manager.Record(peerID, peers.EventTimeout)
	}
	// A reset can be the remote transport's resource/rate limiter. It is not
	// evidence that the authenticated peer sent an invalid protocol object.
}
