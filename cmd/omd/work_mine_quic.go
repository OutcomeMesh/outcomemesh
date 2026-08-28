package main

import (
	"context"
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
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/chainsession"
	"github.com/outcomemesh/outcomemesh/node/peers"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

func runWorkMineQUIC(arguments []string) error {
	flags := flag.NewFlagSet("work-mine-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "QUIC-v1 libp2p listen multiaddress")
	var peerAddresses repeatedStringFlag
	var peerIDs repeatedStringFlag
	flags.Var(&peerAddresses, "peer", "cooperating WorkGraph peer multiaddress; repeat for up to 8 peers")
	flags.Var(&peerIDs, "peer-id", "matching OutcomeMesh peer ID; omit all or repeat once per peer")
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
	peerManager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		return err
	}
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
	notifier, err := newWorkAnchorNotifier(ctx, targets, func(notifyContext context.Context, target workPeerTarget) error {
		return notifyWorkAnchor(notifyContext, host, chainSession, peerManager, target)
	})
	if err != nil {
		return err
	}
	defer notifier.Close()
	fmt.Printf("mining_work_quic peer_id=%s libp2p_id=%s network=%d activation_height=%d peers=%d relay_every=%d relay_interval=%s listen=%s\n",
		host.ID(), host.Libp2pID(), document.NetworkID, profile.ActivationHeight, len(targets), *relayEvery, *relayInterval,
		strings.Join(host.Addresses(), ","))
	for minedCount := uint64(0); minedCount < *count; {
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
		roundContext, finishRound := roundControl.Begin(ctx, miningContext.AnchorParent)
		publisher, err := newWorkSharePublisher(
			roundContext, targets, *relayEvery, *relayInterval,
			func(relayContext context.Context, target workPeerTarget, ids []types.Hash) (worksession.Stats, error) {
				return relayWorkShares(relayContext, round, host, peerManager, target, ids)
			},
		)
		if err != nil {
			finishRound()
			return err
		}
		started := time.Now()
		mined, err := round.Mine(roundContext, miner, inclusion, *startNonce, publisher.Publish)
		finishRound()
		relayStats := publisher.Close()
		if err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() == nil {
				_ = roundManager.Invalidate()
				fmt.Fprintln(os.Stderr, "restart WorkGraph mining on notified chain tip")
				continue
			}
			return err
		}
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
		fmt.Printf("work_mined_quic height=%d id=%s nonce=%d weak_shares=%d included_shares=%d relay_peers=%d/%d relay_failed_peers=%d relayed_shares=%d relay_rejected=%d relay_failures=%d relay_dropped=%d pending_relay=%d anchor_notify_queued=%d elapsed=%s state=%s\n",
			selected.Height, id, mined.WinningNonce, mined.WeakShares, len(mined.Block.Shares),
			relayStats.ReachedPeers, relayStats.Peers, relayStats.FailedPeers, relayStats.Relayed, relayStats.Rejected,
			relayStats.Failures, relayStats.Dropped, relayStats.Pending, notifyQueued,
			time.Since(started).Round(time.Millisecond), selected.StateRoot)
		minedCount++
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
		sessionErr := round.Serve(handlerContext, limited)
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
	mu         sync.Mutex
	generation uint64
	parent     types.Hash
	cancel     context.CancelFunc
}

func (control *workMiningRoundControl) Begin(parent context.Context, parentID types.Hash) (context.Context, func()) {
	control.mu.Lock()
	if control.cancel != nil {
		control.cancel()
	}
	control.generation++
	generation := control.generation
	result, cancel := context.WithCancel(parent)
	control.parent = parentID
	control.cancel = cancel
	control.mu.Unlock()
	return result, func() {
		cancel()
		control.mu.Lock()
		defer control.mu.Unlock()
		if control.generation == generation {
			control.parent = types.Hash{}
			control.cancel = nil
		}
	}
}

func (control *workMiningRoundControl) Advance(parentID types.Hash) {
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.cancel != nil && control.parent != parentID {
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
