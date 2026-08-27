package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
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
	peerAddress := flags.String("peer", "", "cooperating WorkGraph peer multiaddress including /p2p/<id>")
	peerIDText := flags.String("peer-id", "", "expected OutcomeMesh peer ID as 64 hex characters")
	minerText := flags.String("miner", defaultDevelopmentAddress().String(), "reward address as 64 hex characters")
	count := flags.Uint64("count", 1, "number of version-1 anchors")
	startNonce := flags.Uint64("start-nonce", 0, "first WorkSeal nonce to test per round")
	relayEvery := flags.Int("relay-every", 128, "unpublished weak shares collected before a relay attempt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *keyPath == "" || *peerAddress == "" || *count == 0 || *relayEvery <= 0 || *relayEvery > wire.MaxShareInventoryIDs {
		return fmt.Errorf("key and peer are required; count must be positive and relay-every must be 1..%d", wire.MaxShareInventoryIDs)
	}
	miner, err := parseAddress(*minerText)
	if err != nil {
		return fmt.Errorf("miner: %w", err)
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
	if err := installWorkMiningHandlers(host, chainSession, roundManager, peerManager); err != nil {
		return err
	}
	fmt.Printf("mining_work_quic peer_id=%s libp2p_id=%s network=%d activation_height=%d relay_every=%d listen=%s\n",
		host.ID(), host.Libp2pID(), document.NetworkID, profile.ActivationHeight, *relayEvery,
		strings.Join(host.Addresses(), ","))
	for index := uint64(0); index < *count; index++ {
		round, err := roundManager.Current()
		if err != nil {
			return err
		}
		inclusion, err := workgraph.InclusionRoot(nil)
		if err != nil {
			return err
		}
		publisher := &workSharePublisher{
			ctx: ctx, round: round, host: host, peerManager: peerManager,
			peerAddress: *peerAddress, expectedPeer: expectedPeer, relayEvery: *relayEvery,
		}
		started := time.Now()
		mined, err := round.Mine(ctx, miner, inclusion, *startNonce, publisher.Publish)
		if err != nil {
			return err
		}
		publisher.Flush()
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
		fmt.Printf("work_mined_quic height=%d id=%s nonce=%d weak_shares=%d included_shares=%d relayed_shares=%d relay_rejected=%d relay_failures=%d pending_relay=%d elapsed=%s state=%s\n",
			selected.Height, id, mined.WinningNonce, mined.WeakShares, len(mined.Block.Shares),
			publisher.relayed, publisher.rejected, publisher.failures, len(publisher.pending),
			time.Since(started).Round(time.Millisecond), selected.StateRoot)
	}
	return nil
}

func installWorkMiningHandlers(
	host *libp2ptransport.Host,
	chainSession *chainsession.Node,
	roundManager *workround.Manager,
	peerManager *peers.Manager,
) error {
	if host == nil || chainSession == nil || roundManager == nil || peerManager == nil {
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
	return host.SetWorkGraphHandler(func(handlerContext context.Context, peerID types.Hash, stream libp2pnetwork.Stream) {
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
	})
}

type workSharePublisher struct {
	ctx          context.Context
	round        *workround.Round
	host         *libp2ptransport.Host
	peerManager  *peers.Manager
	peerAddress  string
	expectedPeer *types.Hash
	relayEvery   int
	pending      []types.Hash
	relayed      uint64
	rejected     uint64
	failures     uint64
}

func (publisher *workSharePublisher) Publish(share workgraph.Share) error {
	id, err := share.ID()
	if err != nil {
		return err
	}
	publisher.pending = append(publisher.pending, id)
	if len(publisher.pending) >= publisher.relayEvery {
		publisher.Flush()
	}
	return nil
}

// Flush is best-effort: network failure must not stop objective hard-PoW
// search. Successfully announced prefixes are removed exactly; an error keeps
// the complete unannounced suffix for the next bounded attempt.
func (publisher *workSharePublisher) Flush() {
	if publisher == nil || len(publisher.pending) == 0 {
		return
	}
	sort.Slice(publisher.pending, func(left, right int) bool {
		return types.CompareHash(publisher.pending[left], publisher.pending[right]) < 0
	})
	for len(publisher.pending) > 0 {
		count := min(len(publisher.pending), wire.MaxShareInventoryIDs)
		selected := publisher.pending[:count]
		stream, peerID, err := publisher.host.OpenWorkGraphStream(
			publisher.ctx, publisher.peerAddress, publisher.expectedPeer,
		)
		if err != nil {
			publisher.failures++
			fmt.Fprintf(os.Stderr, "publish WorkGraph shares: %v\n", err)
			return
		}
		if err := publisher.peerManager.Acquire(peerID); err != nil {
			_ = stream.Reset()
			publisher.failures++
			return
		}
		limited := &peerLimitedStream{Stream: stream, manager: publisher.peerManager, peerID: peerID}
		stats, sessionErr := publisher.round.RelayInventory(publisher.ctx, limited, selected)
		publisher.peerManager.Release(peerID)
		recordWorkPeerSession(publisher.peerManager, peerID, sessionErr)
		if sessionErr != nil || stats.Announced <= 0 || stats.Announced > len(selected) {
			publisher.failures++
			if sessionErr != nil && publisher.ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "publish WorkGraph shares to %s: %v\n", peerID, sessionErr)
			}
			return
		}
		publisher.relayed += uint64(stats.Announced)
		publisher.rejected += uint64(stats.Rejected)
		publisher.pending = publisher.pending[stats.Announced:]
	}
}
