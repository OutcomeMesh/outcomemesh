package libp2ptransport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/chainsession"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

type versionedChainFixture struct {
	document genesis.Document
	ledger   *reference.Store
	router   *activation.Router
	node     *chainsession.Node
	config   activation.Config
}

func TestQUICVersionedChainSynchronizesDivergentActivationFork(t *testing.T) {
	sessionConfig := chainsession.DefaultSessionConfig()
	sessionConfig.BatchSize = 2
	sessionConfig.MaxSyncBatches = 8
	sessionConfig.MaxFrameBytes = wire.MinVersionedChainFrameBodyBytes
	source := newVersionedChainFixture(t, 716, 2, sessionConfig)
	destination := newVersionedChainFixture(t, 716, 2, sessionConfig)
	firstSourceWork := extendVersionedChain(t, source, "source", 4)
	extendVersionedChain(t, destination, "destination", 2)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	type serveResult struct {
		peer types.Hash
		err  error
	}
	served := make(chan serveResult, 1)
	server, err := libp2ptransport.New(ctx, testKey("versioned-chain-server"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetVersionedChainHandler(func(handlerContext context.Context, peerID types.Hash, stream network.Stream) {
		served <- serveResult{peer: peerID, err: source.node.Serve(handlerContext, stream)}
	}); err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, testKey("versioned-chain-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	wrong := types.DomainHash("test/libp2p/versioned-chain-wrong-peer")
	if _, _, err := client.OpenVersionedChainStream(ctx, server.Addresses()[0], &wrong); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatalf("wrong versioned-chain pin error=%v", err)
	}
	expected := server.ID()
	stream, remoteID, err := client.OpenVersionedChainStream(ctx, server.Addresses()[0], &expected)
	if err != nil {
		t.Fatal(err)
	}
	if stream.Protocol() != libp2ptransport.VersionedChainProtocol {
		t.Fatalf("negotiated protocol=%q", stream.Protocol())
	}
	tip, err := destination.node.Synchronize(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	result := <-served
	if result.err != nil || result.peer != client.ID() || remoteID != server.ID() {
		t.Fatalf("authenticated sync remote=%s served=%s err=%v", remoteID, result.peer, result.err)
	}
	sourceTip, err := source.router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	destinationTip, err := destination.router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(tip, sourceTip) || !storage.EqualTips(sourceTip, destinationTip) {
		t.Fatal("versioned QUIC stream did not converge activation-aware tips")
	}
	activationBlock, err := destination.router.BlockByID(firstSourceWork)
	if err != nil || activationBlock.Version() != workblock.Version1 {
		t.Fatalf("synchronized activation block version=%d err=%v", activationBlock.Version(), err)
	}
}

func TestQUICVersionedChainProtocolIsDisabledUntilHandlerInstalled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(ctx, testKey("versioned-disabled-server"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, testKey("versioned-disabled-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err := client.OpenVersionedChainStream(ctx, server.Addresses()[0], nil); err == nil {
		t.Fatal("versioned chain protocol negotiated without an explicit handler")
	}
}

func TestQUICVersionedChainConcurrencyScopesAreIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxStreamsPerPeer = 1
	config.MaxVersionedChainStreams = 2
	config.MaxVersionedChainStreamsPerPeer = 1
	accepted := make(chan types.Hash, 4)
	activeAccepted := make(chan types.Hash, 1)
	release := make(chan struct{})
	server, err := libp2ptransport.New(ctx, testKey("versioned-limit-server"), config, func(_ context.Context, peerID types.Hash, stream network.Stream) {
		activeAccepted <- peerID
		_ = stream.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer close(release)
	if err := server.SetVersionedChainHandler(func(_ context.Context, peerID types.Hash, stream network.Stream) {
		accepted <- peerID
		<-release
		_ = stream.Close()
	}); err != nil {
		t.Fatal(err)
	}
	firstClient, err := libp2ptransport.New(ctx, testKey("versioned-limit-client-a"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	secondClient, err := libp2ptransport.New(ctx, testKey("versioned-limit-client-b"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	thirdClient, err := libp2ptransport.New(ctx, testKey("versioned-limit-client-c"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer thirdClient.Close()

	first, _, err := firstClient.OpenVersionedChainStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	waitForPeer(t, ctx, accepted, firstClient.ID())

	active, _, err := firstClient.OpenStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatalf("active v0 scope was consumed by versioned stream: %v", err)
	}
	if _, err := active.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	waitForPeer(t, ctx, activeAccepted, firstClient.ID())

	tryUnadmittedVersionedStream(t, ctx, firstClient, server.Addresses()[0], accepted)

	second, _, err := secondClient.OpenVersionedChainStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	waitForPeer(t, ctx, accepted, secondClient.ID())

	tryUnadmittedVersionedStream(t, ctx, thirdClient, server.Addresses()[0], accepted)
}

func TestQUICVersionedChainFixedWindowBudgets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxVersionedChainStreamsPerMinute = 1
	config.MaxVersionedChainStreamsGlobalPerMinute = 2
	accepted := make(chan types.Hash, 4)
	server, err := libp2ptransport.New(ctx, testKey("versioned-rate-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetVersionedChainHandler(func(_ context.Context, peerID types.Hash, stream network.Stream) {
		accepted <- peerID
		_ = stream.Close()
	}); err != nil {
		t.Fatal(err)
	}
	firstClient, err := libp2ptransport.New(ctx, testKey("versioned-rate-client-a"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	secondClient, err := libp2ptransport.New(ctx, testKey("versioned-rate-client-b"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	thirdClient, err := libp2ptransport.New(ctx, testKey("versioned-rate-client-c"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer thirdClient.Close()

	openVersionedAndWait(t, ctx, firstClient, server.Addresses()[0], accepted)
	tryUnadmittedVersionedStream(t, ctx, firstClient, server.Addresses()[0], accepted)
	openVersionedAndWait(t, ctx, secondClient, server.Addresses()[0], accepted)
	tryUnadmittedVersionedStream(t, ctx, thirdClient, server.Addresses()[0], accepted)
}

func TestRejectsIncoherentVersionedChainLimits(t *testing.T) {
	tests := []func(*libp2ptransport.Config){
		func(config *libp2ptransport.Config) {
			config.MaxVersionedChainStreams = libp2ptransport.MaxVersionedChainStreamsLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxVersionedChainStreamsPerPeer = libp2ptransport.MaxVersionedChainStreamsPerPeerLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxVersionedChainStreamsPerMinute = libp2ptransport.MaxVersionedChainStreamsPerMinuteLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxVersionedChainStreamsGlobalPerMinute = config.MaxVersionedChainStreamsPerMinute - 1
		},
	}
	for index, mutate := range tests {
		config := libp2ptransport.DefaultConfig()
		mutate(&config)
		if _, err := libp2ptransport.New(context.Background(), testKey("invalid-versioned-limit"), config, nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatalf("case %d error=%v", index, err)
		}
	}
}

func waitForPeer(t testing.TB, ctx context.Context, peers <-chan types.Hash, expected types.Hash) {
	t.Helper()
	select {
	case actual := <-peers:
		if actual != expected {
			t.Fatalf("admitted peer=%s want=%s", actual, expected)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func openVersionedAndWait(
	t testing.TB,
	ctx context.Context,
	client *libp2ptransport.Host,
	address string,
	accepted <-chan types.Hash,
) {
	t.Helper()
	stream, _, err := client.OpenVersionedChainStream(ctx, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	waitForPeer(t, ctx, accepted, client.ID())
	_ = stream.Close()
}

func tryUnadmittedVersionedStream(
	t testing.TB,
	ctx context.Context,
	client *libp2ptransport.Host,
	address string,
	accepted <-chan types.Hash,
) {
	t.Helper()
	stream, _, err := client.OpenVersionedChainStream(ctx, address, nil)
	if err == nil {
		_ = stream.SetDeadline(time.Now().Add(250 * time.Millisecond))
		_, _ = stream.Write([]byte{1})
		_ = stream.Reset()
	}
	select {
	case peerID := <-accepted:
		t.Fatalf("peer %s bypassed versioned-chain admission", peerID)
	case <-time.After(300 * time.Millisecond):
	}
}

func newVersionedChainFixture(
	t testing.TB,
	networkID uint32,
	activationHeight uint64,
	sessionConfig chainsession.SessionConfig,
) versionedChainFixture {
	t.Helper()
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version: genesis.Version0, NetworkID: networkID, Timestamp: 1_700_000_000,
		Target: target, BlockSubsidy: 10_220,
	}
	ledger, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	legacy := legacyblock.ParametersFromGenesis(document)
	activationConfig := activation.Config{
		Legacy: legacy,
		Work: workblock.Parameters{
			NetworkID: networkID, BlockSubsidy: document.BlockSubsidy,
			RewardMaturity: legacy.RewardMaturity, ActivationHeight: activationHeight,
			DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
			TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: 3,
		},
		Now: func() uint64 { return document.Timestamp + 100_000 },
	}
	router, err := activation.New(ledger, activationConfig)
	if err != nil {
		t.Fatal(err)
	}
	node, err := chainsession.NewNode(router, document, sessionConfig)
	if err != nil {
		t.Fatal(err)
	}
	return versionedChainFixture{
		document: document, ledger: ledger, router: router, node: node, config: activationConfig,
	}
}

func extendVersionedChain(t testing.TB, fixture versionedChainFixture, label string, workBlocks int) types.Hash {
	t.Helper()
	mineVersionedLegacy(t, fixture, label+"-base")
	var first types.Hash
	for index := 0; index < workBlocks; index++ {
		id := mineVersionedWork(t, fixture, label+string(rune('a'+index)))
		if index == 0 {
			first = id
		}
	}
	return first
}

func mineVersionedLegacy(t testing.TB, fixture versionedChainFixture, label string) {
	t.Helper()
	parent, err := fixture.router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	preState, err := fixture.ledger.SnapshotAt(parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	parentContext, err := storage.ParentContext(fixture.ledger, parent)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := legacyblock.Prepare(
		preState, parentContext, nil, versionedChainAddress(label),
		parent.Timestamp+fixture.config.Legacy.TargetSpacing, fixture.config.Legacy,
	)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err = legacyblock.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := activation.Legacy(candidate, fixture.config.Work.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.router.Submit(routed); err != nil {
		t.Fatal(err)
	}
}

func mineVersionedWork(t testing.TB, fixture versionedChainFixture, label string) types.Hash {
	t.Helper()
	parent, err := fixture.router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := fixture.router.PrepareWork(
		parent.ID, parent.Timestamp+fixture.config.Work.TargetSpacing, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	template, err := payload.SealTemplate(versionedChainAddress(label), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	seal, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := payload.Finalize(seal, nil)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := activation.Work(candidate, fixture.config.Work.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.router.Submit(routed); err != nil {
		t.Fatal(err)
	}
	id, err := routed.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func versionedChainAddress(label string) types.Address {
	return types.Address(types.DomainHash("test/libp2p/versioned-chain-miner", []byte(label)))
}
