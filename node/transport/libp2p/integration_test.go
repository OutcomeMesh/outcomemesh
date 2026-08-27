package libp2ptransport_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/mempool"
	"github.com/outcomemesh/outcomemesh/node/session"
	"github.com/outcomemesh/outcomemesh/node/syncer"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workpool"
	"github.com/outcomemesh/outcomemesh/node/worksession"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

func TestQUICHostAuthenticatesIdentityAndSynchronizesFork(t *testing.T) {
	document := testGenesis()
	sourceStore, sourceChain, sourceSession := testNode(t, document)
	defer sourceStore.Close()
	destinationStore, _, destinationSession := testNode(t, document)
	defer destinationStore.Close()
	miner := types.Address(types.DomainHash("test/libp2p/miner"))
	for range uint64(3) {
		tip, err := sourceChain.Status()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sourceChain.Mine(context.Background(), nil, miner, tip.Timestamp+1, 0); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	serverKey := testKey("server")
	server, err := libp2ptransport.New(ctx, serverKey, libp2ptransport.DefaultConfig(), func(handlerContext context.Context, _ types.Hash, stream network.Stream) {
		serverDone <- sourceSession.Serve(handlerContext, stream)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, testKey("client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	addresses := server.Addresses()
	if len(addresses) == 0 || !strings.Contains(addresses[0], "/quic-v1/p2p/") {
		t.Fatalf("server addresses = %v", addresses)
	}
	wantServerID := types.DomainHash("OMESH/p2p/ed25519/v0", serverKey.Public().(ed25519.PublicKey))
	if server.ID() != wantServerID {
		t.Fatalf("OutcomeMesh peer ID = %s, want %s", server.ID(), wantServerID)
	}
	parsedServerID, err := libp2ptransport.PeerIDFromAddress(addresses[0])
	if err != nil || parsedServerID != wantServerID {
		t.Fatalf("parsed OutcomeMesh peer ID = %s, want %s (error %v)", parsedServerID, wantServerID, err)
	}
	for _, invalid := range []string{"", "/ip4/127.0.0.1/tcp/9844/p2p/" + server.Libp2pID().String()} {
		if _, err := libp2ptransport.PeerIDFromAddress(invalid); !errors.Is(err, libp2ptransport.ErrAddress) {
			t.Fatalf("peer address %q error = %v", invalid, err)
		}
	}
	wrong := types.DomainHash("test/libp2p/wrong-peer")
	if _, _, err := client.OpenStream(ctx, addresses[0], &wrong); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatalf("wrong pin error = %v", err)
	}
	now := uint64(time.Now().Unix())
	record, err := discovery.Sign(serverKey, document.NetworkID, 1, now+600, addresses)
	if err != nil {
		t.Fatal(err)
	}
	stream, remoteID, err := client.OpenRecord(ctx, record, document.NetworkID, now)
	if err != nil {
		t.Fatal(err)
	}
	if remoteID != wantServerID || !strings.Contains(stream.Conn().ConnState().Transport, "quic") {
		t.Fatalf("remote=%s transport=%q", remoteID, stream.Conn().ConnState().Transport)
	}
	status, err := destinationSession.Synchronize(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	sourceTip, _ := sourceStore.Tip()
	destinationTip, _ := destinationStore.Tip()
	if status.TipID != sourceTip.ID || !storage.EqualTips(sourceTip, destinationTip) {
		t.Fatal("QUIC stream did not converge ledger tips")
	}
}

func TestRejectsNonQUICListenAddress(t *testing.T) {
	for _, address := range []string{
		"/ip4/127.0.0.1/tcp/0",
		"/ip4/127.0.0.1/udp/0/quic-v1/webtransport",
	} {
		config := libp2ptransport.DefaultConfig()
		config.Listen = []string{address}
		if _, err := libp2ptransport.New(context.Background(), testKey("invalid"), config, nil); !errors.Is(err, libp2ptransport.ErrAddress) {
			t.Fatalf("address %q error = %v", address, err)
		}
	}
}

func TestRejectsIncoherentResourceLimits(t *testing.T) {
	config := libp2ptransport.DefaultConfig()
	config.MaxConnections = config.MaxFileDescriptors + 1
	if _, err := libp2ptransport.New(context.Background(), testKey("resource-limits"), config, nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatalf("resource limit error = %v", err)
	}
	config = libp2ptransport.DefaultConfig()
	config.MaxWorkStreamsPerPeer = libp2ptransport.MaxWorkStreamsPerPeerLimit + 1
	if _, err := libp2ptransport.New(context.Background(), testKey("work-resource-limits"), config, nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatalf("WorkGraph stream limit error = %v", err)
	}
	config = libp2ptransport.DefaultConfig()
	config.MaxWorkStreamsPerMinute = libp2ptransport.MaxWorkStreamsPerMinuteLimit + 1
	if _, err := libp2ptransport.New(context.Background(), testKey("work-rate-limits"), config, nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatalf("WorkGraph rate limit error = %v", err)
	}
	config = libp2ptransport.DefaultConfig()
	config.MaxWorkStreamsGlobalPerMinute = config.MaxWorkStreamsPerMinute - 1
	if _, err := libp2ptransport.New(context.Background(), testKey("work-global-rate-limits"), config, nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatalf("WorkGraph global rate limit error = %v", err)
	}
}

func TestQUICHostEnforcesPerPeerStreamLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxStreamsPerPeer = 1
	started := make(chan struct{})
	secondAccepted := make(chan struct{})
	release := make(chan struct{})
	var handlerCount atomic.Int32
	server, err := libp2ptransport.New(ctx, testKey("limited-server"), config, func(_ context.Context, _ types.Hash, stream network.Stream) {
		if handlerCount.Add(1) == 1 {
			close(started)
			<-release
		} else {
			close(secondAccepted)
		}
		_ = stream.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer close(release)
	client, err := libp2ptransport.New(ctx, testKey("limited-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	addresses := server.Addresses()
	if len(addresses) == 0 {
		t.Fatal("server has no QUIC address")
	}
	first, _, err := client.OpenStream(ctx, addresses[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	secondContext, secondCancel := context.WithTimeout(ctx, time.Second)
	defer secondCancel()
	second, _, err := client.OpenStream(secondContext, addresses[0], nil)
	if err != nil {
		return
	}
	defer second.Reset()
	_ = second.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := second.Write([]byte{1}); err != nil {
		return
	}
	select {
	case <-secondAccepted:
		t.Fatal("second concurrent stream bypassed per-peer resource limit")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestQUICWorkGraphRelayNegotiatesLimitsAndAuthenticatesPeer(t *testing.T) {
	validation := testWorkContext()
	sourcePool, _ := workpool.New(validation)
	destinationPool, _ := workpool.New(validation)
	parent := mineWeakShare(t, validation, testWorkShare(validation, "quic-parent", nil))
	parentID, _ := parent.ID()
	child := mineWeakShare(t, validation, testWorkShare(validation, "quic-child", []types.Hash{parentID}))
	if _, err := sourcePool.Add(child); err != nil {
		t.Fatal(err)
	}
	if _, err := sourcePool.Add(parent); err != nil {
		t.Fatal(err)
	}
	sourceSession, err := worksession.New(sourcePool, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	destinationConfig := worksession.DefaultConfig()
	destinationConfig.MaxFrameBytes = 512
	destinationSession, err := worksession.New(destinationPool, destinationConfig)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	type serveResult struct {
		peer types.Hash
		err  error
	}
	serverDone := make(chan serveResult, 1)
	server, err := libp2ptransport.New(ctx, testKey("work-server"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetWorkGraphHandler(func(handlerContext context.Context, peerID types.Hash, stream network.Stream) {
		serverDone <- serveResult{peer: peerID, err: destinationSession.Serve(handlerContext, stream)}
	}); err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, testKey("work-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	addresses := server.Addresses()
	if len(addresses) == 0 {
		t.Fatal("server has no QUIC address")
	}
	wrong := types.DomainHash("test/libp2p/work-wrong-peer")
	if _, _, err := client.OpenWorkGraphStream(ctx, addresses[0], &wrong); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatalf("wrong WorkGraph pin error=%v", err)
	}
	expected := server.ID()
	stream, remoteID, err := client.OpenWorkGraphStream(ctx, addresses[0], &expected)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := sourceSession.Relay(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	served := <-serverDone
	if served.err != nil || served.peer != client.ID() || remoteID != server.ID() {
		t.Fatalf("authenticated relay remote=%s served=%s err=%v", remoteID, served.peer, served.err)
	}
	if stats.Accepted != 2 || stats.Batches != 2 {
		t.Fatalf("negotiated relay stats=%+v", stats)
	}
	if status := destinationPool.Status(); status.Accepted != 2 || status.Pending != 0 {
		t.Fatalf("destination WorkGraph status=%+v", status)
	}
}

func TestQUICWorkGraphRejectsMiningContextMismatch(t *testing.T) {
	destinationContext := testWorkContext()
	sourceContext := destinationContext
	sourceContext.PayloadRoot = types.DomainHash("test/libp2p/work-other-payload")
	sourcePool, _ := workpool.New(sourceContext)
	destinationPool, _ := workpool.New(destinationContext)
	sourceSession, _ := worksession.New(sourcePool, worksession.DefaultConfig())
	destinationSession, _ := worksession.New(destinationPool, worksession.DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	server, err := libp2ptransport.New(ctx, testKey("work-context-server"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetWorkGraphHandler(func(handlerContext context.Context, _ types.Hash, stream network.Stream) {
		serverDone <- destinationSession.Serve(handlerContext, stream)
	}); err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, testKey("work-context-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, _, err := client.OpenWorkGraphStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sourceSession.Relay(ctx, stream)
	if err := <-serverDone; !errors.Is(err, worksession.ErrContext) {
		t.Fatalf("QUIC context mismatch error=%v", err)
	}
}

func TestQUICWorkGraphProtocolIsDisabledUntilHandlerInstalled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(ctx, testKey("work-disabled-server"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, testKey("work-disabled-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err := client.OpenWorkGraphStream(ctx, server.Addresses()[0], nil); err == nil {
		t.Fatal("WorkGraph protocol negotiated without an explicit handler")
	}
}

func TestQUICHostEnforcesWorkGraphStreamLimitSeparately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxWorkStreamsPerPeer = 1
	started := make(chan struct{})
	secondAccepted := make(chan struct{})
	release := make(chan struct{})
	var handlerCount atomic.Int32
	server, err := libp2ptransport.New(ctx, testKey("work-limited-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer close(release)
	if err := server.SetWorkGraphHandler(func(_ context.Context, _ types.Hash, stream network.Stream) {
		if handlerCount.Add(1) == 1 {
			close(started)
			<-release
		} else {
			close(secondAccepted)
		}
		_ = stream.Close()
	}); err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, testKey("work-limited-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, _, err := client.OpenWorkGraphStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	secondContext, secondCancel := context.WithTimeout(ctx, time.Second)
	defer secondCancel()
	second, _, err := client.OpenWorkGraphStream(secondContext, server.Addresses()[0], nil)
	if err != nil {
		return
	}
	defer second.Reset()
	_ = second.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := second.Write([]byte{1}); err != nil {
		return
	}
	select {
	case <-secondAccepted:
		t.Fatal("second WorkGraph stream bypassed its per-peer protocol limit")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestQUICHostEnforcesWorkGraphPerPeerRateBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxWorkStreamsPerMinute = 1
	handled := make(chan struct{}, 2)
	server, err := libp2ptransport.New(ctx, testKey("work-rate-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetWorkGraphHandler(func(_ context.Context, _ types.Hash, stream network.Stream) {
		handled <- struct{}{}
		_ = stream.Close()
	}); err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, testKey("work-rate-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, _, err := client.OpenWorkGraphStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	select {
	case <-handled:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second, _, err := client.OpenWorkGraphStream(ctx, server.Addresses()[0], nil)
	if err == nil {
		_ = second.SetDeadline(time.Now().Add(250 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Close()
	}
	select {
	case <-handled:
		t.Fatal("second WorkGraph stream bypassed the fixed-window peer rate budget")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestQUICHostEnforcesWorkGraphGlobalRateBudgetAcrossPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxWorkStreamsPerMinute = 1
	config.MaxWorkStreamsGlobalPerMinute = 1
	handled := make(chan types.Hash, 2)
	server, err := libp2ptransport.New(ctx, testKey("work-global-rate-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetWorkGraphHandler(func(_ context.Context, peerID types.Hash, stream network.Stream) {
		handled <- peerID
		_ = stream.Close()
	}); err != nil {
		t.Fatal(err)
	}
	firstClient, err := libp2ptransport.New(ctx, testKey("work-global-rate-client-a"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	secondClient, err := libp2ptransport.New(ctx, testKey("work-global-rate-client-b"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	first, _, err := firstClient.OpenWorkGraphStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	select {
	case peerID := <-handled:
		if peerID != firstClient.ID() {
			t.Fatalf("first admitted peer=%s", peerID)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second, _, err := secondClient.OpenWorkGraphStream(ctx, server.Addresses()[0], nil)
	if err == nil {
		_ = second.SetDeadline(time.Now().Add(250 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Close()
	}
	select {
	case peerID := <-handled:
		t.Fatalf("second identity %s bypassed the global WorkGraph rate budget", peerID)
	case <-time.After(300 * time.Millisecond):
	}
}

func testGenesis() genesis.Document {
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	return genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    715,
		Timestamp:    1_700_715_000,
		Target:       target,
		BlockSubsidy: 10,
	}
}

func testNode(t testing.TB, document genesis.Document) (*reference.Store, *chain.Chain, *session.Node) {
	t.Helper()
	store, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	chainService, err := chain.New(store, block.ParametersFromGenesis(document))
	if err != nil {
		t.Fatal(err)
	}
	syncService, err := syncer.New(store, chainService, document)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := mempool.New(mempool.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	sessionService, err := session.New(syncService, store, pool, session.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return store, chainService, sessionService
}

func testKey(label string) ed25519.PrivateKey {
	seed := types.DomainHash("test/libp2p/key", []byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func testWorkContext() workgraph.Context {
	var target types.Hash
	target[2] = 0x7f
	for index := 3; index < len(target); index++ {
		target[index] = 0xff
	}
	return workgraph.Context{
		NetworkID: 715, Height: 9, AnchorParent: types.DomainHash("test/libp2p/work-anchor"),
		AnchorTarget: target, PayloadRoot: types.DomainHash("test/libp2p/work-payload"),
		AnchorTimestamp: 1_700_715_100, MedianTimePast: 1_700_715_000,
	}
}

func testWorkShare(validation workgraph.Context, label string, parents []types.Hash) workgraph.Share {
	inclusion, _ := workgraph.InclusionRoot(nil)
	return workgraph.Share{
		Version: workgraph.Version0, NetworkID: validation.NetworkID, Height: validation.Height,
		AnchorParent: validation.AnchorParent, Timestamp: validation.AnchorTimestamp,
		Target: validation.AnchorTarget, PayloadRoot: validation.PayloadRoot,
		Miner:         types.Address(types.DomainHash("test/libp2p/work-miner", []byte(label))),
		InclusionRoot: inclusion, Parents: append([]types.Hash(nil), parents...),
	}
}

func mineWeakShare(t testing.TB, validation workgraph.Context, template workgraph.Share) workgraph.Share {
	t.Helper()
	for nonce := uint64(0); ; nonce++ {
		candidate := template
		candidate.Nonce = nonce
		if err := workgraph.ValidateShare(validation, candidate); err != nil {
			continue
		}
		hard, err := workgraph.MeetsAnchor(candidate)
		if err == nil && !hard {
			return candidate
		}
	}
}
