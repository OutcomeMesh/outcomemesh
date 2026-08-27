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
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/mempool"
	"github.com/outcomemesh/outcomemesh/node/session"
	"github.com/outcomemesh/outcomemesh/node/syncer"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
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
