package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/chainsession"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/peers"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

func TestWorkDiscoveryRotatesPastAtomicAdversarialBootstrapBatch(t *testing.T) {
	const (
		networkID        uint32 = 20260830
		activationHeight uint64 = 5
	)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	document, clientSession := newAdversarialDiscoveryChainNode(t, networkID, activationHeight)
	_, goodSession := newAdversarialDiscoveryChainNode(t, networkID, activationHeight)
	_, adversarialSession := newAdversarialDiscoveryChainNode(t, networkID, activationHeight)

	clientHost := newAdversarialDiscoveryHost(t, ctx, "client")
	goodHost := newAdversarialDiscoveryHost(t, ctx, "good-bootstrap")
	adversarialHost := newAdversarialDiscoveryHost(t, ctx, "adversarial-bootstrap")
	leafKey := testAutomaticWorkKey("adversarial-leaf")
	leafHost := newAdversarialDiscoveryHostWithKey(t, ctx, leafKey)
	now := unixNow()
	leafRecord, err := discovery.SignActivation(
		leafKey, networkID, 1, now+600, activationHeight,
		discovery.FeatureVersionedChainV1|discovery.FeatureWorkGraphV1|discovery.FeaturePeerExchangeV1,
		leafHost.Addresses(),
	)
	if err != nil {
		t.Fatal(err)
	}
	goodBook, _ := discovery.NewBook(networkID, 8)
	if err := goodBook.Add(leafRecord, now); err != nil {
		t.Fatal(err)
	}
	goodSession.AttachDiscovery(goodBook)
	if err := goodHost.SetVersionedChainHandler(func(handlerContext context.Context, _ types.Hash, stream libp2pnetwork.Stream) {
		_ = goodSession.Serve(handlerContext, stream)
	}); err != nil {
		t.Fatal(err)
	}

	validPoison := signAdversarialDiscoveryRecord(t, "valid-poison", networkID, activationHeight, now)
	foreignPoison := signAdversarialDiscoveryRecord(t, "foreign-poison", networkID, activationHeight+1, now)
	if err := adversarialHost.SetVersionedChainHandler(func(_ context.Context, _ types.Hash, stream libp2pnetwork.Stream) {
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := wire.ReadMessage(stream); err != nil {
			return
		}
		hello, err := adversarialSession.Status()
		if err != nil || wire.WriteMessage(stream, hello) != nil {
			return
		}
		if _, err := wire.ReadMessage(stream); err != nil {
			return
		}
		_ = wire.WriteMessage(stream, wire.Peers{Version: wire.Version0, Records: [][]byte{
			validPoison.CanonicalBytes(), foreignPoison.CanonicalBytes(),
		}})
	}); err != nil {
		t.Fatal(err)
	}

	clientBook, _ := discovery.NewBookWithPolicy(networkID, discovery.DefaultPolicy())
	clientSession.AttachDiscovery(clientBook)
	manager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	targets := []workPeerTarget{
		{id: adversarialHost.ID(), address: adversarialHost.Addresses()[0]},
		{id: goodHost.ID(), address: goodHost.Addresses()[0]},
	}
	data := t.TempDir()
	results, err := refreshWorkPeerBook(
		ctx, data, document.NetworkID, activationHeight, clientHost, clientSession,
		manager, clientBook, targets, len(targets),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("bootstrap rotation results=%+v", results)
	}
	var goodResult, adversarialResult *workDiscoveryRefreshResult
	for index := range results {
		switch results[index].PeerID {
		case goodHost.ID():
			goodResult = &results[index]
		case adversarialHost.ID():
			adversarialResult = &results[index]
		}
	}
	if goodResult == nil || goodResult.Err != nil || goodResult.Records != 1 {
		t.Fatalf("good bootstrap result=%+v", goodResult)
	}
	if adversarialResult == nil || !errors.Is(adversarialResult.Err, discovery.ErrCapabilities) {
		t.Fatalf("adversarial bootstrap result=%+v", adversarialResult)
	}
	restored, err := openPeerBook(data, networkID, now)
	if err != nil {
		t.Fatal(err)
	}
	records := restored.List(now, 8)
	leafID, _ := leafRecord.PeerID()
	if len(records) != 1 {
		t.Fatalf("atomic adversarial batch left %d records", len(records))
	}
	storedID, err := records[0].PeerID()
	if err != nil || storedID != leafID || !records[0].Supports(discovery.FeatureWorkGraphV1, activationHeight) {
		t.Fatalf("persisted record=%+v id=%s error=%v", records[0], storedID, err)
	}
}

func newAdversarialDiscoveryChainNode(
	t testing.TB,
	networkID uint32,
	activationHeight uint64,
) (genesis.Document, *chainsession.Node) {
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
	legacy := legacyblock.ParametersFromGenesis(document)
	router, err := activation.New(ledger, activation.Config{
		Legacy: legacy,
		Work: workblock.Parameters{
			NetworkID: networkID, BlockSubsidy: document.BlockSubsidy,
			RewardMaturity: legacy.RewardMaturity, ActivationHeight: activationHeight,
			DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
			TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: 3,
		},
		Now: func() uint64 { return document.Timestamp + 100_000 },
	})
	if err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = router.Close()
		_ = ledger.Close()
	})
	node, err := chainsession.NewNode(router, document, chainsession.DefaultSessionConfig())
	if err != nil {
		t.Fatal(err)
	}
	return document, node
}

func newAdversarialDiscoveryHost(t testing.TB, ctx context.Context, label string) *libp2ptransport.Host {
	t.Helper()
	return newAdversarialDiscoveryHostWithKey(t, ctx, testAutomaticWorkKey(label))
}

func newAdversarialDiscoveryHostWithKey(
	t testing.TB,
	ctx context.Context,
	key ed25519.PrivateKey,
) *libp2ptransport.Host {
	t.Helper()
	host, err := libp2ptransport.New(ctx, key, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host
}

func signAdversarialDiscoveryRecord(
	t testing.TB,
	label string,
	networkID uint32,
	activationHeight uint64,
	now uint64,
) discovery.Record {
	t.Helper()
	record, err := discovery.SignActivation(
		testAutomaticWorkKey(label), networkID, 1, now+600, activationHeight,
		discovery.FeatureVersionedChainV1|discovery.FeaturePeerExchangeV1,
		[]string{"127.0.0.1:9845"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
