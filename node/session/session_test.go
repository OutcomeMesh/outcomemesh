package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/mempool"
	"github.com/outcomemesh/outcomemesh/node/syncer"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
	"github.com/outcomemesh/outcomemesh/wallet"
)

type nodeFixture struct {
	document genesis.Document
	store    *reference.Store
	chain    *chain.Chain
	pool     *mempool.Pool
	session  *Node
	key      ed25519.PrivateKey
}

func TestSessionSynchronizesDivergentForks(t *testing.T) {
	t.Parallel()

	source := newNodeFixture(t, 606)
	defer source.store.Close()
	destination := newNodeFixture(t, 606)
	defer destination.store.Close()
	mine(t, source, types.Address(types.DomainHash("test/session/miner-a")), 4)
	mine(t, destination, types.Address(types.DomainHash("test/session/miner-b")), 2)

	client, server := net.Pipe()
	serverDone := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { serverDone <- source.session.Serve(ctx, server) }()
	status, err := destination.session.Synchronize(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server failed after sync: %v", err)
	}
	sourceTip, _ := source.store.Tip()
	if status.TipID != sourceTip.ID || status.TipHeight != sourceTip.Height {
		t.Fatalf("destination status height=%d id=%s, source height=%d id=%s", status.TipHeight, status.TipID, sourceTip.Height, sourceTip.ID)
	}
}

func TestHeaderFirstSyncRejectsInvalidContextBeforeRequestingBodies(t *testing.T) {
	t.Parallel()

	source := newNodeFixture(t, 617)
	defer source.store.Close()
	destination := newNodeFixture(t, 617)
	defer destination.store.Close()
	mine(t, source, types.Address(types.DomainHash("test/session/header-first/miner")), 1)

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type serverResult struct {
		bodyRequested bool
		err           error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		message, err := wire.ReadMessage(server)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		if _, ok := message.(wire.Status); !ok {
			serverDone <- serverResult{err: ErrUnexpected}
			return
		}
		status, err := source.session.sync.Status()
		if err == nil {
			err = wire.WriteMessage(server, status)
		}
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		message, err = wire.ReadMessage(server)
		request, ok := message.(wire.GetHeaders)
		if err != nil || !ok {
			serverDone <- serverResult{err: err}
			return
		}
		headers, err := source.session.sync.HeadersAfter(request)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		headers.Values[0].Timestamp = source.document.Timestamp
		if err := wire.WriteMessage(server, headers); err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		message, err = wire.ReadMessage(server)
		_, bodyRequested := message.(wire.GetBlocks)
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			err = nil
		}
		serverDone <- serverResult{bodyRequested: bodyRequested, err: err}
	}()

	_, err := destination.session.Synchronize(ctx, client)
	if !errors.Is(err, block.ErrMedianTimePast) {
		t.Fatalf("invalid header error = %v", err)
	}
	_ = client.Close()
	result := <-serverDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.bodyRequested {
		t.Fatal("client requested block bodies after header validation failed")
	}
	tip, err := destination.store.Tip()
	if err != nil || tip.Height != 0 {
		t.Fatalf("invalid header mutated destination: height=%d err=%v", tip.Height, err)
	}
}

func TestSessionRelaysValidTransactionAndRejectsDuplicate(t *testing.T) {
	t.Parallel()

	sender := newNodeFixture(t, 607)
	defer sender.store.Close()
	receiver := newNodeFixture(t, 607)
	defer receiver.store.Close()
	preState, err := sender.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := wallet.BuildNativeTransfer(preState, sender.key, wallet.TransferRequest{
		NetworkID:     sender.document.NetworkID,
		CurrentHeight: 0,
		ValidFor:      20,
		Recipient:     types.Address(types.DomainHash("test/session/recipient")),
		Amount:        100,
		Fee:           1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exchangeTransaction(t, sender.session, receiver.session, transaction); err != nil {
		t.Fatal(err)
	}
	if receiver.pool.Len() != 1 {
		t.Fatalf("receiver mempool size = %d, want 1", receiver.pool.Len())
	}
	if err := exchangeTransaction(t, sender.session, receiver.session, transaction); !errors.Is(err, ErrRejected) {
		t.Fatalf("duplicate relay error = %v", err)
	}
}

func TestResponderRejectsWrongNetworkDuringHandshake(t *testing.T) {
	t.Parallel()

	left := newNodeFixture(t, 608)
	defer left.store.Close()
	right := newNodeFixture(t, 609)
	defer right.store.Close()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- left.session.Serve(ctx, server) }()
	_, _ = right.session.Synchronize(ctx, client)
	_ = client.Close()
	if err := <-serverDone; !errors.Is(err, syncer.ErrNetwork) {
		t.Fatalf("responder error = %v, want network mismatch", err)
	}
}

func TestSessionExchangesSignedPeerAdvertisements(t *testing.T) {
	t.Parallel()

	serverNode := newNodeFixture(t, 612)
	defer serverNode.store.Close()
	clientNode := newNodeFixture(t, 612)
	defer clientNode.store.Close()
	serverBook, err := discovery.NewBook(612, 8)
	if err != nil {
		t.Fatal(err)
	}
	clientBook, err := discovery.NewBook(612, 8)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	for index, address := range []string{"127.0.0.1:9844", "127.0.0.1:9845"} {
		seed := types.DomainHash("test/session/discovery", []byte{byte(index)})
		record, err := discovery.Sign(ed25519.NewKeyFromSeed(seed[:]), 612, 1, now+600, []string{address})
		if err != nil {
			t.Fatal(err)
		}
		if err := serverBook.Add(record, now); err != nil {
			t.Fatal(err)
		}
	}
	serverNode.session.AttachDiscovery(serverBook)
	clientNode.session.AttachDiscovery(clientBook)

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverNode.session.Serve(ctx, server) }()
	records, err := clientNode.session.Discover(ctx, client, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || clientBook.Len(now) != 2 {
		t.Fatalf("discovered=%d book=%d, want 2", len(records), clientBook.Len(now))
	}
	_ = client.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestEstablishedSessionCanSyncThenRefreshDiscovery(t *testing.T) {
	t.Parallel()

	serverNode := newNodeFixture(t, 618)
	defer serverNode.store.Close()
	clientNode := newNodeFixture(t, 618)
	defer clientNode.store.Close()
	serverBook, err := discovery.NewBook(618, 8)
	if err != nil {
		t.Fatal(err)
	}
	clientBook, err := discovery.NewBook(618, 8)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	seed := types.DomainHash("test/session/established-discovery")
	record, err := discovery.Sign(ed25519.NewKeyFromSeed(seed[:]), 618, 1, now+600, []string{"127.0.0.1:9844"})
	if err != nil {
		t.Fatal(err)
	}
	if err := serverBook.Add(record, now); err != nil {
		t.Fatal(err)
	}
	serverNode.session.AttachDiscovery(serverBook)
	clientNode.session.AttachDiscovery(clientBook)

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverNode.session.Serve(ctx, server) }()
	if _, err := clientNode.session.Synchronize(ctx, client); err != nil {
		t.Fatal(err)
	}
	records, err := clientNode.session.DiscoverEstablished(ctx, client, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || clientBook.Len(now) != 1 {
		t.Fatalf("records=%d book=%d", len(records), clientBook.Len(now))
	}
	// Replaying the exact signed gossip record on the same session is a no-op,
	// not a stale-sequence disconnect.
	if _, err := clientNode.session.DiscoverEstablished(ctx, client, 8); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestSessionDownloadsRootVerifiedSnapshotWithoutImportingIt(t *testing.T) {
	t.Parallel()

	source := newNodeFixture(t, 614)
	defer source.store.Close()
	destination := newNodeFixture(t, 614)
	defer destination.store.Close()
	mine(t, source, types.Address(types.DomainHash("test/session/snapshot/miner")), 3)
	destinationBefore, err := destination.store.Tip()
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- source.session.Serve(ctx, server) }()
	verified, remote, err := destination.session.DownloadSnapshot(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Root() != remote.StateRoot {
		t.Fatalf("snapshot root = %s, advertised = %s", verified.Root(), remote.StateRoot)
	}
	sourceState, err := source.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if verified.Len() != sourceState.Len() || verified.Root() != sourceState.Root() {
		t.Fatal("downloaded snapshot differs from source")
	}
	destinationAfter, err := destination.store.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if !storage.EqualTips(destinationBefore, destinationAfter) {
		t.Fatal("verification-only snapshot path mutated destination ledger")
	}
	_ = client.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestResponderEnforcesPerSessionMessageBudget(t *testing.T) {
	t.Parallel()

	serverNode := newNodeFixture(t, 615)
	defer serverNode.store.Close()
	clientNode := newNodeFixture(t, 615)
	defer clientNode.store.Close()
	serverNode.session.config.MaxInboundMessages = 1

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverNode.session.Serve(ctx, server) }()
	status, err := clientNode.session.sync.Status()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, status); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadMessage(client); err != nil {
		t.Fatal(err)
	}
	request := wire.GetPeers{Version: wire.Version0, Limit: 1}
	if err := wire.WriteMessage(client, request); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadMessage(client); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, request); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; !errors.Is(err, ErrSessionBudget) {
		t.Fatalf("session budget error = %v", err)
	}
	_ = client.Close()
}

func TestResponderEnforcesRequestClassBudget(t *testing.T) {
	t.Parallel()

	serverNode := newNodeFixture(t, 616)
	defer serverNode.store.Close()
	clientNode := newNodeFixture(t, 616)
	defer clientNode.store.Close()
	serverNode.session.config.MaxPeerRequests = 1

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverNode.session.Serve(ctx, server) }()
	status, err := clientNode.session.sync.Status()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, status); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadMessage(client); err != nil {
		t.Fatal(err)
	}
	request := wire.GetPeers{Version: wire.Version0, Limit: wire.MaxPeerRecords}
	if err := wire.WriteMessage(client, request); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadMessage(client); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, request); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; !errors.Is(err, ErrSessionBudget) {
		t.Fatalf("request-class budget error = %v", err)
	}
	_ = client.Close()
}

func exchangeTransaction(t testing.TB, sender, receiver *Node, transaction outcome.Transaction) error {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- receiver.Serve(ctx, server) }()
	err := sender.SendTransaction(ctx, client, transaction)
	_ = client.Close()
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatalf("receiver session error: %v", serverErr)
	}
	return err
}

func newNodeFixture(t testing.TB, networkID uint32) nodeFixture {
	t.Helper()
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	seed := types.DomainHash("test/session/genesis-key")
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	document := genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    networkID,
		Timestamp:    1_700_600_000,
		Target:       target,
		BlockSubsidy: 10,
		Allocations: []resource.Resource{{
			ID:      types.ResourceID(types.DomainHash("test/session/genesis-resource")),
			Version: resource.Version0,
			Owner:   owner,
			Asset:   types.NativeAssetID(),
			Amount:  10_000,
		}},
	}
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
	sessionService, err := New(syncService, store, pool, Config{
		HandshakeTimeout: time.Second,
		RequestTimeout:   time.Second,
		MaxSyncBatches:   16,
	})
	if err != nil {
		t.Fatal(err)
	}
	return nodeFixture{document: document, store: store, chain: chainService, pool: pool, session: sessionService, key: privateKey}
}

func mine(t testing.TB, value nodeFixture, miner types.Address, count uint64) {
	t.Helper()
	for range count {
		tip, err := value.chain.Status()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := value.chain.Mine(context.Background(), nil, miner, tip.Timestamp+1, 0); err != nil {
			t.Fatal(err)
		}
	}
}
