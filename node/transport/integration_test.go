package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/mempool"
	"github.com/outcomemesh/outcomemesh/node/session"
	"github.com/outcomemesh/outcomemesh/node/syncer"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

func TestAuthenticatedTCPStreamRunsFullForkSync(t *testing.T) {
	t.Parallel()

	document := integrationGenesis()
	sourceStore, sourceChain, sourceSession := integrationNode(t, document)
	defer sourceStore.Close()
	destinationStore, _, destinationSession := integrationNode(t, document)
	defer destinationStore.Close()
	miner := types.Address(types.DomainHash("test/transport/integration/miner"))
	for range uint64(3) {
		tip, err := sourceChain.Status()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sourceChain.Mine(context.Background(), nil, miner, tip.Timestamp+1, 0); err != nil {
			t.Fatal(err)
		}
	}
	sourceIdentity := integrationIdentity(t, "source")
	destinationIdentity := integrationIdentity(t, "destination")
	listener, err := transport.Listen("127.0.0.1:0", sourceIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			_ = connection.Close()
			serverDone <- transport.ErrPeerCertificate
			return
		}
		serverDone <- sourceSession.Serve(ctx, tlsConnection)
	}()
	expected := sourceIdentity.ID()
	connection, peerID, err := transport.Dial(ctx, listener.Addr().String(), destinationIdentity, &expected)
	if err != nil {
		t.Fatal(err)
	}
	if peerID != expected {
		t.Fatal("dial authenticated the wrong peer")
	}
	status, err := destinationSession.Synchronize(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	sourceTip, _ := sourceStore.Tip()
	destinationTip, _ := destinationStore.Tip()
	if status.TipID != sourceTip.ID || !storage.EqualTips(sourceTip, destinationTip) {
		t.Fatal("authenticated stream did not converge ledger tips")
	}
}

func integrationGenesis() genesis.Document {
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	return genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    707,
		Timestamp:    1_700_700_000,
		Target:       target,
		BlockSubsidy: 10,
	}
}

func integrationNode(t testing.TB, document genesis.Document) (*reference.Store, *chain.Chain, *session.Node) {
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

func integrationIdentity(t testing.TB, label string) transport.Identity {
	t.Helper()
	seed := types.DomainHash("test/transport/integration/identity/" + label)
	identity, err := transport.NewIdentity(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
