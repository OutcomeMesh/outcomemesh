package session

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/wallet"
)

func TestSessionSynchronizesDivergentForksProtocol2(t *testing.T) {
	t.Parallel()

	source := newNodeFixture(t, 606, 2)
	defer source.store.Close()
	destination := newNodeFixture(t, 606, 2)
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

func TestSessionDownloadsRootVerifiedSnapshotWithoutImportingItProtocol2(t *testing.T) {
	t.Parallel()

	source := newNodeFixture(t, 614, 2)
	defer source.store.Close()
	destination := newNodeFixture(t, 614, 2)
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
func TestSessionRelaysValidTransactionAndRejectsDuplicateProtocol2(t *testing.T) {
	t.Parallel()

	sender := newNodeFixture(t, 607, 2)
	defer sender.store.Close()
	receiver := newNodeFixture(t, 607, 2)
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
