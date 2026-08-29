package libp2ptransport_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/tieexchange"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestQUICTiePairProtocolAuthenticatesBothEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	binding := tieexchange.Binding{
		PlanID: types.DomainHash("test/libp2p/tie-pair-plan"),
		PairID: types.DomainHash("test/libp2p/tie-pair-artifact"), Sequence: 3,
	}
	observer := types.DomainHash("test/libp2p/tie-pair-observer")
	receipt := types.DomainHash("test/libp2p/tie-pair-receipt")
	coordinatorKey := testKey("tie-pair-coordinator")
	coordinatorID := types.DomainHash("OMESH/p2p/ed25519/v0", coordinatorKey.Public().(ed25519.PublicKey))
	serverDone := make(chan error, 1)
	server, err := libp2ptransport.New(ctx, testKey("tie-pair-observer-transport"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetTiePairHandler(coordinatorID, func(_ context.Context, peerID types.Hash, stream network.Stream) {
		if peerID != coordinatorID {
			serverDone <- errors.New("handler received an unpinned coordinator identity")
			_ = stream.Reset()
			return
		}
		request, receiveErr := tieexchange.ReadRequest(stream, binding)
		if receiveErr == nil && string(request.Artifact) != "bounded-pair" {
			receiveErr = errors.New("wrong pair body")
		}
		if receiveErr == nil {
			receiveErr = tieexchange.WriteAcknowledgement(stream, tieexchange.Acknowledgement{
				Binding: binding, ObserverPublicKey: observer, ReceiptTail: receipt,
			})
		}
		if receiveErr == nil {
			_, receiveErr = tieexchange.ReadConfirmation(stream, binding, receipt)
		}
		serverDone <- receiveErr
	}); err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, coordinatorKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	wrong := types.DomainHash("test/libp2p/tie-pair-wrong-observer-transport")
	if _, _, err := client.OpenTiePairStream(ctx, server.Addresses()[0], &wrong); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatalf("wrong observer pin error=%v", err)
	}
	expected := server.ID()
	stream, remote, err := client.OpenTiePairStream(ctx, server.Addresses()[0], &expected)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if remote != expected || stream.Protocol() != libp2ptransport.TiePairProtocol {
		t.Fatalf("remote=%s protocol=%q", remote, stream.Protocol())
	}
	if err := tieexchange.WriteRequest(stream, tieexchange.Request{Binding: binding, Artifact: []byte("bounded-pair")}); err != nil {
		t.Fatal(err)
	}
	acknowledgement, err := tieexchange.ReadAcknowledgement(stream, binding, observer)
	if err != nil || acknowledgement.ReceiptTail != receipt {
		t.Fatalf("acknowledgement=%+v err=%v", acknowledgement, err)
	}
	if err := tieexchange.WriteConfirmation(stream, tieexchange.Confirmation{
		Binding: binding, ReceiptTail: acknowledgement.ReceiptTail,
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestQUICTiePairProtocolDisabledUntilExplicitlyInstalled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(ctx, testKey("tie-pair-disabled-server"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, testKey("tie-pair-disabled-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err := client.OpenTiePairStream(ctx, server.Addresses()[0], nil); err == nil {
		t.Fatal("tie-pair protocol negotiated without an explicit handler")
	}
}

func TestQUICTiePairFixedWindowRateBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxTiePairStreamsPerMinute = 1
	handled := make(chan struct{}, 2)
	clientKey := testKey("tie-pair-rate-client")
	clientID := types.DomainHash("OMESH/p2p/ed25519/v0", clientKey.Public().(ed25519.PublicKey))
	server, err := libp2ptransport.New(ctx, testKey("tie-pair-rate-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetTiePairHandler(clientID, func(_ context.Context, _ types.Hash, stream network.Stream) {
		handled <- struct{}{}
		_ = stream.Close()
	}); err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, clientKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, _, err := client.OpenTiePairStream(ctx, server.Addresses()[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = first.Write([]byte{1})
	_ = first.Close()
	select {
	case <-handled:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second, _, err := client.OpenTiePairStream(ctx, server.Addresses()[0], nil)
	if err == nil {
		_ = second.SetDeadline(time.Now().Add(250 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Close()
	}
	select {
	case <-handled:
		t.Fatal("second tie-pair stream bypassed its fixed-window peer rate budget")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestQUICTiePairRejectsIncoherentResourceLimits(t *testing.T) {
	config := libp2ptransport.DefaultConfig()
	config.MaxTiePairStreamsPerPeer = libp2ptransport.MaxTiePairStreamsPerPeerLimit + 1
	if _, err := libp2ptransport.New(context.Background(), testKey("tie-pair-invalid-limits"), config, nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatalf("tie-pair resource limit error=%v", err)
	}
}
