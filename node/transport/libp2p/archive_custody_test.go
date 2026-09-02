package libp2ptransport_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestQUICArchiveCustodyProtocolIsExplicitPinnedAndAllowlisted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(
		ctx, testKey("custody-explicit-server"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(
		ctx, testKey("custody-explicit-client"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err := client.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], server.ID(),
	); err == nil {
		t.Fatal("custody protocol negotiated without an explicit handler")
	}

	other := types.DomainHash("test/libp2p/custody-other")
	descending := []types.Hash{client.ID(), other}
	if types.CompareHash(descending[0], descending[1]) < 0 {
		descending[0], descending[1] = descending[1], descending[0]
	}
	for index, allowed := range [][]types.Hash{
		nil,
		{{}},
		{client.ID(), client.ID()},
		descending,
	} {
		if err := server.SetArchiveCustodyHandler(
			allowed, func(context.Context, types.Hash, network.Stream) {},
		); !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatalf("invalid custody allowlist case %d error=%v", index, err)
		}
	}
	handled := make(chan types.Hash, 1)
	if err := server.SetArchiveCustodyHandler(
		[]types.Hash{client.ID()},
		func(_ context.Context, peerID types.Hash, stream network.Stream) {
			var request [1]byte
			if _, readErr := stream.Read(request[:]); readErr == nil {
				handled <- peerID
			}
			_ = stream.Close()
		},
	); err != nil {
		t.Fatal(err)
	}
	outsider, err := libp2ptransport.New(
		ctx, testKey("custody-explicit-outsider"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer outsider.Close()
	if unauthorized, _, openErr := outsider.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], server.ID(),
	); openErr == nil {
		_ = unauthorized.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = unauthorized.Write([]byte{1})
		_ = unauthorized.Reset()
	}
	select {
	case peerID := <-handled:
		t.Fatalf("unauthorized custody peer %s reached handler", peerID)
	case <-time.After(200 * time.Millisecond):
	}
	wrongServer := types.DomainHash("test/libp2p/wrong-custody-server")
	if _, _, err := client.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], wrongServer,
	); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatalf("wrong custody server pin error=%v", err)
	}
	stream, remote, err := client.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if remote != server.ID() || stream.Protocol() != libp2ptransport.ArchiveCustodyProtocol {
		t.Fatalf("custody remote=%s protocol=%q", remote, stream.Protocol())
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case peerID := <-handled:
		if peerID != client.ID() {
			t.Fatalf("custody handler peer=%s want=%s", peerID, client.ID())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = stream.Close()
}

func TestQUICArchiveCustodyRateBudgetIsIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxArchiveCustodyStreamsPerMinute = 1
	config.MaxArchiveCustodyStreamsGlobalPerMinute = 1
	first, err := libp2ptransport.New(
		ctx, testKey("custody-rate-client-a"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := libp2ptransport.New(
		ctx, testKey("custody-rate-client-b"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	allowed := []types.Hash{first.ID(), second.ID()}
	sort.Slice(allowed, func(left, right int) bool {
		return types.CompareHash(allowed[left], allowed[right]) < 0
	})
	server, err := libp2ptransport.New(
		ctx, testKey("custody-rate-server"), config, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	custodyAccepted := make(chan types.Hash, 2)
	if err := server.SetArchiveCustodyHandler(
		allowed,
		func(_ context.Context, peerID types.Hash, stream network.Stream) {
			custodyAccepted <- peerID
			_ = stream.Close()
		},
	); err != nil {
		t.Fatal(err)
	}
	objectAccepted := make(chan types.Hash, 1)
	if err := server.SetArchiveObjectHandler(
		allowed,
		func(_ context.Context, peerID types.Hash, stream network.Stream) {
			objectAccepted <- peerID
			_ = stream.Close()
		},
	); err != nil {
		t.Fatal(err)
	}
	openCustodyAndWait(t, ctx, first, server, custodyAccepted)
	rejected, _, rejectedErr := second.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if rejectedErr == nil {
		_ = rejected.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = rejected.Write([]byte{1})
		_ = rejected.Reset()
	}
	select {
	case peerID := <-custodyAccepted:
		t.Fatalf("peer %s bypassed custody global rate budget", peerID)
	case <-time.After(250 * time.Millisecond):
	}
	objectStream, _, err := second.OpenArchiveObjectStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objectStream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case peerID := <-objectAccepted:
		if peerID != second.ID() {
			t.Fatalf("object handler peer=%s want=%s", peerID, second.ID())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = objectStream.Close()
}

func TestQUICArchiveCustodyEnforcesConcurrentPeerLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxArchiveCustodyStreamsPerMinute = 2
	config.MaxArchiveCustodyStreamsGlobalPerMinute = 2
	client, err := libp2ptransport.New(
		ctx, testKey("custody-concurrent-client"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	server, err := libp2ptransport.New(
		ctx, testKey("custody-concurrent-server"), config, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetArchiveCustodyHandler(
		[]types.Hash{client.ID()},
		func(_ context.Context, _ types.Hash, stream network.Stream) {
			started <- struct{}{}
			<-release
			_ = stream.Close()
		},
	); err != nil {
		t.Fatal(err)
	}
	first, _, err := client.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second, _, secondErr := client.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if secondErr == nil {
		_ = second.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Reset()
	}
	select {
	case <-started:
		t.Fatal("second custody stream bypassed the concurrent per-peer limit")
	case <-time.After(250 * time.Millisecond):
	}
	close(release)
	_ = first.Close()
}

func TestQUICArchiveCustodyRejectsIncoherentResourceLimits(t *testing.T) {
	tests := []func(*libp2ptransport.Config){
		func(config *libp2ptransport.Config) {
			config.MaxArchiveCustodyStreams = libp2ptransport.MaxArchiveCustodyStreamsLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxArchiveCustodyStreamsPerPeer = libp2ptransport.MaxArchiveCustodyStreamsPerPeerLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxArchiveCustodyStreamsPerMinute = libp2ptransport.MaxArchiveCustodyStreamsPerMinuteLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxArchiveCustodyStreamsGlobalPerMinute = config.MaxArchiveCustodyStreamsPerMinute - 1
		},
	}
	for index, mutate := range tests {
		config := libp2ptransport.DefaultConfig()
		mutate(&config)
		if _, err := libp2ptransport.New(
			context.Background(), testKey("custody-invalid-limits"), config, nil,
		); !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatalf("invalid custody limits case %d error=%v", index, err)
		}
	}
}

func openCustodyAndWait(
	t testing.TB,
	ctx context.Context,
	client *libp2ptransport.Host,
	server *libp2ptransport.Host,
	accepted <-chan types.Hash,
) {
	t.Helper()
	stream, _, err := client.OpenArchiveCustodyStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case peerID := <-accepted:
		if peerID != client.ID() {
			t.Fatalf("custody admitted peer=%s want=%s", peerID, client.ID())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = stream.Close()
}
