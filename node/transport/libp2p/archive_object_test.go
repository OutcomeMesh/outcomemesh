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

func TestQUICArchiveObjectProtocolIsExplicitAndAllowlisted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(
		ctx, testKey("archive-explicit-server"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(
		ctx, testKey("archive-explicit-client"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err := client.OpenArchiveObjectStream(
		ctx, server.Addresses()[0], server.ID(),
	); err == nil {
		t.Fatal("archive-object protocol negotiated without an explicit handler")
	}

	other := types.DomainHash("test/libp2p/archive-other")
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
		if err := server.SetArchiveObjectHandler(
			allowed, func(context.Context, types.Hash, network.Stream) {},
		); !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatalf("invalid allowlist case %d error=%v", index, err)
		}
	}
	handled := make(chan types.Hash, 1)
	if err := server.SetArchiveObjectHandler(
		[]types.Hash{client.ID()},
		func(_ context.Context, peerID types.Hash, stream network.Stream) {
			handled <- peerID
			_ = stream.Close()
		},
	); err != nil {
		t.Fatal(err)
	}
	stream, remote, err := client.OpenArchiveObjectStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if remote != server.ID() || stream.Protocol() != libp2ptransport.ArchiveObjectProtocol {
		t.Fatalf("archive remote=%s protocol=%q", remote, stream.Protocol())
	}
	_, _ = stream.Write([]byte{1})
	_ = stream.Close()
	select {
	case peerID := <-handled:
		if peerID != client.ID() {
			t.Fatalf("archive handler peer=%s want=%s", peerID, client.ID())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestQUICArchiveObjectProtocolEnforcesConcurrentPeerLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxArchiveObjectStreams = 2
	config.MaxArchiveObjectStreamsPerPeer = 1
	client, err := libp2ptransport.New(
		ctx, testKey("archive-concurrent-client"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server, err := libp2ptransport.New(
		ctx, testKey("archive-concurrent-server"), config, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetArchiveObjectHandler(
		[]types.Hash{client.ID()},
		func(_ context.Context, _ types.Hash, stream network.Stream) {
			started <- struct{}{}
			<-release
			_ = stream.Close()
		},
	); err != nil {
		t.Fatal(err)
	}
	first, _, err := client.OpenArchiveObjectStream(ctx, server.Addresses()[0], server.ID())
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
	second, _, secondErr := client.OpenArchiveObjectStream(ctx, server.Addresses()[0], server.ID())
	if secondErr == nil {
		_ = second.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Reset()
	}
	select {
	case <-started:
		t.Fatal("second archive stream bypassed the concurrent per-peer limit")
	case <-time.After(250 * time.Millisecond):
	}
	close(release)
	_ = first.Close()
}

func TestQUICArchiveObjectProtocolEnforcesGlobalRateBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxArchiveObjectStreamsPerMinute = 1
	config.MaxArchiveObjectStreamsGlobalPerMinute = 1
	firstClient, err := libp2ptransport.New(
		ctx, testKey("archive-rate-client-a"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	secondClient, err := libp2ptransport.New(
		ctx, testKey("archive-rate-client-b"), libp2ptransport.DefaultConfig(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	allowed := []types.Hash{firstClient.ID(), secondClient.ID()}
	sort.Slice(allowed, func(left, right int) bool {
		return types.CompareHash(allowed[left], allowed[right]) < 0
	})
	accepted := make(chan types.Hash, 2)
	server, err := libp2ptransport.New(
		ctx, testKey("archive-rate-server"), config, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetArchiveObjectHandler(
		allowed,
		func(_ context.Context, peerID types.Hash, stream network.Stream) {
			accepted <- peerID
			_ = stream.Close()
		},
	); err != nil {
		t.Fatal(err)
	}
	openArchiveObjectAndWait(t, ctx, firstClient, server, accepted)
	second, _, secondErr := secondClient.OpenArchiveObjectStream(
		ctx, server.Addresses()[0], server.ID(),
	)
	if secondErr == nil {
		_ = second.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Reset()
	}
	select {
	case peerID := <-accepted:
		t.Fatalf("peer %s bypassed archive global rate budget", peerID)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestQUICArchiveObjectRejectsIncoherentResourceLimits(t *testing.T) {
	tests := []func(*libp2ptransport.Config){
		func(config *libp2ptransport.Config) {
			config.MaxArchiveObjectStreams = libp2ptransport.MaxArchiveObjectStreamsLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxArchiveObjectStreamsPerPeer = libp2ptransport.MaxArchiveObjectStreamsPerPeerLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxArchiveObjectStreamsPerMinute = libp2ptransport.MaxArchiveObjectStreamsPerMinuteLimit + 1
		},
		func(config *libp2ptransport.Config) {
			config.MaxArchiveObjectStreamsGlobalPerMinute = config.MaxArchiveObjectStreamsPerMinute - 1
		},
	}
	for index, mutate := range tests {
		config := libp2ptransport.DefaultConfig()
		mutate(&config)
		if _, err := libp2ptransport.New(
			context.Background(), testKey("archive-invalid-limits"), config, nil,
		); !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatalf("invalid archive limits case %d error=%v", index, err)
		}
	}
}

func openArchiveObjectAndWait(
	t testing.TB,
	ctx context.Context,
	client *libp2ptransport.Host,
	server *libp2ptransport.Host,
	accepted <-chan types.Hash,
) {
	t.Helper()
	stream, _, err := client.OpenArchiveObjectStream(
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
			t.Fatalf("archive admitted peer=%s want=%s", peerID, client.ID())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = stream.Close()
}
