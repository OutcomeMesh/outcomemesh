package libp2ptransport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestQUICPruneCompletionIsExplicitPinnedAndIndependentlyLimited(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxPruneCompletionStreamsPerMinute = 1
	config.MaxPruneCompletionStreamsGlobalPerMinute = 1
	server, err := libp2ptransport.New(ctx, testKey("prune-completion-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, testKey("prune-completion-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	outsider, err := libp2ptransport.New(ctx, testKey("prune-completion-outsider"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer outsider.Close()
	address := server.Addresses()[0]
	if stream, _, err := client.OpenPruneCompletionStream(ctx, address, server.ID()); err == nil {
		_ = stream.Close()
		t.Fatal("default completion handler installed")
	}
	if _, _, err := client.OpenPruneCompletionStream(ctx, address, types.Hash{}); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatal(err)
	}
	if _, _, err := client.OpenPruneCompletionStream(ctx, address, client.ID()); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatal(err)
	}
	if err := server.SetPruneCompletionHandler(types.Hash{}, func(context.Context, types.Hash, network.Stream) {}); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatal(err)
	}
	if err := server.SetPruneCompletionHandler(client.ID(), nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatal(err)
	}
	handled := make(chan types.Hash, 4)
	if err := server.SetPruneCompletionHandler(client.ID(), func(_ context.Context, id types.Hash, s network.Stream) {
		var b [1]byte
		if _, err := s.Read(b[:]); err == nil {
			handled <- id
		}
		_ = s.Close()
	}); err != nil {
		t.Fatal(err)
	}
	if s, _, err := outsider.OpenPruneCompletionStream(ctx, address, server.ID()); err == nil {
		_ = s.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = s.Write([]byte{1})
		_ = s.Reset()
	}
	select {
	case id := <-handled:
		t.Fatal("outsider reached handler", id)
	case <-time.After(200 * time.Millisecond):
	}
	s, _, err := client.OpenPruneCompletionStream(ctx, address, server.ID())
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol() != libp2ptransport.PruneCompletionProtocol {
		t.Fatal("wrong protocol")
	}
	if _, err := s.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-handled:
		if id != client.ID() {
			t.Fatal("wrong peer")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = s.Close()
	if s, _, err := client.OpenPruneCompletionStream(ctx, address, server.ID()); err == nil {
		_ = s.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = s.Write([]byte{1})
		_ = s.Reset()
	}
	select {
	case <-handled:
		t.Fatal("completion rate budget bypassed")
	case <-time.After(200 * time.Millisecond):
	}
	// Completion traffic cannot consume the custody protocol's rate scope.
	if err := server.SetArchiveCustodyHandler([]types.Hash{client.ID()}, func(_ context.Context, id types.Hash, s network.Stream) { handled <- id; _ = s.Close() }); err != nil {
		t.Fatal(err)
	}
	s, _, err = client.OpenArchiveCustodyStream(ctx, address, server.ID())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Write([]byte{1})
	defer s.Close()
	select {
	case <-handled:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestQUICPruneCompletionRejectsInvalidResourceLimits(t *testing.T) {
	for _, mutate := range []func(*libp2ptransport.Config){
		func(c *libp2ptransport.Config) { c.MaxPruneCompletionStreams = 0 },
		func(c *libp2ptransport.Config) {
			c.MaxPruneCompletionStreams = libp2ptransport.MaxPruneCompletionStreamsLimit + 1
		},
		func(c *libp2ptransport.Config) { c.MaxPruneCompletionStreamsPerPeer = 0 },
		func(c *libp2ptransport.Config) { c.MaxPruneCompletionStreamsPerPeer = 2 },
		func(c *libp2ptransport.Config) { c.MaxPruneCompletionStreamsPerMinute = 0 },
		func(c *libp2ptransport.Config) {
			c.MaxPruneCompletionStreamsPerMinute = libp2ptransport.MaxPruneCompletionStreamsPerMinuteLimit + 1
		},
		func(c *libp2ptransport.Config) {
			c.MaxPruneCompletionStreamsGlobalPerMinute = c.MaxPruneCompletionStreamsPerMinute - 1
		},
		func(c *libp2ptransport.Config) {
			c.MaxPruneCompletionStreamsGlobalPerMinute = libp2ptransport.MaxPruneCompletionStreamsGlobalPerMinuteLimit + 1
		},
	} {
		c := libp2ptransport.DefaultConfig()
		mutate(&c)
		h, err := libp2ptransport.New(t.Context(), testKey("invalid-completion-limits"), c, nil)
		if h != nil {
			_ = h.Close()
		}
		if !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatal(err)
		}
	}
}

func TestQUICPruneCompletionConcurrentPeerLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(ctx, testKey("prune-concurrent-server"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, testKey("prune-concurrent-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	if err := server.SetPruneCompletionHandler(client.ID(), func(_ context.Context, _ types.Hash, s network.Stream) {
		entered <- struct{}{}
		<-release
		_ = s.Close()
	}); err != nil {
		t.Fatal(err)
	}
	first, _, err := client.OpenPruneCompletionStream(ctx, server.Addresses()[0], server.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, _ = first.Write([]byte{1})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if second, _, err := client.OpenPruneCompletionStream(ctx, server.Addresses()[0], server.ID()); err == nil {
		_ = second.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Reset()
	}
	select {
	case <-entered:
		t.Fatal("second concurrent completion admitted")
	case <-time.After(200 * time.Millisecond):
	}
}
