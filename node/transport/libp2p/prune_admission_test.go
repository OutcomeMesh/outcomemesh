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

func TestQUICPruneAdmissionIsExplicitPinnedAndIndependentlyLimited(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxPruneAdmissionStreamsPerMinute = 1
	config.MaxPruneAdmissionStreamsGlobalPerMinute = 1
	server, err := libp2ptransport.New(ctx, testKey("prune-admission-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, testKey("prune-admission-client"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	outsider, err := libp2ptransport.New(ctx, testKey("prune-admission-outsider"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer outsider.Close()
	address := server.Addresses()[0]
	if stream, _, err := client.OpenPruneAdmissionStream(ctx, address, server.ID()); err == nil {
		_ = stream.Close()
		t.Fatal("default admission handler installed")
	}
	if _, _, err := client.OpenPruneAdmissionStream(ctx, address, types.Hash{}); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatal(err)
	}
	if _, _, err := client.OpenPruneAdmissionStream(ctx, address, client.ID()); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
		t.Fatal(err)
	}
	if err := server.SetPruneAdmissionHandler(types.Hash{}, func(context.Context, types.Hash, network.Stream) {}); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatal(err)
	}
	if err := server.SetPruneAdmissionHandler(client.ID(), nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatal(err)
	}
	handled := make(chan types.Hash, 4)
	if err := server.SetPruneAdmissionHandler(client.ID(), func(_ context.Context, id types.Hash, s network.Stream) {
		var b [1]byte
		if _, err := s.Read(b[:]); err == nil {
			handled <- id
		}
		_ = s.Close()
	}); err != nil {
		t.Fatal(err)
	}
	if s, _, err := outsider.OpenPruneAdmissionStream(ctx, address, server.ID()); err == nil {
		_ = s.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = s.Write([]byte{1})
		_ = s.Reset()
	}
	select {
	case id := <-handled:
		t.Fatal("outsider reached handler", id)
	case <-time.After(200 * time.Millisecond):
	}
	s, _, err := client.OpenPruneAdmissionStream(ctx, address, server.ID())
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol() != libp2ptransport.PruneAdmissionProtocol {
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
	if s, _, err := client.OpenPruneAdmissionStream(ctx, address, server.ID()); err == nil {
		_ = s.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = s.Write([]byte{1})
		_ = s.Reset()
	}
	select {
	case <-handled:
		t.Fatal("admission rate budget bypassed")
	case <-time.After(200 * time.Millisecond):
	}
	// Admission traffic cannot consume the custody protocol's rate scope.
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
	// A full admission budget must not prevent the same peer from draining work.
	if err := server.SetPruneCompletionHandler(client.ID(), func(_ context.Context, id types.Hash, s network.Stream) { handled <- id; _ = s.Close() }); err != nil {
		t.Fatal(err)
	}
	s, _, err = client.OpenPruneCompletionStream(ctx, address, server.ID())
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

func TestQUICPruneAdmissionRejectsInvalidResourceLimits(t *testing.T) {
	for _, mutate := range []func(*libp2ptransport.Config){
		func(c *libp2ptransport.Config) { c.MaxPruneAdmissionStreams = 0 },
		func(c *libp2ptransport.Config) {
			c.MaxPruneAdmissionStreams = libp2ptransport.MaxPruneAdmissionStreamsLimit + 1
		},
		func(c *libp2ptransport.Config) { c.MaxPruneAdmissionStreamsPerPeer = 0 },
		func(c *libp2ptransport.Config) { c.MaxPruneAdmissionStreamsPerPeer = 2 },
		func(c *libp2ptransport.Config) { c.MaxPruneAdmissionStreamsPerMinute = 0 },
		func(c *libp2ptransport.Config) {
			c.MaxPruneAdmissionStreamsPerMinute = libp2ptransport.MaxPruneAdmissionStreamsPerMinuteLimit + 1
		},
		func(c *libp2ptransport.Config) {
			c.MaxPruneAdmissionStreamsGlobalPerMinute = c.MaxPruneAdmissionStreamsPerMinute - 1
		},
		func(c *libp2ptransport.Config) {
			c.MaxPruneAdmissionStreamsGlobalPerMinute = libp2ptransport.MaxPruneAdmissionStreamsGlobalPerMinuteLimit + 1
		},
	} {
		c := libp2ptransport.DefaultConfig()
		mutate(&c)
		h, err := libp2ptransport.New(t.Context(), testKey("invalid-admission-limits"), c, nil)
		if h != nil {
			_ = h.Close()
		}
		if !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatal(err)
		}
	}
}

func TestQUICPruneAdmissionConcurrentPeerLimit(t *testing.T) {
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
	if err := server.SetPruneAdmissionHandler(client.ID(), func(_ context.Context, _ types.Hash, s network.Stream) {
		entered <- struct{}{}
		<-release
		_ = s.Close()
	}); err != nil {
		t.Fatal(err)
	}
	first, _, err := client.OpenPruneAdmissionStream(ctx, server.Addresses()[0], server.ID())
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
	if second, _, err := client.OpenPruneAdmissionStream(ctx, server.Addresses()[0], server.ID()); err == nil {
		_ = second.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Reset()
	}
	select {
	case <-entered:
		t.Fatal("second concurrent admission admitted")
	case <-time.After(200 * time.Millisecond):
	}
}
