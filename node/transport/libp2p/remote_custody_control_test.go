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

func TestQUICRemoteCustodyControlIsExplicitPinnedAndIndependentlyLimited(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxRemoteCustodyControlStreamsPerMinute = 1
	config.MaxRemoteCustodyControlStreamsGlobalPerMinute = 1
	server, err := libp2ptransport.New(ctx, testKey("remote-control-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	control, err := libp2ptransport.New(ctx, testKey("remote-control-A"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	auditor, err := libp2ptransport.New(ctx, testKey("remote-data-auditor-A"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Close()
	address := server.Addresses()[0]
	if stream, _, err := control.OpenRemoteCustodyControlStream(ctx, address, server.ID()); err == nil {
		_ = stream.Close()
		t.Fatal("default remote control endpoint installed")
	}
	for _, pin := range []types.Hash{{}, control.ID()} {
		if _, _, err := control.OpenRemoteCustodyControlStream(ctx, address, pin); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) {
			t.Fatal("missing or wrong B pin accepted", err)
		}
	}
	if err := server.SetRemoteCustodyControlHandler(types.Hash{}, func(context.Context, types.Hash, network.Stream) {}); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatal(err)
	}
	if err := server.SetRemoteCustodyControlHandler(control.ID(), nil); !errors.Is(err, libp2ptransport.ErrConfiguration) {
		t.Fatal(err)
	}
	handled := make(chan types.Hash, 4)
	if err := server.SetRemoteCustodyControlHandler(control.ID(), func(_ context.Context, id types.Hash, s network.Stream) {
		var b [1]byte
		if _, err := s.Read(b[:]); err == nil {
			handled <- id
		}
		_ = s.Close()
	}); err != nil {
		t.Fatal(err)
	}
	// The separate data auditor is not the A control peer. A rejected data
	// identity must also leave the legitimate control peer's quota available.
	if s, _, err := auditor.OpenRemoteCustodyControlStream(ctx, address, server.ID()); err == nil {
		_ = s.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = s.Write([]byte{1})
		_ = s.Reset()
	}
	select {
	case id := <-handled:
		t.Fatal("data auditor reached control handler", id)
	case <-time.After(200 * time.Millisecond):
	}
	s, peer, err := control.OpenRemoteCustodyControlStream(ctx, address, server.ID())
	if err != nil {
		t.Fatal(err)
	}
	if peer != server.ID() || s.Protocol() != libp2ptransport.RemoteCustodyControlProtocol {
		t.Fatal("wrong authenticated control protocol or peer")
	}
	if _, err := s.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-handled:
		if id != control.ID() {
			t.Fatal("wrong A transport identity")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = s.Close()
	if s, _, err := control.OpenRemoteCustodyControlStream(ctx, address, server.ID()); err == nil {
		_ = s.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = s.Write([]byte{1})
		_ = s.Reset()
	}
	select {
	case <-handled:
		t.Fatal("remote control rate budget bypassed")
	case <-time.After(200 * time.Millisecond):
	}
	// Metadata control has no shared admission/completion/data rate window.
	// The data role is independently pinned, even on the same B host.
	if err := server.SetArchiveCustodyHandler([]types.Hash{auditor.ID()}, func(_ context.Context, id types.Hash, s network.Stream) { handled <- id; _ = s.Close() }); err != nil {
		t.Fatal(err)
	}
	s, _, err = auditor.OpenArchiveCustodyStream(ctx, address, server.ID())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Write([]byte{1})
	defer s.Close()
	select {
	case id := <-handled:
		if id != auditor.ID() {
			t.Fatal("wrong data identity")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := server.SetPruneAdmissionHandler(control.ID(), func(_ context.Context, id types.Hash, s network.Stream) { handled <- id; _ = s.Close() }); err != nil {
		t.Fatal(err)
	}
	s, _, err = control.OpenPruneAdmissionStream(ctx, address, server.ID())
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
	if err := server.SetPruneCompletionHandler(control.ID(), func(_ context.Context, id types.Hash, s network.Stream) { handled <- id; _ = s.Close() }); err != nil {
		t.Fatal(err)
	}
	s, _, err = control.OpenPruneCompletionStream(ctx, address, server.ID())
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

func TestQUICRemoteCustodyControlRejectsInvalidResourceLimits(t *testing.T) {
	for _, mutate := range []func(*libp2ptransport.Config){
		func(c *libp2ptransport.Config) { c.MaxRemoteCustodyControlStreams = 0 },
		func(c *libp2ptransport.Config) {
			c.MaxRemoteCustodyControlStreams = libp2ptransport.MaxRemoteCustodyControlStreamsLimit + 1
		},
		func(c *libp2ptransport.Config) { c.MaxRemoteCustodyControlStreamsPerPeer = 0 },
		func(c *libp2ptransport.Config) {
			c.MaxRemoteCustodyControlStreamsPerPeer = libp2ptransport.MaxRemoteCustodyControlStreamsPerPeerLimit + 1
		},
		func(c *libp2ptransport.Config) {
			c.MaxRemoteCustodyControlStreams = 1
			c.MaxRemoteCustodyControlStreamsPerPeer = 2
		},
		func(c *libp2ptransport.Config) { c.MaxRemoteCustodyControlStreamsPerMinute = 0 },
		func(c *libp2ptransport.Config) {
			c.MaxRemoteCustodyControlStreamsPerMinute = libp2ptransport.MaxRemoteCustodyControlStreamsPerMinuteLimit + 1
		},
		func(c *libp2ptransport.Config) {
			c.MaxRemoteCustodyControlStreamsGlobalPerMinute = c.MaxRemoteCustodyControlStreamsPerMinute - 1
		},
		func(c *libp2ptransport.Config) {
			c.MaxRemoteCustodyControlStreamsGlobalPerMinute = libp2ptransport.MaxRemoteCustodyControlStreamsGlobalPerMinuteLimit + 1
		},
	} {
		c := libp2ptransport.DefaultConfig()
		mutate(&c)
		h, err := libp2ptransport.New(t.Context(), testKey("invalid-remote-control-limits"), c, nil)
		if h != nil {
			_ = h.Close()
		}
		if !errors.Is(err, libp2ptransport.ErrConfiguration) {
			t.Fatal(err)
		}
	}
}

func TestQUICRemoteCustodyControlConcurrentPeerLimitDoesNotConsumeDataScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.MaxRemoteCustodyControlStreamsPerPeer = 1
	server, err := libp2ptransport.New(ctx, testKey("remote-concurrent-server"), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	control, err := libp2ptransport.New(ctx, testKey("remote-concurrent-A"), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	if err := server.SetRemoteCustodyControlHandler(control.ID(), func(_ context.Context, _ types.Hash, s network.Stream) {
		entered <- struct{}{}
		<-release
		_ = s.Close()
	}); err != nil {
		t.Fatal(err)
	}
	first, _, err := control.OpenRemoteCustodyControlStream(ctx, server.Addresses()[0], server.ID())
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
	if second, _, err := control.OpenRemoteCustodyControlStream(ctx, server.Addresses()[0], server.ID()); err == nil {
		_ = second.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = second.Write([]byte{1})
		_ = second.Reset()
	}
	select {
	case <-entered:
		t.Fatal("second concurrent control stream admitted")
	case <-time.After(200 * time.Millisecond):
	}
	dataEntered := make(chan struct{}, 1)
	if err := server.SetArchiveCustodyHandler([]types.Hash{control.ID()}, func(_ context.Context, _ types.Hash, s network.Stream) { dataEntered <- struct{}{}; _ = s.Close() }); err != nil {
		t.Fatal(err)
	}
	data, _, err := control.OpenArchiveCustodyStream(ctx, server.Addresses()[0], server.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	_, _ = data.Write([]byte{1})
	select {
	case <-dataEntered:
	case <-ctx.Done():
		t.Fatal("full control scope blocked data", ctx.Err())
	}
}
