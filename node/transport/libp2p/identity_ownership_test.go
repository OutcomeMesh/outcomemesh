package libp2ptransport_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestTransportOwnsIdentityAfterCallerErasesKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{"/ip4/127.0.0.1/udp/0/quic-v1"}
	sk, ck := testKey("owned-server"), testKey("owned-client")
	sid, cid := types.DomainHash("OMESH/p2p/ed25519/v0", sk[32:]), types.DomainHash("OMESH/p2p/ed25519/v0", ck[32:])
	server, err := libp2ptransport.New(ctx, sk, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2ptransport.New(ctx, ck, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clear(sk)
	clear(ck)
	done := make(chan error, 1)
	if err = server.SetPruneServiceHandler([]types.Hash{cid}, func(_ context.Context, peer types.Hash, s network.Stream) {
		defer s.Close()
		if peer != cid {
			done <- libp2ptransport.ErrUnexpectedPeer
			return
		}
		s.SetDeadline(time.Now().Add(time.Second))
		var b [1]byte
		_, e := io.ReadFull(s, b[:])
		if e == nil {
			_, e = s.Write(b[:])
		}
		if e == nil {
			e = s.CloseWrite()
		}
		done <- e
	}); err != nil {
		t.Fatal(err)
	}
	stream, peer, err := client.OpenPruneServiceStream(ctx, server.Addresses()[0], sid)
	if err != nil {
		t.Fatal("cleared caller keys changed live identity", err)
	}
	defer stream.Close()
	if peer != sid || client.ID() != cid {
		t.Fatal("transport identity changed")
	}
	if err = stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	stream.CloseWrite()
	var b [1]byte
	if _, err = io.ReadFull(stream, b[:]); err != nil || b[0] != 42 {
		t.Fatal("authenticated exchange", err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
