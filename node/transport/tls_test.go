package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestMutualTLSAuthenticatesStablePeerIdentities(t *testing.T) {
	t.Parallel()

	serverIdentity := deterministicIdentity(t, "server")
	clientIdentity := deterministicIdentity(t, "client")
	listener, err := Listen("127.0.0.1:0", serverIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			serverDone <- ErrPeerCertificate
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			serverDone <- err
			return
		}
		peerID, err := PeerID(tlsConnection)
		if err != nil || peerID != clientIdentity.ID() {
			serverDone <- ErrUnexpectedPeer
			return
		}
		var input [4]byte
		if _, err := io.ReadFull(tlsConnection, input[:]); err != nil {
			serverDone <- err
			return
		}
		if string(input[:]) != "ping" {
			serverDone <- errors.New("unexpected payload")
			return
		}
		_, err = tlsConnection.Write([]byte("pong"))
		serverDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	expected := serverIdentity.ID()
	connection, peerID, err := Dial(ctx, listener.Addr().String(), clientIdentity, &expected)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if peerID != serverIdentity.ID() {
		t.Fatalf("server peer ID = %s, want %s", peerID, serverIdentity.ID())
	}
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		t.Fatal(err)
	}
	if string(response[:]) != "pong" {
		t.Fatalf("response = %q", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialRejectsUnexpectedPeerIdentity(t *testing.T) {
	t.Parallel()

	serverIdentity := deterministicIdentity(t, "wrong-peer/server")
	clientIdentity := deterministicIdentity(t, "wrong-peer/client")
	listener, err := Listen("127.0.0.1:0", serverIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		if tlsConnection, ok := connection.(*tls.Conn); ok {
			_ = tlsConnection.Handshake()
		}
	}()
	expected := types.DomainHash("test/transport/not-the-server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, _, err := Dial(ctx, listener.Addr().String(), clientIdentity, &expected)
	if connection != nil {
		_ = connection.Close()
	}
	if !errors.Is(err, ErrUnexpectedPeer) {
		t.Fatalf("dial error = %v, want unexpected peer", err)
	}
	<-serverDone
}

func TestIdentityCopiesPrivateKey(t *testing.T) {
	t.Parallel()

	seed := types.DomainHash("test/transport/key-copy")
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	identity, err := NewIdentity(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	want := identity.ID()
	privateKey[0] ^= 0xff
	if identity.ID() != want {
		t.Fatal("caller mutation changed identity")
	}
	returned := identity.PrivateKey()
	returned[0] ^= 0xff
	if identity.ID() != want || len(identity.PrivateKey()) != ed25519.PrivateKeySize {
		t.Fatal("returned key mutation changed identity")
	}
}

func deterministicIdentity(t testing.TB, label string) Identity {
	t.Helper()
	seed := types.DomainHash("test/transport/identity/" + label)
	identity, err := NewIdentity(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
