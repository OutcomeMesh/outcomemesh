package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestManagedCustodyAuditPinnedQUIC(t *testing.T) {
	f := newManagedAuditFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	client, err := libp2ptransport.New(ctx, testKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := libp2ptransport.New(ctx, testKey(47), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.ID() != f.intent.ReplicaPeerID {
		t.Fatal("replica host does not match the retained intent")
	}
	// A raw remote replica exercises Audit-side enforcement only. The local
	// joint test below checks both tickets under their one original owner.
	replica := f.rawReplica(t)
	served := make(chan error, 1)
	if err := server.SetArchiveCustodyHandler([]types.Hash{client.ID()}, func(ctx context.Context, peer types.Hash, stream network.Stream) {
		_, err := replica.Serve(ctx, stream)
		served <- err
	}); err != nil {
		t.Fatal(err)
	}
	before := testCoordination(t, f.serve.archive.f.coordinator)
	session := f.open(t)
	stream, authenticatedReplica, err := client.OpenArchiveCustodyStream(ctx, server.Addresses()[0], server.ID())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := session.Audit(ctx, authenticatedReplica, stream)
	if err != nil || accepted.JournalSequence != 1 {
		t.Fatal("managed audit over pinned QUIC", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("raw replica did not drain")
	}
	recovered, err := session.Recover(ctx)
	if err != nil || !recovered.Recovered || !reflect.DeepEqual(accepted.Record, recovered.Record) {
		t.Fatal("offline recovery changed the accepted network record", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, f.serve.archive.f.coordinator)) {
		t.Fatal("network audit implicitly completed authority")
	}
}

func TestManagedCustodyPairPinnedQUIC(t *testing.T) {
	f := newManagedAuditFixture(t)
	audit, serve := f.open(t), f.serve.open(t)
	paired, err := NewManagedCustodyAuditServePair(audit, serve)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	client, err := libp2ptransport.New(ctx, testKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := libp2ptransport.New(ctx, testKey(47), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	type acceptedStream struct {
		peer   types.Hash
		stream network.Stream
	}
	inbound := make(chan acceptedStream, 1)
	release, drained := make(chan struct{}), make(chan struct{})
	if err := server.SetArchiveCustodyHandler([]types.Hash{client.ID()}, func(ctx context.Context, peer types.Hash, stream network.Stream) {
		defer close(drained)
		select {
		case inbound <- acceptedStream{peer: peer, stream: stream}:
		case <-ctx.Done():
			_ = stream.Close()
			return
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
	}); err != nil {
		t.Fatal(err)
	}
	left, replicaID, err := client.OpenArchiveCustodyStream(ctx, server.Addresses()[0], server.ID())
	if err != nil {
		t.Fatal(err)
	}
	// libp2p negotiates lazily. Flush only its transport protocol header so
	// both authenticated ends exist before the joint guard permits app I/O.
	if _, err := left.Write(nil); err != nil {
		t.Fatal("custody protocol negotiation", err)
	}
	var right acceptedStream
	select {
	case right = <-inbound:
	case <-ctx.Done():
		t.Fatal("authenticated replica stream not received")
	}
	before := testCoordination(t, f.serve.archive.f.coordinator)
	result, exchangeErr := paired.Exchange(ctx, replicaID, right.peer, left, right.stream)
	close(release)
	<-drained
	if exchangeErr != nil || result.Audit.JournalSequence != 1 || result.Serve.JournalSequence != 1 ||
		result.Audit.Report.RenewedReceiptID != result.Serve.RenewedReceiptID {
		t.Fatal("same-owner paired QUIC exchange", exchangeErr)
	}
	if !reflect.DeepEqual(before, testCoordination(t, f.serve.archive.f.coordinator)) {
		t.Fatal("paired QUIC exchange implicitly completed authority")
	}
}
