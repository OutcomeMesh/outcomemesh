package store

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type completionServeResult struct {
	commit Commit
	err    error
}

func completionHosts(t testing.TB) (*libp2ptransport.Host, *libp2ptransport.Host) {
	t.Helper()
	config := libp2ptransport.DefaultConfig()
	config.MaxPruneCompletionStreamsPerMinute = 60
	config.MaxPruneCompletionStreamsGlobalPerMinute = 60
	server, err := libp2ptransport.New(t.Context(), testKey(45), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := libp2ptransport.New(t.Context(), testKey(46), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func installCompletionServer(t testing.TB, f *pruneFixture, server, client *libp2ptransport.Host, wrap func(network.Stream) completionwire.Stream) <-chan completionServeResult {
	t.Helper()
	session, err := NewPruneCompletionServer(f.executor, f.coordinator, client.ID(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan completionServeResult, 16)
	if err := server.SetPruneCompletionHandler(client.ID(), func(ctx context.Context, peer types.Hash, stream network.Stream) {
		var rw completionwire.Stream = stream
		if wrap != nil {
			rw = wrap(stream)
		}
		c, err := session.Serve(ctx, peer, rw)
		results <- completionServeResult{c, err}
	}); err != nil {
		t.Fatal(err)
	}
	return results
}

func awaitCompletionServe(t testing.TB, results <-chan completionServeResult) completionServeResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("completion handler did not drain")
		return completionServeResult{}
	}
}

func TestPruneCompletionQUICConfirmsExactEntryAndRetriesAfterRestart(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			finishPruneForCompletion(t, f, outcome)
			entry := pruneCompletionEntry(t, f)
			id, _ := entry.ID()
			terminal := pruneSnapshot(t, f.executor)
			server, client := completionHosts(t)
			results := installCompletionServer(t, f, server, client, nil)
			ack, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second)
			if err != nil || ack.EntryID != id {
				t.Fatal(err)
			}
			if result := awaitCompletionServe(t, results); result.err != nil || !result.commit.Appended {
				t.Fatal(result.err)
			}
			stop := f.stop(t)
			appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
			f.reopen(t)
			results = installCompletionServer(t, f, server, client, nil)
			retry, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second)
			if err != nil || retry.EntryID != id || retry.Nonce == ack.Nonce {
				t.Fatal("retry changed entry or reused exchange nonce", err)
			}
			if result := awaitCompletionServe(t, results); result.err != nil || result.commit.Appended || result.commit.Snapshot.Phase != custodyauthority.Retired {
				t.Fatal(result.err)
			}
			if !reflect.DeepEqual(terminal, pruneSnapshot(t, f.executor)) {
				t.Fatal("network completion changed executor")
			}
		})
	}
}

type lostCompletionReply struct {
	network.Stream
	partial bool
}

func (s lostCompletionReply) Write(b []byte) (int, error) {
	if s.partial {
		n, err := s.Stream.Write(b[:len(b)/2])
		if err != nil {
			return n, err
		}
		return n, io.ErrClosedPipe
	}
	return 0, io.ErrClosedPipe
}

func TestPruneCompletionQUICLostReplyLeavesExactDurableDecision(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost", true: "partial"}[partial], func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			finishPruneForCompletion(t, f, "cancelled")
			entry := pruneCompletionEntry(t, f)
			server, client := completionHosts(t)
			results := installCompletionServer(t, f, server, client, func(s network.Stream) completionwire.Stream { return lostCompletionReply{s, partial} })
			ack, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second)
			if !errors.Is(err, completionwire.ErrUnconfirmed) || ack != (completionwire.Acknowledgement{}) {
				t.Fatal("lost reply asserted noncommit or success", err)
			}
			if result := awaitCompletionServe(t, results); result.err == nil {
				t.Fatal("reply failure hidden")
			}
			if c := testCoordination(t, f.coordinator); c.Pending != nil || c.Authority.Pending != 0 {
				t.Fatal("reply loss discarded completion")
			}
			f.reopen(t)
			results = installCompletionServer(t, f, server, client, nil)
			if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			if result := awaitCompletionServe(t, results); result.err != nil || result.commit.Appended {
				t.Fatal("retry duplicated completion", result.err)
			}
		})
	}
}

func TestPruneCompletionQUICRequiresRequestEOFBeforeAuthorityWrite(t *testing.T) {
	for _, mode := range []string{"no-eof", "extra-byte", "second-request", "wrong-outcome", "wrong-consumer", "unfinished"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			finishPruneForCompletion(t, f, "cancelled")
			entry := pruneCompletionEntry(t, f)
			if mode == "wrong-outcome" {
				entry = testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Complete, types.Hash{}, entry.Command.TicketID, testHash(94))
			}
			if mode == "wrong-consumer" {
				c := entry.Command
				c.ActorPublicKey = [32]byte{}
				c.Signature = [64]byte{}
				c, _ = c.Sign(testKey(5))
				entry, _ = custodyauthority.SignEntry(c, testKey(1))
			}
			if mode == "unfinished" {
				f = newPruneFixtureWithStorageID(t, testHash(91))
				f.admit(t, true)
				ticket, _ := f.admission.ID()
				entry = testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Complete, types.Hash{}, ticket, testHash(95))
			}
			before := testCoordination(t, f.coordinator)
			server, client := completionHosts(t)
			results := installCompletionServer(t, f, server, client, nil)
			stream, _, err := client.OpenPruneCompletionStream(t.Context(), server.Addresses()[0], server.ID())
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			r := completionwire.Request{Nonce: testHash(93), Entry: entry}
			if err := completionwire.WriteRequest(stream, r); err != nil {
				t.Fatal(err)
			}
			if mode == "extra-byte" {
				_, _ = stream.Write([]byte{1})
			}
			if mode == "second-request" {
				_ = completionwire.WriteRequest(stream, r)
			}
			if mode != "no-eof" {
				_ = stream.CloseWrite()
			}
			if _, err := completionwire.ReadAcknowledgement(stream); err == nil {
				t.Fatal("invalid request got acknowledgement")
			}
			if result := awaitCompletionServe(t, results); result.err == nil {
				t.Fatal("invalid request reached success")
			}
			if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) {
				t.Fatal("invalid/unclosed request wrote authority")
			}
		})
	}
}

func TestPruneCompletionQUICCancellationCannotAbandonConfirmedDecision(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "succeeded")
	entry := pruneCompletionEntry(t, f)
	server, client := completionHosts(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	setCoordinatorHooks(f.coordinator, storeHooks{at: func(stage string) error {
		if stage == "confirm-before-publish" {
			close(entered)
			<-release
		}
		return nil
	}})
	results := installCompletionServer(t, f, server, client, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.CompletePrune(ctx, server.Addresses()[0], server.ID(), entry, 2*time.Second)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("completion did not reach confirmation")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, completionwire.ErrUnconfirmed) || !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled client remained blocked")
	}
	unblock()
	_ = awaitCompletionServe(t, results)
	if c := testCoordination(t, f.coordinator); c.Pending != nil || c.Authority.Pending != 0 {
		t.Fatal("client disappearance discarded server decision")
	}
	setCoordinatorHooks(f.coordinator, storeHooks{})
	if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
		t.Fatal("retry after cancelled caller changed decision", r.err)
	}
}
