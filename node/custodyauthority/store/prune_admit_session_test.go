package store

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func installAdmissionServer(t testing.TB, f *pruneFixture, server, client *libp2ptransport.Host, wrap func(network.Stream) admissionwire.Stream) <-chan completionServeResult {
	t.Helper()
	session, err := NewPruneAdmissionServer(f.executor, f.coordinator, client.ID(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan completionServeResult, 16)
	if err := server.SetPruneAdmissionHandler(client.ID(), func(ctx context.Context, peer types.Hash, stream network.Stream) {
		var rw admissionwire.Stream = stream
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

func TestPruneAdmissionQUICLifecycleAndHistoricalRetry(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	server, client := completionHosts(t)
	results := installAdmissionServer(t, f, server, client, nil)
	ack, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), f.admission, 2*time.Second)
	id, _ := f.admission.ID()
	if err != nil || ack.EntryID != id {
		t.Fatal(err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || !r.commit.Appended {
		t.Fatal(r.err)
	}
	assertPruneAdmissionConfirmed(t, f)
	// The wire does not execute. A separate local call must take the live guard.
	if r, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil }); err != nil || !r.Applied {
		t.Fatal(err)
	}
	entry := pruneCompletionEntry(t, f)
	completed := installCompletionServer(t, f, server, client, nil)
	if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if r := awaitCompletionServe(t, completed); r.err != nil {
		t.Fatal(r.err)
	}
	stop := f.stop(t)
	appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
	f.reopen(t)
	terminal := pruneSnapshot(t, f.executor)
	results = installAdmissionServer(t, f, server, client, nil)
	retry, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), f.admission, 2*time.Second)
	if err != nil || retry.EntryID != id || retry.Nonce == ack.Nonce {
		t.Fatal(err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended || r.commit.Snapshot.Phase != custodyauthority.Retired {
		t.Fatal(r.err)
	}
	if !reflect.DeepEqual(terminal, pruneSnapshot(t, f.executor)) {
		t.Fatal("historical retry changed effect")
	}
}

func TestPruneAdmissionQUICLostReplyAndBindingFailure(t *testing.T) {
	for _, mode := range []string{"lost", "partial", "binding-fault"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			f.admission = pruneAdmissionEntry(t, f)
			server, client := completionHosts(t)
			var wrap func(network.Stream) admissionwire.Stream
			if mode == "binding-fault" {
				f.executor.pins.hooks.at = func(stage string) error {
					if stage == "pins-admission-confirm-before-publish" {
						return errors.New("cannot confirm binding")
					}
					return nil
				}
			} else {
				wrap = func(s network.Stream) admissionwire.Stream { return lostCompletionReply{s, mode == "partial"} }
			}
			results := installAdmissionServer(t, f, server, client, wrap)
			ack, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), f.admission, 2*time.Second)
			if !errors.Is(err, admissionwire.ErrUnconfirmed) || ack != (admissionwire.Acknowledgement{}) {
				t.Fatal("incomplete exchange claimed outcome", err)
			}
			if r := awaitCompletionServe(t, results); r.err == nil {
				t.Fatal("lost reply or binding failure hidden")
			}
			f.reopen(t)
			if mode == "binding-fault" {
				assertPinnedRecoveryStage(t, pruneSnapshot(t, f.executor), "pins-admission-confirm-before-publish")
			}
			results = installAdmissionServer(t, f, server, client, nil)
			if _, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), f.admission, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
				t.Fatal("retry repeated authority decision", r.err)
			}
			assertPruneAdmissionConfirmed(t, f)
		})
	}
}

func TestPruneAdmissionQUICRequiresExactRequestAndEOF(t *testing.T) {
	for _, mode := range []string{"no-eof", "extra-byte", "second-request", "wrong-request", "wrong-consumer", "wrong-head"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			entry := pruneAdmissionEntry(t, f)
			c := entry.Command
			actor := byte(4)
			switch mode {
			case "wrong-request":
				c.OperationID = testHash(99)
			case "wrong-consumer":
				actor = 5
				c.ActorPublicKey = [32]byte{}
			case "wrong-head":
				c.ExpectedHead = testHash(98)
			}
			c, err := c.Sign(testKey(actor))
			if err != nil {
				t.Fatal(err)
			}
			entry, err = custodyauthority.SignEntry(c, testKey(1))
			if err != nil {
				t.Fatal(err)
			}
			before, prepared := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
			server, client := completionHosts(t)
			results := installAdmissionServer(t, f, server, client, nil)
			s, _, err := client.OpenPruneAdmissionStream(t.Context(), server.Addresses()[0], server.ID())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			_ = s.SetDeadline(time.Now().Add(3 * time.Second))
			r := admissionwire.Request{Nonce: testHash(93), Entry: entry}
			if err := admissionwire.WriteRequest(s, r); err != nil {
				t.Fatal(err)
			}
			if mode == "extra-byte" {
				_, _ = s.Write([]byte{1})
			}
			if mode == "second-request" {
				_ = admissionwire.WriteRequest(s, r)
			}
			if mode != "no-eof" {
				_ = s.CloseWrite()
			}
			if _, err := admissionwire.ReadAcknowledgement(s); err == nil {
				t.Fatal("invalid request acknowledged")
			}
			if r := awaitCompletionServe(t, results); r.err == nil {
				t.Fatal("invalid request reached success")
			}
			if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(prepared, pruneSnapshot(t, f.executor)) {
				t.Fatal("invalid request mutated owner")
			}
		})
	}
}

func TestPruneAdmissionQUICClientCancellationDuringBinding(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admission = pruneAdmissionEntry(t, f)
	server, client := completionHosts(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	f.executor.pins.hooks.at = func(stage string) error {
		if stage == "pins-admission-confirm-before-publish" {
			close(entered)
			<-release
		}
		return nil
	}
	results := installAdmissionServer(t, f, server, client, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.AdmitPrune(ctx, server.Addresses()[0], server.ID(), f.admission, 2*time.Second)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("binding not reached")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, admissionwire.ErrUnconfirmed) || !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled client stuck")
	}
	unblock()
	awaitCompletionServe(t, results)
	assertPruneAdmissionConfirmed(t, f)
}

func TestPruneAdmissionQUICHistoricalAckCannotExecuteClosedTicket(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	f.admit(t, true)
	ticket, _ := f.admission.ID()
	// The low-level trusted local primitive can close a ticket independently.
	// Even then an admission ACK must not bypass Execute's current-state check.
	appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Complete, types.Hash{}, ticket, testHash(99)))
	server, client := completionHosts(t)
	results := installAdmissionServer(t, f, server, client, nil)
	if _, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), f.admission, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
		t.Fatal(r.err)
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("historical reply authorized effect"); return 200, nil }); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal(err)
	}
	if pruneSnapshot(t, f.executor).Stage != PruneAdmitted {
		t.Fatal("closed ticket started")
	}
}

func TestPruneAdmissionServerRequiresPinnedOwners(t *testing.T) {
	f := newPruneFixture(t)
	if _, err := NewPruneAdmissionServer(f.executor, f.coordinator, testHash(91), time.Second); !errors.Is(err, ErrPrunePin) {
		t.Fatal(err)
	}
	for _, timeout := range []time.Duration{0, admissionwire.MaximumTimeout + 1} {
		if _, err := NewPruneAdmissionServer(f.executor, f.coordinator, testHash(91), timeout); !errors.Is(err, admissionwire.ErrProtocol) {
			t.Fatal(err)
		}
	}
}
