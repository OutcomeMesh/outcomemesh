package main

import (
	"context"
	"errors"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/tieexchange"
)

func TestTieCampaignSlotGateWaitsAcrossPublicationHandoff(t *testing.T) {
	gate := newTieCampaignSlotGate()
	defer gate.close()
	first := &tieCampaignSlotHandler{handle: func(context.Context, types.Hash, libp2pnetwork.Stream) {}}
	second := &tieCampaignSlotHandler{handle: func(context.Context, types.Hash, libp2pnetwork.Stream) {}}
	if err := gate.install(first); err != nil {
		t.Fatal(err)
	}
	if slot, err := gate.wait(context.Background()); err != nil || slot != first {
		t.Fatalf("first slot: %v", err)
	}
	gate.retire(first)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		slot *tieCampaignSlotHandler
		err  error
	}
	resultChannel := make(chan result, 1)
	go func() { slot, err := gate.wait(ctx); resultChannel <- result{slot, err} }()
	select {
	case result := <-resultChannel:
		t.Fatalf("returned retired handler before next publication: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	if err := gate.install(second); err != nil {
		t.Fatal(err)
	}
	gate.retire(first) // A deferred old-slot cleanup must not retire its successor.
	select {
	case result := <-resultChannel:
		if result.err != nil || result.slot != second {
			t.Fatalf("wrong handoff: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("new handler did not wake the waiter")
	}
	if err := gate.install(first); !errors.Is(err, tieexchange.ErrProtocol) {
		t.Fatal("active handler replaced without retirement")
	}
	if slot, err := gate.wait(ctx); err != nil || slot != second {
		t.Fatal("old cleanup changed active handler")
	}
}

func TestTieCampaignSlotGateStopsWaitingOnCancellationAndClose(t *testing.T) {
	for _, mode := range []string{"cancellation", "deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			gate := newTieCampaignSlotGate()
			defer gate.close()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			switch mode {
			case "cancellation":
				cancel()
			case "close":
				gate.close()
			}
			if slot, err := gate.wait(ctx); err == nil || slot != nil {
				t.Fatal("inactive gate supplied a handler")
			}
			if mode == "close" {
				slot := &tieCampaignSlotHandler{handle: func(context.Context, types.Hash, libp2pnetwork.Stream) {}}
				if err := gate.install(slot); err == nil {
					t.Fatal("closed gate reopened")
				}
			}
		})
	}
}

type tieGateResetStream struct {
	libp2pnetwork.Stream
	reset bool
}

func (stream *tieGateResetStream) Reset() error { stream.reset = true; return nil }

func TestTieCampaignSlotGateDispatchReleasesCancelledWaiter(t *testing.T) {
	gate := newTieCampaignSlotGate()
	defer gate.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	stream := &tieGateResetStream{}
	gate.dispatch(ctx, types.Hash{1}, stream)
	if !stream.reset {
		t.Fatal("cancelled waiter kept the stream reservation")
	}
}
