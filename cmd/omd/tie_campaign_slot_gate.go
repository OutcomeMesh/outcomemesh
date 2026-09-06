package main

import (
	"context"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/tieexchange"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const tieCampaignSlotReadyTimeout = 30 * time.Second

type tieCampaignSlotHandler struct{ handle libp2ptransport.Handler }

// One authenticated transport handler spans the campaign. Between slots it
// waits for publication/handler readiness instead of reading a new request with
// the retired slot's binding and spending the coordinator's retry budget.
// Admission still happens exclusively in the selected slot handler, with its
// original signed binding and deadlines. No bytes are read while waiting.
type tieCampaignSlotGate struct {
	mu      sync.Mutex
	ready   chan struct{}
	current *tieCampaignSlotHandler
	closed  bool
}

func newTieCampaignSlotGate() *tieCampaignSlotGate {
	return &tieCampaignSlotGate{ready: make(chan struct{})}
}

func (gate *tieCampaignSlotGate) install(slot *tieCampaignSlotHandler) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.closed || gate.current != nil || slot == nil || slot.handle == nil {
		return tieexchange.ErrProtocol
	}
	gate.current = slot
	close(gate.ready)
	return nil
}

func (gate *tieCampaignSlotGate) retire(slot *tieCampaignSlotHandler) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if slot != nil && gate.current == slot {
		gate.current = nil
		gate.ready = make(chan struct{})
	}
}

func (gate *tieCampaignSlotGate) close() {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.closed {
		return
	}
	gate.closed = true
	if gate.current == nil {
		close(gate.ready)
	}
	gate.current = nil
}

func (gate *tieCampaignSlotGate) wait(ctx context.Context) (*tieCampaignSlotHandler, error) {
	if ctx == nil {
		return nil, tieexchange.ErrProtocol
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		gate.mu.Lock()
		slot, ready, closed := gate.current, gate.ready, gate.closed
		gate.mu.Unlock()
		if closed {
			return nil, tieexchange.ErrProtocol
		}
		if slot != nil {
			return slot, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ready:
		}
	}
}

func (gate *tieCampaignSlotGate) dispatch(ctx context.Context, remote types.Hash, stream libp2pnetwork.Stream) {
	// The transport has already checked the coordinator identity and charged
	// its existing per-peer stream/rate limits. One waiter cannot hold that
	// reservation forever when a checkpoint is missing or the campaign exits.
	waitContext, cancel := context.WithTimeout(ctx, tieCampaignSlotReadyTimeout)
	slot, err := gate.wait(waitContext)
	cancel()
	if err != nil {
		_ = stream.Reset()
		return
	}
	slot.handle(ctx, remote, stream)
}
