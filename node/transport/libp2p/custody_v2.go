package libp2ptransport

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const CustodyV2Protocol protocol.ID = "/outcomemesh/custody/v2"

// SetCustodyV2Handler explicitly enables a separate authenticated protocol.
// Rejected peers do not consume its bounded concurrency/rate budget. The handler
// must still check the exact scope and signed request; transport is not a vote.
func (h *Host) SetCustodyV2Handler(clients []types.Hash, handler Handler) error {
	if h == nil || h.inner == nil || handler == nil || len(clients) == 0 || len(clients) > 16 {
		return ErrConfiguration
	}
	allowed := map[types.Hash]bool{}
	for _, id := range clients {
		if id.IsZero() || allowed[id] {
			return ErrConfiguration
		}
		allowed[id] = true
	}
	var mu sync.Mutex
	var window time.Time
	count := 0
	active := make(chan struct{}, 8)
	h.inner.SetStreamHandler(CustodyV2Protocol, func(stream network.Stream) {
		peer, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || !allowed[peer] {
			_ = stream.Reset()
			return
		}
		now := time.Now()
		mu.Lock()
		if window.IsZero() || now.Before(window) || now.Sub(window) >= time.Minute {
			window = now
			count = 0
		}
		accept := count < 256
		if accept {
			count++
		}
		mu.Unlock()
		if !accept {
			_ = stream.Reset()
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			_ = stream.Reset()
			return
		}
		handler(h.context, peer, stream)
	})
	return nil
}
func (h *Host) OpenCustodyV2Stream(ctx context.Context, address string, expected types.Hash) (network.Stream, types.Hash, error) {
	if expected.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return h.openStream(ctx, address, &expected, CustodyV2Protocol)
}
