package libp2ptransport

import (
	"context"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/outcomemesh/outcomemesh/core/types"
)

// PruneServiceProtocol carries only the isolated owner's signed public exchange.
// Registration is explicit and does not enable other custody endpoints.
const PruneServiceProtocol protocol.ID = "/outcomemesh/prune-service/0"

func (h *Host) SetPruneServiceHandler(peers []types.Hash, handler Handler) error {
	return h.setCustodyHandler(PruneServiceProtocol, peers, handler)
}
func (h *Host) OpenPruneServiceStream(ctx context.Context, address string, expected types.Hash) (network.Stream, types.Hash, error) {
	if expected.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return h.openStream(ctx, address, &expected, PruneServiceProtocol)
}
