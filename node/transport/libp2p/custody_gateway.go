package libp2ptransport

import (
	"context"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/outcomemesh/outcomemesh/core/types"
)

// CustodyGatewayProtocol carries signed gateway envelopes, never legacy V2
// execution requests. Enabling it does not enable another custody protocol.
const CustodyGatewayProtocol protocol.ID = "/outcomemesh/custody-gateway/5"

func (h *Host) SetCustodyGatewayHandler(clients []types.Hash, handler Handler) error {
	return h.setCustodyHandler(CustodyGatewayProtocol, clients, handler)
}

func (h *Host) OpenCustodyGatewayStream(ctx context.Context, address string, expected types.Hash) (network.Stream, types.Hash, error) {
	if expected.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return h.openStream(ctx, address, &expected, CustodyGatewayProtocol)
}
