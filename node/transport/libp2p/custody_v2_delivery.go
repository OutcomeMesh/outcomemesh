package libp2ptransport

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const AdmissionDeliveryProtocol protocol.ID = "/outcomemesh/custody/v2/admission-delivery"
const EnrolledAdmissionDeliveryProtocol protocol.ID = "/outcomemesh/custody/v4/enrollment-delivery"

// SetAdmissionDeliveryHandler enables only the enrolled sender on a separate
// protocol. Authentication and its small independent request budget precede the
// handler's bounded proof allocation. Transport admission is not job admission.
func (h *Host) SetAdmissionDeliveryHandler(sender types.Hash, handler Handler) error {
	return h.setAdmissionDeliveryHandler(AdmissionDeliveryProtocol, sender, handler)
}
func (h *Host) SetEnrolledAdmissionDeliveryHandler(sender types.Hash, handler Handler) error {
	return h.setAdmissionDeliveryHandler(EnrolledAdmissionDeliveryProtocol, sender, handler)
}
func (h *Host) setAdmissionDeliveryHandler(protocolID protocol.ID, sender types.Hash, handler Handler) error {
	if h == nil || h.inner == nil || sender.IsZero() || handler == nil {
		return ErrConfiguration
	}
	var mu sync.Mutex
	var window time.Time
	count := 0
	active := make(chan struct{}, 2)
	h.inner.SetStreamHandler(protocolID, func(stream network.Stream) {
		peer, e := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if e != nil || peer != sender {
			_ = stream.Reset()
			return
		}
		now := time.Now()
		mu.Lock()
		if window.IsZero() || now.Before(window) || now.Sub(window) >= time.Minute {
			window, count = now, 0
		}
		allowed := count < 32
		if allowed {
			count++
		}
		mu.Unlock()
		if !allowed {
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

func (h *Host) OpenAdmissionDeliveryStream(ctx context.Context, address string, expected types.Hash) (network.Stream, types.Hash, error) {
	if expected.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return h.openStream(ctx, address, &expected, AdmissionDeliveryProtocol)
}

func (h *Host) OpenEnrolledAdmissionDeliveryStream(ctx context.Context, address string, expected types.Hash) (network.Stream, types.Hash, error) {
	if expected.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return h.openStream(ctx, address, &expected, EnrolledAdmissionDeliveryProtocol)
}
