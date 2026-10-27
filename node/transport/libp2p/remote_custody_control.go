package libp2ptransport

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
)

// SetRemoteCustodyControlHandler explicitly enables a metadata-only control
// protocol for one independently pinned A control transport identity. This
// identity is separate from the custody data auditor. The concrete owned
// endpoint must validate Plan/Begin, retain its worker and actually drain before
// signing a response; authenticating a peer does not authorize execution.
// Rejected peers do not consume the independent control rate budget.
func (value *Host) SetRemoteCustodyControlHandler(expectedPeer types.Hash, handler Handler) error {
	if value == nil || value.inner == nil || expectedPeer.IsZero() || handler == nil {
		return ErrConfiguration
	}
	value.inner.SetStreamHandler(RemoteCustodyControlProtocol, func(stream network.Stream) {
		remote, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || remote != expectedPeer || !value.allowRemoteCustodyControlStream(remote, time.Now()) {
			_ = stream.Reset()
			return
		}
		handler(value.context, remote, stream)
	})
	return nil
}

func (value *Host) allowRemoteCustodyControlStream(peer types.Hash, now time.Time) bool {
	value.remoteCustodyControlMu.Lock()
	defer value.remoteCustodyControlMu.Unlock()
	if value.remoteCustodyControlWindowStart.IsZero() || now.Sub(value.remoteCustodyControlWindowStart) >= time.Minute || now.Before(value.remoteCustodyControlWindowStart) {
		value.remoteCustodyControlWindowStart = now
		value.remoteCustodyControlGlobalCount = 0
		clear(value.remoteCustodyControlPeerCounts)
	}
	if value.remoteCustodyControlGlobalCount >= value.maxGlobalRemoteCustodyControlStreamsPerMinute || value.remoteCustodyControlPeerCounts[peer] >= value.maxRemoteCustodyControlStreamsPerMinute {
		return false
	}
	value.remoteCustodyControlGlobalCount++
	value.remoteCustodyControlPeerCounts[peer]++
	return true
}

// OpenRemoteCustodyControlStream opens only this protocol with an independent
// exact B transport pin. It does not exchange a request or grant permission.
func (value *Host) OpenRemoteCustodyControlStream(ctx context.Context, address string, expectedPeer types.Hash) (network.Stream, types.Hash, error) {
	if expectedPeer.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return value.openStream(ctx, address, &expectedPeer, RemoteCustodyControlProtocol)
}
