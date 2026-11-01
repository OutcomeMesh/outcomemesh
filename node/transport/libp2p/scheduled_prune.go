package libp2ptransport

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
)

// SetScheduledPruneHandler explicitly enables only the scheduled-command protocol for
// one independently configured transport peer. Unauthorized peers cannot consume
// its independent rate budget. The concrete handler must enforce the retained
// executor request and both signatures; transport identity alone cannot admit
// an operation.
func (value *Host) SetScheduledPruneHandler(expectedPeer types.Hash, handler Handler) error {
	if value == nil || value.inner == nil || expectedPeer.IsZero() || handler == nil {
		return ErrConfiguration
	}
	value.inner.SetStreamHandler(ScheduledPruneProtocol, func(stream network.Stream) {
		remote, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || remote != expectedPeer || !value.allowScheduledPruneStream(remote, time.Now()) {
			_ = stream.Reset()
			return
		}
		handler(value.context, remote, stream)
	})
	return nil
}

func (value *Host) allowScheduledPruneStream(peer types.Hash, now time.Time) bool {
	value.scheduledPruneMu.Lock()
	defer value.scheduledPruneMu.Unlock()
	if value.scheduledPruneWindowStart.IsZero() || now.Sub(value.scheduledPruneWindowStart) >= time.Minute || now.Before(value.scheduledPruneWindowStart) {
		value.scheduledPruneWindowStart = now
		value.scheduledPruneGlobalCount = 0
		clear(value.scheduledPrunePeerCounts)
	}
	if value.scheduledPruneGlobalCount >= value.maxGlobalScheduledPruneStreamsPerMinute || value.scheduledPrunePeerCounts[peer] >= value.maxScheduledPruneStreamsPerMinute {
		return false
	}
	value.scheduledPruneGlobalCount++
	value.scheduledPrunePeerCounts[peer]++
	return true
}

func (value *Host) OpenScheduledPruneStream(ctx context.Context, address string, expectedPeer types.Hash) (network.Stream, types.Hash, error) {
	if expectedPeer.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return value.openStream(ctx, address, &expectedPeer, ScheduledPruneProtocol)
}

// DeliverScheduledPrune exchanges only the supplied already co-signed scheduled Prune intent
// with the pinned endpoint. It neither retains client intent nor retries; callers
// must retain that exact intent independently and never infer non-commit from an
// error. A reply is not a current-authority grant or proof of a client's durable
// receipt. No default daemon handler or live archive policy is installed here.
func (value *Host) DeliverScheduledPrune(ctx context.Context, address string, expectedPeer types.Hash, intent scheduledwire.Intent, timeout time.Duration) (scheduledwire.Acknowledgement, error) {
	if ctx == nil || timeout < scheduledwire.MinimumTimeout || timeout > scheduledwire.MaximumTimeout || value == nil || intent.ClientPeerID != value.ID() || intent.ServerPeerID != expectedPeer {
		return scheduledwire.Acknowledgement{}, scheduledwire.ErrProtocol
	}
	if _, err := intent.CanonicalBytes(); err != nil {
		return scheduledwire.Acknowledgement{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, _, err := value.OpenScheduledPruneStream(bounded, address, expectedPeer)
	if err != nil {
		return scheduledwire.Acknowledgement{}, err
	}
	return scheduledwire.Exchange(bounded, stream, intent, timeout)
}
