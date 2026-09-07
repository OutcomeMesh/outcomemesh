package libp2ptransport

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
)

// SetPruneCompletionHandler explicitly enables only the completion protocol for
// one independently configured transport peer. Unauthorized peers cannot consume
// its independent rate budget. The concrete handler must enforce terminal local
// evidence and signatures; a transport identity alone cannot complete a ticket.
func (value *Host) SetPruneCompletionHandler(expectedPeer types.Hash, handler Handler) error {
	if value == nil || value.inner == nil || expectedPeer.IsZero() || handler == nil {
		return ErrConfiguration
	}
	value.inner.SetStreamHandler(PruneCompletionProtocol, func(stream network.Stream) {
		remote, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || remote != expectedPeer || !value.allowPruneCompletionStream(remote, time.Now()) {
			_ = stream.Reset()
			return
		}
		handler(value.context, remote, stream)
	})
	return nil
}

func (value *Host) allowPruneCompletionStream(peer types.Hash, now time.Time) bool {
	value.pruneCompletionMu.Lock()
	defer value.pruneCompletionMu.Unlock()
	if value.pruneCompletionWindowStart.IsZero() || now.Sub(value.pruneCompletionWindowStart) >= time.Minute || now.Before(value.pruneCompletionWindowStart) {
		value.pruneCompletionWindowStart = now
		value.pruneCompletionGlobalCount = 0
		clear(value.pruneCompletionPeerCounts)
	}
	if value.pruneCompletionGlobalCount >= value.maxGlobalPruneCompletionStreamsPerMinute || value.pruneCompletionPeerCounts[peer] >= value.maxPruneCompletionStreamsPerMinute {
		return false
	}
	value.pruneCompletionGlobalCount++
	value.pruneCompletionPeerCounts[peer]++
	return true
}

func (value *Host) OpenPruneCompletionStream(ctx context.Context, address string, expectedPeer types.Hash) (network.Stream, types.Hash, error) {
	if expectedPeer.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return value.openStream(ctx, address, &expectedPeer, PruneCompletionProtocol)
}

// CompletePrune exchanges only the supplied already co-signed Complete entry
// with the pinned endpoint. It neither retains client intent nor retries; callers
// must retain that exact entry independently and never infer non-commit from an
// error. A reply is not a current-authority grant or proof of a client's durable
// receipt. No default daemon handler or live archive policy is installed here.
func (value *Host) CompletePrune(ctx context.Context, address string, expectedPeer types.Hash, entry custodyauthority.Entry, timeout time.Duration) (completionwire.Acknowledgement, error) {
	if ctx == nil || timeout < completionwire.MinimumTimeout || timeout > completionwire.MaximumTimeout || entry.Command.Kind != custodyauthority.Complete {
		return completionwire.Acknowledgement{}, completionwire.ErrProtocol
	}
	if _, err := entry.CanonicalBytes(); err != nil {
		return completionwire.Acknowledgement{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, _, err := value.OpenPruneCompletionStream(bounded, address, expectedPeer)
	if err != nil {
		return completionwire.Acknowledgement{}, err
	}
	return completionwire.Exchange(bounded, stream, entry, timeout)
}
