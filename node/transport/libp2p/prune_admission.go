package libp2ptransport

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
)

// SetPruneAdmissionHandler explicitly enables only the admission protocol for
// one independently configured transport peer. Unauthorized peers cannot consume
// its independent rate budget. The concrete handler must enforce the retained
// executor request and both signatures; transport identity alone cannot admit
// an operation.
func (value *Host) SetPruneAdmissionHandler(expectedPeer types.Hash, handler Handler) error {
	if value == nil || value.inner == nil || expectedPeer.IsZero() || handler == nil {
		return ErrConfiguration
	}
	value.inner.SetStreamHandler(PruneAdmissionProtocol, func(stream network.Stream) {
		remote, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || remote != expectedPeer || !value.allowPruneAdmissionStream(remote, time.Now()) {
			_ = stream.Reset()
			return
		}
		handler(value.context, remote, stream)
	})
	return nil
}

func (value *Host) allowPruneAdmissionStream(peer types.Hash, now time.Time) bool {
	value.pruneAdmissionMu.Lock()
	defer value.pruneAdmissionMu.Unlock()
	if value.pruneAdmissionWindowStart.IsZero() || now.Sub(value.pruneAdmissionWindowStart) >= time.Minute || now.Before(value.pruneAdmissionWindowStart) {
		value.pruneAdmissionWindowStart = now
		value.pruneAdmissionGlobalCount = 0
		clear(value.pruneAdmissionPeerCounts)
	}
	if value.pruneAdmissionGlobalCount >= value.maxGlobalPruneAdmissionStreamsPerMinute || value.pruneAdmissionPeerCounts[peer] >= value.maxPruneAdmissionStreamsPerMinute {
		return false
	}
	value.pruneAdmissionGlobalCount++
	value.pruneAdmissionPeerCounts[peer]++
	return true
}

func (value *Host) OpenPruneAdmissionStream(ctx context.Context, address string, expectedPeer types.Hash) (network.Stream, types.Hash, error) {
	if expectedPeer.IsZero() {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	return value.openStream(ctx, address, &expectedPeer, PruneAdmissionProtocol)
}

// AdmitPrune exchanges only the supplied already co-signed prune Admit entry
// with the pinned endpoint. It neither retains client intent nor retries; callers
// must retain that exact entry independently and never infer non-commit from an
// error. A reply is not a current-authority grant or proof of a client's durable
// receipt. No default daemon handler or live archive policy is installed here.
func (value *Host) AdmitPrune(ctx context.Context, address string, expectedPeer types.Hash, entry custodyauthority.Entry, timeout time.Duration) (admissionwire.Acknowledgement, error) {
	if ctx == nil || timeout < admissionwire.MinimumTimeout || timeout > admissionwire.MaximumTimeout || (entry.Command.Kind != custodyauthority.Admit || entry.Command.Purpose != custodyauthority.Prune) {
		return admissionwire.Acknowledgement{}, admissionwire.ErrProtocol
	}
	if _, err := entry.CanonicalBytes(); err != nil {
		return admissionwire.Acknowledgement{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, _, err := value.OpenPruneAdmissionStream(bounded, address, expectedPeer)
	if err != nil {
		return admissionwire.Acknowledgement{}, err
	}
	return admissionwire.Exchange(bounded, stream, entry, timeout)
}
