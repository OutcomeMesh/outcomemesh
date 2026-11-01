package store

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
)

// DeliverScheduledPrune opens only an existing independently pinned outbox and
// performs at most one exchange. The shared config carries paths/route only;
// its intent format and receipt remain distinct from both legacy protocols.
// A retained receipt returns offline after checking the original client key.
func DeliverScheduledPrune(ctx context.Context, key ed25519.PrivateKey, config PruneDeliveryConfig) (ack scheduledwire.Acknowledgement, err error) {
	if err := validatePruneDelivery(ctx, config); err != nil {
		return ack, err
	}
	outbox, err := OpenScheduledPruneOutbox(config.Path, config.Assignment, config.IntentID)
	if err != nil {
		return ack, err
	}
	defer func() {
		err = errors.Join(err, outbox.Close())
		if err != nil {
			ack = scheduledwire.Acknowledgement{}
			err = errors.Join(scheduledwire.ErrUnconfirmed, err)
		}
	}()
	state, err := outbox.Snapshot()
	if err != nil {
		return ack, err
	}
	i := state.Intent
	if err := validatePruneRuntimePeers(config.Assignment, i.ClientPeerID, i.ServerPeerID); err != nil {
		return ack, err
	}
	if _, err := pruneRuntimeKey(key, i.ClientPeerID); err != nil {
		return ack, err
	}
	if state.Acknowledgement != nil {
		return *state.Acknowledgement, nil
	}
	host, err := newPruneRuntimeHost(ctx, config.Assignment, i.ClientPeerID, i.ServerPeerID, key, config.Transport)
	if err != nil {
		return ack, err
	}
	defer func() { err = errors.Join(err, host.Close()) }()
	return outbox.Deliver(ctx, host, config.Address, config.Timeout)
}
