package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// PruneDeliveryConfig selects one ALREADY prepared client outbox and one explicit
// route. Neither an absent root nor a rejected command can cause initialization,
// replacement, signing, head refresh or another network attempt.
type PruneDeliveryConfig struct {
	Path       string
	Assignment custodyauthority.Assignment
	IntentID   types.Hash
	Address    string
	Timeout    time.Duration
	Transport  libp2ptransport.Config
}

func validatePruneDelivery(ctx context.Context, config PruneDeliveryConfig) error {
	if ctx == nil || config.Timeout < admissionwire.MinimumTimeout || config.Timeout > admissionwire.MaximumTimeout {
		return ErrPruneRuntime
	}
	return ctx.Err()
}

// DeliverPruneAdmission owns an existing outbox and a fresh transport for one
// explicit call. It validates the retained client pin before opening a listener.
// Transport closes before journal ownership is released. A local ACK remains
// historical; this call never contacts an execution API or generates a key.
func DeliverPruneAdmission(ctx context.Context, key ed25519.PrivateKey, config PruneDeliveryConfig) (ack admissionwire.Acknowledgement, err error) {
	if err := validatePruneDelivery(ctx, config); err != nil {
		return ack, err
	}
	outbox, err := OpenAdmissionOutbox(config.Path, config.Assignment, config.IntentID)
	if err != nil {
		return ack, err
	}
	defer func() {
		err = errors.Join(err, outbox.Close())
		if err != nil {
			ack = admissionwire.Acknowledgement{}
			err = errors.Join(admissionwire.ErrUnconfirmed, err)
		}
	}()
	local, err := outbox.Snapshot()
	if err != nil {
		return ack, err
	}
	intent := local.Intent
	if local.Acknowledgement != nil {
		if err := validatePruneRuntimePeers(config.Assignment, intent.ClientPeerID, intent.ServerPeerID); err != nil {
			return ack, err
		}
		if _, err := pruneRuntimeKey(key, intent.ClientPeerID); err != nil {
			return ack, err
		}
		return *local.Acknowledgement, nil // no socket, even with an offline route
	}
	host, err := newPruneRuntimeHost(ctx, config.Assignment, intent.ClientPeerID, intent.ServerPeerID, key, config.Transport)
	if err != nil {
		return ack, err
	}
	defer func() { err = errors.Join(err, host.Close()) }()
	return outbox.Deliver(ctx, host, config.Address, config.Timeout)
}

// DeliverPruneCompletion is the separately typed completion counterpart. Only
// a durable checked receipt can report delivery. Open and failure cleanup cannot
// append authority history or turn a missing response into a terminal outcome.
func DeliverPruneCompletion(ctx context.Context, key ed25519.PrivateKey, config PruneDeliveryConfig) (ack completionwire.Acknowledgement, err error) {
	if err := validatePruneDelivery(ctx, config); err != nil {
		return ack, err
	}
	outbox, err := OpenCompletionOutbox(config.Path, config.Assignment, config.IntentID)
	if err != nil {
		return ack, err
	}
	defer func() {
		err = errors.Join(err, outbox.Close())
		if err != nil {
			ack = completionwire.Acknowledgement{}
			err = errors.Join(completionwire.ErrUnconfirmed, err)
		}
	}()
	local, err := outbox.Snapshot()
	if err != nil {
		return ack, err
	}
	intent := local.Intent
	if local.Acknowledgement != nil {
		if err := validatePruneRuntimePeers(config.Assignment, intent.ClientPeerID, intent.ServerPeerID); err != nil {
			return ack, err
		}
		if _, err := pruneRuntimeKey(key, intent.ClientPeerID); err != nil {
			return ack, err
		}
		return *local.Acknowledgement, nil
	}
	host, err := newPruneRuntimeHost(ctx, config.Assignment, intent.ClientPeerID, intent.ServerPeerID, key, config.Transport)
	if err != nil {
		return ack, err
	}
	defer func() { err = errors.Join(err, host.Close()) }()
	return outbox.Deliver(ctx, host, config.Address, config.Timeout)
}
