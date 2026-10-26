package store

import (
	"context"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
)

// PruneAdmissionServer exposes only the ordered local admission adapter selected
// by its explicit primary or prepared-secondary constructor, for one pinned
// executor and one independently configured transport identity. Transport
// identity never substitutes for either command signature.
// The host must supply the authenticated peer, never a peer ID from the request.
// Ownership of executor/coordinator remains with the caller through all handlers.
type PruneAdmissionServer struct {
	executor    *PruneExecutor
	coordinator *Coordinator
	peer        types.Hash
	timeout     time.Duration
	prepared    *preparedArchiveSecondarySession
	hooks       storeHooks
}

func NewPruneAdmissionServer(executor *PruneExecutor, coordinator *Coordinator, peer types.Hash, timeout time.Duration) (*PruneAdmissionServer, error) {
	if executor == nil || coordinator == nil || peer.IsZero() || timeout < admissionwire.MinimumTimeout || timeout > admissionwire.MaximumTimeout {
		return nil, admissionwire.ErrProtocol
	}
	s, err := executor.Snapshot()
	if err != nil {
		return nil, err
	}
	if s.Protection == nil {
		return nil, ErrPrunePin
	}
	if _, err := coordinator.Snapshot(); err != nil {
		return nil, err
	}
	return &PruneAdmissionServer{executor: executor, coordinator: coordinator, peer: peer, timeout: timeout}, nil
}

// Serve owns one stream. An exact request AND EOF must arrive before any
// authority mutation. Only prune Admit may act, only for the retained request.
// Primary replies follow authority AND executor admission confirmation; prepared
// secondary replies follow the exact target authority's independent confirmation.
// An error sends no negative disposition: missing replies remain unresolved.
// This never starts, cancels, recovers effects, completes, signs, stops or retires.
// An ACK is historical evidence, not a remote execution capability.
func (server *PruneAdmissionServer) Serve(ctx context.Context, authenticatedPeer types.Hash, stream admissionwire.Stream) (Commit, error) {
	if stream == nil {
		return Commit{}, admissionwire.ErrProtocol
	}
	defer stream.Close()
	if server == nil || authenticatedPeer != server.peer || authenticatedPeer.IsZero() {
		return Commit{}, admissionwire.ErrProtocol
	}
	bounded, cleanup, err := admissionwire.BoundStream(ctx, stream, server.timeout)
	if err != nil {
		return Commit{}, err
	}
	defer cleanup()
	request, err := admissionwire.ReadRequest(stream)
	if err != nil {
		return Commit{}, errors.Join(err, bounded.Err())
	}
	if err := admissionwire.RequireEOF(stream); err != nil {
		return Commit{}, errors.Join(err, bounded.Err())
	}
	if err := server.hooks.reach("admission-request"); err != nil {
		return Commit{}, err
	}
	var result Commit
	if server.prepared == nil {
		result, err = server.executor.Admit(bounded, server.coordinator, request.Entry)
	} else {
		config := server.prepared.config
		result, err = server.executor.AdmitPreparedArchiveSecondary(bounded, server.prepared.primary, server.coordinator,
			config.InventoryPath, config.InventoryID, config.PolicyID, request.Entry)
	}
	if err != nil {
		return Commit{}, err
	}
	if err := server.hooks.reach("admission-confirmed"); err != nil {
		return Commit{}, err
	}
	ack := admissionwire.Acknowledgement{Nonce: request.Nonce, EntryID: result.EntryID}
	if err := admissionwire.WriteAcknowledgement(stream, ack); err != nil {
		return Commit{}, errors.Join(err, bounded.Err())
	}
	if err := stream.CloseWrite(); err != nil {
		return Commit{}, err
	}
	if err := server.hooks.reach("admission-replied"); err != nil {
		return Commit{}, err
	}
	return result, nil
}
