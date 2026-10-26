package store

import (
	"context"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
)

// PruneCompletionServer exposes only the local terminal-completion adapter
// selected by its explicit primary or prepared-secondary constructor, for one
// pinned executor and one independently configured transport
// identity. Transport identity never substitutes for either command signature.
// The host must supply the authenticated peer, never a peer ID from the request.
// Ownership of executor/coordinator remains with the caller through all handlers.
type PruneCompletionServer struct {
	executor    *PruneExecutor
	coordinator *Coordinator
	peer        types.Hash
	timeout     time.Duration
	prepared    *preparedArchiveSecondarySession
	hooks       storeHooks
}

func NewPruneCompletionServer(executor *PruneExecutor, coordinator *Coordinator, peer types.Hash, timeout time.Duration) (*PruneCompletionServer, error) {
	if executor == nil || coordinator == nil || peer.IsZero() || timeout < completionwire.MinimumTimeout || timeout > completionwire.MaximumTimeout {
		return nil, completionwire.ErrProtocol
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
	return &PruneCompletionServer{executor: executor, coordinator: coordinator, peer: peer, timeout: timeout}, nil
}

// Serve owns one stream. An exact request AND EOF must arrive before any
// authority mutation. Only Complete may act, only for retained terminal evidence,
// and the reply follows independent authority confirmation. An error sends no
// negative disposition: the client must regard missing replies as unresolved.
// This never admits, starts, cancels, recovers, signs, stops or retires anything.
func (server *PruneCompletionServer) Serve(ctx context.Context, authenticatedPeer types.Hash, stream completionwire.Stream) (Commit, error) {
	if stream == nil {
		return Commit{}, completionwire.ErrProtocol
	}
	defer stream.Close()
	if server == nil || authenticatedPeer != server.peer || authenticatedPeer.IsZero() {
		return Commit{}, completionwire.ErrProtocol
	}
	bounded, cleanup, err := completionwire.BoundStream(ctx, stream, server.timeout)
	if err != nil {
		return Commit{}, err
	}
	defer cleanup()
	request, err := completionwire.ReadRequest(stream)
	if err != nil {
		return Commit{}, errors.Join(err, bounded.Err())
	}
	if err := completionwire.RequireEOF(stream); err != nil {
		return Commit{}, errors.Join(err, bounded.Err())
	}
	if err := server.hooks.reach("completion-request"); err != nil {
		return Commit{}, err
	}
	var result Commit
	if server.prepared == nil {
		result, err = server.executor.Complete(bounded, server.coordinator, request.Entry)
	} else {
		config := server.prepared.config
		result, err = server.executor.CompletePreparedArchiveSecondary(bounded, server.coordinator,
			config.InventoryPath, config.InventoryID, config.PolicyID, request.Entry)
	}
	if err != nil {
		return Commit{}, err
	}
	if err := server.hooks.reach("completion-confirmed"); err != nil {
		return Commit{}, err
	}
	ack := completionwire.Acknowledgement{Nonce: request.Nonce, EntryID: result.EntryID}
	if err := completionwire.WriteAcknowledgement(stream, ack); err != nil {
		return Commit{}, errors.Join(err, bounded.Err())
	}
	if err := stream.CloseWrite(); err != nil {
		return Commit{}, err
	}
	if err := server.hooks.reach("completion-replied"); err != nil {
		return Commit{}, err
	}
	return result, nil
}
