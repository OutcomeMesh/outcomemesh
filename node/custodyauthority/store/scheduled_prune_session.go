package store

import (
	"context"
	"errors"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// ScheduledPruneCommandServer accepts one independently pinned delivery intent.
// Each call owns the original roots through validation and durable application.
// Idle servers hold no roots; local recovery remains an explicit operator action.
// A concurrent owner makes delivery fail closed. No caller-supplied paths, fresh
// review, signature, outcome or execution capability can cross this surface.
type ScheduledPruneCommandServer struct {
	config  ScheduledPruneCommandConfig
	intent  scheduledwire.Intent
	id      types.Hash
	timeout time.Duration
	hooks   storeHooks
}

func NewScheduledPruneCommandServer(config ScheduledPruneCommandConfig, intent scheduledwire.Intent, expectedID types.Hash, timeout time.Duration) (*ScheduledPruneCommandServer, error) {
	id, err := intent.ID()
	entryID, _ := intent.Entry.ID()
	if err != nil || expectedID.IsZero() || id != expectedID || timeout < scheduledwire.MinimumTimeout || timeout > scheduledwire.MaximumTimeout ||
		config.PlanID != intent.PlanID || config.EntryID != entryID || config.AssignmentID != intent.Entry.Command.AssignmentID || config.InventoryID != intent.InventoryID ||
		config.Storage != nil || config.PrepareSettlement || config.ClosurePath != "" || !config.ClosureID.IsZero() || config.SettlementPath != "" || !config.SettlementID.IsZero() {
		return nil, errors.Join(ErrScheduledPrune, err)
	}
	config.CustodyPolicy.TrustedAuditors = append([][32]byte(nil), config.CustodyPolicy.TrustedAuditors...)
	return &ScheduledPruneCommandServer{config: config, intent: intent, id: id, timeout: timeout}, nil
}

// Register enables only the new protocol on the pinned receiving transport.
// Host lifetime and shutdown remain the caller's responsibility. No default node
// endpoint is installed, and legacy admission/completion handlers are unchanged.
func (s *ScheduledPruneCommandServer) Register(host *libp2ptransport.Host) error {
	if s == nil || host == nil || host.ID() != s.intent.ServerPeerID {
		return ErrScheduledPrune
	}
	return host.SetScheduledPruneHandler(s.intent.ClientPeerID, func(ctx context.Context, peer types.Hash, stream network.Stream) {
		if err := s.Serve(ctx, peer, stream); err != nil {
			_ = stream.Reset()
		}
	})
}

// Serve requires a complete exact request and EOF before opening any owner.
// Replies follow original authority/executor confirmation and successful close.
// A missing reply says nothing about whether the command was committed.
func (s *ScheduledPruneCommandServer) Serve(ctx context.Context, peer types.Hash, stream scheduledwire.Stream) error {
	if stream == nil {
		return scheduledwire.ErrProtocol
	}
	defer stream.Close()
	if s == nil || peer.IsZero() || peer != s.intent.ClientPeerID {
		return scheduledwire.ErrProtocol
	}
	bounded, cleanup, err := scheduledwire.BoundStream(ctx, stream, s.timeout)
	if err != nil {
		return err
	}
	defer cleanup()
	r, err := scheduledwire.ReadRequest(stream)
	if err != nil {
		return err
	}
	if r.Intent != s.intent {
		return ErrScheduledPrune
	}
	if err := scheduledwire.RequireEOF(stream); err != nil {
		return err
	}
	if err := s.hooks.reach("scheduled-delivery-request"); err != nil {
		return err
	}
	if _, err := runScheduledPruneCommandBound(bounded, s.config, "apply", s.intent.ReviewID, s.hooks, &s.intent); err != nil {
		return err
	}
	if err := s.hooks.reach("scheduled-delivery-confirmed"); err != nil {
		return err
	}
	if err := bounded.Err(); err != nil {
		return err
	}
	if err := scheduledwire.WriteAcknowledgement(stream, scheduledwire.Acknowledgement{Nonce: r.Nonce, IntentID: s.id}); err != nil {
		return err
	}
	return stream.CloseWrite()
}
