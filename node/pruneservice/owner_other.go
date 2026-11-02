//go:build !linux && !darwin

package pruneservice

import (
	"context"
	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

type Owner struct{}

func CreateIdentity(string) (Identity, error) { return Identity{}, ErrUnsupported }
func ReadIdentity(string) (Identity, error)   { return Identity{}, ErrUnsupported }
func Prepare(context.Context, string, Config, uint32) (wire.Descriptor, error) {
	return wire.Descriptor{}, ErrUnsupported
}
func Configure(context.Context, string, wire.Descriptor, Config) error { return ErrUnsupported }
func Open(context.Context, string, types.Hash, wire.Position, *wire.Request) (*Owner, error) {
	return nil, ErrUnsupported
}
func (*Owner) Descriptor() wire.Descriptor { return wire.Descriptor{} }
func (*Owner) Snapshot() (Snapshot, error) { return Snapshot{}, ErrUnsupported }
func (*Owner) Execute(context.Context, wire.Request, func(context.Context, wire.Challenge) (custodyfence.Command, error)) (wire.Response, error) {
	return wire.Response{}, ErrUnsupported
}
func (*Owner) Recover(context.Context, wire.Request) (wire.Response, error) {
	return wire.Response{}, ErrUnsupported
}
func (*Owner) Close() error                                               { return nil }
func Serve(context.Context, *Owner, string, func(types.Hash) error) error { return ErrUnsupported }
func SocketID(string) (types.Hash, error)                                 { return types.Hash{}, ErrUnsupported }
func CleanupSocket(string, types.Hash) error                              { return ErrUnsupported }

func ReviewContinuation(context.Context, string, types.Hash, wire.Position, wire.Request) (ContinuationReview, error) {
	return ContinuationReview{}, ErrUnsupported
}
func Continue(context.Context, string, types.Hash, wire.Position, wire.Request, types.Hash) (Snapshot, error) {
	return Snapshot{}, ErrUnsupported
}

func (*Owner) ReviewSettlement(context.Context, wire.Request, SettlementInput) (store.ScheduledPruneCommandResult, error) {
	return store.ScheduledPruneCommandResult{}, ErrUnsupported
}
func (*Owner) Settle(context.Context, wire.Request, SettlementInput, types.Hash) (wire.Response, error) {
	return wire.Response{}, ErrUnsupported
}
