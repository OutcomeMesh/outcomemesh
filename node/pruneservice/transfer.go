package pruneservice

import (
	"encoding/json"
	"path/filepath"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// TransferBundle optionally moves every original runtime placement together
// with its owner. Source and Destination identify entire private directories.
type TransferBundle struct {
	Source, Destination string
}

// TransferReview identifies the original owner, its complete event state and
// the locked runtime. It grants no execution, settlement or ticket release.
type TransferReview struct {
	SignerInstalled                                                   bool
	RuntimePlacementsID, ExecutorPlacementsID, SettlementPlacementsID types.Hash
	Source, Destination                                               string
	Bundle                                                            TransferBundle
	DescriptorID, RootID, InventoryID                                 types.Hash
	Position                                                          wire.Position
	OwnerFilesID, ScopeID, RuntimeReviewID                            types.Hash
	ContainerID, SourceParentID, DestinationParentID                  types.Hash
}

func (r TransferReview) ID() (types.Hash, error) {
	if r.RuntimePlacementsID.IsZero() || r.ExecutorPlacementsID.IsZero() || r.SettlementPlacementsID.IsZero() || !validTransferPaths(r.Source, r.Destination, r.Bundle) || !r.Position.Valid() ||
		r.DescriptorID.IsZero() || r.RootID.IsZero() || r.InventoryID.IsZero() || r.OwnerFilesID.IsZero() ||
		r.ScopeID.IsZero() || r.RuntimeReviewID.IsZero() || r.ContainerID.IsZero() || r.SourceParentID.IsZero() || r.DestinationParentID.IsZero() {
		return types.Hash{}, ErrOwner
	}
	b, err := json.Marshal(r)
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"transfer/review/v0", b), nil
}

func validTransferPaths(source, dest string, b TransferBundle) bool {
	valid := func(p string) bool {
		return utf8.ValidString(p) && len(p) <= 4096 && filepath.IsAbs(p) && filepath.Clean(p) == p && filepath.Dir(p) != p
	}
	if !valid(source) || !valid(dest) || source == dest {
		return false
	}
	if b == (TransferBundle{}) {
		return true
	}
	if !valid(b.Source) || !valid(b.Destination) || b.Source == b.Destination {
		return false
	}
	a, err := filepath.Rel(b.Source, source)
	z, e := filepath.Rel(b.Destination, dest)
	return err == nil && e == nil && a == z && a != "." && filepath.IsLocal(a)
}
