//go:build linux || darwin

package pruneservice

import (
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodygateway"
)

type transferScope uint8

const (
	transferExecutor transferScope = iota
	transferSettlement
	transferRuntime
)

func (r *TransferReview) placementID(part transferScope) *types.Hash {
	switch part {
	case transferExecutor:
		return &r.ExecutorPlacementsID
	case transferSettlement:
		return &r.SettlementPlacementsID
	default:
		return &r.RuntimePlacementsID
	}
}

func (o *Owner) transferPlacements(part transferScope) (types.Hash, error) {
	// These are the permanent root and lock names used by the original stores.
	// The DB's own transient file set may change on close or compaction; its
	// separate position journal and permanent lock carry its protected position.
	type placement struct {
		path, lock string
		dir        bool
	}
	r := o.config.Runtime
	p := []placement{{r.ExecutorPath, "prune.lock", true}, {r.ExecutorPinsPath, "prune-pins.lock", true}}
	if part != transferExecutor {
		p = append(p, placement{r.ChainPath, "", true}, placement{r.ChainPinsPath, "positions.lock", true})
		for _, a := range r.Authorities {
			if part == transferRuntime || a.AssignmentID == o.descriptor.Binding.AssignmentID {
				p = append(p, placement{a.AuthorityPath, "authority.lock", true}, placement{a.AuthorityPinsPath, "intent.lock", true})
			}
		}
	}
	if part == transferRuntime {
		p = append(p, placement{r.InventoryPath, "", false})
		for _, s := range r.Sources {
			p = append(p, placement{s.Directory, "", true}, placement{s.JournalPath, "journal.lock", true})
		}
	}
	e := codec.NewEncoder(2048)
	for _, v := range p {
		logical := v.path
		if o.transferred != nil && o.transferred.Bundle != (TransferBundle{}) {
			b := o.transferred.Bundle
			rel, err := filepath.Rel(b.Destination, v.path)
			if err != nil || !filepath.IsLocal(rel) || rel == "." {
				return types.Hash{}, ErrOwner
			}
			logical = filepath.Join(b.Source, rel)
		}
		id, err := custodygateway.PlacementIDAt(v.path, logical, v.dir)
		if err != nil {
			return types.Hash{}, err
		}
		e.Fixed(id[:])
		if v.lock != "" {
			id, err = custodygateway.PlacementIDAt(filepath.Join(v.path, v.lock), filepath.Join(logical, v.lock), false)
			if err != nil {
				return types.Hash{}, err
			}
			e.Fixed(id[:])
		}
	}
	return types.DomainHash(domain+"transfer/runtime-placements/v0", e.Bytes()), nil
}

func (o *Owner) checkTransferredPlacements(part transferScope) error {
	if o.transferred == nil {
		return nil
	}
	got, err := o.transferPlacements(part)
	if err != nil || got != *o.transferred.placementID(part) {
		return errors.Join(ErrOwner, err)
	}
	return nil
}

func (o *Owner) checkTransferredRuntime() error { return o.checkTransferredPlacements(transferRuntime) }
func (o *Owner) checkTransferredExecutor() error {
	return o.checkTransferredPlacements(transferExecutor)
}
func (o *Owner) checkTransferredSettlement() error {
	return o.checkTransferredPlacements(transferSettlement)
}
