package pruneservice

import (
	"encoding/json"
	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// ContinuationReview describes a single original inode and its exact missing
// suffix. It is a local comparison, not permission to execute Prune.
type ContinuationReview struct {
	DescriptorID, RequestID, OwnerFilesID types.Hash
	Before                                wire.Position
	Record                                string
	Exists                                bool
	FileID, PrefixID, TargetID            types.Hash
	RetainedBytes, TargetBytes            uint32
}

func (r ContinuationReview) ID() (types.Hash, error) {
	if r.DescriptorID.IsZero() || r.RequestID.IsZero() || r.OwnerFilesID.IsZero() || !r.Before.Valid() ||
		(r.Record != "intent" && r.Record != "result") || r.PrefixID.IsZero() || r.TargetID.IsZero() ||
		r.RetainedBytes > r.TargetBytes || r.TargetBytes == 0 || r.Exists == r.FileID.IsZero() || (!r.Exists && r.RetainedBytes != 0) {
		return types.Hash{}, ErrOwner
	}
	limit := uint32(wire.MaximumResponseBytes)
	if r.Record == "intent" {
		limit = wire.RequestBytes
	}
	if r.TargetBytes > limit {
		return types.Hash{}, ErrOwner
	}
	b, err := json.Marshal(r)
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(domain+"continuation-review/v0", b), nil
}
