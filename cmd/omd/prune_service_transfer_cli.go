package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

type pruneServiceTransferReviewReport struct {
	ReviewID         string
	Review           service.TransferReview
	ExecutionGranted bool
}

func validatePruneServiceTransfer(a pruneServiceCLIFlags) error {
	if custodyPathsOverlap(a.Root, a.Destination) || (a.StorageRoot == "") != (a.StorageDestination == "") {
		return wire.ErrArtifact
	}
	if a.StorageRoot != "" {
		rel, err := filepath.Rel(a.StorageRoot, a.Root)
		if err != nil || rel == "." || !filepath.IsLocal(rel) ||
			filepath.Join(a.StorageDestination, rel) != a.Destination || custodyPathsOverlap(a.StorageRoot, a.StorageDestination) {
			return wire.ErrArtifact
		}
	}
	if a.TransferID != "" {
		_, err := pruneExternalID("transfer-id", a.TransferID)
		return err
	}
	return nil
}

func runPruneServiceTransfer(ctx context.Context, a pruneServiceCLIFlags, did types.Hash, p wire.Position) ([]byte, error) {
	bundle := service.TransferBundle{Source: a.StorageRoot, Destination: a.StorageDestination}
	if a.Action == "transfer-review" {
		r, err := service.ReviewTransfer(ctx, a.Root, a.Destination, did, p, bundle, a.Output, a.Descriptor, a.Position)
		if err != nil {
			return nil, err
		}
		id, err := r.ID()
		if err != nil {
			return nil, err
		}
		return json.Marshal(pruneServiceTransferReviewReport{ReviewID: id.String(), Review: r})
	}
	id, err := pruneExternalID("transfer-id", a.TransferID)
	if err != nil {
		return nil, err
	}
	report, err := json.Marshal(struct {
		TransferID, DescriptorID, Source, Destination string
		StorageRoot, StorageDestination               string `json:",omitempty"`
		Position                                      wire.Position
		ExecutionGranted                              bool
	}{id.String(), did.String(), a.Root, a.Destination, a.StorageRoot, a.StorageDestination, p, false})
	if err != nil {
		return nil, err
	}
	// A conflicting destination must be detected before moving the owner. An
	// identical receipt still requires the original owner to confirm the move.
	prior, err := readRegularArtifact(a.Output, len(report))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && !bytes.Equal(prior, report) {
		return nil, wire.ErrArtifact
	}
	r, err := service.Transfer(ctx, a.Root, a.Destination, did, p, id, bundle, a.Output, a.Descriptor, a.Position)
	if err != nil {
		return nil, err
	}
	if got, err := r.ID(); err != nil || got != id {
		return nil, wire.ErrArtifact
	}
	return report, nil
}
