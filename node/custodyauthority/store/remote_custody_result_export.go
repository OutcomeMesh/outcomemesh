package store

import (
	"context"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// ExportResultReviewed publishes the exact sealed B entry, not a refreshed
// response or an A acceptance claim. It cannot Start, sign, seal or complete.
func (s *RemoteCustodyServeService) ExportResultReviewed(ctx context.Context, path string, expected types.Hash) (id types.Hash, returnErr error) {
	if s == nil || ctx == nil || path == "" || expected.IsZero() {
		return id, ErrRemoteCustody
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	review, err := s.reviewLocked(ctx)
	if err != nil {
		return id, err
	}
	actual, err := review.ID()
	if err != nil || actual != expected {
		return id, ErrManagedCustodyReview
	}
	worker, err := s.worker.Snapshot(ctx)
	if err != nil {
		return id, err
	}
	if worker.Stage != remoteworker.Sealed || worker.Pending != 0 || worker.Seal == nil || worker.Seal.Disposition != remoteworker.RetainedResult {
		return id, ErrRemoteCustody
	}
	for _, root := range []string{s.workerPath, s.journal.Directory(), s.objects.Directory()} {
		if _, _, err := coordinatorPaths(filepath.Dir(path), root); err != nil {
			return id, err
		}
	}
	if s.placement != nil && path == s.placement.placement.Path {
		return id, ErrRemotePlacement
	}
	err = s.withSourceDecision(ctx, func(d *workarchive.CustodyJournalDecision) error {
		entry, err := s.currentResult(d)
		if err != nil {
			return err
		}
		id, err = entry.ID()
		if err != nil || id != worker.Seal.ResultID {
			return ErrRemoteCustody
		}
		b, err := entry.CanonicalBytes()
		if err != nil {
			return err
		}
		return publishCustodyArtifactBytes(ctx, path, b)
	})
	return id, err
}
