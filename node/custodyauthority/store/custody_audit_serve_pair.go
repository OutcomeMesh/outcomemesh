package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var ErrManagedCustodyPair = errors.New("invalid local managed custody audit/serve pair")

// ManagedCustodyAuditServePair runs both local participants under ONE original
// authority guard. It is not a network grant or a distributed authority service.
// Both journals and all artifact/object roots must be distinct original roots.
// The caller retains the coordinator and supplies authenticated stream ends.
type ManagedCustodyAuditServePair struct {
	audit *ManagedCustodyAuditSession
	serve *ManagedCustodyServeSession
}

type ManagedCustodyAuditServeResult struct {
	Audit workarchive.CustodyAuditResult
	Serve workarchive.CustodyServeReport
}

// NewManagedCustodyAuditServePair accepts only private sessions bound to the
// same original owner. Two copied coordinators cannot substitute for that owner.
// Current tickets, exact challenge and all placement are rechecked at Exchange.
func NewManagedCustodyAuditServePair(audit *ManagedCustodyAuditSession, serve *ManagedCustodyServeSession) (*ManagedCustodyAuditServePair, error) {
	if audit == nil || serve == nil || audit.coordinator == nil || audit.cycle == nil ||
		serve.session == nil || audit.coordinator != serve.coordinator || audit.binding.AssignmentID != serve.binding.AssignmentID ||
		audit.cycle.Intent().ReplicaPeerID == serve.auditorPeer {
		return nil, ErrManagedCustodyPair
	}
	return &ManagedCustodyAuditServePair{audit: audit, serve: serve}, nil
}

// Exchange validates both pending tickets before either participant enters I/O.
// It invokes the private sessions concurrently, never the public adapters that
// would recursively acquire the same non-reentrant coordinator. Every accepted
// effect, stream close and cancellation callback drains before the guard exits.
// A partial failure can leave committed evidence and completes neither ticket.
func (pair *ManagedCustodyAuditServePair) Exchange(ctx context.Context,
	authenticatedReplica, authenticatedAuditor types.Hash,
	auditorStream, replicaStream workarchive.CustodySessionStream,
) (result ManagedCustodyAuditServeResult, returnErr error) {
	return pair.exchange(ctx, authenticatedReplica, authenticatedAuditor, auditorStream, replicaStream, nil)
}

// exchange composes an optional local comparison inside the original authority
// guard. It is private so a checked snapshot cannot become a reusable permit.
func (pair *ManagedCustodyAuditServePair) exchange(ctx context.Context,
	authenticatedReplica, authenticatedAuditor types.Hash,
	auditorStream, replicaStream workarchive.CustodySessionStream, before func() error,
) (result ManagedCustodyAuditServeResult, returnErr error) {
	if auditorStream == nil || replicaStream == nil {
		return result, errors.Join(ErrManagedCustodyPair, closeManagedCustodyPairStreams(auditorStream, replicaStream))
	}
	auditStream := &managedCustodyServeStream{CustodySessionStream: auditorStream}
	serveStream := &managedCustodyServeStream{CustodySessionStream: replicaStream}
	var auditIO workarchive.CustodySessionStream = auditStream
	if half, ok := auditorStream.(interface{ CloseWrite() error }); ok {
		auditIO = &managedCustodyPairDuplexStream{managedCustodyServeStream: auditStream, half: half}
	}
	if pair == nil || pair.audit == nil || pair.serve == nil || ctx == nil ||
		authenticatedReplica.IsZero() || authenticatedAuditor.IsZero() ||
		authenticatedReplica != pair.audit.cycle.Intent().ReplicaPeerID || authenticatedAuditor != pair.serve.auditorPeer {
		return result, errors.Join(ErrManagedCustodyPair, closeManagedCustodyPairStreams(auditStream, serveStream))
	}
	entered := false
	err := pair.audit.coordinator.WithOperation(ctx, pair.audit.binding, func() (err error) {
		entered = true
		runContext, cancel := context.WithCancel(ctx)
		streams := []*managedCustodyServeStream{auditStream, serveStream}
		stops := make([]func() bool, len(streams))
		drained := make([]chan struct{}, len(streams))
		for i, stream := range streams {
			drained[i] = make(chan struct{})
			done := drained[i]
			stops[i] = context.AfterFunc(runContext, func() { defer close(done); _ = stream.Close() })
		}
		defer func() {
			cancel()
			for i, stop := range stops {
				if !stop() {
					<-drained[i]
				}
			}
			err = errors.Join(err, closeManagedCustodyPairStreams(auditStream, serveStream), ctx.Err())
		}()
		if err := pair.audit.coordinator.checkOperation(pair.serve.binding); err != nil {
			return err
		}
		if err := pair.audit.revalidate(); err != nil {
			return err
		}
		if err := pair.validateRoots(); err != nil {
			return err
		}
		if before != nil {
			if err := before(); err != nil {
				return err
			}
		}
		challenge, err := pair.audit.cycle.PrepareChallenge(runContext)
		if err != nil {
			return err
		}
		challengeID, err := challenge.ID()
		if err != nil || challengeID != pair.serve.challengeID {
			return errors.Join(ErrManagedCustodyPair, err)
		}
		finished := make(chan error, 2)
		go func() {
			accepted, err := pair.audit.auditGuarded(runContext, auditIO)
			err = errors.Join(err, auditStream.Close())
			result.Audit = accepted
			if err != nil {
				cancel()
			}
			finished <- err
		}()
		go func() {
			served, err := pair.serve.session.ServeExpected(runContext, serveStream, pair.serve.challengeID)
			err = errors.Join(err, serveStream.Close())
			result.Serve = served
			if err != nil {
				cancel()
			}
			finished <- err
		}()
		// Receive both completions before reading their disjoint result fields or
		// allowing the original owner to process completion/stop/retirement.
		for range 2 {
			err = errors.Join(err, <-finished)
		}
		return err
	})
	if !entered {
		err = errors.Join(err, closeManagedCustodyPairStreams(auditStream, serveStream))
	}
	if err != nil {
		return ManagedCustodyAuditServeResult{}, err
	}
	return result, nil
}

type managedCustodyPairDuplexStream struct {
	*managedCustodyServeStream
	half interface{ CloseWrite() error }
}

func (stream *managedCustodyPairDuplexStream) CloseWrite() error { return stream.half.CloseWrite() }

func (pair *ManagedCustodyAuditServePair) validateRoots() error {
	a, s := pair.audit, pair.serve
	roots := []string{a.coordinator.authority.path, a.coordinator.journal.path,
		filepath.Dir(a.intentPath), a.artifactsPath, a.journalPath, s.journalPath, s.objects.Directory()}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if _, _, err := coordinatorPaths(roots[i], roots[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

func closeManagedCustodyPairStreams(streams ...workarchive.CustodySessionStream) error {
	var wait sync.WaitGroup
	errorsByStream := make([]error, len(streams))
	for i, stream := range streams {
		if stream == nil {
			continue
		}
		wait.Add(1)
		go func() { defer wait.Done(); errorsByStream[i] = stream.Close() }()
	}
	wait.Wait()
	return errors.Join(errorsByStream...)
}
