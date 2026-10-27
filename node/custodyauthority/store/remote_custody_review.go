package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// RemoteCustodyReview is a local comparison, never an execution grant. Paths,
// public scope and live positions are compared under the original owner again.
type RemoteCustodyReview struct {
	Role                                                        string
	AssignmentID, PlanID, BeginID, AuditTicketID, ServeTicketID types.Hash
	Confirmed, Observed                                         custodyauthority.Position
	PendingEntryID, ActiveBeginID                               types.Hash
	Phase                                                       custodyauthority.Phase
	Pending                                                     uint16
	JournalSequence                                             uint64
	JournalHeadID, CurrentReceiptID                             types.Hash
	WorkerStage, WorkerPending                                  remoteworker.Stage
	SealID                                                      types.Hash
	Paths                                                       []string
	JournalLimits                                               workarchive.CustodyJournalLimits
	ObjectPolicy                                                workarchive.ObjectStorePolicy
	Timeout                                                     time.Duration
}

func (r RemoteCustodyReview) ID() (types.Hash, error) {
	if (r.Role != "audit" && r.Role != "serve") || r.AssignmentID.IsZero() || r.PlanID.IsZero() || r.BeginID.IsZero() ||
		r.ServeTicketID.IsZero() || r.CurrentReceiptID.IsZero() || r.Timeout <= 0 || r.JournalLimits.Validate() != nil || len(r.Paths) == 0 {
		return types.Hash{}, ErrManagedCustodyReview
	}
	e := codec.NewEncoder(2048)
	e.BytesField([]byte(r.Role))
	for _, id := range []types.Hash{r.AssignmentID, r.PlanID, r.BeginID, r.AuditTicketID, r.ServeTicketID, r.Confirmed.HeadID, r.Observed.HeadID, r.PendingEntryID, r.ActiveBeginID, r.JournalHeadID, r.CurrentReceiptID, r.SealID} {
		e.Fixed(id[:])
	}
	e.U64(r.Confirmed.Sequence)
	e.U64(r.Observed.Sequence)
	e.U8(uint8(r.Phase))
	e.U16(r.Pending)
	e.U64(r.JournalSequence)
	e.U8(uint8(r.WorkerStage))
	e.U8(uint8(r.WorkerPending))
	e.U64(uint64(r.Timeout))
	e.U64(r.JournalLimits.MaximumBytes)
	e.U64(r.JournalLimits.MaximumPaths)
	e.U64(r.ObjectPolicy.MaximumObjects)
	e.U64(r.ObjectPolicy.MaximumBytes)
	e.U16(uint16(len(r.Paths)))
	for _, p := range r.Paths {
		if p == "" || len(p) > 32<<10 {
			return types.Hash{}, ErrManagedCustodyReview
		}
		e.BytesField([]byte(p))
	}
	return types.DomainHash("OMESH/local/remote-custody-review/v0", e.Bytes()), nil
}

type remoteCustodyReviewKey struct{}

// WithRemoteCustodyReview requests a fresh local comparison inside an A action.
// It adds a condition, not authority; the ordinary live checks remain mandatory.
func WithRemoteCustodyReview(ctx context.Context, expected types.Hash) (context.Context, error) {
	if ctx == nil || expected.IsZero() {
		return nil, ErrManagedCustodyReview
	}
	return context.WithValue(ctx, remoteCustodyReviewKey{}, expected), nil
}

func (runtime *RemoteCustodyAuditRuntime) Review(ctx context.Context) (r RemoteCustodyReview, returnErr error) {
	err := runtime.action(ctx, func(run context.Context) error { var err error; r, err = runtime.reviewLocked(run); return err })
	if err != nil {
		return RemoteCustodyReview{}, err
	}
	return r, nil
}

func (runtime *RemoteCustodyAuditRuntime) reviewLocked(ctx context.Context) (r RemoteCustodyReview, returnErr error) {
	current, err := runtime.life.owner.snapshot()
	if err != nil {
		return r, err
	}
	decision, err := runtime.journal.AcquireDecision()
	if err != nil {
		return r, err
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	if err := runtime.checkSourceIdentity(); err != nil {
		return r, err
	}
	state, err := decision.State()
	if err != nil {
		return r, err
	}
	receipt, err := state.CurrentReceipt.ID()
	if err != nil {
		return r, err
	}
	w := runtime.scope.Worker
	audit, _ := runtime.admission.ID()
	serve, _ := w.Plan.Admission.ID()
	r = RemoteCustodyReview{Role: "audit", AssignmentID: w.Plan.AssignmentID, PlanID: w.PlanID, BeginID: w.BeginID, AuditTicketID: audit, ServeTicketID: serve,
		Confirmed: current.Confirmed, Observed: custodyauthority.Position{Sequence: current.Authority.Sequence, HeadID: current.Authority.HeadID}, Phase: current.Authority.Phase, Pending: current.Authority.Pending,
		JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID, CurrentReceiptID: receipt,
		Paths:         []string{runtime.life.owner.authority.path, runtime.life.owner.journal.path, runtime.session.intentPath, runtime.session.journalPath, runtime.session.artifactsPath},
		JournalLimits: runtime.journalLimits, Timeout: runtime.timeout}
	if current.Pending != nil {
		r.PendingEntryID, _ = current.Pending.ID()
	}
	if current.Authority.Remote != nil {
		r.ActiveBeginID = current.Authority.Remote.BeginEntryID
	}
	return r, ctx.Err()
}

// InspectRemoteCustodyServe opens the selected existing owners for inspection
// only. Unlike the live service Close, its cleanup cannot seal a session.
func InspectRemoteCustodyServe(ctx context.Context, c RemoteCustodyServeServiceConfig) (r RemoteCustodyReview, returnErr error) {
	s, err := OpenRemoteCustodyServeService(ctx, c)
	if err != nil {
		return r, err
	}
	defer func() { returnErr = errors.Join(returnErr, s.worker.Close()) }()
	return s.Review(ctx)
}

func (s *RemoteCustodyServeService) Review(ctx context.Context) (r RemoteCustodyReview, returnErr error) {
	if s == nil || ctx == nil {
		return r, ErrClosed
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.reviewLocked(ctx)
}

func (s *RemoteCustodyServeService) reviewLocked(ctx context.Context) (r RemoteCustodyReview, returnErr error) {
	s.mu.Lock()
	closed := s.closed || s.closing
	s.mu.Unlock()
	if closed || s.worker == nil {
		return r, ErrClosed
	}
	worker, err := s.worker.Snapshot(ctx)
	if err != nil {
		return r, err
	}
	err = s.withSourceDecision(ctx, func(d *workarchive.CustodyJournalDecision) error {
		state, err := d.State()
		if err != nil {
			return err
		}
		receipt, err := state.CurrentReceipt.ID()
		if err != nil {
			return err
		}
		w := s.scope.Worker
		serve, _ := w.Plan.Admission.ID()
		r = RemoteCustodyReview{Role: "serve", AssignmentID: w.Plan.AssignmentID, PlanID: w.PlanID, BeginID: w.BeginID, ServeTicketID: serve,
			JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID, CurrentReceiptID: receipt, WorkerStage: worker.Stage, WorkerPending: worker.Pending, SealID: worker.SealID,
			Paths: []string{s.workerPath, s.journal.Directory(), s.objects.Directory()}, JournalLimits: s.journalLimits, ObjectPolicy: s.objectPolicy, Timeout: s.sessionConfig.RequestTimeout}
		return nil
	})
	return r, err
}

func (s *RemoteCustodyServeService) StartReviewed(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config, expected types.Hash) error {
	if s == nil || ctx == nil || expected.IsZero() {
		return ErrManagedCustodyReview
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	r, err := s.reviewLocked(ctx)
	if err != nil {
		return err
	}
	id, err := r.ID()
	if err != nil || id != expected {
		return errors.Join(ErrManagedCustodyReview, err)
	}
	return s.Start(ctx, key, config)
}
