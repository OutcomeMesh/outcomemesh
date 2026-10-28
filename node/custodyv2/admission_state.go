package custodyv2

import (
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// AdmissionSnapshot is detached diagnostic history, never permission to execute
// a job. Pending includes two units for a single active Audit/Serve job; spent
// units never decrease. Raw V2 execution does not yet require this coordinator.
type AdmissionSnapshot struct {
	GenesisID                     types.Hash
	Position                      custodyfence.Position
	SpentOperations               uint32
	PendingOperations             uint16
	ActiveContextID, ActivePlanID types.Hash
	SourceSequence                uint64
	SourceHeadID, SourceReceiptID types.Hash
	CurrentReceipt                workarchive.ReplicaReceipt
	RetainUntil                   uint64
}

// AdmissionState is a reference machine only. The assignment-global durable
// witness owns serialization and vote persistence. An isolated copied state,
// receipt, or snapshot cannot establish globally current admission permission.
type AdmissionState struct {
	mu                      sync.Mutex
	genesis                 AdmissionGenesis
	snapshot                AdmissionSnapshot
	usedContexts, usedPlans map[types.Hash]bool
}

func NewAdmissionState(g AdmissionGenesis, pin types.Hash) (*AdmissionState, error) {
	b, e := g.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	g, e = DecodeAdmissionGenesis(b)
	if e != nil {
		return nil, e
	}
	id, e := g.ID()
	if e != nil || pin.IsZero() || pin != id {
		return nil, ErrAdmission
	}
	rid, _ := g.Initial.ID()
	return &AdmissionState{genesis: g, snapshot: AdmissionSnapshot{GenesisID: id, Position: custodyfence.Position{HeadID: id}, SourceReceiptID: rid, CurrentReceipt: g.Initial, RetainUntil: g.Initial.RetainUntil}, usedContexts: make(map[types.Hash]bool), usedPlans: make(map[types.Hash]bool)}, nil
}
func (s *AdmissionState) Snapshot() AdmissionSnapshot {
	if s == nil {
		return AdmissionSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot
}
func (s *AdmissionState) ValidateNext(e AdmissionEntry) error {
	if s == nil {
		return ErrAdmission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validateNext(e)
}
func (s *AdmissionState) validateNext(e AdmissionEntry) error {
	if s.snapshot.GenesisID.IsZero() {
		return ErrAdmission
	}
	if err := e.Verify(s.genesis); err != nil {
		return err
	}
	x := s.snapshot
	if e.ExpectedSequence != x.Position.Sequence || e.ExpectedHead != x.Position.HeadID {
		return ErrAdmissionHead
	}
	cid, _ := e.Context.ID()
	pid, _ := e.Context.Plan.ID()
	intent := e.Context.Plan.Intent
	switch e.Kind {
	case AdmissionAdmit:
		if !x.ActiveContextID.IsZero() || x.PendingOperations != 0 {
			return ErrAdmissionActive
		}
		if s.usedContexts[cid] || s.usedPlans[pid] {
			return ErrAdmission
		}
		if x.SpentOperations > s.genesis.Assignment.Base.MaximumOperations || s.genesis.Assignment.Base.MaximumOperations-x.SpentOperations < 2 || s.genesis.Assignment.Base.MaximumPending < 2 {
			return ErrAdmissionBudget
		}
		rid, _ := e.Context.Previous.ID()
		if intent.PriorSequence != x.SourceSequence || intent.PriorHeadID != x.SourceHeadID || intent.PriorReceiptID != x.SourceReceiptID || rid != x.SourceReceiptID || e.Context.Previous != x.CurrentReceipt {
			return ErrAdmission
		}
	case AdmissionClose:
		if x.ActiveContextID.IsZero() || x.ActiveContextID != cid || x.ActivePlanID != pid || x.PendingOperations != 2 || e.Closure == nil {
			return ErrAdmissionActive
		}
	default:
		return ErrAdmission
	}
	return nil
}
func (s *AdmissionState) Apply(c AdmissionCertificate) error {
	if s == nil {
		return ErrAdmission
	}
	raw, e := c.CanonicalBytes()
	if e != nil {
		return e
	}
	c, e = DecodeAdmissionCertificate(raw)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := c.Verify(s.genesis); e != nil {
		return e
	}
	if e := s.validateNext(c.Entry); e != nil {
		return e
	}
	id, _ := c.Entry.ID()
	cid, _ := c.Entry.Context.ID()
	pid, _ := c.Entry.Context.Plan.ID()
	x := s.snapshot
	switch c.Entry.Kind {
	case AdmissionAdmit:
		x.SpentOperations += 2
		x.PendingOperations = 2
		x.ActiveContextID = cid
		x.ActivePlanID = pid
		s.usedContexts[cid] = true
		s.usedPlans[pid] = true
	case AdmissionClose:
		if c.Entry.Closure.Serve.Proposal.Outcome == ServeFulfilled {
			bundle, _, e := c.Entry.Closure.Serve.Proposal.fulfilled()
			if e != nil {
				return e
			}
			x.CurrentReceipt = bundle.Result.Entry.Record.RenewedReceipt
			x.SourceReceiptID, _ = x.CurrentReceipt.ID()
			x.SourceHeadID, _ = bundle.Result.Entry.ID()
			x.SourceSequence = bundle.Result.Entry.Sequence
			x.RetainUntil = max(x.RetainUntil, x.CurrentReceipt.RetainUntil)
		}
		x.PendingOperations = 0
		x.ActiveContextID = types.Hash{}
		x.ActivePlanID = types.Hash{}
	}
	x.Position = custodyfence.Position{Sequence: x.Position.Sequence + 1, HeadID: id}
	s.snapshot = x
	return nil
}
