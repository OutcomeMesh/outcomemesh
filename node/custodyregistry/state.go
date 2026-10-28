package custodyregistry

import (
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

// Snapshot is detached diagnostic state, not an activation or latest-head
// receipt. MaximumOperations/MaximumPending are the immutable registry caps;
// they are not a refunded or newly granted execution balance.
type Snapshot struct {
	RegistryID, DescriptorID                                      types.Hash
	Position                                                      custodyfence.Position
	SelectedAssignmentID, SelectedGenesisID, SelectedDescriptorID types.Hash
	MaximumOperations                                             uint32
	MaximumPending                                                uint16
	SelectionFinal                                                bool
}

type State struct {
	mu       sync.Mutex
	genesis  Genesis
	snapshot Snapshot
}

func NewState(g Genesis, pin types.Hash) (*State, error) {
	id, e := g.ID()
	if e != nil || pin.IsZero() || id != pin {
		return nil, ErrRegistry
	}
	raw, _ := g.CanonicalBytes()
	g, e = DecodeGenesis(raw)
	if e != nil {
		return nil, e
	}
	did, _ := g.DescriptorID()
	return &State{genesis: g, snapshot: Snapshot{RegistryID: id, DescriptorID: did, Position: custodyfence.Position{HeadID: id}, MaximumOperations: g.MaximumOperations, MaximumPending: g.MaximumPending}}, nil
}

func (s *State) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot
}

func (s *State) ValidateNext(selection Selection) error {
	if s == nil {
		return ErrRegistry
	}
	raw, e := selection.CanonicalBytes()
	if e != nil {
		return e
	}
	selection, e = DecodeSelection(raw)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validateNext(selection)
}

func (s *State) validateNext(selection Selection) error {
	if s.snapshot.SelectionFinal || s.snapshot.Position.Sequence != 0 {
		return ErrSelected
	}
	return selection.Verify(s.genesis)
}

func (s *State) Apply(c Certificate) error {
	if s == nil {
		return ErrRegistry
	}
	raw, e := c.CanonicalBytes()
	if e != nil {
		return e
	}
	c, e = DecodeCertificate(raw)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.validateNext(c.Selection); e != nil {
		return e
	}
	if e := c.Verify(s.genesis); e != nil {
		return e
	}
	id, _ := c.Selection.ID()
	aid, _ := c.Selection.Initial.Assignment.ID()
	gid, _ := c.Selection.Initial.ID()
	did, _ := c.Selection.Initial.DescriptorID()
	s.snapshot.Position = custodyfence.Position{Sequence: 1, HeadID: id}
	s.snapshot.SelectedAssignmentID = aid
	s.snapshot.SelectedGenesisID = gid
	s.snapshot.SelectedDescriptorID = did
	s.snapshot.SelectionFinal = true
	return nil
}
