package custodyfence

import "github.com/outcomemesh/outcomemesh/core/types"

type Phase uint8

const (
	Unused Phase = iota
	Claimed
	Unknown
	ResultRecorded
	UnclaimedClosed
)

type Position struct {
	Sequence uint64
	HeadID   types.Hash
}

// Snapshot is diagnostic, never a current grant. ResultRecorded still retains
// the obligation: this protocol does not validate custody, settle tickets or
// authorize deletion. UnclaimedClosed proves absence of a quorum claim under
// this scope, not absence of physical work outside the fenced adapter.
type Snapshot struct {
	ScopeID             types.Hash
	Position            Position
	Phase               Phase
	ClaimID, EvidenceID types.Hash
	SessionID           types.Hash `json:",omitzero"`
	ObligationHeld      bool
}

// State is a sequential reference machine. Witness owns serialization and
// durability. Callers must not use detached State values as execution rights.
type State struct {
	scope    Scope
	snapshot Snapshot
}

func NewState(s Scope, pin types.Hash) (*State, error) {
	id, err := s.ID()
	if err != nil || pin.IsZero() || pin != id {
		return nil, ErrScope
	}
	s.Witnesses = append([][32]byte(nil), s.Witnesses...)
	return &State{scope: s, snapshot: Snapshot{ScopeID: id, Position: Position{HeadID: id}}}, nil
}
func (s *State) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return s.snapshot
}
func (s *State) ValidateNext(c Command) error {
	if s == nil {
		return ErrScope
	}
	if err := c.Verify(s.scope); err != nil {
		return err
	}
	x := s.snapshot
	if c.ExpectedSequence != x.Position.Sequence || c.ExpectedHead != x.Position.HeadID {
		return ErrTransition
	}
	switch c.Kind {
	case Claim, CloseUnclaimed:
		if x.Phase != Unused {
			return ErrTransition
		}
	case MarkUnknown:
		if x.Phase != Claimed || c.ClaimID != x.ClaimID {
			return ErrTransition
		}
	case RecordResult:
		if (x.Phase != Claimed && x.Phase != Unknown) || c.ClaimID != x.ClaimID {
			return ErrTransition
		}
	default:
		return ErrTransition
	}
	return nil
}
func (s *State) Apply(c Certificate) error {
	if s == nil {
		return ErrScope
	}
	if err := c.Verify(s.scope); err != nil {
		return err
	}
	if err := s.ValidateNext(c.Command); err != nil {
		return err
	}
	id, _ := c.Command.ID()
	x := s.snapshot
	x.Position = Position{Sequence: x.Position.Sequence + 1, HeadID: id}
	x.EvidenceID = c.Command.EvidenceID
	switch c.Command.Kind {
	case Claim:
		x.Phase = Claimed
		x.ClaimID = id
		x.EvidenceID = types.Hash{}
		if c.Command.Version == Version1 {
			x.SessionID = c.Command.EvidenceID
		}
		x.ObligationHeld = true
	case MarkUnknown:
		x.Phase = Unknown
	case RecordResult:
		x.Phase = ResultRecorded
	case CloseUnclaimed:
		x.Phase = UnclaimedClosed
	}
	s.snapshot = x
	return nil
}
