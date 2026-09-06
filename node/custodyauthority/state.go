package custodyauthority

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
)

type Phase uint8

const (
	Accepting Phase = 1 + iota
	Stopping
	Retired
)

var (
	ErrHead        = errors.New("custody authority compare-and-append head differs")
	ErrPhase       = errors.New("custody authority phase forbids this operation")
	ErrActor       = errors.New("custody authority actor is not allowed for this operation")
	ErrOperation   = errors.New("custody authority operation is unknown, reused, or already completed")
	ErrOutstanding = errors.New("custody authority still has outstanding operations")
	ErrLimit       = errors.New("custody authority admission limit reached")
)

// Operation records one admitted effect and its eventual terminal evidence.
// CompletionID/EvidenceID remain zero until the same consumer explicitly closes
// it. An unknown, disconnected or restarted consumer is never presumed done.
type Operation struct {
	TicketID          types.Hash
	ConsumerPublicKey [ed25519.PublicKeySize]byte
	OperationID       types.Hash
	Purpose           Purpose
	CompletionID      types.Hash
	EvidenceID        types.Hash
}

// Snapshot is detached diagnostic state, not a signed current-state proof or an
// import format. Reconstruct state by replaying the ordered entries, never by
// treating a caller-supplied snapshot as authoritative.
type Snapshot struct {
	AssignmentID types.Hash
	Sequence     uint64
	HeadID       types.Hash
	Phase        Phase
	Pending      uint16
	StopID       types.Hash
	StopIntentID types.Hash
	RetirementID types.Hash
	Operations   []Operation // sorted by ticket ID, including completed operations
}

type operationKey struct {
	consumer [ed25519.PublicKeySize]byte
	id       types.Hash
}

// Position is an independently retained exact history pin. A pin prevents
// accepting a different prefix; it does not prove no newer remote entry exists.
type Position struct {
	Sequence uint64
	HeadID   types.Hash
}

// State is a concurrency-safe, in-memory reference machine. Apply validates
// the entire transition before changing anything. It has no clock, deadline,
// automatic release, restart exception, force-complete, resume or activation.
//
// ValidateNext followed by Apply is NOT a transaction across callers. A durable
// adapter must hold its own serialization guard over validation, publication
// and application, publish no grant before durable acceptance, and recover by
// complete replay. This package deliberately supplies no live network adapter.
type State struct {
	mu           sync.Mutex
	assignment   Assignment
	id           types.Hash
	sequence     uint64
	head         types.Hash
	phase        Phase
	pending      uint16
	stopID       types.Hash
	stopIntentID types.Hash
	retirementID types.Hash
	consumers    map[[ed25519.PublicKeySize]byte]Purpose
	operations   map[types.Hash]Operation
	requests     map[operationKey]types.Hash
}

// NewState bootstraps an unused assignment. It must NEVER replace Replay on
// restart or on missing/partitioned storage: doing so would forget admissions.
// expectedID is independently trusted, not extracted from an incoming command.
func NewState(assignment Assignment, expectedID types.Hash) (*State, error) {
	id, err := assignment.ID()
	if err != nil || expectedID.IsZero() || id != expectedID {
		return nil, ErrAssignment
	}
	assignment.Auditors = append([][ed25519.PublicKeySize]byte(nil), assignment.Auditors...)
	assignment.Consumers = append([]Consumer(nil), assignment.Consumers...)
	state := &State{assignment: assignment, id: id, head: id, phase: Accepting,
		consumers:  make(map[[ed25519.PublicKeySize]byte]Purpose, len(assignment.Consumers)),
		operations: make(map[types.Hash]Operation), requests: make(map[operationKey]types.Hash)}
	for _, consumer := range assignment.Consumers {
		state.consumers[consumer.PublicKey] = consumer.Purposes
	}
	return state, nil
}

// Replay reconstructs exactly the independently pinned position, rejecting a
// valid-but-shorter prefix as well as a gap, fork, or extension beyond that pin.
// This verifies historical completeness relative to the pin, not remote freshness.
func Replay(assignment Assignment, expectedID types.Hash, entries []Entry, expected Position) (*State, error) {
	state, err := NewState(assignment, expectedID)
	if err != nil {
		return nil, err
	}
	// Every admission has at most one completion, plus one stop and retirement.
	// Admission exhaustion never consumes the capacity needed to drain/retire.
	if uint64(len(entries)) > 2*uint64(assignment.MaximumOperations)+2 {
		return nil, ErrLimit
	}
	if expected.HeadID.IsZero() || expected.Sequence != uint64(len(entries)) {
		return nil, ErrHead
	}
	for index, entry := range entries {
		if err := state.Apply(entry); err != nil {
			return nil, fmt.Errorf("custody authority entry %d: %w", index+1, err)
		}
	}
	if state.head != expected.HeadID {
		return nil, ErrHead
	}
	return state, nil
}

func (state *State) ValidateNext(entry Entry) error {
	if state == nil {
		return ErrAssignment
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	_, err := state.validateNext(entry)
	return err
}

func (state *State) validateNext(entry Entry) (types.Hash, error) {
	if state.id.IsZero() {
		return types.Hash{}, ErrAssignment
	}
	id, err := entry.ID()
	if err != nil {
		return types.Hash{}, err
	}
	command := entry.Command
	if entry.AuthorityPublicKey != state.assignment.AuthorityPublicKey || command.AssignmentID != state.id {
		return types.Hash{}, ErrAssignment
	}
	if command.ExpectedSequence != state.sequence || command.ExpectedHead != state.head {
		return types.Hash{}, ErrHead
	}
	if state.phase == Retired {
		return types.Hash{}, ErrPhase
	}
	if state.sequence >= 2*uint64(state.assignment.MaximumOperations)+2 {
		return types.Hash{}, ErrLimit
	}
	switch command.Kind {
	case Admit:
		if state.phase != Accepting {
			return types.Hash{}, ErrPhase
		}
		if state.consumers[command.ActorPublicKey]&command.Purpose == 0 {
			return types.Hash{}, ErrActor
		}
		if _, exists := state.requests[operationKey{command.ActorPublicKey, command.OperationID}]; exists {
			return types.Hash{}, ErrOperation
		}
		if uint32(len(state.operations)) >= state.assignment.MaximumOperations || state.pending >= state.assignment.MaximumPending {
			return types.Hash{}, ErrLimit
		}
	case Complete:
		if state.phase != Accepting && state.phase != Stopping {
			return types.Hash{}, ErrPhase
		}
		operation, exists := state.operations[command.TicketID]
		if !exists || !operation.CompletionID.IsZero() {
			return types.Hash{}, ErrOperation
		}
		if operation.ConsumerPublicKey != command.ActorPublicKey {
			return types.Hash{}, ErrActor
		}
		if state.pending == 0 {
			return types.Hash{}, ErrOperation
		}
	case Stop:
		if command.ActorPublicKey != state.assignment.AuthorityPublicKey {
			return types.Hash{}, ErrActor
		}
		if state.phase != Accepting {
			return types.Hash{}, ErrPhase
		}
	case Retire:
		if command.ActorPublicKey != state.assignment.AuthorityPublicKey {
			return types.Hash{}, ErrActor
		}
		if state.phase != Stopping || command.EvidenceID != state.stopID {
			return types.Hash{}, ErrPhase
		}
		if state.pending != 0 {
			return types.Hash{}, ErrOutstanding
		}
	default:
		return types.Hash{}, ErrCommand
	}
	return id, nil
}

func (state *State) Apply(entry Entry) error {
	if state == nil {
		return ErrAssignment
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	id, err := state.validateNext(entry)
	if err != nil {
		return err
	}
	c := entry.Command
	switch c.Kind {
	case Admit:
		state.operations[id] = Operation{TicketID: id, ConsumerPublicKey: c.ActorPublicKey, OperationID: c.OperationID, Purpose: c.Purpose}
		state.requests[operationKey{c.ActorPublicKey, c.OperationID}] = id
		state.pending++
	case Complete:
		operation := state.operations[c.TicketID]
		operation.CompletionID, operation.EvidenceID = id, c.EvidenceID
		state.operations[c.TicketID] = operation
		state.pending--
	case Stop:
		state.phase, state.stopID, state.stopIntentID = Stopping, id, c.EvidenceID
	case Retire:
		state.phase, state.retirementID = Retired, id
	}
	state.sequence++
	state.head = id
	return nil
}

func (state *State) Snapshot() (Snapshot, error) {
	if state == nil {
		return Snapshot{}, ErrAssignment
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.id.IsZero() {
		return Snapshot{}, ErrAssignment
	}
	snapshot := Snapshot{AssignmentID: state.id, Sequence: state.sequence, HeadID: state.head,
		Phase: state.phase, Pending: state.pending, StopID: state.stopID, StopIntentID: state.stopIntentID, RetirementID: state.retirementID,
		Operations: make([]Operation, 0, len(state.operations))}
	for _, operation := range state.operations {
		snapshot.Operations = append(snapshot.Operations, operation)
	}
	sort.Slice(snapshot.Operations, func(i, j int) bool {
		return types.CompareHash(snapshot.Operations[i].TicketID, snapshot.Operations[j].TicketID) < 0
	})
	return snapshot, nil
}

// LookupOperation lets a retry distinguish unknown, still-pending and completed
// work without admitting the same operation twice. It returns a detached point-
// in-time observation, not permission to execute or to reuse a completed ticket.
func (state *State) LookupOperation(consumer [ed25519.PublicKeySize]byte, operationID types.Hash) (Operation, bool) {
	if state == nil {
		return Operation{}, false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	id, exists := state.requests[operationKey{consumer, operationID}]
	if !exists {
		return Operation{}, false
	}
	return state.operations[id], true
}
