package custodyfence

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const ObservationBytes = 308
const ObservationBytesV1 = ObservationBytes + 32

// Observation authenticates exact current local metadata for one request ID.
// It is historical upon release, never an execution grant or an external pin.
type Observation struct {
	Version   uint16
	RequestID types.Hash
	Witness   [32]byte
	Snapshot  Snapshot
	PendingID types.Hash
	Signature [64]byte
}

func (o Observation) unsignedBytes() ([]byte, error) {
	x := o.Snapshot
	if (o.Version != Version0 && o.Version != Version1) || o.RequestID.IsZero() || types.Hash(o.Witness).IsZero() || x.ScopeID.IsZero() || x.Position.HeadID.IsZero() || x.Position.Sequence > 3 {
		return nil, ErrWitness
	}
	if o.Version == Version0 && !x.SessionID.IsZero() {
		return nil, ErrWitness
	}
	if o.Version == Version1 && (x.Phase == Claimed || x.Phase == Unknown || x.Phase == ResultRecorded) && x.SessionID.IsZero() {
		return nil, ErrWitness
	}
	if (x.Phase == Unused || x.Phase == UnclaimedClosed) && !x.SessionID.IsZero() {
		return nil, ErrWitness
	}
	switch x.Phase {
	case Unused:
		if x.Position.Sequence != 0 || x.Position.HeadID != x.ScopeID || !x.ClaimID.IsZero() || !x.EvidenceID.IsZero() || x.ObligationHeld {
			return nil, ErrWitness
		}
	case Claimed:
		if x.Position.Sequence != 1 || x.ClaimID != x.Position.HeadID || x.ClaimID.IsZero() || !x.EvidenceID.IsZero() || !x.ObligationHeld {
			return nil, ErrWitness
		}
	case Unknown:
		if x.Position.Sequence != 2 || x.ClaimID.IsZero() || x.EvidenceID.IsZero() || !x.ObligationHeld {
			return nil, ErrWitness
		}
	case ResultRecorded:
		if (x.Position.Sequence != 2 && x.Position.Sequence != 3) || x.ClaimID.IsZero() || x.EvidenceID.IsZero() || !x.ObligationHeld {
			return nil, ErrWitness
		}
	case UnclaimedClosed:
		if x.Position.Sequence != 1 || !x.ClaimID.IsZero() || x.EvidenceID.IsZero() || x.ObligationHeld {
			return nil, ErrWitness
		}
	default:
		return nil, ErrWitness
	}
	e := codec.NewEncoder(ObservationBytes)
	e.Fixed([]byte("OMCFOB00"))
	e.U16(o.Version)
	for _, b := range [][]byte{o.RequestID[:], o.Witness[:], x.ScopeID[:]} {
		e.Fixed(b)
	}
	e.U64(x.Position.Sequence)
	e.Fixed(x.Position.HeadID[:])
	e.Fixed(o.PendingID[:])
	e.U8(uint8(x.Phase))
	e.Fixed(x.ClaimID[:])
	e.Fixed(x.EvidenceID[:])
	if x.ObligationHeld {
		e.U8(1)
	} else {
		e.U8(0)
	}
	if o.Version == Version1 {
		e.Fixed(x.SessionID[:])
	}
	return e.Bytes(), nil
}
func (o Observation) CanonicalBytes() ([]byte, error) {
	b, err := o.unsignedBytes()
	if err != nil {
		return nil, err
	}
	h := types.DomainHash(fenceDomain(o.Version, "observation/signature"), b)
	if !ed25519.Verify(o.Witness[:], h[:], o.Signature[:]) {
		return nil, ErrWitness
	}
	return append(b, o.Signature[:]...), nil
}
func (o Observation) Verify(s Scope, request types.Hash, witness [32]byte) error {
	if _, err := o.CanonicalBytes(); err != nil {
		return err
	}
	id, err := s.ID()
	if err != nil || o.Snapshot.ScopeID != id || o.Version != s.Version || o.RequestID != request || o.Witness != witness {
		return ErrWitness
	}
	for _, k := range s.Witnesses {
		if k == witness {
			return nil
		}
	}
	return ErrWitness
}
func DecodeObservation(b []byte) (Observation, error) {
	var o Observation
	if len(b) != ObservationBytes && len(b) != ObservationBytesV1 {
		return o, ErrWitness
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFOB00" {
		return o, ErrWitness
	}
	o.Version, _ = d.U16()
	if (o.Version == Version0 && len(b) != ObservationBytes) || (o.Version == Version1 && len(b) != ObservationBytesV1) {
		return o, ErrWitness
	}
	for _, v := range [][]byte{o.RequestID[:], o.Witness[:], o.Snapshot.ScopeID[:]} {
		readFixed(d, v)
	}
	o.Snapshot.Position.Sequence, _ = d.U64()
	readFixed(d, o.Snapshot.Position.HeadID[:])
	readFixed(d, o.PendingID[:])
	phase, _ := d.U8()
	o.Snapshot.Phase = Phase(phase)
	readFixed(d, o.Snapshot.ClaimID[:])
	readFixed(d, o.Snapshot.EvidenceID[:])
	held, _ := d.U8()
	if held > 1 {
		return Observation{}, ErrWitness
	}
	o.Snapshot.ObligationHeld = held == 1
	if o.Version == Version1 {
		readFixed(d, o.Snapshot.SessionID[:])
	}
	readFixed(d, o.Signature[:])
	if _, err := o.CanonicalBytes(); err != nil {
		return Observation{}, err
	}
	return o, nil
}

// Inspect holds the original kernel lock and exact pin while reading. It loads
// no private seed, signs nothing, and returns no mutable witness owner.
func Inspect(path string, s Scope, pin types.Hash, public [32]byte, expected WitnessPin) (snapshot Snapshot, observed WitnessPin, returnErr error) {
	w, err := openMember(path, s, pin, public, nil, func(w *Witness) error {
		if w.pin() != expected {
			return ErrTransition
		}
		return nil
	})
	if err != nil {
		return snapshot, observed, err
	}
	defer func() { returnErr = errors.Join(returnErr, w.Close()) }()
	return w.Snapshot()
}

// Observe signs only facts read under the retained original witness owner.
func (w *Witness) Observe(request types.Hash) (Observation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !validKey(w.key) || request.IsZero() {
		return Observation{}, ErrWitness
	}
	if err := w.check(); err != nil {
		return Observation{}, err
	}
	o := Observation{Version: w.state.scope.Version, RequestID: request, Witness: w.public, Snapshot: w.state.Snapshot(), PendingID: w.pin().PendingID}
	b, err := o.unsignedBytes()
	if err != nil {
		return Observation{}, err
	}
	h := types.DomainHash(fenceDomain(o.Version, "observation/signature"), b)
	copy(o.Signature[:], ed25519.Sign(w.key, h[:]))
	return o, nil
}

// VoteAt permits exact lost-response retry, never a competing proposal. A
// nonzero independently retained pending ID must match the original journal.
func (w *Witness) VoteAt(expected WitnessPin, c Command) (Vote, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return Vote{}, err
	}
	actual := w.pin()
	id, err := c.ID()
	if err != nil {
		return Vote{}, err
	}
	if actual.Position != expected.Position || (!expected.PendingID.IsZero() && expected.PendingID != actual.PendingID) || (!actual.PendingID.IsZero() && actual.PendingID != id) {
		return Vote{}, ErrTransition
	}
	return w.voteLocked(c)
}

// CommitAt permits only the selected pre-position or this exact one-transition
// extension after lost output. A quorum may override a minority local proposal;
// it cannot change a nonzero independently retained pending pin.
func (w *Witness) CommitAt(expected WitnessPin, cert Certificate) error {
	b, err := cert.CanonicalBytes()
	if err != nil {
		return err
	}
	cert, err = DecodeCertificate(b)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return err
	}
	actual := w.pin()
	id, _ := cert.Command.ID()
	if actual.Position == expected.Position {
		if !expected.PendingID.IsZero() && actual.PendingID != expected.PendingID {
			return ErrTransition
		}
	} else if actual.Position.Sequence != expected.Position.Sequence+1 || actual.Position.HeadID != id || !actual.PendingID.IsZero() {
		return ErrTransition
	} else if !w.historicalPendingMatches(expected) {
		return ErrTransition
	}
	if cert.Command.ExpectedSequence != expected.Position.Sequence || cert.Command.ExpectedHead != expected.Position.HeadID {
		return ErrTransition
	}
	return w.commitLocked(cert, b)
}

func (w *Witness) historicalPendingMatches(before WitnessPin) bool {
	if before.PendingID.IsZero() {
		return true
	}
	c, err := DecodeCommand(w.files[recordName(before.Position.Sequence+1, "vote")])
	if err != nil {
		return false
	}
	id, err := c.ID()
	return err == nil && id == before.PendingID
}
