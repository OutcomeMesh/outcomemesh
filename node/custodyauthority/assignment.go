// Package custodyauthority implements the bounded reference state machine for
// one operational archive-custody assignment. It is not consensus, a network
// authority, durable storage, or a live permission to use an archive. Adapters
// must durably serialize this history and enforce it at every acceptance path.
package custodyauthority

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0               uint16 = 0
	Version1               uint16 = 1
	MaximumMembers                = 64
	MaximumOperations      uint32 = 65_536
	MaximumPending         uint16 = 1_024
	MaximumAssignmentBytes        = 8 * 1024
)

// Purpose identifies the live effect being serialized, not an evidence-key
// role. Consumer control keys are deliberately separate from evidence keys.
type Purpose uint8

const (
	Audit Purpose = 1 << iota
	Serve
	Prune
	AllPurposes = Audit | Serve | Prune
)

type Consumer struct {
	PublicKey [ed25519.PublicKeySize]byte
	Purposes  Purpose
}

// Assignment is a closed, immutable bootstrap scope. IncarnationID distinguishes
// explicitly selected generations; it must not be inferred from a peer's input.
// Changing the assignment is not activation: version 0 has no successor or
// membership-update transition. The operator must independently pin its ID.
type Assignment struct {
	Version            uint16
	NetworkID          uint32
	GenesisID          types.Hash
	ActivationHeight   uint64
	BaseID             types.Hash
	ManifestID         types.Hash
	StatementID        types.Hash
	InitialReceiptID   types.Hash
	CustodyPolicyID    types.Hash
	IncarnationID      types.Hash
	AuthorityPublicKey [ed25519.PublicKeySize]byte
	ReplicaPublicKey   [ed25519.PublicKeySize]byte
	Auditors           [][ed25519.PublicKeySize]byte
	Consumers          []Consumer
	MaximumOperations  uint32
	MaximumPending     uint16
	// Version 1 independently pins the remote worker's control and transport
	// roles. Version 0 must leave both zero; this is not an in-place upgrade.
	RemoteControlPublicKey   [ed25519.PublicKeySize]byte
	RemoteTransportPublicKey [ed25519.PublicKeySize]byte
}

var (
	ErrAssignment   = errors.New("invalid custody authority assignment")
	assignmentMagic = [8]byte{'O', 'M', 'C', 'A', 'A', 'S', 'G', 'N'}
)

func (assignment Assignment) validate() error {
	if (assignment.Version != Version0 && assignment.Version != Version1) || assignment.NetworkID == 0 || assignment.GenesisID.IsZero() ||
		assignment.ActivationHeight == 0 || assignment.BaseID.IsZero() || assignment.ManifestID.IsZero() ||
		assignment.StatementID.IsZero() || assignment.InitialReceiptID.IsZero() || assignment.CustodyPolicyID.IsZero() ||
		assignment.IncarnationID.IsZero() || len(assignment.Auditors) == 0 || len(assignment.Auditors) > MaximumMembers ||
		len(assignment.Consumers) == 0 || len(assignment.Consumers) > MaximumMembers ||
		assignment.MaximumOperations == 0 || assignment.MaximumOperations > MaximumOperations ||
		assignment.MaximumPending == 0 || assignment.MaximumPending > MaximumPending ||
		uint32(assignment.MaximumPending) > assignment.MaximumOperations {
		return ErrAssignment
	}
	seen := make(map[[ed25519.PublicKeySize]byte]bool)
	add := func(key [ed25519.PublicKeySize]byte) bool {
		if types.Hash(key).IsZero() || seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	if !add(assignment.AuthorityPublicKey) || !add(assignment.ReplicaPublicKey) {
		return ErrAssignment
	}
	for index, key := range assignment.Auditors {
		if !add(key) || (index > 0 && bytes.Compare(assignment.Auditors[index-1][:], key[:]) >= 0) {
			return ErrAssignment
		}
	}
	var covered Purpose
	for index, consumer := range assignment.Consumers {
		if !add(consumer.PublicKey) || consumer.Purposes == 0 || consumer.Purposes & ^AllPurposes != 0 ||
			(index > 0 && bytes.Compare(assignment.Consumers[index-1].PublicKey[:], consumer.PublicKey[:]) >= 0) {
			return ErrAssignment
		}
		covered |= consumer.Purposes
	}
	// This checks declared coverage, not that the operator enumerated every
	// real deployment. Unknown or omitted consumers receive no admission.
	if covered != AllPurposes {
		return ErrAssignment
	}
	if assignment.Version == Version0 {
		if assignment.RemoteControlPublicKey != [32]byte{} || assignment.RemoteTransportPublicKey != [32]byte{} {
			return ErrAssignment
		}
	} else if !add(assignment.RemoteControlPublicKey) || !add(assignment.RemoteTransportPublicKey) {
		return ErrAssignment
	}
	return nil
}

func (assignment Assignment) CanonicalBytes() ([]byte, error) {
	if err := assignment.validate(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumAssignmentBytes)
	e.Fixed(assignmentMagic[:])
	e.U16(assignment.Version)
	e.U32(assignment.NetworkID)
	e.Fixed(assignment.GenesisID[:])
	e.U64(assignment.ActivationHeight)
	for _, id := range []types.Hash{assignment.BaseID, assignment.ManifestID, assignment.StatementID,
		assignment.InitialReceiptID, assignment.CustodyPolicyID, assignment.IncarnationID} {
		e.Fixed(id[:])
	}
	e.Fixed(assignment.AuthorityPublicKey[:])
	e.Fixed(assignment.ReplicaPublicKey[:])
	e.U32(assignment.MaximumOperations)
	e.U16(assignment.MaximumPending)
	e.U16(uint16(len(assignment.Auditors)))
	for _, key := range assignment.Auditors {
		e.Fixed(key[:])
	}
	e.U16(uint16(len(assignment.Consumers)))
	for _, consumer := range assignment.Consumers {
		e.Fixed(consumer.PublicKey[:])
		e.U8(uint8(consumer.Purposes))
	}
	if assignment.Version == Version1 {
		e.Fixed(assignment.RemoteControlPublicKey[:])
		e.Fixed(assignment.RemoteTransportPublicKey[:])
	}
	return e.Bytes(), nil
}

func DecodeAssignment(input []byte) (Assignment, error) {
	if len(input) == 0 || len(input) > MaximumAssignmentBytes {
		return Assignment{}, ErrAssignment
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(len(assignmentMagic))
	if err != nil || !bytes.Equal(magic, assignmentMagic[:]) {
		return Assignment{}, ErrAssignment
	}
	var a Assignment
	if a.Version, err = d.U16(); err != nil {
		return Assignment{}, ErrAssignment
	}
	if a.NetworkID, err = d.U32(); err != nil {
		return Assignment{}, ErrAssignment
	}
	if !decodeFixed(d, a.GenesisID[:]) {
		return Assignment{}, ErrAssignment
	}
	if a.ActivationHeight, err = d.U64(); err != nil {
		return Assignment{}, ErrAssignment
	}
	for _, id := range []*types.Hash{&a.BaseID, &a.ManifestID, &a.StatementID, &a.InitialReceiptID, &a.CustodyPolicyID, &a.IncarnationID} {
		if !decodeFixed(d, id[:]) {
			return Assignment{}, ErrAssignment
		}
	}
	if !decodeFixed(d, a.AuthorityPublicKey[:]) || !decodeFixed(d, a.ReplicaPublicKey[:]) {
		return Assignment{}, ErrAssignment
	}
	if a.MaximumOperations, err = d.U32(); err != nil {
		return Assignment{}, ErrAssignment
	}
	if a.MaximumPending, err = d.U16(); err != nil {
		return Assignment{}, ErrAssignment
	}
	count, err := d.U16()
	if err != nil || count == 0 || count > MaximumMembers || int(count)*ed25519.PublicKeySize > d.Remaining() {
		return Assignment{}, ErrAssignment
	}
	a.Auditors = make([][ed25519.PublicKeySize]byte, count)
	for index := range a.Auditors {
		if !decodeFixed(d, a.Auditors[index][:]) {
			return Assignment{}, ErrAssignment
		}
	}
	count, err = d.U16()
	if err != nil || count == 0 || count > MaximumMembers || int(count)*(ed25519.PublicKeySize+1) > d.Remaining() {
		return Assignment{}, ErrAssignment
	}
	a.Consumers = make([]Consumer, count)
	for index := range a.Consumers {
		if !decodeFixed(d, a.Consumers[index].PublicKey[:]) {
			return Assignment{}, ErrAssignment
		}
		purpose, _ := d.U8()
		a.Consumers[index].Purposes = Purpose(purpose)
	}
	if a.Version == Version1 && (!decodeFixed(d, a.RemoteControlPublicKey[:]) || !decodeFixed(d, a.RemoteTransportPublicKey[:])) {
		return Assignment{}, ErrAssignment
	}
	if d.Finish() != nil || a.validate() != nil {
		return Assignment{}, ErrAssignment
	}
	return a, nil
}

func (assignment Assignment) ID() (types.Hash, error) {
	encoded, err := assignment.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(authorityDomain(assignment.Version, "assignment/id"), encoded), nil
}

// WithRemoteParticipant derives a NEW opt-in version-1 bootstrap scope and ID.
// It does not migrate, activate or replace any existing owner/history. The
// caller must separately establish and independently pin the fresh assignment.
func WithRemoteParticipant(assignmentV0 Assignment, control, transport [32]byte) (Assignment, error) {
	if assignmentV0.Version != Version0 {
		return Assignment{}, ErrAssignment
	}
	b, err := assignmentV0.CanonicalBytes()
	if err != nil {
		return Assignment{}, err
	}
	a, err := DecodeAssignment(b)
	if err != nil {
		return Assignment{}, err
	}
	a.Version, a.RemoteControlPublicKey, a.RemoteTransportPublicKey = Version1, control, transport
	if err := a.validate(); err != nil {
		return Assignment{}, err
	}
	return a, nil
}

// MaximumEntries preserves drain capacity for every admitted operation. A V1
// Serve ticket may additionally have one Begin and one Drained record. Unknown
// versions return zero; callers validate the assignment before using this bound.
func MaximumEntries(assignment Assignment) uint64 {
	switch assignment.Version {
	case Version0:
		return 2*uint64(assignment.MaximumOperations) + 2
	case Version1:
		return 4*uint64(assignment.MaximumOperations) + 2
	default:
		return 0
	}
}

func authorityDomain(version uint16, suffix string) string {
	if version == Version1 {
		return "OMESH/custody-authority/" + suffix + "/v1"
	}
	return "OMESH/custody-authority/" + suffix + "/v0"
}

func decodeFixed(d *codec.Decoder, destination []byte) bool {
	value, err := d.Fixed(len(destination))
	if err != nil {
		return false
	}
	copy(destination, value)
	return true
}
