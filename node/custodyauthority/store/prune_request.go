package store

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const MaximumPruneRequestBytes = 1024

var (
	ErrPruneRequest = errors.New("invalid retained custody prune request")
	ErrPruneStage   = errors.New("custody prune journal stage forbids this operation")
	ErrPruneOutcome = errors.New("prune effect outcome is unresolved; inspect retained storage without re-executing")
)

// PruneRequest is retained BEFORE requesting authority admission. Its ID is
// the admission's OperationID; the later ticket is not part of this preimage.
// StorageID optionally binds a local database incarnation. It is not a physical
// database identity or rollback pin, and must be selected before admission.
type PruneRequest struct {
	FencePolicyID     types.Hash
	ScheduleID        types.Hash
	AssignmentID      types.Hash
	ConsumerPublicKey [32]byte
	StorageID         types.Hash
	Boundary          workchain.CanonicalFloor
}

func (request PruneRequest) CanonicalBytes() ([]byte, error) {
	if !request.FencePolicyID.IsZero() && request.ScheduleID.IsZero() {
		return nil, ErrPruneRequest
	}
	if request.ScheduleID.IsZero() != (request.Boundary.RadixActivationHeight == 0) || (!request.ScheduleID.IsZero() && request.StorageID.IsZero()) || request.AssignmentID.IsZero() || request.ConsumerPublicKey == [32]byte{} || !request.Boundary.PruneTicketID.IsZero() {
		return nil, ErrPruneRequest
	}
	floor, err := request.Boundary.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrPruneRequest, err)
	}
	e := codec.NewEncoder(MaximumPruneRequestBytes)
	e.Fixed([]byte("OMCPREQS"))
	version := uint16(0)
	if !request.StorageID.IsZero() {
		version = 1
	}
	if !request.ScheduleID.IsZero() {
		version = 2
	}
	if !request.FencePolicyID.IsZero() {
		version = 3
	}
	e.U16(version)
	e.Fixed(request.AssignmentID[:])
	e.Fixed(request.ConsumerPublicKey[:])
	if version >= 1 {
		e.Fixed(request.StorageID[:])
	}
	if version >= 2 {
		e.Fixed(request.ScheduleID[:])
	}
	if version == 3 {
		e.Fixed(request.FencePolicyID[:])
	}
	e.BytesField(floor)
	if e.Len() > MaximumPruneRequestBytes {
		return nil, ErrPruneRequest
	}
	return e.Bytes(), nil
}

func (request PruneRequest) ID() (types.Hash, error) {
	encoded, err := request.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	domain := "OMESH/custody-prune/request/id/v0"
	if !request.StorageID.IsZero() {
		domain = "OMESH/custody-prune/request/id/v1"
	}
	if !request.ScheduleID.IsZero() {
		domain = "OMESH/custody-prune/request/id/v2"
	}
	if !request.FencePolicyID.IsZero() {
		domain = "OMESH/custody-prune/request/id/v3"
	}
	return types.DomainHash(domain, encoded), nil
}

func DecodePruneRequest(input []byte) (PruneRequest, error) {
	if len(input) > MaximumPruneRequestBytes {
		return PruneRequest{}, ErrPruneRequest
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCPREQS")) {
		return PruneRequest{}, ErrPruneRequest
	}
	version, err := d.U16()
	if err != nil || version > 3 {
		return PruneRequest{}, ErrPruneRequest
	}
	var request PruneRequest
	for _, destination := range [][]byte{request.AssignmentID[:], request.ConsumerPublicKey[:]} {
		value, err := d.Fixed(32)
		if err != nil {
			return PruneRequest{}, ErrPruneRequest
		}
		copy(destination, value)
	}
	if version >= 1 {
		value, err := d.Fixed(types.HashSize)
		if err != nil {
			return PruneRequest{}, ErrPruneRequest
		}
		copy(request.StorageID[:], value)
		if request.StorageID.IsZero() {
			return PruneRequest{}, ErrPruneRequest
		}
	}
	if version >= 2 {
		value, err := d.Fixed(types.HashSize)
		if err != nil {
			return PruneRequest{}, ErrPruneRequest
		}
		copy(request.ScheduleID[:], value)
		if request.ScheduleID.IsZero() {
			return PruneRequest{}, ErrPruneRequest
		}
	}
	if version == 3 {
		value, err := d.Fixed(types.HashSize)
		if err != nil {
			return PruneRequest{}, ErrPruneRequest
		}
		copy(request.FencePolicyID[:], value)
		if request.FencePolicyID.IsZero() {
			return PruneRequest{}, ErrPruneRequest
		}
	}
	floor, err := d.BytesField(MaximumPruneRequestBytes)
	if err != nil {
		return PruneRequest{}, ErrPruneRequest
	}
	request.Boundary, err = workchain.DecodeCanonicalFloor(floor)
	if err != nil || d.Finish() != nil {
		return PruneRequest{}, ErrPruneRequest
	}
	if _, err := request.CanonicalBytes(); err != nil {
		return PruneRequest{}, err
	}
	return request, nil
}

func validatePruneRequest(assignment custodyauthority.Assignment, request PruneRequest, expectedID types.Hash) error {
	aid, err := assignment.ID()
	if err != nil || aid != request.AssignmentID {
		return custodyauthority.ErrAssignment
	}
	id, err := request.ID()
	if err != nil || id != expectedID || expectedID.IsZero() {
		return ErrPruneRequest
	}
	b := request.Boundary
	if b.BaseID != assignment.BaseID || (request.ScheduleID.IsZero() && (b.ManifestID != assignment.ManifestID || b.StatementID != assignment.StatementID)) || (!request.ScheduleID.IsZero() && (assignment.Version != custodyauthority.Version0 || b.RadixActivationHeight < assignment.ActivationHeight)) ||
		b.Anchor.Height < assignment.ActivationHeight || b.AncestryNodes-2 != b.Anchor.Height-assignment.ActivationHeight {
		return ErrPruneRequest
	}
	for _, consumer := range assignment.Consumers {
		if consumer.PublicKey == request.ConsumerPublicKey && consumer.Purposes&custodyauthority.Prune != 0 {
			return nil
		}
	}
	return custodyauthority.ErrActor
}

func pruneAdmissionBinding(assignment custodyauthority.Assignment, request PruneRequest, admission custodyauthority.Entry) (OperationBinding, error) {
	id, err := request.ID()
	if err != nil {
		return OperationBinding{}, err
	}
	ticket, err := admission.ID()
	c := admission.Command
	if err != nil || c.ScheduleID != request.ScheduleID || admission.AuthorityPublicKey != assignment.AuthorityPublicKey || c.AssignmentID != request.AssignmentID ||
		c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Prune || c.ActorPublicKey != request.ConsumerPublicKey || c.OperationID != id {
		return OperationBinding{}, custodyauthority.ErrOperation
	}
	return OperationBinding{ScheduleID: request.ScheduleID, AssignmentID: request.AssignmentID, TicketID: ticket, ConsumerPublicKey: request.ConsumerPublicKey,
		OperationID: id, Purpose: custodyauthority.Prune}, nil
}

func pruneEffectMatches(request PruneRequest, admission custodyauthority.Entry, effect workchain.CanonicalPruneEffect) bool {
	ticket, err := admission.ID()
	if err != nil || effect.Operation.AssignmentID != request.AssignmentID || effect.Operation.TicketID != ticket ||
		effect.Operation.StorageID != request.StorageID || effect.Operation.ScheduleID != request.ScheduleID {
		return false
	}
	if _, err := effect.ID(); err != nil {
		return false
	}
	l, le := request.Boundary.CanonicalBytes()
	r, re := effect.Operation.Boundary.CanonicalBytes()
	return le == nil && re == nil && bytes.Equal(l, r)
}
