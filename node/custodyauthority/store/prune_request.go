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
// It binds a logical chain context, not a physical database identity/rollback pin.
type PruneRequest struct {
	AssignmentID      types.Hash
	ConsumerPublicKey [32]byte
	Boundary          workchain.CanonicalFloor
}

func (request PruneRequest) CanonicalBytes() ([]byte, error) {
	if request.AssignmentID.IsZero() || request.ConsumerPublicKey == [32]byte{} || !request.Boundary.PruneTicketID.IsZero() {
		return nil, ErrPruneRequest
	}
	floor, err := request.Boundary.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrPruneRequest, err)
	}
	e := codec.NewEncoder(MaximumPruneRequestBytes)
	e.Fixed([]byte("OMCPREQS"))
	e.U16(0)
	e.Fixed(request.AssignmentID[:])
	e.Fixed(request.ConsumerPublicKey[:])
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
	return types.DomainHash("OMESH/custody-prune/request/id/v0", encoded), nil
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
	if err != nil || version != 0 {
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
	if b.BaseID != assignment.BaseID || b.ManifestID != assignment.ManifestID || b.StatementID != assignment.StatementID ||
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
	if err != nil || admission.AuthorityPublicKey != assignment.AuthorityPublicKey || c.AssignmentID != request.AssignmentID ||
		c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Prune || c.ActorPublicKey != request.ConsumerPublicKey || c.OperationID != id {
		return OperationBinding{}, custodyauthority.ErrOperation
	}
	return OperationBinding{AssignmentID: request.AssignmentID, TicketID: ticket, ConsumerPublicKey: request.ConsumerPublicKey,
		OperationID: id, Purpose: custodyauthority.Prune}, nil
}

func pruneEffectMatches(request PruneRequest, admission custodyauthority.Entry, effect workchain.CanonicalPruneEffect) bool {
	ticket, err := admission.ID()
	if err != nil || effect.Operation.AssignmentID != request.AssignmentID || effect.Operation.TicketID != ticket {
		return false
	}
	if _, err := effect.ID(); err != nil {
		return false
	}
	l, le := request.Boundary.CanonicalBytes()
	r, re := effect.Operation.Boundary.CanonicalBytes()
	return le == nil && re == nil && bytes.Equal(l, r)
}
