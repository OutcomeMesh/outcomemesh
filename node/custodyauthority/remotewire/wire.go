// Package remotewire carries bounded remote custody CONTROL metadata only.
// Canonical proposals and replies are not current authority or execution
// capabilities. Owned endpoints must enforce original owners, durable Begin,
// actual worker drain, and original local result verification separately.
// Custody proof bodies never travel through this protocol.
package remotewire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
)

const (
	Version0      uint16 = 0
	MaxFrameBytes        = 4 * 1024
)

type Kind uint8

const (
	Start Kind = 1 + iota
	Seal
	Reconcile
)

type Status uint8

const (
	StatusStarted Status = 1 + iota
	StatusDrained
)

var (
	ErrProtocol    = errors.New("invalid remote custody control protocol")
	ErrUnconfirmed = errors.New("no complete confirmed remote control reply; retain the exact plan and original hold")
)

type Request struct {
	Version uint16
	Kind    Kind
	Nonce   types.Hash
	Plan    remoteworker.Plan
	Begin   custodyauthority.Entry
}

func (r Request) validateShape() error {
	if r.Version != Version0 || (r.Kind != Start && r.Kind != Seal && r.Kind != Reconcile) || r.Nonce.IsZero() {
		return ErrProtocol
	}
	planID, err := r.Plan.ID()
	if err != nil {
		return errors.Join(ErrProtocol, err)
	}
	if _, err := r.Begin.CanonicalBytes(); err != nil {
		return errors.Join(ErrProtocol, err)
	}
	c := r.Begin.Command
	ticket, err := r.Plan.Admission.ID()
	if err != nil || r.Begin.Version != custodyauthority.Version1 || c.Version != custodyauthority.Version1 || c.Kind != custodyauthority.RemoteBegin || c.Purpose != custodyauthority.Serve ||
		c.AssignmentID != r.Plan.AssignmentID || r.Begin.AuthorityPublicKey != r.Plan.Admission.AuthorityPublicKey || c.OperationID != planID || c.TicketID != ticket || c.EvidenceID != r.Plan.Admission.Command.OperationID {
		return errors.Join(ErrProtocol, err)
	}
	return nil
}

// Validate checks static scope and independent exact pins only. It cannot show
// that A applied Begin or that a remote Start may execute now.
func (r Request) Validate(a custodyauthority.Assignment, expectedPlanID, expectedBeginID types.Hash) error {
	if err := r.validateShape(); err != nil {
		return err
	}
	if err := r.Plan.Validate(a); err != nil {
		return errors.Join(ErrProtocol, err)
	}
	p, err := r.Plan.ID()
	if err != nil {
		return err
	}
	b, err := r.Begin.ID()
	if err != nil || expectedPlanID.IsZero() || expectedBeginID.IsZero() || p != expectedPlanID || b != expectedBeginID {
		return errors.Join(ErrProtocol, err)
	}
	c := r.Begin.Command
	draft, err := custodyauthority.BuildRemoteBeginCommand(a, r.Plan.Admission, p, custodyauthority.Position{Sequence: c.ExpectedSequence, HeadID: c.ExpectedHead})
	c.Signature = [64]byte{}
	if err != nil || c != draft {
		return errors.Join(ErrProtocol, err)
	}
	return nil
}

func (r Request) CanonicalBytes() ([]byte, error) {
	if err := r.validateShape(); err != nil {
		return nil, err
	}
	p, _ := r.Plan.CanonicalBytes()
	b, _ := r.Begin.CanonicalBytes()
	e := codec.NewEncoder(MaxFrameBytes)
	e.Fixed([]byte("OMCRCREQ"))
	e.U16(r.Version)
	e.U8(uint8(r.Kind))
	e.Fixed(r.Nonce[:])
	e.BytesField(p)
	e.BytesField(b)
	encoded := e.Bytes()
	if len(encoded) > MaxFrameBytes {
		return nil, ErrProtocol
	}
	return encoded, nil
}

func DecodeRequest(input []byte) (Request, error) {
	if len(input) == 0 || len(input) > MaxFrameBytes {
		return Request{}, ErrProtocol
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCRCREQ")) {
		return Request{}, ErrProtocol
	}
	var r Request
	r.Version, err = d.U16()
	if err != nil {
		return Request{}, ErrProtocol
	}
	kind, err := d.U8()
	if err != nil {
		return Request{}, ErrProtocol
	}
	r.Kind = Kind(kind)
	if !readFixed(d, r.Nonce[:]) {
		return Request{}, ErrProtocol
	}
	p, err := d.BytesField(remoteworker.MaximumPlanBytes)
	if err != nil {
		return Request{}, ErrProtocol
	}
	r.Plan, err = remoteworker.DecodePlan(p)
	if err != nil {
		return Request{}, errors.Join(ErrProtocol, err)
	}
	b, err := d.BytesField(custodyauthority.MaximumEntryBytes)
	if err != nil {
		return Request{}, ErrProtocol
	}
	r.Begin, err = custodyauthority.DecodeEntry(b)
	if err != nil {
		return Request{}, errors.Join(ErrProtocol, err)
	}
	if d.Finish() != nil {
		return Request{}, ErrProtocol
	}
	if err := r.validateShape(); err != nil {
		return Request{}, err
	}
	return r, nil
}

// Response contains no result body. RetainedResult's ResultID is the exact
// original custody journal-entry ID; a concrete A validator must compare it
// with A's ORIGINAL accepted local Audit entry, not a copied B journal.
type Response struct {
	Version uint16
	Status  Status
	Nonce   types.Hash
	PlanID  types.Hash
	BeginID types.Hash
	Seal    remoteworker.Seal
	Drain   custodyauthority.Command
}

func (s Response) validateShape() error {
	if s.Version != Version0 || s.Nonce.IsZero() || s.PlanID.IsZero() || s.BeginID.IsZero() {
		return ErrProtocol
	}
	switch s.Status {
	case StatusStarted:
		if s.Seal != (remoteworker.Seal{}) || s.Drain != (custodyauthority.Command{}) {
			return ErrProtocol
		}
	case StatusDrained:
		id, err := s.Seal.ID()
		if err != nil || s.Seal.PlanID != s.PlanID || s.Seal.BeginID != s.BeginID {
			return errors.Join(ErrProtocol, err)
		}
		if _, err := s.Drain.CanonicalBytes(); err != nil {
			return errors.Join(ErrProtocol, err)
		}
		c := s.Drain
		if c.Version != custodyauthority.Version1 || c.Kind != custodyauthority.RemoteDrained || c.OperationID != s.BeginID || c.EvidenceID != id {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}

func (s Response) CanonicalBytes() ([]byte, error) {
	if err := s.validateShape(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaxFrameBytes)
	e.Fixed([]byte("OMCRCRSP"))
	e.U16(s.Version)
	e.U8(uint8(s.Status))
	for _, id := range []types.Hash{s.Nonce, s.PlanID, s.BeginID} {
		e.Fixed(id[:])
	}
	if s.Status == StatusDrained {
		seal, _ := s.Seal.CanonicalBytes()
		drain, _ := s.Drain.CanonicalBytes()
		e.BytesField(seal)
		e.BytesField(drain)
	}
	b := e.Bytes()
	if len(b) > MaxFrameBytes {
		return nil, ErrProtocol
	}
	return b, nil
}

func DecodeResponse(input []byte) (Response, error) {
	if len(input) == 0 || len(input) > MaxFrameBytes {
		return Response{}, ErrProtocol
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCRCRSP")) {
		return Response{}, ErrProtocol
	}
	var s Response
	s.Version, err = d.U16()
	if err != nil {
		return Response{}, ErrProtocol
	}
	status, err := d.U8()
	if err != nil {
		return Response{}, ErrProtocol
	}
	s.Status = Status(status)
	for _, id := range []*types.Hash{&s.Nonce, &s.PlanID, &s.BeginID} {
		if !readFixed(d, id[:]) {
			return Response{}, ErrProtocol
		}
	}
	if s.Status == StatusDrained {
		seal, err := d.BytesField(remoteworker.SealBytes)
		if err != nil {
			return Response{}, ErrProtocol
		}
		s.Seal, err = remoteworker.DecodeSeal(seal)
		if err != nil {
			return Response{}, errors.Join(ErrProtocol, err)
		}
		drain, err := d.BytesField(custodyauthority.MaximumCommandBytes)
		if err != nil {
			return Response{}, ErrProtocol
		}
		s.Drain, err = custodyauthority.DecodeCommand(drain)
		if err != nil {
			return Response{}, errors.Join(ErrProtocol, err)
		}
	}
	if d.Finish() != nil {
		return Response{}, ErrProtocol
	}
	if err := s.validateShape(); err != nil {
		return Response{}, err
	}
	return s, nil
}

func validateContext(r Request, s Response) error {
	if err := r.validateShape(); err != nil {
		return err
	}
	if err := s.validateShape(); err != nil {
		return err
	}
	p, _ := r.Plan.ID()
	b, _ := r.Begin.ID()
	if s.Nonce != r.Nonce || s.PlanID != p || s.BeginID != b || r.Kind == Seal && s.Status != StatusDrained {
		return ErrProtocol
	}
	if s.Status == StatusDrained {
		c, begin := s.Drain, r.Begin.Command
		if c.AssignmentID != r.Plan.AssignmentID || c.ActorPublicKey != begin.ActorPublicKey || c.TicketID != begin.TicketID || c.ExpectedSequence != begin.ExpectedSequence+1 || c.ExpectedHead != b {
			return ErrProtocol
		}
	}
	return nil
}

// ValidateResponse verifies B's signed immutable drain commitment. It does not
// attest physical quiescence, validate a proof body or apply an A transition.
// StatusStarted is advisory and cannot clear A's hold.
func ValidateResponse(a custodyauthority.Assignment, r Request, s Response) error {
	p, err := r.Plan.ID()
	if err != nil {
		return err
	}
	b, err := r.Begin.ID()
	if err != nil {
		return err
	}
	if err := r.Validate(a, p, b); err != nil {
		return err
	}
	if err := validateContext(r, s); err != nil {
		return err
	}
	if s.Status == StatusDrained {
		id, _ := s.Seal.ID()
		draft, err := custodyauthority.BuildRemoteDrainedCommand(a, r.Begin, id, custodyauthority.Position{Sequence: s.Drain.ExpectedSequence, HeadID: s.Drain.ExpectedHead})
		command := s.Drain
		command.Signature = [64]byte{}
		if err != nil || command != draft {
			return errors.Join(ErrProtocol, err)
		}
	}
	return nil
}

func ReadRequest(reader io.Reader) (Request, error) {
	b, err := readFrame(reader)
	if err != nil {
		return Request{}, err
	}
	return DecodeRequest(b)
}
func ReadResponse(reader io.Reader) (Response, error) {
	b, err := readFrame(reader)
	if err != nil {
		return Response{}, err
	}
	return DecodeResponse(b)
}
func WriteRequest(writer io.Writer, r Request) error {
	b, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	return writeFrame(writer, b)
}
func WriteResponse(writer io.Writer, s Response) error {
	b, err := s.CanonicalBytes()
	if err != nil {
		return err
	}
	return writeFrame(writer, b)
}

func readFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, ErrProtocol
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrameBytes {
		return nil, ErrProtocol
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(reader, b)
	return b, err
}
func writeFrame(writer io.Writer, b []byte) error {
	if writer == nil || len(b) == 0 || len(b) > MaxFrameBytes {
		return ErrProtocol
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, b)
}
func writeAll(writer io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := writer.Write(b)
		if n < 0 || n > len(b) || n == 0 && err == nil {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
func readFixed(d *codec.Decoder, target []byte) bool {
	b, err := d.Fixed(len(target))
	if err != nil {
		return false
	}
	copy(target, b)
	return true
}

// RequireEOF reads at most one additional byte. A frame without its complete
// write-side close is not a complete request/reply. Impose a deadline first.
func RequireEOF(reader io.Reader) error {
	if reader == nil {
		return ErrProtocol
	}
	var b [1]byte
	n, err := io.ReadFull(reader, b[:])
	if n == 0 && err == io.EOF {
		return nil
	}
	return errors.Join(ErrProtocol, err)
}
