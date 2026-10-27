package custodyv2

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const MaximumRequestBytes = 8192
const MaximumResponseBytes = MaximumResultBytes + 4096

type Operation uint8

const (
	Prepare Operation = 1 + iota
	Execute
	RecoverResult
)

type Request struct {
	Version        uint16
	Operation      Operation
	ScopeID, Nonce types.Hash
	Prefix         []custodyfence.Certificate
}

func (r Request) CanonicalBytes() ([]byte, error) {
	if r.Version != Version2 || r.ScopeID.IsZero() || r.Nonce.IsZero() {
		return nil, ErrProtocol
	}
	switch r.Operation {
	case Prepare:
		if len(r.Prefix) != 0 {
			return nil, ErrProtocol
		}
	case Execute:
		if len(r.Prefix) != 1 {
			return nil, ErrProtocol
		}
	case RecoverResult:
		if len(r.Prefix) < 1 || len(r.Prefix) > 2 {
			return nil, ErrProtocol
		}
	default:
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(MaximumRequestBytes)
	e.Fixed([]byte("OMCVREQ2"))
	e.U16(r.Version)
	e.U8(uint8(r.Operation))
	e.Fixed(r.ScopeID[:])
	e.Fixed(r.Nonce[:])
	e.U8(uint8(len(r.Prefix)))
	for _, q := range r.Prefix {
		b, err := q.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(b)
	}
	return e.Bytes(), nil
}
func (r Request) ID() (types.Hash, error) {
	b, e := r.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody/v2/request/id", b), nil
}
func (r Request) Validate(c Context) error {
	if _, e := r.CanonicalBytes(); e != nil {
		return e
	}
	s, e := c.Scope()
	if e != nil {
		return e
	}
	id, _ := s.ID()
	if r.ScopeID != id {
		return ErrProtocol
	}
	state, e := custodyfence.NewState(s, id)
	if e != nil {
		return e
	}
	for _, q := range r.Prefix {
		if e := state.Apply(q); e != nil {
			return e
		}
	}
	if len(r.Prefix) > 0 {
		x := state.Snapshot()
		if (x.Phase != custodyfence.Claimed && x.Phase != custodyfence.Unknown) || x.SessionID.IsZero() {
			return ErrProtocol
		}
	}
	return nil
}
func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if len(raw) > MaximumRequestBytes {
		return r, ErrProtocol
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVREQ2") {
		return r, ErrProtocol
	}
	r.Version, _ = d.U16()
	op, _ := d.U8()
	r.Operation = Operation(op)
	fixed(d, r.ScopeID[:])
	fixed(d, r.Nonce[:])
	n, e := d.U8()
	if e != nil || n > 2 {
		return r, ErrProtocol
	}
	r.Prefix = make([]custodyfence.Certificate, int(n))
	for i := range r.Prefix {
		b, e := d.BytesField(custodyfence.MaximumCertificateBytes)
		if e != nil {
			return Request{}, e
		}
		r.Prefix[i], e = custodyfence.DecodeCertificate(b)
		if e != nil {
			return Request{}, e
		}
	}
	if d.Finish() != nil {
		return Request{}, ErrProtocol
	}
	if _, e := r.CanonicalBytes(); e != nil {
		return Request{}, e
	}
	return r, nil
}

type Response struct {
	Version   uint16
	Operation Operation
	RequestID types.Hash
	Candidate Candidate
	Result    Result
	Command   custodyfence.Command
}

func (r Response) CanonicalBytes() ([]byte, error) {
	if r.Version != Version2 || r.RequestID.IsZero() {
		return nil, ErrProtocol
	}
	e := codec.NewEncoder(4096)
	e.Fixed([]byte("OMCVRSP2"))
	e.U16(r.Version)
	e.U8(uint8(r.Operation))
	e.Fixed(r.RequestID[:])
	switch r.Operation {
	case Prepare:
		if r.Result.Version != 0 || r.Command != (custodyfence.Command{}) {
			return nil, ErrProtocol
		}
		b, err := r.Candidate.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(b)
	case Execute, RecoverResult:
		if r.Candidate != (Candidate{}) {
			return nil, ErrProtocol
		}
		b, err := r.Result.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(b)
		b, err = r.Command.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		e.BytesField(b)
	default:
		return nil, ErrProtocol
	}
	return e.Bytes(), nil
}
func DecodeResponse(raw []byte) (Response, error) {
	var r Response
	if len(raw) > MaximumResponseBytes {
		return r, ErrProtocol
	}
	d := codec.NewDecoder(raw)
	if !magic(d, "OMCVRSP2") {
		return r, ErrProtocol
	}
	r.Version, _ = d.U16()
	op, _ := d.U8()
	r.Operation = Operation(op)
	fixed(d, r.RequestID[:])
	b, e := d.BytesField(MaximumResultBytes)
	if e != nil {
		return r, e
	}
	switch r.Operation {
	case Prepare:
		r.Candidate, e = DecodeCandidate(b)
	case Execute, RecoverResult:
		r.Result, e = DecodeResult(b)
		if e != nil {
			return Response{}, e
		}
		b, e = d.BytesField(custodyfence.CommandBytes)
		if e == nil {
			r.Command, e = custodyfence.DecodeCommand(b)
		}
	default:
		return Response{}, ErrProtocol
	}
	if e != nil || d.Finish() != nil {
		return Response{}, ErrProtocol
	}
	if _, e := r.CanonicalBytes(); e != nil {
		return Response{}, e
	}
	return r, nil
}
func ValidateResponse(c Context, request Request, r Response) error {
	if e := request.Validate(c); e != nil {
		return e
	}
	if _, e := r.CanonicalBytes(); e != nil {
		return e
	}
	id, _ := request.ID()
	if r.RequestID != id || r.Operation != request.Operation {
		return ErrProtocol
	}
	if r.Operation == Prepare {
		return r.Candidate.Verify(c)
	}
	if e := r.Result.Verify(c, request.Prefix[0]); e != nil {
		return e
	}
	s, e := c.Scope()
	if e != nil {
		return e
	}
	state, e := custodyfence.NewState(s, request.ScopeID)
	if e != nil {
		return e
	}
	for _, q := range request.Prefix {
		if e := state.Apply(q); e != nil {
			return e
		}
	}
	x := state.Snapshot()
	rid, _ := r.Result.ID()
	command := r.Command
	if command.Kind != custodyfence.RecordResult || command.ExpectedSequence != x.Position.Sequence || command.ExpectedHead != x.Position.HeadID || command.ClaimID != x.ClaimID || command.EvidenceID != rid {
		return ErrProtocol
	}
	return command.Verify(s)
}
func WriteRequest(w io.Writer, r Request) error {
	b, e := r.CanonicalBytes()
	if e != nil {
		return e
	}
	return writeFrame(w, b, MaximumRequestBytes)
}
func ReadRequest(r io.Reader) (Request, error) {
	b, e := readFrame(r, MaximumRequestBytes)
	if e != nil {
		return Request{}, e
	}
	return DecodeRequest(b)
}
func WriteResponse(w io.Writer, r Response) error {
	b, e := r.CanonicalBytes()
	if e != nil {
		return e
	}
	return writeFrame(w, b, MaximumResponseBytes)
}
func ReadResponse(r io.Reader) (Response, error) {
	b, e := readFrame(r, MaximumResponseBytes)
	if e != nil {
		return Response{}, e
	}
	return DecodeResponse(b)
}
func readFrame(r io.Reader, limit int) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || uint64(n) > uint64(limit) {
		return nil, ErrProtocol
	}
	b := make([]byte, int(n))
	_, e := io.ReadFull(r, b)
	return b, e
}
func writeFrame(w io.Writer, b []byte, limit int) error {
	if len(b) == 0 || len(b) > limit {
		return ErrProtocol
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	for _, part := range [][]byte{h[:], b} {
		for len(part) > 0 {
			n, e := w.Write(part)
			if n < 0 || n > len(part) {
				return io.ErrShortWrite
			}
			part = part[n:]
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}

// Exchange makes exactly one attempt. A failed Execute reply never licenses a retry.
func Exchange(ctx context.Context, stream remotewire.Stream, c Context, r Request, timeout time.Duration) (response Response, returnErr error) {
	if stream == nil {
		return Response{}, ErrProtocol
	}
	defer func() {
		if e := stream.Close(); e != nil {
			response = Response{}
			returnErr = errors.Join(ErrUncertain, returnErr, e)
		}
	}()
	if e := r.Validate(c); e != nil {
		return Response{}, e
	}
	run, cleanup, e := remotewire.BoundStream(ctx, stream, timeout)
	if e != nil {
		return Response{}, e
	}
	defer cleanup()
	if e := WriteRequest(stream, r); e != nil {
		return Response{}, e
	}
	if e := stream.CloseWrite(); e != nil {
		return Response{}, e
	}
	reply, e := ReadResponse(stream)
	if e != nil {
		return Response{}, e
	}
	if e := remotewire.RequireEOF(stream); e != nil {
		return Response{}, e
	}
	if e := run.Err(); e != nil {
		return Response{}, e
	}
	return reply, ValidateResponse(c, r, reply)
}
