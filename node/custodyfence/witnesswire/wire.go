// Package witnesswire carries one authenticated, bounded witness request. It
// transports durable endorsements and observations, never execution grants.
package witnesswire

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const Version0 uint16 = 0
const Version1 uint16 = 1
const MaxFrameBytes = 4096

type Kind uint8

const (
	Review Kind = 1 + iota
	Vote
	Commit
)

var ErrProtocol = errors.New("invalid custody witness protocol")

type Request struct {
	Version        uint16
	Kind           Kind
	ScopeID, Nonce types.Hash
	Expected       custodyfence.WitnessPin
	Command        custodyfence.Command
	Certificate    custodyfence.Certificate
}

func (r Request) CanonicalBytes() ([]byte, error) {
	if (r.Version != Version0 && r.Version != Version1) || r.ScopeID.IsZero() || r.Nonce.IsZero() || r.Expected.Position.HeadID.IsZero() || r.Expected.Position.Sequence > 3 {
		return nil, ErrProtocol
	}
	var body []byte
	var err error
	switch r.Kind {
	case Review:
		if r.Command != (custodyfence.Command{}) || r.Certificate.Command != (custodyfence.Command{}) || r.Certificate.Version != 0 || len(r.Certificate.Votes) != 0 {
			return nil, ErrProtocol
		}
	case Vote:
		if r.Certificate.Command != (custodyfence.Command{}) || r.Certificate.Version != 0 || len(r.Certificate.Votes) != 0 {
			return nil, ErrProtocol
		}
		body, err = r.Command.CanonicalBytes()
		if r.Command.Version != r.Version || r.Command.ScopeID != r.ScopeID || r.Command.ExpectedSequence != r.Expected.Position.Sequence || r.Command.ExpectedHead != r.Expected.Position.HeadID {
			return nil, ErrProtocol
		}
	case Commit:
		if r.Command != (custodyfence.Command{}) {
			return nil, ErrProtocol
		}
		body, err = r.Certificate.CanonicalBytes()
		c := r.Certificate.Command
		if c.Version != r.Version || c.ScopeID != r.ScopeID || c.ExpectedSequence != r.Expected.Position.Sequence || c.ExpectedHead != r.Expected.Position.HeadID {
			return nil, ErrProtocol
		}
	default:
		return nil, ErrProtocol
	}
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaxFrameBytes)
	e.Fixed([]byte("OMCFWR00"))
	e.U16(r.Version)
	e.U8(uint8(r.Kind))
	e.Fixed(r.ScopeID[:])
	e.Fixed(r.Nonce[:])
	e.U64(r.Expected.Position.Sequence)
	e.Fixed(r.Expected.Position.HeadID[:])
	e.Fixed(r.Expected.PendingID[:])
	e.BytesField(body)
	return e.Bytes(), nil
}
func (r Request) ID() (types.Hash, error) {
	b, err := r.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(requestDomain(r.Version), b), nil
}
func (r Request) Validate(s custodyfence.Scope) error {
	if _, err := r.CanonicalBytes(); err != nil {
		return err
	}
	id, err := s.ID()
	if err != nil || id != r.ScopeID || r.Version != s.Version {
		return ErrProtocol
	}
	switch r.Kind {
	case Vote:
		return r.Command.Verify(s)
	case Commit:
		return r.Certificate.Verify(s)
	}
	return nil
}
func DecodeRequest(b []byte) (Request, error) {
	var r Request
	if len(b) > MaxFrameBytes {
		return r, ErrProtocol
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFWR00" {
		return r, ErrProtocol
	}
	r.Version, _ = d.U16()
	k, _ := d.U8()
	r.Kind = Kind(k)
	fixed(d, r.ScopeID[:])
	fixed(d, r.Nonce[:])
	r.Expected.Position.Sequence, _ = d.U64()
	fixed(d, r.Expected.Position.HeadID[:])
	fixed(d, r.Expected.PendingID[:])
	body, err := d.BytesField(custodyfence.MaximumCertificateBytes)
	if err != nil || d.Finish() != nil {
		return Request{}, ErrProtocol
	}
	switch r.Kind {
	case Review:
		if len(body) != 0 {
			return Request{}, ErrProtocol
		}
	case Vote:
		r.Command, err = custodyfence.DecodeCommand(body)
	case Commit:
		r.Certificate, err = custodyfence.DecodeCertificate(body)
	default:
		return Request{}, ErrProtocol
	}
	if err != nil {
		return Request{}, err
	}
	if _, err := r.CanonicalBytes(); err != nil {
		return Request{}, err
	}
	return r, nil
}

type Response struct {
	Version     uint16
	Observation custodyfence.Observation
	Vote        custodyfence.Vote
}

func (r Response) CanonicalBytes() ([]byte, error) {
	if (r.Version != Version0 && r.Version != Version1) || r.Version != r.Observation.Version {
		return nil, ErrProtocol
	}
	obs, err := r.Observation.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	var vote []byte
	if r.Vote != (custodyfence.Vote{}) {
		vote, err = r.Vote.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		if r.Vote.Version != r.Version || r.Vote.Witness != r.Observation.Witness || r.Vote.CommandID != r.Observation.PendingID {
			return nil, ErrProtocol
		}
	}
	e := codec.NewEncoder(MaxFrameBytes)
	e.Fixed([]byte("OMCFWS00"))
	e.U16(r.Version)
	e.Fixed(obs)
	e.BytesField(vote)
	return e.Bytes(), nil
}
func DecodeResponse(b []byte) (Response, error) {
	var r Response
	if len(b) > MaxFrameBytes {
		return r, ErrProtocol
	}
	d := codec.NewDecoder(b)
	magic, _ := d.Fixed(8)
	if string(magic) != "OMCFWS00" {
		return r, ErrProtocol
	}
	r.Version, _ = d.U16()
	obsSize := custodyfence.ObservationBytes
	if r.Version == Version1 {
		obsSize = custodyfence.ObservationBytesV1
	}
	obs, err := d.Fixed(obsSize)
	if err != nil {
		return r, ErrProtocol
	}
	r.Observation, err = custodyfence.DecodeObservation(obs)
	if err != nil {
		return Response{}, err
	}
	v, err := d.BytesField(custodyfence.VoteBytes)
	if err != nil || d.Finish() != nil {
		return Response{}, ErrProtocol
	}
	if len(v) > 0 {
		r.Vote, err = custodyfence.DecodeVote(v)
		if err != nil {
			return Response{}, err
		}
	}
	if _, err := r.CanonicalBytes(); err != nil {
		return Response{}, err
	}
	return r, nil
}
func ValidateResponse(s custodyfence.Scope, r Request, response Response, witness [32]byte) error {
	if err := r.Validate(s); err != nil {
		return err
	}
	if _, err := response.CanonicalBytes(); err != nil {
		return err
	}
	id, _ := r.ID()
	o := response.Observation
	if err := o.Verify(s, id, witness); err != nil {
		return err
	}
	actual := custodyfence.WitnessPin{Position: o.Snapshot.Position, PendingID: o.PendingID}
	switch r.Kind {
	case Review:
		if actual != r.Expected || response.Vote != (custodyfence.Vote{}) {
			return ErrProtocol
		}
	case Vote:
		cid, _ := r.Command.ID()
		if response.Version != r.Version || actual.Position != r.Expected.Position || actual.PendingID != cid || response.Vote.CommandID != cid || response.Vote.Witness != witness {
			return ErrProtocol
		}
	case Commit:
		c := r.Certificate.Command
		cid, _ := c.ID()
		if actual.Position.Sequence != r.Expected.Position.Sequence+1 || actual.Position.HeadID != cid || !actual.PendingID.IsZero() || response.Vote != (custodyfence.Vote{}) {
			return ErrProtocol
		}
		x := o.Snapshot
		switch c.Kind {
		case custodyfence.Claim:
			if x.Phase != custodyfence.Claimed || x.ClaimID != cid || c.Version == custodyfence.Version1 && x.SessionID != c.EvidenceID {
				return ErrProtocol
			}
		case custodyfence.MarkUnknown:
			if x.Phase != custodyfence.Unknown || x.ClaimID != c.ClaimID || x.EvidenceID != c.EvidenceID {
				return ErrProtocol
			}
		case custodyfence.RecordResult:
			if x.Phase != custodyfence.ResultRecorded || x.ClaimID != c.ClaimID || x.EvidenceID != c.EvidenceID {
				return ErrProtocol
			}
		case custodyfence.CloseUnclaimed:
			if x.Phase != custodyfence.UnclaimedClosed || x.EvidenceID != c.EvidenceID {
				return ErrProtocol
			}
		}
	}
	return nil
}

// Assemble verifies each full response, including nonce/request binding. It
// rejects duplicate witnesses instead of counting them toward the quorum.
func Assemble(s custodyfence.Scope, requests []Request, responses []Response) (custodyfence.Certificate, error) {
	if len(requests) != len(responses) || len(requests) == 0 || len(requests) > custodyfence.MaximumWitnesses {
		return custodyfence.Certificate{}, ErrProtocol
	}
	out := custodyfence.Certificate{Version: requests[0].Command.Version, Command: requests[0].Command}
	seen := map[[32]byte]bool{}
	for i, r := range requests {
		v := responses[i].Vote
		if r.Kind != Vote || r.Command != out.Command || seen[v.Witness] {
			return custodyfence.Certificate{}, ErrProtocol
		}
		if err := ValidateResponse(s, r, responses[i], v.Witness); err != nil {
			return custodyfence.Certificate{}, err
		}
		seen[v.Witness] = true
		out.Votes = append(out.Votes, v)
	}
	for i := 1; i < len(out.Votes); i++ {
		for j := i; j > 0 && string(out.Votes[j].Witness[:]) < string(out.Votes[j-1].Witness[:]); j-- {
			out.Votes[j], out.Votes[j-1] = out.Votes[j-1], out.Votes[j]
		}
	}
	return out, out.Verify(s)
}
func fixed(d *codec.Decoder, b []byte) { v, _ := d.Fixed(len(b)); copy(b, v) }
func readFrame(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxFrameBytes {
		return nil, ErrProtocol
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > MaxFrameBytes {
		return ErrProtocol
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
	for _, part := range [][]byte{prefix[:], b} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if n < 0 || n > len(part) {
				return ErrProtocol
			}
			part = part[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}
func ReadRequest(r io.Reader) (Request, error) {
	b, err := readFrame(r)
	if err != nil {
		return Request{}, err
	}
	return DecodeRequest(b)
}
func ReadResponse(r io.Reader) (Response, error) {
	b, err := readFrame(r)
	if err != nil {
		return Response{}, err
	}
	return DecodeResponse(b)
}
func WriteRequest(w io.Writer, r Request) error {
	b, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	return writeFrame(w, b)
}
func WriteResponse(w io.Writer, r Response) error {
	b, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	return writeFrame(w, b)
}

func requestDomain(version uint16) string {
	if version == Version1 {
		return "OMESH/custody-fence/witness-request/id/v1"
	}
	return "OMESH/custody-fence/witness-request/id/v0"
}
