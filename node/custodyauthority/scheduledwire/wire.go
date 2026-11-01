// Package scheduledwire carries explicitly reviewed scheduled Prune commands.
// Intent pins are checked against original owners by the concrete receiver.
// Acknowledgements describe historical delivery, never execution permission.
package scheduledwire

import (
	"bytes"
	"errors"
	"io"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	RequestBytes         = 10 + types.HashSize + IntentBytes
	AcknowledgementBytes = 10 + 2*types.HashSize
)

var (
	ErrProtocol    = errors.New("invalid scheduled prune delivery protocol")
	ErrUnconfirmed = errors.New("no confirmed scheduled prune reply; retain the exact intent")
	requestMagic   = []byte("OMCPSREQ\x00\x00")
	ackMagic       = []byte("OMCPSACK\x00\x00")
)

type Request struct {
	Nonce  types.Hash
	Intent Intent
}

// Acknowledgement binds one fresh exchange to one exact intent. It says nothing
// about current authority phase and is not independently signed or durable at
// the client. A lost/invalid reply never proves that the entry was not committed.
type Acknowledgement struct {
	Nonce    types.Hash
	IntentID types.Hash
}

func (r Request) CanonicalBytes() ([]byte, error) {
	if r.Nonce.IsZero() {
		return nil, ErrProtocol
	}
	intent, err := r.Intent.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	encoded := append([]byte(nil), requestMagic...)
	encoded = append(encoded, r.Nonce[:]...)
	return append(encoded, intent...), nil
}

func DecodeRequest(input []byte) (Request, error) {
	if len(input) != RequestBytes || !bytes.HasPrefix(input, requestMagic) {
		return Request{}, ErrProtocol
	}
	var r Request
	copy(r.Nonce[:], input[10:42])
	var err error
	r.Intent, err = DecodeIntent(input[42:])
	if err != nil || r.Nonce.IsZero() {
		return Request{}, errors.Join(ErrProtocol, err)
	}
	return r, nil
}

func (a Acknowledgement) CanonicalBytes() ([]byte, error) {
	if a.Nonce.IsZero() || a.IntentID.IsZero() {
		return nil, ErrProtocol
	}
	encoded := append([]byte(nil), ackMagic...)
	encoded = append(encoded, a.Nonce[:]...)
	return append(encoded, a.IntentID[:]...), nil
}

func DecodeAcknowledgement(input []byte) (Acknowledgement, error) {
	if len(input) != AcknowledgementBytes || !bytes.HasPrefix(input, ackMagic) {
		return Acknowledgement{}, ErrProtocol
	}
	var a Acknowledgement
	copy(a.Nonce[:], input[10:42])
	copy(a.IntentID[:], input[42:])
	if a.Nonce.IsZero() || a.IntentID.IsZero() {
		return Acknowledgement{}, ErrProtocol
	}
	return a, nil
}

func ReadRequest(reader io.Reader) (Request, error) {
	var encoded [RequestBytes]byte
	if err := readFrame(reader, encoded[:], requestMagic); err != nil {
		return Request{}, err
	}
	return DecodeRequest(encoded[:])
}

func ReadAcknowledgement(reader io.Reader) (Acknowledgement, error) {
	var encoded [AcknowledgementBytes]byte
	if err := readFrame(reader, encoded[:], ackMagic); err != nil {
		return Acknowledgement{}, err
	}
	return DecodeAcknowledgement(encoded[:])
}

func readFrame(reader io.Reader, encoded, magic []byte) error {
	if reader == nil {
		return ErrProtocol
	}
	if _, err := io.ReadFull(reader, encoded[:10]); err != nil {
		return err
	}
	if !bytes.Equal(encoded[:10], magic) {
		return ErrProtocol
	}
	_, err := io.ReadFull(reader, encoded[10:])
	return err
}

func WriteRequest(writer io.Writer, r Request) error {
	encoded, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	return writeAll(writer, encoded)
}

func WriteAcknowledgement(writer io.Writer, a Acknowledgement) error {
	encoded, err := a.CanonicalBytes()
	if err != nil {
		return err
	}
	return writeAll(writer, encoded)
}

func writeAll(writer io.Writer, encoded []byte) error {
	if writer == nil {
		return ErrProtocol
	}
	for len(encoded) != 0 {
		n, err := writer.Write(encoded)
		if n < 0 || n > len(encoded) || n == 0 && err == nil {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		encoded = encoded[n:]
	}
	return nil
}

// RequireEOF reads at most one extra byte. The caller must impose a deadline;
// a complete frame without write-side closure is not a complete request/reply.
func RequireEOF(reader io.Reader) error {
	if reader == nil {
		return ErrProtocol
	}
	var extra [1]byte
	n, err := io.ReadFull(reader, extra[:])
	if n == 0 && err == io.EOF {
		return nil
	}
	return errors.Join(ErrProtocol, err)
}
