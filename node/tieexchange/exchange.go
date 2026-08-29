// Package tieexchange defines the bounded application protocol used to move a
// pre-published controlled-tie pair from a coordinator to an independent
// observer over an authenticated stream.
package tieexchange

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
)

const Version0 uint16 = 0

const (
	requestHeaderBytes   = 8 + 2 + types.HashSize + types.HashSize + 8 + 8
	acknowledgementBytes = 8 + 2 + types.HashSize + types.HashSize + 8 + types.HashSize + types.HashSize
	confirmationBytes    = 8 + 2 + types.HashSize + types.HashSize + 8 + types.HashSize
)

var (
	requestMagic         = [8]byte{'O', 'M', 'T', 'P', 'A', 'I', 'R', 'Q'}
	acknowledgementMagic = [8]byte{'O', 'M', 'T', 'P', 'A', 'I', 'R', 'A'}
	confirmationMagic    = [8]byte{'O', 'M', 'T', 'P', 'A', 'I', 'R', 'C'}

	ErrProtocol = errors.New("invalid controlled-tie exchange protocol")
	ErrBinding  = errors.New("controlled-tie exchange binding mismatch")
	ErrLimit    = errors.New("controlled-tie exchange artifact exceeds limit")
)

// Binding is published before transfer. It prevents a valid artifact for one
// calibration slot from being replayed into another slot or plan.
type Binding struct {
	PlanID   types.Hash
	PairID   types.Hash
	Sequence uint64
}

type Request struct {
	Binding  Binding
	Artifact []byte
}

// Acknowledgement is returned only after local deterministic replay, ordered
// admission, and durable creation of the observer's signed receipt.
type Acknowledgement struct {
	Binding           Binding
	ObserverPublicKey types.Hash
	ReceiptTail       types.Hash
}

// Confirmation proves to the one-shot receiver that the coordinator read the
// durable acknowledgement before the observer tears down its QUIC host.
type Confirmation struct {
	Binding     Binding
	ReceiptTail types.Hash
}

func (binding Binding) Validate() error {
	if binding.PlanID.IsZero() || binding.PairID.IsZero() || binding.Sequence == 0 {
		return ErrProtocol
	}
	return nil
}

func WriteRequest(writer io.Writer, request Request) error {
	if writer == nil || request.Binding.Validate() != nil || len(request.Artifact) == 0 {
		return ErrProtocol
	}
	if len(request.Artifact) > tieproducer.MaximumPairArtifactBytes {
		return ErrLimit
	}
	var header [requestHeaderBytes]byte
	copy(header[:8], requestMagic[:])
	binary.BigEndian.PutUint16(header[8:10], Version0)
	copy(header[10:42], request.Binding.PlanID[:])
	copy(header[42:74], request.Binding.PairID[:])
	binary.BigEndian.PutUint64(header[74:82], request.Binding.Sequence)
	binary.BigEndian.PutUint64(header[82:90], uint64(len(request.Artifact)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, request.Artifact)
}

// ReadRequest rejects unexpected published metadata and oversized lengths
// before allocating or reading the artifact body.
func ReadRequest(reader io.Reader, expected Binding) (Request, error) {
	if reader == nil || expected.Validate() != nil {
		return Request{}, ErrProtocol
	}
	var header [requestHeaderBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Request{}, err
	}
	if string(header[:8]) != string(requestMagic[:]) || binary.BigEndian.Uint16(header[8:10]) != Version0 {
		return Request{}, ErrProtocol
	}
	var actual Binding
	copy(actual.PlanID[:], header[10:42])
	copy(actual.PairID[:], header[42:74])
	actual.Sequence = binary.BigEndian.Uint64(header[74:82])
	if actual.Validate() != nil {
		return Request{}, ErrProtocol
	}
	if actual != expected {
		return Request{}, ErrBinding
	}
	length := binary.BigEndian.Uint64(header[82:90])
	if length == 0 {
		return Request{}, ErrProtocol
	}
	if length > tieproducer.MaximumPairArtifactBytes {
		return Request{}, ErrLimit
	}
	artifact := make([]byte, int(length))
	if _, err := io.ReadFull(reader, artifact); err != nil {
		return Request{}, err
	}
	return Request{Binding: actual, Artifact: artifact}, nil
}

func WriteAcknowledgement(writer io.Writer, acknowledgement Acknowledgement) error {
	if writer == nil || acknowledgement.Binding.Validate() != nil ||
		acknowledgement.ObserverPublicKey.IsZero() || acknowledgement.ReceiptTail.IsZero() {
		return ErrProtocol
	}
	var encoded [acknowledgementBytes]byte
	copy(encoded[:8], acknowledgementMagic[:])
	binary.BigEndian.PutUint16(encoded[8:10], Version0)
	copy(encoded[10:42], acknowledgement.Binding.PlanID[:])
	copy(encoded[42:74], acknowledgement.Binding.PairID[:])
	binary.BigEndian.PutUint64(encoded[74:82], acknowledgement.Binding.Sequence)
	copy(encoded[82:114], acknowledgement.ObserverPublicKey[:])
	copy(encoded[114:146], acknowledgement.ReceiptTail[:])
	return writeAll(writer, encoded[:])
}

func ReadAcknowledgement(reader io.Reader, expected Binding, expectedObserver types.Hash) (Acknowledgement, error) {
	if reader == nil || expected.Validate() != nil || expectedObserver.IsZero() {
		return Acknowledgement{}, ErrProtocol
	}
	var encoded [acknowledgementBytes]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return Acknowledgement{}, err
	}
	if string(encoded[:8]) != string(acknowledgementMagic[:]) || binary.BigEndian.Uint16(encoded[8:10]) != Version0 {
		return Acknowledgement{}, ErrProtocol
	}
	var result Acknowledgement
	copy(result.Binding.PlanID[:], encoded[10:42])
	copy(result.Binding.PairID[:], encoded[42:74])
	result.Binding.Sequence = binary.BigEndian.Uint64(encoded[74:82])
	copy(result.ObserverPublicKey[:], encoded[82:114])
	copy(result.ReceiptTail[:], encoded[114:146])
	if result.Binding.Validate() != nil || result.ReceiptTail.IsZero() {
		return Acknowledgement{}, ErrProtocol
	}
	if result.Binding != expected || result.ObserverPublicKey != expectedObserver {
		return Acknowledgement{}, ErrBinding
	}
	return result, nil
}

func WriteConfirmation(writer io.Writer, confirmation Confirmation) error {
	if writer == nil || confirmation.Binding.Validate() != nil || confirmation.ReceiptTail.IsZero() {
		return ErrProtocol
	}
	var encoded [confirmationBytes]byte
	copy(encoded[:8], confirmationMagic[:])
	binary.BigEndian.PutUint16(encoded[8:10], Version0)
	copy(encoded[10:42], confirmation.Binding.PlanID[:])
	copy(encoded[42:74], confirmation.Binding.PairID[:])
	binary.BigEndian.PutUint64(encoded[74:82], confirmation.Binding.Sequence)
	copy(encoded[82:114], confirmation.ReceiptTail[:])
	return writeAll(writer, encoded[:])
}

func ReadConfirmation(reader io.Reader, expected Binding, expectedReceipt types.Hash) (Confirmation, error) {
	if reader == nil || expected.Validate() != nil || expectedReceipt.IsZero() {
		return Confirmation{}, ErrProtocol
	}
	var encoded [confirmationBytes]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return Confirmation{}, err
	}
	if string(encoded[:8]) != string(confirmationMagic[:]) || binary.BigEndian.Uint16(encoded[8:10]) != Version0 {
		return Confirmation{}, ErrProtocol
	}
	var result Confirmation
	copy(result.Binding.PlanID[:], encoded[10:42])
	copy(result.Binding.PairID[:], encoded[42:74])
	result.Binding.Sequence = binary.BigEndian.Uint64(encoded[74:82])
	copy(result.ReceiptTail[:], encoded[82:114])
	if result.Binding.Validate() != nil || result.ReceiptTail.IsZero() {
		return Confirmation{}, ErrProtocol
	}
	if result.Binding != expected || result.ReceiptTail != expectedReceipt {
		return Confirmation{}, ErrBinding
	}
	return result, nil
}

func writeAll(writer io.Writer, input []byte) error {
	for len(input) > 0 {
		written, err := writer.Write(input)
		if written < 0 || written > len(input) {
			return io.ErrShortWrite
		}
		input = input[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
