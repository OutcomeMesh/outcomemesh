package servicewire

import (
	"encoding/binary"
	"io"

	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const (
	RequestFrame uint8 = 1 + iota
	ChallengeFrame
	ApprovalFrame
	ResponseFrame
)

func frameLimit(kind uint8) int {
	switch kind {
	case RequestFrame:
		return RequestBytes
	case ChallengeFrame:
		return MaximumChallengeBytes
	case ApprovalFrame:
		return custodyfence.CommandBytes
	case ResponseFrame:
		return MaximumResponseBytes
	default:
		return 0
	}
}

// Frames contain a one-byte type and four-byte network-order payload length.
// Each payload carries its own canonical magic/version. Callers must enforce
// their exchange state and EOF at the final input boundary before execution.
func ReadFrame(r io.Reader) (uint8, []byte, error) {
	return readFrame(r, 0)
}

// ReadExpectedFrame rejects another message kind before allocating its payload.
func ReadExpectedFrame(r io.Reader, expected uint8) ([]byte, error) {
	if frameLimit(expected) == 0 {
		return nil, ErrArtifact
	}
	_, b, err := readFrame(r, expected)
	return b, err
}

func readFrame(r io.Reader, expected uint8) (uint8, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	limit := frameLimit(head[0])
	n := binary.BigEndian.Uint32(head[1:])
	if limit == 0 || n == 0 || n > uint32(limit) || (expected != 0 && head[0] != expected) {
		return 0, nil, ErrArtifact
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return head[0], b, nil
}
func WriteFrame(w io.Writer, kind uint8, b []byte) error {
	limit := frameLimit(kind)
	if limit == 0 || len(b) == 0 || len(b) > limit {
		return ErrArtifact
	}
	var head [5]byte
	head[0] = kind
	binary.BigEndian.PutUint32(head[1:], uint32(len(b)))
	for _, p := range [][]byte{head[:], b} {
		for len(p) > 0 {
			n, err := w.Write(p)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(p) {
				return io.ErrShortWrite
			}
			p = p[n:]
		}
	}
	return nil
}
func RequireEOF(r io.Reader) error {
	var b [1]byte
	n, err := r.Read(b[:])
	if n == 0 && err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrArtifact
}
