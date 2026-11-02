package servicewire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestExpectedFrameRejectsOtherKindBeforeReadingPayload(t *testing.T) {
	for _, kind := range []uint8{RequestFrame, ChallengeFrame, ApprovalFrame, ResponseFrame} {
		for _, want := range []uint8{RequestFrame, ChallengeFrame, ApprovalFrame, ResponseFrame, 0, 255} {
			var header [5]byte
			header[0] = kind
			binary.BigEndian.PutUint32(header[1:], 1)
			raw := append(header[:], byte(7))
			r := bytes.NewReader(raw)
			b, err := ReadExpectedFrame(r, want)
			if kind == want {
				if err != nil || !bytes.Equal(b, []byte{7}) {
					t.Fatal("expected frame", err)
				}
			} else {
				if err == nil || b != nil || r.Len() < 1 {
					t.Fatal("wrong kind consumed payload")
				}
			}
		}
	}
}
