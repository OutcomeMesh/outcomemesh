package gatewayclient

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type shortWriter struct{ b bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.b.Write(p)
}
func TestGatewayFramingShortWritesAndLimits(t *testing.T) {
	w := new(shortWriter)
	if e := WriteFrame(w, []byte("test")); e != nil {
		t.Fatal(e)
	}
	b, e := ReadFrame(&w.b, 4)
	if e != nil || string(b) != "test" {
		t.Fatal(e)
	}
	for _, n := range []uint32{0, 5, 0xffffffff} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		if _, e := ReadFrame(bytes.NewReader(b[:]), 4); e == nil {
			t.Fatal(n)
		}
	}
	for n := 0; n < 8; n++ {
		raw := []byte{0, 0, 0, 4, 't', 'e', 's', 't'}
		if _, e := ReadFrame(bytes.NewReader(raw[:n]), 4); e == nil {
			t.Fatal(n)
		}
	}
	if _, e := ReadFrame(bytes.NewReader(nil), 4); e != io.EOF {
		t.Fatal(e)
	}
}
