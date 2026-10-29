package wire

import (
	"bytes"
	"testing"
)

func TestRadixChainHelloRequiresCanonicalSchedule(t *testing.T) {
	h := testChainHello()
	var old bytes.Buffer
	if e := WriteMessage(&old, h); e != nil {
		t.Fatal(e)
	}
	h.Version = ChainHelloRadix
	h.RadixActivationHeight = 8
	var buf bytes.Buffer
	if e := WriteMessage(&buf, h); e != nil {
		t.Fatal(e)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	if len(raw) != old.Len()+8 {
		t.Fatal("hello size")
	}
	got, e := ReadMessage(&buf)
	if e != nil {
		t.Fatal(e)
	}
	v, ok := got.(ChainHello)
	if !ok || v.Version != 3 || v.RadixActivationHeight != 8 {
		t.Fatal("lost schedule")
	}
	for i := 0; i < len(raw); i++ {
		if _, e = ReadMessage(bytes.NewReader(raw[:i])); e == nil {
			t.Fatal("truncated hello", i)
		}
	}
	for _, bad := range []ChainHello{func() ChainHello { x := h; x.Version = 1; return x }(), func() ChainHello { x := h; x.RadixActivationHeight = 0; return x }(), func() ChainHello { x := h; x.RadixActivationHeight = 4; return x }()} {
		if e = bad.Validate(); e == nil {
			t.Fatal("bad schedule accepted")
		}
	}
}
func FuzzRadixChainHello(f *testing.F) {
	h := testChainHello()
	h.Version = ChainHelloRadix
	h.RadixActivationHeight = 8
	var b bytes.Buffer
	if e := WriteMessage(&b, h); e != nil {
		f.Fatal(e)
	}
	f.Add(b.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		reader := bytes.NewReader(b)
		v, e := ReadMessage(reader)
		if e != nil {
			return
		}
		var out bytes.Buffer
		if e = WriteMessage(&out, v); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(out.Bytes(), b[:len(b)-reader.Len()]) {
			t.Fatal("noncanonical frame")
		}
	})
}
