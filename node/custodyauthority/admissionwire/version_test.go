package admissionwire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestAdmissionLegacyWireRejectsCanonicalV1Entry(t *testing.T) {
	r := request(t)
	c := r.Entry.Command
	c.Version = custodyauthority.Version1
	var err error
	c, err = c.Sign(key(6))
	if err != nil {
		t.Fatal(err)
	}
	r.Entry, err = custodyauthority.SignEntry(c, key(7))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := r.Entry.CanonicalBytes()
	if err != nil {
		t.Fatal("regression requires a valid V1 co-signed entry", err)
	}
	if parsed, err := custodyauthority.DecodeEntry(encoded); err != nil || parsed != r.Entry {
		t.Fatal("V1 core entry was invalid", err)
	}
	if _, err := r.CanonicalBytes(); !errors.Is(err, ErrProtocol) {
		t.Fatal("legacy admission encoded a V1 entry", err)
	}
	var output bytes.Buffer
	if err := WriteRequest(&output, r); !errors.Is(err, ErrProtocol) || output.Len() != 0 {
		t.Fatal("legacy admission wrote V1 bytes", err)
	}
	raw := append([]byte(nil), requestMagic...)
	raw = append(raw, r.Nonce[:]...)
	raw = append(raw, encoded...)
	if len(raw) != RequestBytes {
		t.Fatal("regression frame has wrong length")
	}
	if _, err := DecodeRequest(raw); !errors.Is(err, ErrProtocol) {
		t.Fatal("legacy admission decoded V1", err)
	}
	if _, err := ReadRequest(bytes.NewReader(raw)); !errors.Is(err, ErrProtocol) {
		t.Fatal("legacy admission stream accepted V1", err)
	}
	for _, mixed := range []Request{
		{Nonce: r.Nonce, Entry: custodyauthority.Entry{Version: custodyauthority.Version0, Command: c}},
		{Nonce: r.Nonce, Entry: custodyauthority.Entry{Version: custodyauthority.Version1, Command: request(t).Entry.Command}},
	} {
		if _, err := mixed.CanonicalBytes(); !errors.Is(err, ErrProtocol) {
			t.Fatal("legacy admission version guard omitted a nested version", err)
		}
	}
}
