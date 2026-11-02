package serviceclient

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// Public deterministic artifacts from servicewire's fixed-vector fixture. They
// contain test signatures only. Re-signing below changes only the test peer UID
// and enclosing exchange IDs, while preserving the exact original Prune proof.
//
//go:embed testdata/public_exchange.json
var publicExchange []byte

type exchangeFixture struct {
	d                  wire.Descriptor
	q                  wire.Request
	c                  wire.Challenge
	result, settlement wire.Response
}

func loadFixture(t testing.TB) exchangeFixture {
	t.Helper()
	var raw [][]byte
	if err := json.Unmarshal(publicExchange, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 5 {
		t.Fatal("invalid public fixture")
	}
	d, err := wire.DecodeDescriptor(raw[0])
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.DecodeRequest(raw[1])
	if err != nil {
		t.Fatal(err)
	}
	c, err := wire.DecodeChallenge(raw[2])
	if err != nil {
		t.Fatal(err)
	}
	r, err := wire.DecodeResponse(raw[3])
	if err != nil {
		t.Fatal(err)
	}
	s, err := wire.DecodeResponse(raw[4])
	if err != nil {
		t.Fatal(err)
	}
	d.OwnerUID = uint32(os.Geteuid())
	d.ParticipantUID = 65534
	if d.ParticipantUID == d.OwnerUID {
		d.ParticipantUID--
	}
	d, err = d.Sign(fencetest.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	q.DescriptorID, err = d.ID()
	if err != nil {
		t.Fatal(err)
	}
	q, err = q.Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	c.DescriptorID = q.DescriptorID
	c.RequestID, _ = q.ID()
	c.Before, _ = q.IntentPosition()
	c, err = c.Sign(d, q, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	r.DescriptorID = q.DescriptorID
	r.RequestID = c.RequestID
	r, err = r.Sign(d, q, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	s.DescriptorID = q.DescriptorID
	s.RequestID = c.RequestID
	s, err = s.Sign(d, q, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	return exchangeFixture{d, q, c, r, s}
}

func TestCallValidatesBeforeDialing(t *testing.T) {
	f := loadFixture(t)
	for _, test := range []struct {
		name   string
		ctx    context.Context
		socket string
		d      wire.Descriptor
		q      wire.Request
	}{
		{"nil context", nil, filepath.Join(t.TempDir(), "absent.sock"), f.d, f.q},
		{"relative socket", t.Context(), "relative.sock", f.d, f.q},
		{"invalid descriptor", t.Context(), filepath.Join(t.TempDir(), "absent.sock"), wire.Descriptor{}, f.q},
		{"invalid request", t.Context(), filepath.Join(t.TempDir(), "absent.sock"), f.d, wire.Request{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Call(test.ctx, test.socket, test.d, test.q, nil); !errors.Is(err, wire.ErrAccess) {
				t.Fatalf("reached dialing instead of access rejection: %v", err)
			}
		})
	}
	if !gatewayclient.Supported() {
		if _, err := Call(t.Context(), filepath.Join(t.TempDir(), "absent.sock"), f.d, f.q, nil); !errors.Is(err, wire.ErrAccess) {
			t.Fatalf("unsupported platform attempted transport: %v", err)
		}
	}
}
