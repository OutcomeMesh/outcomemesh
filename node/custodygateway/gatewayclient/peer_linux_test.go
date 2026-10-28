//go:build linux

package gatewayclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGatewayClientChecksKernelServerUID(t *testing.T) {
	key := func(v byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{v}, 32)) }
	h := types.DomainHash("peer-test", []byte("test"))
	d := wire.Descriptor{RootID: h, SourceID: h, GenesisID: h, GenesisDescriptorID: h, EnrollmentID: h, OwnerUID: uint32(os.Geteuid()) + 1, ParticipantUID: 65534, EventLimit: 8}
	if d.OwnerUID == d.ParticipantUID {
		d.ParticipantUID = 65533
	}
	copy(d.Gateway[:], key(2).Public().(ed25519.PublicKey))
	copy(d.Issuer[:], key(1).Public().(ed25519.PublicKey))
	var pub [32]byte
	copy(pub[:], key(3).Public().(ed25519.PublicKey))
	d.Clients = [][32]byte{pub}
	d, e := d.Sign(key(1))
	if e != nil {
		t.Fatal(e)
	}
	id, _ := d.ID()
	q, e := (wire.Request{DescriptorID: id, Nonce: h, Kind: wire.Inspect}).Sign(key(3))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "socket")
	l, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, e = Call(ctx, path, d, q); !errors.Is(e, wire.ErrAccess) {
		t.Fatal("wrong server UID accepted", e)
	}
}
