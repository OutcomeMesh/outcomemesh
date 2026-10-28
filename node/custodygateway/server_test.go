//go:build linux || darwin

package custodygateway

import (
	"context"
	"errors"
	"github.com/outcomemesh/outcomemesh/core/types"
	client "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGatewaySocketCleanupCannotResetOwners(t *testing.T) {
	o := testOwner(t)
	socket := filepath.Join(filepath.Dir(o.root), "gateway.sock")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if !client.Supported() {
		if e := Serve(ctx, o, socket, nil); e == nil {
			t.Fatal("unsupported peer identity silently accepted")
		}
		return
	}
	ready := make(chan types.Hash, 1)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, o, socket, func(id types.Hash) error { ready <- id; return nil }) }()
	var id types.Hash
	select {
	case id = <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not start")
	}
	if e := CleanupSocket(o.root, socket, id); e == nil {
		t.Fatal("live owner socket removed")
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	o.Close()
	if _, e := os.Stat(socket); e != nil {
		t.Fatal("shutdown removed evidence", e)
	}
	if e := CleanupSocket(o.root, socket, testHash("wrong socket")); e == nil {
		t.Fatal("unreviewed cleanup")
	}
	if e := CleanupSocket(o.root, socket, id); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(socket); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	if _, e := ReadIdentity(o.root); e != nil {
		t.Fatal("cleanup changed owner identity", e)
	}
}
