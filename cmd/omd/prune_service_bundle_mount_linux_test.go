//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	"golang.org/x/sys/unix"
)

func TestPruneStorageBundleRefusesOtherMount(t *testing.T) {
	f, bundle := newPruneTransferBundle(t)
	parent, err := os.MkdirTemp("/dev/shm", "prune-transfer-")
	if err != nil {
		t.Skipf("no writable second filesystem: %v", err)
	}
	t.Cleanup(func() { os.Remove(parent) })
	var a, b unix.Stat_t
	if err := unix.Stat(bundle.Source, &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(parent, &b); err != nil {
		t.Fatal(err)
	}
	if a.Dev == b.Dev {
		t.Skip("both fixtures use the same filesystem")
	}
	bundle.Destination = filepath.Join(parent, "moved")
	did, _ := f.descriptor.ID()
	_, err = service.ReviewTransfer(t.Context(), f.root, filepath.Join(bundle.Destination, "owner"), did, wire.Position{}, bundle, filepath.Join(f.public, "report"))
	if !errors.Is(err, syscall.EXDEV) {
		t.Fatal("expected cross-mount rejection", err)
	}
	if _, err = os.Lstat(bundle.Destination); !os.IsNotExist(err) {
		t.Fatal("destination created", err)
	}
	f.open(t, wire.Position{}, nil)
	f.assertObligations(t)
}
