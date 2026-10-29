package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/state"
)

func TestInitProtocol2MineReopenAndRefuseWorkGraph(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	if e := runInit([]string{"--data", dir, "--protocol-version", "2", "--network", "10102", "--timestamp", "1700000000", "--difficulty-bits", "9"}); e != nil {
		t.Fatal(e)
	}
	doc, e := loadGenesis(dir)
	if e != nil || doc.Version != genesis.Version2 {
		t.Fatal("genesis", e)
	}
	id, _ := doc.ID()
	if e := runWorkEnable([]string{"--data", dir, "--activation-height", "1", "--confirm-genesis", id.String()}); e == nil {
		t.Fatal("WorkGraph v1 accepted radix")
	}
	if _, e := os.Stat(filepath.Join(dir, workActivationFilename)); !os.IsNotExist(e) {
		t.Fatal("wrote incompatible profile")
	}
	if e := runMine([]string{"--data", dir, "--count", "2"}); e != nil {
		t.Fatal(e)
	}
	if e := runVerify([]string{"--data", dir}); e != nil {
		t.Fatal(e)
	}
	s, e := openStore(dir, doc)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	tip, e := s.Tip()
	if e != nil || tip.Height != 2 {
		t.Fatal("tip", e)
	}
	snapshot, e := s.Snapshot()
	if e != nil || snapshot.CommitmentVersion() != state.CommitmentRadixV1 {
		t.Fatal("state", e)
	}
	for h := uint64(1); h <= 2; h++ {
		b, e := s.Block(h)
		if e != nil || b.Header.Version != 2 {
			t.Fatal("block", e)
		}
	}
	for _, v := range []string{"1", "2", "3", "65538"} {
		path := filepath.Join(t.TempDir(), "bad")
		if e := runInit([]string{"--data", path, "--protocol-version", v}); e == nil {
			t.Fatal("implicit network or unsupported version", v)
		}
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("invalid init wrote data")
		}
	}
}
