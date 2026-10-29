package pebblestore

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

func TestProtocol2ForkReopenAndDirectCommitBinding(t *testing.T) {
	doc := testGenesis()
	doc.Version = genesis.Version2
	path := filepath.Join(t.TempDir(), "db")
	s, e := Open(path, doc)
	if e != nil {
		t.Fatal(e)
	}
	r, e := reference.New(doc)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	base, _ := s.Tip()
	params := block.ParametersFromGenesis(doc)
	parent := base
	var tips = []storage.Tip{base}
	var roots = []types.Hash{base.StateRoot}
	for i := 0; i < 8; i++ {
		// Build a longer competing branch after three canonical extensions.
		if i == 3 {
			parent = base
		}
		pre, e := s.SnapshotAt(parent.ID)
		if e != nil {
			t.Fatal(e)
		}
		context, e := storage.ParentContext(s, parent)
		if e != nil {
			t.Fatal(e)
		}
		candidate, result, e := block.Prepare(pre, context, nil, types.Address{byte(i + 1)}, parent.Timestamp+1, params)
		if e != nil {
			t.Fatal(e)
		}
		for _, store := range []storage.Ledger{s, r} {
			wrong := candidate
			wrong.Header.Version = 0
			if _, e := store.Commit(parent, wrong, result.State); !errors.Is(e, block.ErrUnsupportedVersion) {
				t.Fatal("store version bypass", e)
			}
			legacy, _ := state.New(result.State.Resources())
			if _, e := store.Commit(parent, candidate, legacy); !errors.Is(e, state.ErrCommitmentVersion) {
				t.Fatal("store state downgrade", e)
			}
			if _, e := store.Commit(parent, candidate, result.State); e != nil {
				t.Fatal(e)
			}
		}
		id, _ := candidate.Header.ID()
		parent, e = s.TipByID(id)
		if e != nil {
			t.Fatal(e)
		}
		tips = append(tips, parent)
		roots = append(roots, result.FinalRoot)
	}
	check := func(s *Store) {
		t.Helper()
		for i, tip := range tips {
			a, e := s.SnapshotAt(tip.ID)
			if e != nil {
				t.Fatal(e)
			}
			b, e := r.SnapshotAt(tip.ID)
			if e != nil || a.Root() != roots[i] || a.Root() != b.Root() || a.CommitmentVersion() != state.CommitmentRadixV1 {
				t.Fatal("replay root/version", e)
			}
		}
		a, _ := s.Tip()
		b, _ := r.Tip()
		if !storage.EqualTips(a, b) {
			t.Fatal("fork selection")
		}
	}
	check(s)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	old := doc
	old.Version = 0
	if bad, e := Open(path, old); e == nil {
		bad.Close()
		t.Fatal("genesis downgrade accepted")
	}
	s, e = Open(path, doc)
	if e != nil {
		t.Fatal(e)
	}
	check(s)
	s.Close()
	s, e = OpenExistingReadOnly(path, doc, DefaultPolicy())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	check(s)
}
