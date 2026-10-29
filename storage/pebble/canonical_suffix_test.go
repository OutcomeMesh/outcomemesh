package pebblestore

import (
	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
	"testing"
)

func TestCanonicalAppendRetainsPrefixAndOnlyBuildsOneHeight(t *testing.T) {
	doc := testGenesis()
	s, e := Open(t.TempDir(), doc)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var retained []types.Hash
	for range 40 {
		parent, candidate, post := prepareBlockForStore(t, s, doc)
		next, e := storage.NextTip(parent, candidate)
		if e != nil {
			t.Fatal(e)
		}
		suffix, common, e := s.canonicalSuffixUnlocked(parent, next, candidate)
		if e != nil || common != parent.Height || len(suffix) != 1 || suffix[next.Height] != next.ID {
			t.Fatal("append scanned prefix", len(suffix), common, e)
		}
		tip, e := s.Commit(parent, candidate, post)
		if e != nil {
			t.Fatal(e)
		}
		retained = append(retained, tip.ID)
	}
	for i, id := range retained {
		b, e := s.Block(uint64(i + 1))
		if e != nil {
			t.Fatal(e)
		}
		got, _ := b.Header.ID()
		if got != id {
			t.Fatal("prefix changed")
		}
	}
	// Build a fork from height 38: exactly two old heights are divergent.
	ancestor, e := s.TipByID(retained[37])
	if e != nil {
		t.Fatal(e)
	}
	candidate, _ := prepareStoredChild(t, s, ancestor, types.Address{9}, block.ParametersFromGenesis(doc))
	next, e := storage.NextTip(ancestor, candidate)
	if e != nil {
		t.Fatal(e)
	}
	current, e := s.Tip()
	if e != nil {
		t.Fatal(e)
	}
	suffix, common, e := s.canonicalSuffixUnlocked(current, next, candidate)
	if e != nil || common != 38 || len(suffix) != 1 {
		t.Fatal("fork suffix", len(suffix), common, e)
	}
}
