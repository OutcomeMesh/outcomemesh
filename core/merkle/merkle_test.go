package merkle

import (
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestRootPreservesOrderAndDuplicatesOddNode(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	got := Root(payloads, "empty", "leaf", "node")
	a := types.DomainHash("leaf", []byte("a"))
	b := types.DomainHash("leaf", []byte("b"))
	c := types.DomainHash("leaf", []byte("c"))
	ab := types.DomainHash("node", a[:], b[:])
	cc := types.DomainHash("node", c[:], c[:])
	want := types.DomainHash("node", ab[:], cc[:])
	if got != want {
		t.Fatalf("root: got %s want %s", got, want)
	}

	reordered := Root([][]byte{payloads[1], payloads[0], payloads[2]}, "empty", "leaf", "node")
	if reordered == got {
		t.Fatal("reordering leaves did not change the root")
	}
}

func TestEmptyRootUsesSeparateDomain(t *testing.T) {
	t.Parallel()

	if got, want := Root(nil, "empty-a", "leaf", "node"), types.DomainHash("empty-a"); got != want {
		t.Fatalf("empty root: got %s want %s", got, want)
	}
	if Root(nil, "empty-a", "leaf", "node") == Root(nil, "empty-b", "leaf", "node") {
		t.Fatal("empty domains did not separate roots")
	}
}
