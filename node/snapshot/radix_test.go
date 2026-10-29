package snapshot

import (
	"errors"
	"github.com/outcomemesh/outcomemesh/core/state"
	"testing"
)

func TestSnapshotCommitmentMustComeFromLocalChain(t *testing.T) {
	for _, count := range []int{0, 3} {
		for _, version := range []uint16{state.CommitmentV0, state.CommitmentRadixV1} {
			source, e := state.NewVersion(testState(t, count).Resources(), version)
			if e != nil {
				t.Fatal(e)
			}
			ex, e := NewExporter(91, testTip(source), source, 2)
			if e != nil {
				t.Fatal(e)
			}
			m := ex.Manifest()
			for _, expected := range []uint16{0, 1} {
				c, e := NewCollectorVersion(m, testAnchor(m), 10, expected)
				if e != nil {
					t.Fatal(e)
				}
				for i := uint32(0); i < m.ChunkCount; i++ {
					chunk, e := ex.Chunk(i)
					if e != nil {
						t.Fatal(e)
					}
					if e = c.Add(chunk); e != nil {
						t.Fatal(e)
					}
				}
				got, e := c.Finalize()
				if expected != version {
					if !errors.Is(e, ErrStateRoot) {
						t.Fatal("root selected peer version", e)
					}
				} else if e != nil || got.CommitmentVersion() != version || got.Root() != source.Root() {
					t.Fatal("versioned snapshot", e)
				}
			}
			if _, e := NewCollectorVersion(m, testAnchor(m), 10, 2); !errors.Is(e, state.ErrCommitmentVersion) {
				t.Fatal("unknown commitment", e)
			}
		}
	}
}
