package workchain

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestRadixForkTransitionCheckpointAndColdReopen(t *testing.T) {
	p := testParameters()
	p.RadixActivationHeight = 3
	base := testBaseWithResources(t, p, 30)
	dir := filepath.Join(t.TempDir(), "work")
	policy := DefaultPolicy()
	policy.CheckpointEvery = 2
	policy.CheckpointKeep = 2
	s, e := OpenWithPolicy(dir, base, p, policy)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if s != nil {
			s.Close()
		}
	}()
	a, rA := mineChild(t, s, base.Tip.ID, base.Tip.Timestamp+60, "a1")
	if _, _, e = s.Commit(a, a.Header.Seal.Timestamp); e != nil {
		t.Fatal(e)
	}
	b, rB := mineChild(t, s, base.Tip.ID, base.Tip.Timestamp+60, "b1")
	if _, _, e = s.Commit(b, b.Header.Seal.Timestamp); e != nil {
		t.Fatal(e)
	}
	branches := []struct {
		label string
		r     workblock.Result
	}{{"a", rA}, {"b", rB}}
	var all []workblock.Block
	all = append(all, a, b)
	for i := range branches {
		for h := uint64(2); h <= 4; h++ {
			b, r := mineChild(t, s, branches[i].r.BlockID, base.Tip.Timestamp+h*60, branches[i].label)
			if b.Header.Version != p.VersionAt(h) || r.State.CommitmentVersion() != p.CommitmentAt(h) {
				t.Fatal("wrong version")
			}
			if _, _, e = s.Commit(b, b.Header.Seal.Timestamp); e != nil {
				t.Fatal(e)
			}
			branches[i].r = r
			all = append(all, b)
		}
	}
	tip, e := s.Tip()
	if e != nil || tip.ID != branches[0].r.BlockID {
		t.Fatal("exact-work incumbent", e)
	}
	c, rC := mineChild(t, s, branches[1].r.BlockID, base.Tip.Timestamp+5*60, "b5")
	if _, _, e = s.Commit(c, c.Header.Seal.Timestamp); e != nil {
		t.Fatal(e)
	}
	all = append(all, c)
	snapshot, e := s.Snapshot()
	if e != nil || snapshot.Root() != rC.State.Root() {
		t.Fatal("reorg", e)
	}
	clone, e := cloneState(snapshot)
	if e != nil || clone != snapshot {
		t.Fatal("full snapshot rebuild")
	}
	if rA.State.CommitmentVersion() != 0 || rB.State.CommitmentVersion() != 0 || base.State.CommitmentVersion() != 0 {
		t.Fatal("old states mutated")
	}
	checkpoint, e := s.CreateReplayCheckpoint()
	if e != nil || checkpoint.CheckpointHeight == 0 {
		t.Fatal("checkpoint", e)
	}
	if s.LegacyArchiveCompatible() {
		t.Fatal("unversioned archive binding")
	}
	if _, e = s.PruneCanonicalPrefix(CanonicalFloor{}); !errors.Is(e, ErrCanonicalPrune) {
		t.Fatal("prune", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = nil
	wrong := p
	wrong.RadixActivationHeight++
	if other, e := OpenWithPolicy(dir, base, wrong, policy); e == nil {
		other.Close()
		t.Fatal("changed schedule reopened")
	}
	s, e = OpenExistingReadOnly(dir, base, p, policy)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Tip()
	if e != nil || got.ID != rC.BlockID {
		t.Fatal("cold tip", e)
	}
	snapshot, e = s.Snapshot()
	if e != nil || snapshot.Root() != rC.State.Root() || snapshot.CommitmentVersion() != state.CommitmentRadixV1 {
		t.Fatal("cold radix", e)
	}
	inventory, e := s.MigrationBlocks(1 << 20)
	if e != nil || len(inventory) != len(all) {
		t.Fatal("fork inventory", e)
	}
	for _, b := range all {
		id, _ := b.Header.ID()
		v, e := s.BlockByID(id)
		if e != nil || !bytes.Equal(b.CanonicalBytes(), v.CanonicalBytes()) {
			t.Fatal("lost fork", e)
		}
	}
	if _, e = s.MigrationBlocks(1); !errors.Is(e, storage.ErrHistoryLimit) {
		t.Fatal("migration budget", e)
	}
}

func TestMigrationInventoryRefusesOperationalAndPrunedStores(t *testing.T) {
	p := testParameters()
	base := testBase(t, p)
	for _, mode := range []string{"pruned", "effects", "pins", "binding"} {
		t.Run(mode, func(t *testing.T) {
			s, e := New(base, p)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "pruned":
				s.floor.Pruned = true
			case "effects":
				s.persistence = &workPersistence{effectSchema: true}
			case "pins":
				s.persistence = &workPersistence{pins: &storagePositionPins{}}
			case "binding":
				s.persistence = &workPersistence{storageID: base.Tip.ID}
			}
			if _, e = s.MigrationBlocks(1 << 20); !errors.Is(e, ErrCanonicalPrune) {
				t.Fatal(mode, e)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "bound")
	bound, e := CreateBoundWithPolicy(path, base, p, DefaultPolicy(), base.Tip.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = bound.Close(); e != nil {
		t.Fatal(e)
	}
	if s, e := OpenExistingReadOnly(path, base, p, DefaultPolicy()); e == nil {
		s.Close()
		t.Fatal("unbound migration opened bound store")
	}
	if s, e := OpenExistingReadOnly(filepath.Join(t.TempDir(), "absent"), base, p, DefaultPolicy()); e == nil {
		s.Close()
		t.Fatal("read-only bootstrapped absent store")
	}
}
