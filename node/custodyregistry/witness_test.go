package custodyregistry

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func registryWitnessBefore(t testing.TB, g Genesis) custodyfence.WitnessPin {
	t.Helper()
	id, err := g.ID()
	if err != nil {
		t.Fatal(err)
	}
	return custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: id}}
}
func registryWitnessOpen(t testing.TB, path string, g Genesis, seed byte, pin custodyfence.WitnessPin) *Witness {
	t.Helper()
	id, _ := g.ID()
	w, err := OpenWitness(path, g, id, f.Key(seed), pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}
func registryWitnessCreate(t testing.TB, g Genesis, seed byte) (string, *Witness) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry")
	id, _ := g.ID()
	if err := CreateWitness(path, g, id, f.Key(seed)); err != nil {
		t.Fatal(err)
	}
	return path, registryWitnessOpen(t, path, g, seed, registryWitnessBefore(t, g))
}
func registryWitnessCert(t testing.TB, g Genesis, s Selection, seeds ...byte) Certificate {
	t.Helper()
	q := Certificate{Version: Version1, Selection: s}
	for _, seed := range seeds {
		v, err := SignVote(g, s, f.Key(seed))
		if err != nil {
			t.Fatal(err)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if err := q.Verify(g); err != nil {
		t.Fatal(err)
	}
	return q
}
func registryWitnessAlternative(t testing.TB, g Genesis, s Selection, label string) Selection {
	t.Helper()
	a := s.Initial.Assignment.Base
	base, err := workarchive.CreateRemoteCustodyAuthorityAssignment(s.Initial.Manifest, s.Initial.Initial, s.Initial.CustodyPolicy, f.Hash(label), a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s.Initial.Assignment.Base = base
	s.IssuerSignature, s.AuthoritySignature, s.ControlSignature = [64]byte{}, [64]byte{}, [64]byte{}
	for _, role := range []string{"issuer", "authority", "control"} {
		seed := byte(110)
		if role == "authority" {
			seed = 1
		}
		if role == "control" {
			seed = 14
		}
		s, err = s.Sign(g, role, f.Key(seed))
		if err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestCustodyRegistryWitnessQuorumKeepsOneSelectionAndMinorityVote(t *testing.T) {
	g, s := registryFixture(t)
	other := registryWitnessAlternative(t, g, s, "other-assignment")
	before := registryWitnessBefore(t, g)
	var paths []string
	var owners []*Witness
	var votes []Vote
	for i := byte(0); i < 4; i++ {
		path, w := registryWitnessCreate(t, g, 111+i)
		paths = append(paths, path)
		owners = append(owners, w)
		choice := s
		if i == 3 {
			choice = other
		}
		vote, err := w.VoteAt(before, choice)
		if err != nil {
			t.Fatal(err)
		}
		if i < 3 {
			votes = append(votes, vote)
		}
	}
	for _, w := range owners[:3] {
		_, pending, err := w.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.VoteAt(pending, other); err == nil {
			t.Fatal("retained voter signed another assignment")
		}
	}
	sort.Slice(votes, func(i, j int) bool { return bytes.Compare(votes[i].Witness[:], votes[j].Witness[:]) < 0 })
	q := Certificate{Version: Version1, Selection: s, Votes: votes}
	if err := q.Verify(g); err != nil {
		t.Fatal(err)
	}
	sid, _ := s.ID()
	otherID, _ := other.ID()
	rid, _ := g.ID()
	for i, w := range owners {
		_, pending, err := w.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if err := w.CommitAt(pending, q); err != nil {
			t.Fatal(err)
		}
		snapshot, final, err := w.Snapshot()
		if err != nil || !snapshot.SelectionFinal || final.Position != (custodyfence.Position{Sequence: 1, HeadID: sid}) || !final.PendingID.IsZero() {
			t.Fatal(snapshot, final, err)
		}
		if _, err := w.VoteAt(final, other); err == nil {
			t.Fatal("selected registry voted again")
		}
		_ = w.Close()
		w = registryWitnessOpen(t, paths[i], g, 111+byte(i), final)
		if err := w.CommitAt(pending, q); err != nil {
			t.Fatal("lost commit retry changed selection", err)
		}
		if i == 3 {
			raw, err := os.ReadFile(filepath.Join(paths[i], "selection.vote"))
			if err != nil {
				t.Fatal(err)
			}
			retained, err := DecodeSelection(raw)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := retained.ID()
			if id != otherID {
				t.Fatal("majority discarded minority proposal")
			}
		}
		_ = w.Close()
		_, err = OpenWitness(paths[i], g, rid, f.Key(111+byte(i)), before)
		if err == nil {
			t.Fatal("stale open unexpectedly succeeded")
		}
	}
}

func TestCustodyRegistryWitnessLostWritesRecoverOnlyExactAttempt(t *testing.T) {
	for _, stage := range []string{"selection.vote-before-sync", "selection.vote-durable", "selection.certificate-before-sync", "selection.certificate-durable"} {
		t.Run(stage, func(t *testing.T) {
			g, s := registryFixture(t)
			other := registryWitnessAlternative(t, g, s, "other-crash-assignment")
			path, w := registryWitnessCreate(t, g, 111)
			id, _ := g.ID()
			before := registryWitnessBefore(t, g)
			q := registryWitnessCert(t, g, s, 111, 112, 113)
			isVote := stage[:len("selection.vote")] == "selection.vote"
			if !isVote {
				if _, err := w.VoteAt(before, s); err != nil {
					t.Fatal(err)
				}
				_, before, _ = w.Snapshot()
			}
			w.hook = func(at string) error {
				if at == stage {
					return errors.New("injected durable boundary")
				}
				return nil
			}
			if isVote {
				if _, err := w.VoteAt(before, s); !errors.Is(err, ErrUncertain) {
					t.Fatal(err)
				}
			} else if err := w.CommitAt(before, q); !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			if _, _, err := w.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatal("uncertain owner stayed usable", err)
			}
			_ = w.Close()
			if bad, err := OpenWitness(path, g, id, f.Key(111), before); err == nil {
				_ = bad.Close()
				t.Fatal("cold open adopted advanced pin")
			}
			var recovered *Witness
			var err error
			if isVote {
				if bad, err := RecoverVote(path, g, id, f.Key(111), before, other); err == nil {
					_ = bad.Close()
					t.Fatal("foreign vote recovered")
				}
				recovered, err = RecoverVote(path, g, id, f.Key(111), before, s)
				if err != nil {
					t.Fatal(err)
				}
				defer recovered.Close()
				vote, err := recovered.VoteAt(before, s)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := SignVote(g, s, f.Key(111))
				if err != nil || vote != expected {
					t.Fatal("vote recovery changed signature", err)
				}
				if _, err := os.Lstat(filepath.Join(path, "selection.certificate")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("open created a certificate", err)
				}
			} else {
				if bad, err := RecoverCommit(path, g, id, f.Key(111), before, registryWitnessCert(t, g, other, 111, 112, 113)); err == nil {
					_ = bad.Close()
					t.Fatal("foreign commit recovered")
				}
				recovered, err = RecoverCommit(path, g, id, f.Key(111), before, q)
				if err != nil {
					t.Fatal(err)
				}
				defer recovered.Close()
				if err := recovered.CommitAt(before, q); err != nil {
					t.Fatal(err)
				}
				x, _, err := recovered.Snapshot()
				if err != nil || !x.SelectionFinal {
					t.Fatal(x, err)
				}
			}
		})
	}
}

func TestCustodyRegistryWitnessPinsTheExactCertificateSubset(t *testing.T) {
	g, s := registryFixture(t)
	path, w := registryWitnessCreate(t, g, 111)
	before := registryWitnessBefore(t, g)
	if _, err := w.VoteAt(before, s); err != nil {
		t.Fatal(err)
	}
	_, pending, _ := w.Snapshot()
	q := registryWitnessCert(t, g, s, 111, 112, 113)
	other := registryWitnessCert(t, g, s, 112, 113, 114)
	if err := w.CommitAt(pending, q); err != nil {
		t.Fatal(err)
	}
	if err := w.CommitAt(pending, other); err == nil {
		t.Fatal("another valid QC subset replaced attempt")
	}
	_ = w.Close()
	id, _ := g.ID()
	if bad, err := RecoverCommit(path, g, id, f.Key(111), pending, other); err == nil {
		_ = bad.Close()
		t.Fatal("cold QC subset replacement accepted")
	}
	w, err := RecoverCommit(path, g, id, f.Key(111), pending, q)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.CommitAt(pending, q); err != nil {
		t.Fatal(err)
	}
}

func registryWitnessCopy(t testing.TB, source, destination string) {
	t.Helper()
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, entry.Name()), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCustodyRegistryWitnessOriginalPlacementAndDescriptorPins(t *testing.T) {
	g, s := registryFixture(t)
	path, w := registryWitnessCreate(t, g, 111)
	id, _ := g.ID()
	before := registryWitnessBefore(t, g)
	if bad, err := OpenWitness(path, g, id, f.Key(111), before); err == nil {
		_ = bad.Close()
		t.Fatal("second live owner obtained lock")
	}
	_ = w.Close()
	copyPath := filepath.Join(t.TempDir(), "copy")
	registryWitnessCopy(t, path, copyPath)
	if bad, err := OpenWitness(copyPath, g, id, f.Key(111), before); err == nil {
		_ = bad.Close()
		t.Fatal("copy adopted original registry")
	}
	moved := path + "-moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if bad, err := OpenWitness(moved, g, id, f.Key(111), before); err == nil {
		_ = bad.Close()
		t.Fatal("moved registry opened")
	}
	if err := os.Rename(moved, path); err != nil {
		t.Fatal(err)
	}
	changed := g
	changed.MaximumOperations++
	changedID, _ := changed.ID()
	if changedID != id {
		t.Fatal("descriptor changed namespace")
	}
	if bad, err := OpenWitness(path, changed, id, f.Key(111), before); err == nil {
		_ = bad.Close()
		t.Fatal("foreign descriptor adopted")
	}
	if bad, err := OpenWitness(path, g, f.Hash("wrong-anchor"), f.Key(111), before); err == nil {
		_ = bad.Close()
		t.Fatal("foreign anchor pin adopted")
	}
	if bad, err := OpenWitness(path, g, id, f.Key(112), before); err == nil {
		_ = bad.Close()
		t.Fatal("another member adopted root")
	}
	if err := os.WriteFile(filepath.Join(path, "unexpected"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if bad, err := OpenWitness(path, g, id, f.Key(111), before); err == nil {
		_ = bad.Close()
		t.Fatal("extra file accepted")
	}
	if err := os.Remove(filepath.Join(path, "unexpected")); err != nil {
		t.Fatal(err)
	}
	w = registryWitnessOpen(t, path, g, 111, before)
	if _, err := w.VoteAt(before, s); err != nil {
		t.Fatal(err)
	}
	_, pending, _ := w.Snapshot()
	_ = w.Close()
	if err := os.WriteFile(filepath.Join(path, "selection.vote"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if bad, err := OpenWitness(path, g, id, f.Key(111), pending); err == nil {
		_ = bad.Close()
		t.Fatal("partial proposal repaired")
	}
}

func TestCustodyRegistryWitnessConcurrentCandidatesAndReadOnlyOpen(t *testing.T) {
	g, s := registryFixture(t)
	other := registryWitnessAlternative(t, g, s, "parallel-assignment")
	path, w := registryWitnessCreate(t, g, 111)
	before := registryWitnessBefore(t, g)
	var mu sync.Mutex
	success := 0
	var wait sync.WaitGroup
	for _, candidate := range []Selection{s, other} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := w.VoteAt(before, candidate); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	if success != 1 {
		t.Fatal("competing proposals did not choose one", success)
	}
	_, pin, err := w.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	raw, err := os.ReadFile(filepath.Join(path, "selection.vote"))
	if err != nil {
		t.Fatal(err)
	}
	w = registryWitnessOpen(t, path, g, 111, pin)
	defer w.Close()
	after, err := os.ReadFile(filepath.Join(path, "selection.vote"))
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("cold open changed proposal", err)
	}
	if _, err := os.Lstat(filepath.Join(path, "selection.certificate")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cold open created commit", err)
	}
}

func TestCustodyRegistryWitnessInitializationNeverRecreatesOrAcceptsLossyPaths(t *testing.T) {
	g, _ := registryFixture(t)
	id, _ := g.ID()
	parent := t.TempDir()
	invalid := filepath.Join(parent, string([]byte{'b', 'a', 'd', 0xff}))
	if err := CreateWitness(invalid, g, id, f.Key(111)); err == nil {
		t.Fatal("lossy UTF-8 placement accepted")
	}
	if _, err := os.Lstat(invalid); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad path created", err)
	}
	root := filepath.Join(parent, "partial")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := CreateWitness(root, g, id, f.Key(111)); err == nil {
		t.Fatal("existing partial root recreated")
	}
	if bad, err := OpenWitness(root, g, id, f.Key(111), registryWitnessBefore(t, g)); err == nil {
		_ = bad.Close()
		t.Fatal("partial root opened")
	}
	missing := filepath.Join(parent, "missing")
	if bad, err := OpenWitness(missing, g, id, f.Key(111), registryWitnessBefore(t, g)); err == nil {
		_ = bad.Close()
		t.Fatal("missing root adopted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("open created missing root", err)
	}
	wrong := filepath.Join(parent, "wrong-key")
	if err := CreateWitness(wrong, g, id, f.Key(115)); err == nil {
		t.Fatal("foreign key enrolled")
	}
	if _, err := os.Lstat(wrong); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign key created root", err)
	}
	malformed := append([]byte(nil), f.Key(111)...)
	malformed[0] ^= 1
	if err := CreateWitness(wrong, g, id, malformed); err == nil {
		t.Fatal("private seed/public half mismatch enrolled")
	}
	if _, err := os.Lstat(wrong); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("malformed private key created root", err)
	}
}

func TestCustodyRegistryWitnessSamePathRecreationAndPartialCommitAreBlocked(t *testing.T) {
	g, s := registryFixture(t)
	path, w := registryWitnessCreate(t, g, 111)
	id, _ := g.ID()
	before := registryWitnessBefore(t, g)
	_ = w.Close()
	saved := path + "-saved"
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	registryWitnessCopy(t, saved, path)
	if bad, err := OpenWitness(path, g, id, f.Key(111), before); err == nil {
		_ = bad.Close()
		t.Fatal("replacement at the same path adopted old placement")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, path); err != nil {
		t.Fatal(err)
	}
	w = registryWitnessOpen(t, path, g, 111, before)
	q := registryWitnessCert(t, g, s, 111, 112, 113)
	if err := w.CommitAt(before, q); err != nil {
		t.Fatal(err)
	}
	_, final, err := w.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	file := filepath.Join(path, "selection.certificate")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if bad, err := OpenWitness(path, g, id, f.Key(111), final); err == nil {
		_ = bad.Close()
		t.Fatal("truncated committed certificate was repaired")
	}
	if bad, err := RecoverCommit(path, g, id, f.Key(111), before, q); err == nil {
		_ = bad.Close()
		t.Fatal("exact retry overwrote truncated retained certificate")
	}
}
