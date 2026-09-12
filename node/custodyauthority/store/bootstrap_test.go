package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func bootstrapTree(t testing.TB, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			files[name] = "directory"
			return nil
		}
		data, err := os.ReadFile(path)
		files[name] = string(data)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCoordinatedAuthorityBootstrapOwnsBothRoots(t *testing.T) {
	root := t.TempDir()
	writer, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
	coordinator, err := CreateCoordinatedAuthority(writer, pins, testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	initial := testCoordination(t, coordinator)
	if initial.Pending != nil || initial.Confirmed != initialPosition(t) || initial.Authority.Phase != custodyauthority.Accepting || initial.Authority.Sequence != 0 {
		t.Fatal("bootstrap is not an unused confirmed authority")
	}
	if other, err := OpenCoordinator(writer, pins, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrBusy) {
		_ = other.Close()
		t.Fatalf("coordinator did not keep pin ownership: %v", err)
	}
	if other, err := Open(writer, testAssignment(), testAssignmentID(t), initialPosition(t)); !errors.Is(err, ErrBusy) {
		_ = other.Close()
		t.Fatalf("coordinator did not keep authority ownership: %v", err)
	}
	before := bootstrapTree(t, root)
	if err := coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		other, err := OpenCoordinator(writer, pins, testAssignment(), testAssignmentID(t))
		if err != nil {
			t.Fatal(err)
		}
		if got := testCoordination(t, other); !reflect.DeepEqual(got, initial) {
			t.Fatal("read-only reopen advanced bootstrap")
		}
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, bootstrapTree(t, root)) {
		t.Fatal("verification changed retained bytes")
	}
	if other, err := CreateCoordinatedAuthority(writer, pins, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
		_ = other.Close()
		t.Fatalf("second create was not refused: %v", err)
	}
}

func TestCoordinatedAuthorityBootstrapPreservesPartialInitialization(t *testing.T) {
	stages := []string{"authority-before-ready", "authority-ready-file-synced", "authority-ready-directory-synced", "intent-before-ready", "intent-ready-file-synced", "intent-ready-directory-synced"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			writer, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
			fault := errors.New("injected bootstrap boundary")
			reached := false
			coordinator, err := createCoordinatedAuthority(writer, pins, testAssignment(), testAssignmentID(t), storeHooks{at: func(at string) error {
				if at != stage {
					return nil
				}
				reached = true
				// The authority's first ready boundary is already inside both
				// process locks: there is no create-close-reopen ownership gap.
				for _, pair := range [][2]string{{pins, intentLockName}, {writer, lockName}} {
					lock, err := openNamedLock(pair[0], pair[1], false)
					if !errors.Is(err, ErrBusy) {
						if lock != nil {
							_ = lock.Close()
						}
						t.Fatalf("bootstrap boundary lost ownership: %v", err)
					}
				}
				return fault
			}})
			if !reached || coordinator != nil || !errors.Is(err, fault) {
				t.Fatalf("fault was not returned without owner: reached=%t err=%v", reached, err)
			}
			before := bootstrapTree(t, root)
			for _, pair := range [][2]string{{pins, intentLockName}, {writer, lockName}} {
				lock, err := openNamedLock(pair[0], pair[1], false)
				if err != nil {
					t.Fatalf("failed constructor retained a process lock: %v", err)
				}
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if retry, err := CreateCoordinatedAuthority(writer, pins, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
				_ = retry.Close()
				t.Fatalf("partial-root bootstrap retry accepted: %v", err)
			}
			opened, err := OpenCoordinator(writer, pins, testAssignment(), testAssignmentID(t))
			ready := stage == "intent-ready-file-synced" || stage == "intent-ready-directory-synced"
			if ready {
				if err != nil {
					t.Fatal(err)
				}
				if state := testCoordination(t, opened); state.Pending != nil || state.Confirmed != initialPosition(t) {
					t.Fatal("recovered initialization produced an admission")
				}
			} else if err == nil {
				t.Fatal("incomplete initialization was accepted")
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, bootstrapTree(t, root)) {
				t.Fatal("reopen or refused retry changed preserved partial trees")
			}
		})
	}
}

func TestCoordinatedAuthorityBootstrapPreflightsBothTargets(t *testing.T) {
	for _, existing := range []string{"authority", "pins"} {
		t.Run(existing, func(t *testing.T) {
			root := t.TempDir()
			writer, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
			if err := os.Mkdir(filepath.Join(root, existing), 0o700); err != nil {
				t.Fatal(err)
			}
			before := bootstrapTree(t, root)
			owner, err := CreateCoordinatedAuthority(writer, pins, testAssignment(), testAssignmentID(t))
			if !errors.Is(err, os.ErrExist) || owner != nil {
				t.Fatalf("existing target accepted: %v", err)
			}
			if !reflect.DeepEqual(before, bootstrapTree(t, root)) {
				t.Fatal("existing target caused other root to be created")
			}
		})
	}
	root := t.TempDir()
	writer, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
	for _, id := range []types.Hash{{}, testHash(99)} {
		owner, err := CreateCoordinatedAuthority(writer, pins, testAssignment(), id)
		if !errors.Is(err, custodyauthority.ErrAssignment) || owner != nil {
			t.Fatalf("invalid independent ID accepted: %v", err)
		}
	}
	if len(bootstrapTree(t, root)) != 1 {
		t.Fatal("invalid assignment pin created roots")
	}
}

func TestCoordinatedAuthorityBootstrapClosesAfterLoadOrSnapshotFailure(t *testing.T) {
	for _, corrupt := range []string{"authority", "pins"} {
		t.Run(corrupt, func(t *testing.T) {
			root := t.TempDir()
			writer, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
			coordinator, err := createCoordinatedAuthority(writer, pins, testAssignment(), testAssignmentID(t), storeHooks{at: func(stage string) error {
				if stage == "intent-ready-directory-synced" {
					// Pins are loaded next, including their directory layout.
					// The already loaded authority's Snapshot checks retained
					// path identities, not arbitrary new directory entries.
					if corrupt == "authority" {
						return os.Rename(filepath.Join(writer, entriesName), filepath.Join(writer, "preserved-entries"))
					}
					return writeExclusive(filepath.Join(root, corrupt, "unexpected"), []byte("preserved evidence"))
				}
				return nil
			}})
			if err == nil || coordinator != nil {
				t.Fatal("invalid final initialized layout was returned as an owner")
			}
			before := bootstrapTree(t, root)
			for _, pair := range [][2]string{{pins, intentLockName}, {writer, lockName}} {
				lock, err := openNamedLock(pair[0], pair[1], false)
				if err != nil {
					t.Fatalf("load/snapshot error leaked a lock: %v", err)
				}
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if retry, err := CreateCoordinatedAuthority(writer, pins, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
				_ = retry.Close()
				t.Fatalf("failed final check caused root replacement: %v", err)
			}
			if !reflect.DeepEqual(before, bootstrapTree(t, root)) {
				t.Fatal("failed final check discarded retained evidence")
			}
		})
	}
}

func TestBootstrapPlacementIsOnlyAReadOnlyPlacementCheck(t *testing.T) {
	root := t.TempDir()
	writer, pins := filepath.Join(root, "authority"), filepath.Join(root, "pins")
	if err := ValidateBootstrapPaths(writer, pins); err != nil {
		t.Fatal(err)
	}
	if len(bootstrapTree(t, root)) != 1 {
		t.Fatal("placement review created roots")
	}
	if err := ValidateBootstrapPaths(writer, writer); !errors.Is(err, ErrRootOverlap) {
		t.Fatalf("same roots accepted: %v", err)
	}
	if err := os.Mkdir(writer, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootstrapPaths(writer, filepath.Join(writer, "nested")); !errors.Is(err, ErrRootOverlap) {
		t.Fatalf("nested roots accepted: %v", err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(writer, alias); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootstrapPaths(alias, pins); err == nil {
		t.Fatal("symlink root accepted")
	}
	if err := ValidateBootstrapPaths(writer, filepath.Join(root, "missing-parent", "pins")); err == nil {
		t.Fatal("missing parent accepted")
	}
	// Empty existing roots are placement-valid, not initialized or usable.
	if err := os.Mkdir(pins, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootstrapPaths(writer, pins); err != nil {
		t.Fatal(err)
	}
	if owner, err := OpenCoordinator(writer, pins, testAssignment(), testAssignmentID(t)); err == nil {
		_ = owner.Close()
		t.Fatal("placement review silently initialized empty roots")
	}
}
