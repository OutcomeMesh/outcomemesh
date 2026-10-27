//go:build darwin || linux

package store

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func placementFixture(t testing.TB, role string) (RemoteCustodyPlacement, *RemoteCustodyPlacementConfig) {
	t.Helper()
	directory := func() string {
		path, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	bindings := map[string]string{}
	names, err := placementNames(role)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name == "key" || strings.HasSuffix(name, "-key") {
			path := filepath.Join(directory(), "seed")
			if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
				t.Fatal(err)
			}
			bindings[name] = path
		} else {
			bindings[name] = directory()
		}
	}
	paths, err := placementPaths(role, bindings)
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range paths {
		if strings.HasSuffix(name, "-lock") {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	n, err := PrepareRemoteCustodyPlacement(testHash(201), role, filepath.Join(directory(), "placement"), bindings)
	if err != nil {
		for name, path := range paths {
			entry, e := placementEntry(name, path)
			t.Logf("binding %s mode=%o size=%d err=%v", name, entry.Mode, entry.Size, e)
		}
		t.Fatal("prepare placement", err)
	}
	id, err := n.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := PublishRemoteCustodyPlacement(t.Context(), n, id); err != nil {
		t.Fatal("publish placement", err)
	}
	return n, &RemoteCustodyPlacementConfig{Path: n.Path, ID: id, Bindings: bindings}
}

func copyPlacementTree(t testing.TB, source, dest string) {
	t.Helper()
	info, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().IsRegular() {
		b, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, b, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
		return
	}
	err = filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.Mkdir(out, 0o700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRemotePlacementRefusesCopiedKeysRootsLocksAndAnchor(t *testing.T) {
	for _, role := range []string{"audit", "serve"} {
		t.Run(role, func(t *testing.T) {
			n, c := placementFixture(t, role)
			guard, err := openRemotePlacement(c, n.AssignmentID, role, nil)
			if err != nil {
				t.Fatal(err)
			}
			entries := append([]RemoteCustodyPlacementEntry{n.Anchor}, n.Entries...)
			for _, entry := range entries {
				t.Run(entry.Name, func(t *testing.T) {
					// Keep the old inode allocated; unlink/recreate can reuse its number.
					kept := entry.Path + ".retained"
					if err := os.Rename(entry.Path, kept); err != nil {
						t.Fatal(err)
					}
					copyPlacementTree(t, kept, entry.Path)
					if err := guard.check(); !errors.Is(err, ErrRemotePlacement) {
						t.Fatal("live copy accepted", err)
					}
					if err := CheckRemoteCustodyPlacement(c, n.AssignmentID, role); !errors.Is(err, ErrRemotePlacement) {
						t.Fatal("copy accepted after restart", err)
					}
					if err := os.RemoveAll(entry.Path); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(kept, entry.Path); err != nil {
						t.Fatal(err)
					}
					if err := guard.check(); err != nil {
						t.Fatal("original inode restoration lost", err)
					}
				})
			}
			if err := CheckRemoteCustodyPlacement(c, testHash(202), role); err == nil {
				t.Fatal("wrong assignment accepted")
			}
			for name, path := range c.Bindings {
				copyPath := path + ".copy"
				copyPlacementTree(t, path, copyPath)
				m := *c
				m.Bindings = map[string]string{}
				for k, v := range c.Bindings {
					m.Bindings[k] = v
				}
				m.Bindings[name] = copyPath
				if err := CheckRemoteCustodyPlacement(&m, n.AssignmentID, role); err == nil {
					t.Fatal("copied path accepted", name)
				}
			}
		})
	}
}

func TestRemotePlacementCannotSilentlyRebindOrOverwritePin(t *testing.T) {
	if err := CheckRemoteCustodyPlacement(nil, testHash(201), "audit"); !errors.Is(err, ErrRemotePlacement) {
		t.Fatal("nil placement is not verification", err)
	}
	n, c := placementFixture(t, "audit")
	original, err := os.ReadFile(n.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := PublishRemoteCustodyPlacement(t.Context(), n, testHash(203)); err == nil {
		t.Fatal("unreviewed placement accepted")
	}
	if err := PublishRemoteCustodyPlacement(t.Context(), n, c.ID); err != nil {
		t.Fatal("exact retry", err)
	}
	if err := os.Chmod(c.Bindings["key"], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckRemoteCustodyPlacement(c, n.AssignmentID, "audit"); err == nil {
		t.Fatal("public private-key file accepted")
	}
	if _, err := PrepareRemoteCustodyPlacement(n.AssignmentID, "audit", n.Path, c.Bindings); err == nil {
		t.Fatal("insecure re-enrollment accepted")
	}
	if got, _ := os.ReadFile(n.Path); !bytes.Equal(got, original) {
		t.Fatal("failed enrollment changed original pin")
	}
}

func TestRemotePlacementCodecRejectsAmbiguousBindings(t *testing.T) {
	n, _ := placementFixture(t, "serve")
	b, err := n.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRemoteCustodyPlacement(b)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := decoded.CanonicalBytes()
	if !bytes.Equal(got, b) {
		t.Fatal("round trip")
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte{}, b...), 0)} {
		if _, err := DecodeRemoteCustodyPlacement(bad); err == nil {
			t.Fatal("noncanonical placement accepted")
		}
	}
	for _, mutate := range []func(*RemoteCustodyPlacement){func(p *RemoteCustodyPlacement) { p.Entries[0].Name = "unknown" }, func(p *RemoteCustodyPlacement) { p.Entries = p.Entries[1:] }, func(p *RemoteCustodyPlacement) { p.Version = 1 }, func(p *RemoteCustodyPlacement) { p.Entries[0].Path += "/../other" }} {
		p, err := DecodeRemoteCustodyPlacement(b)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&p)
		if _, err := p.CanonicalBytes(); err == nil {
			t.Fatal("malformed binding accepted")
		}
	}
}
