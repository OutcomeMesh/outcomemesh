//go:build linux || darwin

package pruneservice

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateTestDir(t testing.TB) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPruneServiceIdentityKeepsOriginalPlacement(t *testing.T) {
	root := filepath.Join(privateTestDir(t), "owner")
	id, err := CreateIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	if id.Service == id.Transport {
		t.Fatal("role keys overlap")
	}
	got, err := ReadIdentity(root)
	if err != nil || got != id {
		t.Fatalf("identity %v", err)
	}
	if _, err = CreateIdentity(root); err == nil {
		t.Fatal("existing root replaced")
	}
	lock, err := lockRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lockRoot(root); err == nil {
		t.Fatal("competing root owner accepted")
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "key")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if err = os.Rename(keyPath, keyPath+".original"); err != nil {
		t.Fatal(err)
	}
	if err = publish(keyPath, raw); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadIdentity(root); err == nil {
		t.Fatal("byte-identical replacement key accepted")
	}
}

func TestPruneServicePrivateFilesRefuseAliasesAndWritableTrees(t *testing.T) {
	for _, kind := range []string{"hard-link", "symlink", "writable-file", "writable-directory", "readable-root"} {
		t.Run(kind, func(t *testing.T) {
			parent := privateTestDir(t)
			root := filepath.Join(parent, "original")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(root, "data")
			if err := os.WriteFile(p, []byte("retained"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := privateTree(root); err != nil {
				t.Fatal("private root must protect storage-engine readable descendants", err)
			}
			var err error
			switch kind {
			case "hard-link":
				err = os.Link(p, filepath.Join(parent, "alias"))
			case "symlink":
				err = os.Symlink(p, filepath.Join(root, "alias"))
			case "writable-file":
				err = os.Chmod(p, 0666)
			case "writable-directory":
				err = os.Mkdir(filepath.Join(root, "child"), 0777)
				if err == nil {
					err = os.Chmod(filepath.Join(root, "child"), 0777)
				}
			case "readable-root":
				err = os.Chmod(root, 0755)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = privateTree(root); err == nil {
				t.Fatal("unsafe placement accepted")
			}
		})
	}
}

func TestPruneServicePublishNeverReplacesPartialEvidence(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "intent")
	if err := publish(path, []byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := publish(path, []byte("replacement")); err == nil {
		t.Fatal("existing evidence replaced")
	}
	raw, err := privateRead(path, 7)
	if err != nil || !bytes.Equal(raw, []byte("partial")) {
		t.Fatal("evidence changed", err)
	}
	if _, err = privateRead(path, 6); err == nil {
		t.Fatal("size limit bypassed")
	}
}

func TestPruneServicePlacementScanHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := privateTreeContext(ctx, filepath.Join(privateTestDir(t), "absent")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan opened its path: %v", err)
	}
}
