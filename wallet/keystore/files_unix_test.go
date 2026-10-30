//go:build linux || darwin

package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFileBoundary(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "key")
	if e := WriteNew(p, []byte("private")); e != nil {
		t.Fatal(e)
	}
	if e := WriteNew(p, []byte("replacement")); e == nil {
		t.Fatal("overwrite")
	}
	b, e := ReadPrivate(p, 7)
	if e != nil || string(b) != "private" {
		t.Fatal(e)
	}
	if _, e = ReadPrivate(p, 6); e == nil {
		t.Fatal("size limit")
	}
	link := filepath.Join(d, "link")
	if e = os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadPrivate(link, 7); e == nil {
		t.Fatal("symlink")
	}
	if e = os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadPrivate(p, 7); e == nil {
		t.Fatal("public permissions")
	}
	if _, e = ReadPrivate(d, 7); e == nil {
		t.Fatal("directory")
	}
}
