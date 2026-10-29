package keystore

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedKeyAuthentication(t *testing.T) {
	seed := bytes.Repeat([]byte{31}, 32)
	pass := []byte("correct horse battery staple")
	encoded, e := Seal(seed, pass)
	if e != nil {
		t.Fatal(e)
	}
	if len(encoded) != FileSize || bytes.Contains(encoded, seed) {
		t.Fatal("raw seed or format")
	}
	key, e := Open(encoded, pass)
	if e != nil || !bytes.Equal(key, ed25519.NewKeyFromSeed(seed)) {
		t.Fatal("roundtrip", e)
	}
	second, e := Seal(seed, pass)
	if e != nil || bytes.Equal(encoded, second) {
		t.Fatal("random salt/nonce")
	}
	if _, e = Open(encoded, []byte("wrong horse battery staple")); e == nil {
		t.Fatal("wrong password accepted")
	}
	for _, index := range []int{0, 8, 24, HeaderSize, FileSize - 1} {
		bad := bytes.Clone(encoded)
		bad[index] ^= 1
		if _, e = Open(bad, pass); e == nil {
			t.Fatalf("tamper %d", index)
		}
	}
	for _, b := range [][]byte{encoded[:len(encoded)-1], append(bytes.Clone(encoded), 0), seed} {
		if _, e = Open(b, pass); e == nil {
			t.Fatal("bad size accepted")
		}
	}
	for _, pass := range [][]byte{nil, []byte("short"), make([]byte, 1025)} {
		if _, e = Seal(seed, pass); e == nil {
			t.Fatal("weak/oversize password accepted")
		}
	}
}
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
func FuzzKeyEnvelope(f *testing.F) {
	f.Add([]byte("OMKEY001"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := PublicKey(b)
		if e == nil && (len(b) != FileSize || len(p) != 32) {
			t.Fatal("format")
		}
		if e != nil {
			if _, e = Open(b, []byte("bounded password")); e == nil {
				t.Fatal("malformed accepted")
			}
		}
	})
}
