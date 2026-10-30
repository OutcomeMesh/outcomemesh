package main

import (
	"bytes"
	"crypto/ed25519"
	"github.com/outcomemesh/outcomemesh/wallet/keystore"
	"os"
	"path/filepath"
	"testing"
)

func TestWalletEncryptedGenerationAndMigration(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "wallet")
	pass := filepath.Join(d, "password")
	if e := keystore.WriteNew(pass, []byte("exact secret password\n")); e != nil {
		t.Fatal(e)
	}
	if e := runKeygen([]string{"--out", key}); e == nil {
		t.Fatal("unencrypted default")
	}
	if _, e := os.Stat(key); !os.IsNotExist(e) {
		t.Fatal("created without password")
	}
	if e := runKeygen([]string{"--out", key, "--passphrase-file", pass}); e != nil {
		t.Fatal(e)
	}
	decoded, e := loadWalletPrivateKey(key, pass)
	if e != nil || len(decoded) != 64 {
		t.Fatal(e)
	}
	if _, e = loadWalletPrivateKey(key, ""); e == nil {
		t.Fatal("missing password")
	}
	if e = runKeygen([]string{"--out", key, "--passphrase-file", pass}); e == nil {
		t.Fatal("overwritten")
	}
	raw := filepath.Join(d, "legacy")
	seed := bytes.Repeat([]byte{4}, 32)
	if e = keystore.WriteNew(raw, seed); e != nil {
		t.Fatal(e)
	}
	migrated := filepath.Join(d, "migrated")
	if e = runKeyEncrypt([]string{"--in", raw, "--out", migrated, "--passphrase-file", pass}); e != nil {
		t.Fatal(e)
	}
	got, e := loadWalletPrivateKey(migrated, pass)
	if e != nil || !bytes.Equal(got, ed25519.NewKeyFromSeed(seed)) {
		t.Fatal(e)
	}
	before, e := os.ReadFile(raw)
	if e != nil || !bytes.Equal(before, seed) {
		t.Fatal("original lost")
	}
	encoded, e := os.ReadFile(key)
	if e != nil || len(encoded) != keystore.FileSize {
		t.Fatal(e)
	}
	if _, e = loadWalletPrivateKey(raw, pass); e == nil {
		t.Fatal("misleading passphrase")
	}
}
