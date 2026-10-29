// Package keystore encrypts a local Ed25519 seed. Version 1 fixes its KDF
// parameters, so untrusted files cannot select an unbounded memory cost.
package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/argon2"
)

const Magic = "OMKEY001"
const HeaderSize = 8 + 16 + 32
const FileSize = HeaderSize + 12 + 32 + 16
const MaximumPassphraseBytes = 1024

var ErrKey = errors.New("invalid encrypted key or passphrase")
var ErrPassphrase = errors.New("passphrase must contain 12 to 1024 bytes")

func validPassword(p []byte) bool { return len(p) >= 12 && len(p) <= MaximumPassphraseBytes }
func aead(p, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey(p, salt, 3, 64*1024, 4, 32)
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCMWithRandomNonce(block)
}
func Seal(seed, passphrase []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrKey
	}
	if !validPassword(passphrase) {
		return nil, ErrPassphrase
	}
	out := make([]byte, HeaderSize, FileSize)
	copy(out, Magic)
	if _, e := rand.Read(out[8:24]); e != nil {
		return nil, e
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	copy(out[24:], key[32:])
	c, e := aead(passphrase, out[8:24])
	if e != nil {
		return nil, e
	}
	return c.Seal(out, nil, seed, out[:HeaderSize]), nil
}

// PublicKey is unauthenticated until Open succeeds. Use it only for inspection.
func PublicKey(b []byte) (ed25519.PublicKey, error) {
	if len(b) != FileSize || string(b[:8]) != Magic {
		return nil, ErrKey
	}
	return append(ed25519.PublicKey(nil), b[24:HeaderSize]...), nil
}
func Open(b, passphrase []byte) (ed25519.PrivateKey, error) {
	public, e := PublicKey(b)
	if e != nil || !validPassword(passphrase) {
		return nil, ErrKey
	}
	c, e := aead(passphrase, b[8:24])
	if e != nil {
		return nil, ErrKey
	}
	seed, e := c.Open(nil, nil, b[HeaderSize:], b[:HeaderSize])
	if e != nil {
		return nil, ErrKey
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrKey
	}
	key := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(key[32:], public) {
		clear(key)
		return nil, ErrKey
	}
	return key, nil
}
