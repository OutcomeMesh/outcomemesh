package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/wallet/keystore"
)

func walletPassword(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("encrypted wallet requires --passphrase-file (private regular file, 12–1024 bytes; exact bytes, no newline trimming)")
	}
	return keystore.ReadPrivate(path, keystore.MaximumPassphraseBytes)
}
func runKeygen(arguments []string) error {
	f := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := f.String("out", "wallet.key", "new encrypted key, never overwritten")
	password := f.String("passphrase-file", "", "private file containing the exact passphrase bytes")
	plain := f.Bool("plaintext", false, "explicit unencrypted seed for development/daemon identities")
	if e := f.Parse(arguments); e != nil {
		return e
	}
	if f.NArg() != 0 || *plain && *password != "" {
		return errors.New("invalid keygen arguments")
	}
	var pass []byte
	var e error
	if !*plain {
		pass, e = walletPassword(*password)
		if e != nil {
			return e
		}
		defer clear(pass)
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, e = rand.Read(seed); e != nil {
		return e
	}
	encoded := seed
	if !*plain {
		encoded, e = keystore.Seal(seed, pass)
		if e != nil {
			return e
		}
	}
	if e = keystore.WriteNew(*out, encoded); e != nil {
		return e
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	address, e := types.AddressFromPublicKey(key.Public().(ed25519.PublicKey))
	if e != nil {
		return e
	}
	fmt.Printf("created key=%s address=%s encrypted=%t\n", *out, address, !*plain)
	return nil
}
func runKeyEncrypt(arguments []string) error {
	f := flag.NewFlagSet("key-encrypt", flag.ContinueOnError)
	in := f.String("in", "", "original raw seed (preserved)")
	out := f.String("out", "", "new encrypted key")
	password := f.String("passphrase-file", "", "private passphrase file")
	if e := f.Parse(arguments); e != nil {
		return e
	}
	if f.NArg() != 0 || *in == "" || *out == "" {
		return errors.New("in, out and passphrase-file are required")
	}
	seed, e := keystore.ReadPrivate(*in, ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	pass, e := walletPassword(*password)
	if e != nil {
		return e
	}
	defer clear(pass)
	b, e := keystore.Seal(seed, pass)
	if e != nil {
		return e
	}
	if e = keystore.WriteNew(*out, b); e != nil {
		return e
	}
	fmt.Printf("encrypted key=%s original_preserved=true\n", *out)
	return nil
}
func loadWalletPrivateKey(path, passwordPath string) (ed25519.PrivateKey, error) {
	b, e := keystore.ReadPrivate(path, keystore.FileSize)
	if e != nil {
		return nil, e
	}
	defer clear(b)
	if len(b) == ed25519.SeedSize {
		if passwordPath != "" {
			return nil, errors.New("passphrase supplied for an unencrypted seed; use key-encrypt first")
		}
		return ed25519.NewKeyFromSeed(b), nil
	}
	if _, e = keystore.PublicKey(b); e != nil {
		return nil, e
	}
	pass, e := walletPassword(passwordPath)
	if e != nil {
		return nil, e
	}
	defer clear(pass)
	return keystore.Open(b, pass)
}
