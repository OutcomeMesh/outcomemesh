package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/wallet/keystore"
)

func TestWindowsCustodyServerRefusesBeforeMutation(t *testing.T) {
	for _, run := range []func([]string) error{runCustodyGuardCLI, runCustodyGuardRevokeCLI, runCustodyGuardReplaceCLI, runCustodyGatewayCLI, runCustodyGatewayReplaceCLI, runCustodyProfile5CLI} {
		dir := t.TempDir()
		if err := run([]string{"--data", filepath.Join(dir, "new"), "--key", filepath.Join(dir, "key")}); !errors.Is(err, errCustodyServerPlatform) {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("unsupported server touched files", err)
		}
	}
}

func TestWindowsNodeLifecycle(t *testing.T) {
	for _, protocol := range []int{0, 2} {
		t.Run(strconv.Itoa(protocol), func(t *testing.T) {
			dir := t.TempDir()
			password := filepath.Join(dir, "passphrase")
			if err := keystore.WriteNew(password, []byte("private Windows test password")); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(dir, "key")
			if err := runKeygen([]string{"--out", key, "--passphrase-file", password}); err != nil {
				t.Fatal(err)
			}
			private, err := loadWalletPrivateKey(key, password)
			if err != nil {
				t.Fatal(err)
			}
			public := private.Public().(ed25519.PublicKey)
			owner, err := types.AddressFromPublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			data := filepath.Join(dir, "node")
			if err := runInit([]string{"--data", data, "--protocol-version", strconv.Itoa(protocol), "--network", "1001", "--timestamp", "1700000000", "--difficulty-bits", "4", "--owner", owner.String()}); err != nil {
				t.Fatal(err)
			}
			recipient := defaultDevelopmentAddress().String()
			if err := runTransfer([]string{"--data", data, "--key", key, "--passphrase-file", password, "--to", recipient, "--amount", "100"}); err != nil {
				t.Fatal(err)
			}
			if err := runMine([]string{"--data", data, "--count", "2"}); err != nil {
				t.Fatal(err)
			}
			// Each command closes the database. Verification reopens and replays it.
			if err := runVerify([]string{"--data", data}); err != nil {
				t.Fatal(err)
			}
			if err := runStatus([]string{"--data", data}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
