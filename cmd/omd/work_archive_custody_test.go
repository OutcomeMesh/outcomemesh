package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestCustodyJournalLimitFlags(t *testing.T) {
	for _, test := range []struct {
		name    string
		args    []string
		journal string
		valid   bool
	}{
		{name: "legacy defaults", valid: true},
		{name: "journal defaults", journal: "journal", valid: true},
		{name: "custom limits", journal: "journal", args: []string{"--journal-max-bytes", "1048576", "--journal-max-paths", "64"}, valid: true},
		{name: "bytes require journal", args: []string{"--journal-max-bytes", "1048576"}},
		{name: "explicit default requires journal", args: []string{"--journal-max-paths", "262144"}},
		{name: "zero bytes", journal: "journal", args: []string{"--journal-max-bytes", "0"}},
		{name: "insufficient paths", journal: "journal", args: []string{"--journal-max-paths", "8"}},
		{name: "excess paths", journal: "journal", args: []string{"--journal-max-paths", "1048577"}},
		{name: "excess bytes", journal: "journal", args: []string{"--journal-max-bytes", "1099511627777"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			flags := flag.NewFlagSet(test.name, flag.ContinueOnError)
			values := addArchiveCustodyJournalLimitFlags(flags)
			if err := flags.Parse(test.args); err != nil {
				t.Fatal(err)
			}
			if err := values.validate(flags, test.journal); (err == nil) != test.valid {
				t.Fatalf("validation error=%v want_valid=%t", err, test.valid)
			}
			if len(test.args) == 0 && values.limits() != workarchive.DefaultCustodyJournalLimits() {
				t.Fatal("CLI defaults differ from core journal defaults")
			}
		})
	}
}

func TestCustodyImmutableArtifactIsIdempotentAndNoReplace(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "challenge.omcc")
	original := []byte("canonical-custody-challenge")
	if err := publishImmutableArtifact(path, original); err != nil {
		t.Fatal(err)
	}
	if err := publishImmutableArtifact(path, append([]byte(nil), original...)); err != nil {
		t.Fatalf("identical publication was not idempotent: %v", err)
	}
	if err := publishImmutableArtifact(path, []byte("conflicting-challenge")); err == nil {
		t.Fatal("conflicting immutable artifact replaced the first decision")
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, original) {
		t.Fatal("conflicting publication changed the committed artifact")
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("immutable artifact info=%+v error=%v", info, err)
	}

	symlink := filepath.Join(directory, "challenge-link.omcc")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularArtifact(symlink, 1_024); err == nil {
		t.Fatal("custody artifact loader followed a symlink")
	}
}

func TestCustodyCommandsRequireFourDistinctIdentities(t *testing.T) {
	keys := make([]ed25519.PrivateKey, 4)
	publicKeys := make([][ed25519.PublicKeySize]byte, 4)
	for index := range keys {
		seed := types.DomainHash("test/cmd/custody-key-separation", []byte{byte(index)})
		keys[index] = ed25519.NewKeyFromSeed(seed[:])
		copy(publicKeys[index][:], keys[index].Public().(ed25519.PublicKey))
	}
	remoteTransportID := types.DomainHash(
		"OMESH/p2p/ed25519/v0", keys[2].Public().(ed25519.PublicKey),
	)
	if err := validateCustodyKeySeparation(
		keys[0].Public().(ed25519.PublicKey), publicKeys[1],
		remoteTransportID, publicKeys[3],
	); err != nil {
		t.Fatalf("four distinct custody identities rejected: %v", err)
	}
	if err := validateCustodyKeySeparation(
		keys[0].Public().(ed25519.PublicKey), publicKeys[0],
		remoteTransportID, publicKeys[3],
	); err == nil {
		t.Fatal("transport key reused as local custody evidence key")
	}
	if err := validateCustodyKeySeparation(
		keys[0].Public().(ed25519.PublicKey), publicKeys[1],
		types.DomainHash("OMESH/p2p/ed25519/v0", publicKeys[3][:]), publicKeys[3],
	); err == nil {
		t.Fatal("remote transport identity reused as remote custody evidence key")
	}
}

func TestCustodyCommandsRejectIncompleteConfiguration(t *testing.T) {
	for _, command := range []string{"work-archive-custody-checkpoint", "work-archive-custody-verify-checkpoint", "work-archive-custody-backup", "work-archive-custody-verify-backup"} {
		if err := run([]string{command}); err == nil {
			t.Fatalf("%s accepted an incomplete configuration", command)
		}
	}
	if err := run([]string{"work-archive-custody-serve-quic"}); err == nil {
		t.Fatal("custody replica accepted an incomplete configuration")
	}
	if err := run([]string{"work-archive-custody-challenge-quic"}); err == nil {
		t.Fatal("custody auditor accepted an incomplete configuration")
	}
	if err := run([]string{"work-archive-object-serve-quic"}); err == nil {
		t.Fatal("archive object server accepted an incomplete configuration")
	}
	if err := run([]string{"work-archive-object-fetch-quic"}); err == nil {
		t.Fatal("archive object client accepted an incomplete configuration")
	}
}

func TestCustodyJournalCycleArtifactsAreDeterministicAndSeparate(t *testing.T) {
	root := t.TempDir()
	challenge, record, receipt := custodyCycleArtifactPaths(root, 27)
	want := filepath.Join(root, "cycle-00000000000000000027")
	if challenge != filepath.Join(want, "challenge.omcc") ||
		record != filepath.Join(want, "record.omcr") ||
		receipt != filepath.Join(want, "receipt.omrr") {
		t.Fatalf("unexpected custody cycle paths: %q %q %q", challenge, record, receipt)
	}
	journal := filepath.Join(root, "journal")
	if !custodyPathsOverlap(journal, filepath.Join(journal, "artifacts")) {
		t.Fatal("nested custody artifacts were not rejected")
	}
	if custodyPathsOverlap(journal, filepath.Join(root, "artifacts")) {
		t.Fatal("separate custody journal and artifacts were rejected")
	}
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(journal, alias); err != nil {
		t.Fatal(err)
	}
	if !custodyPathsOverlap(journal, filepath.Join(alias, "artifacts")) {
		t.Fatal("symlink alias hid overlapping custody directories")
	}
}

func TestArchiveObjectPeerAllowlistIsCanonicalized(t *testing.T) {
	first := types.DomainHash("test/cmd/archive-object-peer", []byte("first"))
	second := types.DomainHash("test/cmd/archive-object-peer", []byte("second"))
	parsed, err := parseArchivePeerIDs([]string{second.String(), first.String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 || types.CompareHash(parsed[0], parsed[1]) >= 0 {
		t.Fatalf("archive peer allowlist is not canonical: %v", parsed)
	}
	if _, err := parseArchivePeerIDs([]string{first.String(), first.String()}); err == nil {
		t.Fatal("duplicate archive client identity was accepted")
	}
	if _, err := parseArchivePeerIDs(nil); err == nil {
		t.Fatal("empty archive client allowlist was accepted")
	}
}
