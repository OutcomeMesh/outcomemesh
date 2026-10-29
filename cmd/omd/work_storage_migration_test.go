package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type storageRadixFixture struct {
	source, path, pins string
	base               workchain.Base
	storageID          types.Hash
	args               []string
}

func newStorageRadixFixture(t *testing.T) storageRadixFixture {
	t.Helper()
	src := migrationFixture(t)
	_, ledger, r, p, err := openWorkNode(src)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := r.MigrationWorkBlocks(maximumMigrationBytes)
	if err != nil || len(blocks) == 0 {
		t.Fatal(err)
	}
	var baseID types.Hash
	for _, b := range blocks {
		if b.Height() == p.ActivationHeight {
			baseID = b.ParentID()
			break
		}
	}
	base, err := archiveBaseFromLedger(ledger, baseID, p.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	_, parameters, err := r.Parameters()
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ledger.Close(); err != nil {
		t.Fatal(err)
	}
	path, pins := filepath.Join(t.TempDir(), "chain"), filepath.Join(t.TempDir(), "pins")
	storageID := types.DomainHash("test/protected-radix/cli")
	s, err := workchain.CreatePositionPinnedWithPolicy(path, pins, base, parameters, workchain.DefaultPolicy(), storageID)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blocks {
		work, ok := b.WorkBlock()
		if !ok {
			t.Fatal("expected WorkGraph block")
		}
		if _, _, err = s.Commit(work, work.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	args := []string{"--data", src, "--chain", path, "--chain-pins", pins, "--base-id", baseID.String(), "--storage-id", storageID.String(), "--radix-height", "5"}
	return storageRadixFixture{src, path, pins, base, storageID, args}
}
func TestWorkStorageRadixCLIReviewRunInspectAndRejectReplay(t *testing.T) {
	f := newStorageRadixFixture(t)
	var out bytes.Buffer
	if err := workStorageMigrateRadix(context.Background(), f.args, &out); err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(out.String(), "review_id=")
	if len(fields) != 2 {
		t.Fatal(out.String())
	}
	id := strings.TrimSpace(fields[1])
	args := append(append([]string{}, f.args...), "--mode", "run", "--expected-review-id", id)
	if err := workStorageMigrateRadix(context.Background(), args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := workStorageMigrateRadix(context.Background(), args, &bytes.Buffer{}); err == nil {
		t.Fatal("repeat reset transition")
	}
	for _, mode := range []string{"inspect", "confirm"} {
		args := append(append([]string{}, f.args...), "--mode", mode, "--expected-review-id", id)
		if err := workStorageMigrateRadix(context.Background(), args, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	wrong := append(append([]string{}, f.args...), "--mode", "inspect", "--expected-review-id", types.Hash{7}.String())
	if err := workStorageMigrateRadix(context.Background(), wrong, &bytes.Buffer{}); err == nil {
		t.Fatal("wrong retained proof accepted")
	}
}

func TestWorkArchiveRadixCLIProducesProposalAndKeepsSource(t *testing.T) {
	f := newStorageRadixFixture(t)
	_, ledger, r, _, err := openWorkNode(f.source)
	if err != nil {
		t.Fatal(err)
	}
	_, parameters, err := r.Parameters()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := loadGenesis(f.source)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, _ := doc.ID()
	r.Close()
	ledger.Close()
	s, err := workchain.OpenPositionPinnedWithPolicy(f.path, f.pins, f.base, parameters, workchain.DefaultPolicy(), f.storageID)
	if err != nil {
		t.Fatal(err)
	}
	tip, _ := s.Tip()
	binding := workarchive.Binding{NetworkID: parameters.NetworkID, GenesisID: genesisID, ActivationHeight: parameters.ActivationHeight, BaseID: f.base.Tip.ID}
	dir := filepath.Join(t.TempDir(), "archive")
	manifest, _, err := workarchive.ExportDirectory(dir, binding, s, tip.ID, workarchive.DefaultExportOptions())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	stmt, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PrivateKey{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, 32)), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{52}, 32))}
	sign := func(statement workarchive.Statement) workarchive.Checkpoint {
		t.Helper()
		var attestations []workarchive.Attestation
		for _, k := range keys {
			a, err := workarchive.Attest(k, statement)
			if err != nil {
				t.Fatal(err)
			}
			attestations = append(attestations, a)
		}
		cp, err := workarchive.NewCheckpoint(statement, attestations)
		if err != nil {
			t.Fatal(err)
		}
		return cp
	}
	cp := sign(stmt)
	cpPath := filepath.Join(t.TempDir(), "old.omwcp")
	encoded, _ := cp.CanonicalBytes()
	if err = os.WriteFile(cpPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--data", f.source, "--manifest", filepath.Join(dir, "manifest.omwm"), "--checkpoint", cpPath, "--radix-height", "5"}
	for _, k := range keys {
		args = append(args, "--attestor-public-key", hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	}
	before := migrationDigest(t, dir)
	proposalPath := filepath.Join(t.TempDir(), "proposal.omwas")
	if err = workArchiveMigrateRadix(context.Background(), append(append([]string{}, args...), "--statement-out", proposalPath), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(proposalPath)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := workarchive.DecodeStatement(b)
	if err != nil {
		t.Fatal(err)
	}
	next := sign(proposal)
	nextPath := filepath.Join(t.TempDir(), "new.omwcp")
	encoded, _ = next.CanonicalBytes()
	if err = os.WriteFile(nextPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "migrated")
	if err = workArchiveMigrateRadix(context.Background(), append(args, "--mode", "run", "--new-checkpoint", nextPath, "--out", dst), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after := migrationDigest(t, dir)
	if len(after) != len(before) {
		t.Fatal("changed source")
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatal("changed source bytes")
		}
	}
}
