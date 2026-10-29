package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestArchiveRejectsRadixScheduleBeforePublication(t *testing.T) {
	f := newArchiveFixture(t)
	p := f.parameters
	p.RadixActivationHeight = 10
	chain, e := workchain.New(f.base, p)
	if e != nil {
		t.Fatal(e)
	}
	defer chain.Close()
	blocks, e := f.source.MigrationBlocks(1 << 20)
	if e != nil {
		t.Fatal(e)
	}
	for _, b := range blocks {
		if _, _, e = chain.Commit(b, b.Header.Seal.Timestamp); e != nil {
			t.Fatal(e)
		}
	}
	if e = VerifyChain(f.checkpoint, f.policy, chain); e == nil {
		t.Fatal("checkpoint lacks scheduled commitment")
	}
	if _, e = VerifyArchiveDirectory(f.archivePath, f.checkpoint, f.policy, f.base, p, DefaultLimits()); e == nil {
		t.Fatal("archive adopted schedule absent from binding")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "uncreated")
	dst := filepath.Join(parent, "out")
	if _, e = RestoreDirectory(f.archivePath, dst, f.checkpoint, f.policy, f.base, p, DefaultLimits(), workchain.DefaultPolicy()); e == nil {
		t.Fatal("restore accepted schedule")
	}
	if _, e = os.Stat(parent); !os.IsNotExist(e) {
		t.Fatal("restore touched destination", e)
	}
	if _, _, e = ExportDirectory(dst, f.binding, chain, f.manifest.Anchor.ID, DefaultExportOptions()); e == nil {
		t.Fatal("export omitted schedule")
	}
	if _, _, e = ComposeDirectory(dst, f.archivePath, f.checkpoint, f.policy, f.base, p, chain, f.manifest.Anchor.ID, DefaultExportOptions()); e == nil {
		t.Fatal("compose omitted schedule")
	}
	if _, e = os.Stat(parent); !os.IsNotExist(e) {
		t.Fatal("created archive destination", e)
	}
}

func TestRadixArchiveMigrationPreservesChunksAndStatementLineage(t *testing.T) {
	f := newArchiveFixture(t)
	manifest, statement, err := PrepareRadixArchiveMigration(f.archivePath, f.checkpoint, f.policy, f.base, f.parameters, 5, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, statement, f.keys)
	destination := filepath.Join(t.TempDir(), "radix")
	migrated, id, err := MigrateRadixArchiveDirectory(f.archivePath, destination, f.checkpoint, checkpoint, f.policy, f.base, f.parameters, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	expectedID, _ := manifest.ID()
	statementID, _ := statement.ID()
	if expectedID.String() != "33f7bd5b4291c9d9b0d4c347cd2d55ba64ab416b6a77b2b0335445d0cec05ecb" || statementID.String() != "5e0e8e2ac43a9cb717d266bac439530536859d275730988c38adc8fb72af0257" {
		t.Fatal("archive migration vector changed", expectedID, statementID)
	}
	if id != expectedID {
		t.Fatal("signed manifest changed")
	}
	if err = VerifyRadixArchiveTransition(f.manifest, migrated, f.checkpoint, checkpoint, f.policy); err != nil {
		t.Fatal(err)
	}
	for i, d := range f.manifest.Chunks {
		if migrated.Chunks[i] != d {
			t.Fatal("chunk IDs changed")
		}
		old, err := os.ReadFile(filepath.Join(f.archivePath, chunkFileName(uint32(i))))
		if err != nil {
			t.Fatal(err)
		}
		newBytes, err := os.ReadFile(filepath.Join(destination, chunkFileName(uint32(i))))
		if err != nil || !bytes.Equal(old, newBytes) {
			t.Fatal("chunk bytes changed", err)
		}
	}
	// Original evidence remains valid, with its original identity and trust set.
	if _, err = VerifyArchiveDirectory(f.archivePath, f.checkpoint, f.policy, f.base, f.parameters, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	p := f.parameters
	p.RadixActivationHeight = 5
	policy := f.policy
	policy.Binding.RadixActivationHeight = 5
	if _, err = VerifyArchiveDirectory(destination, checkpoint, policy, f.base, p, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err = RestoreDirectory(destination, restored, checkpoint, policy, f.base, p, DefaultLimits(), workchain.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	chain, err := workchain.Open(restored, f.base, p)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	for h := uint64(4); h <= 6; h++ {
		tip, _ := chain.Tip()
		b, _ := mineArchiveChild(t, chain, tip.ID, tip.Timestamp+60, "radix-extension")
		if _, _, err = chain.Commit(b, b.Header.Seal.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	tip, _ := chain.Tip()
	options := DefaultExportOptions()
	options.Version = ManifestVersion2
	output := filepath.Join(t.TempDir(), "v3-blocks")
	next, _, err := ExportDirectory(output, policy.Binding, chain, tip.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	previousID, _ := checkpoint.Statement.ID()
	stmt, err := next.ArchiveStatement(statement.Sequence+1, previousID)
	if err != nil {
		t.Fatal(err)
	}
	nextCheckpoint := signedCheckpoint(t, stmt, f.keys)
	if err = VerifySuccessor(checkpoint, nextCheckpoint, policy, chain); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyArchiveDirectory(output, nextCheckpoint, policy, f.base, p, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	objects, err := OpenObjectStore(filepath.Join(t.TempDir(), "objects"), DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = objects.ImportArchiveDirectory(f.archivePath, f.checkpoint, f.policy, f.base, f.parameters, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	reused, err := objects.ImportArchiveDirectory(destination, checkpoint, policy, f.base, p, DefaultLimits())
	if err != nil || reused.AddedObjects != 0 || reused.ReusedObjects != uint64(len(f.manifest.Chunks)) {
		t.Fatal("migration lost content-addressed reuse", err)
	}
	if _, err = objects.ImportArchiveDirectory(output, nextCheckpoint, policy, f.base, p, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err = objects.MaterializeDirectory(filepath.Join(t.TempDir(), "materialized-v3"), next, nextCheckpoint, policy, f.base, p, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	encoded, err := checkpoint.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckpoint(encoded)
	if err != nil || decoded.Verify(policy) != nil {
		t.Fatal("checkpoint codec", err)
	}
	// Existing unversioned receipt formats must never silently omit the schedule.
	receiptBytes, _ := availabilityCodecSeeds()
	receipt, err := DecodeReplicaReceipt(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Binding.RadixActivationHeight = manifest.Binding.RadixActivationHeight
	if _, err = receipt.CanonicalBytes(); err == nil {
		t.Fatal("legacy receipt omitted radix schedule")
	}
}

func TestRadixArchiveMigrationRejectsRewrittenHistoryOrTrust(t *testing.T) {
	f := newArchiveFixture(t)
	manifest, statement, err := PrepareRadixArchiveMigration(f.archivePath, f.checkpoint, f.policy, f.base, f.parameters, 8, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	original := signedCheckpoint(t, statement, f.keys)
	for _, change := range []string{"height", "sequence", "previous", "anchor", "signers", "manifest"} {
		t.Run(change, func(t *testing.T) {
			m := manifest
			s := statement
			keys := f.keys
			switch change {
			case "height":
				s.RadixActivationHeight = 2
			case "sequence":
				s.Sequence = 1
				s.PreviousID = types.Hash{}
			case "previous":
				s.PreviousID = types.Hash{8}
			case "anchor":
				s.Anchor.StateRoot = types.Hash{9}
			case "signers":
				keys = []ed25519.PrivateKey{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, 32)), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))}
			case "manifest":
				m.Chunks = append([]ChunkDescriptor(nil), m.Chunks...)
				m.Chunks[0].ID = types.Hash{7}
				s.ArchiveManifestID, _ = m.ID()
			}
			cp := signedCheckpoint(t, s, keys)
			if err := VerifyRadixArchiveTransition(f.manifest, m, f.checkpoint, cp, f.policy); err == nil {
				t.Fatal("accepted changed transition")
			}
		})
	}
	target := filepath.Join(t.TempDir(), "existing")
	if err = os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err = MigrateRadixArchiveDirectory(f.archivePath, target, f.checkpoint, original, f.policy, f.base, f.parameters, DefaultLimits()); !errors.Is(err, ErrArchiveExists) {
		t.Fatal(err)
	}
	for _, h := range []uint64{0, 1, 3} {
		if _, _, err = PrepareRadixArchiveMigration(f.archivePath, f.checkpoint, f.policy, f.base, f.parameters, h, DefaultLimits()); err == nil {
			t.Fatal("nonfuture schedule")
		}
	}
}
