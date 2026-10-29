package workarchive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestArchiveExportVerifyRestoreRoundTrip(t *testing.T) {
	fixture := newArchiveFixture(t)
	if fixture.manifest.BlockCount != 3 || len(fixture.manifest.Chunks) != 2 {
		t.Fatalf("archive blocks/chunks=%d/%d want=3/2",
			fixture.manifest.BlockCount, len(fixture.manifest.Chunks))
	}
	archiveEntries, err := os.ReadDir(fixture.archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range archiveEntries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("archive file %s mode=%v want=600", entry.Name(), info.Mode().Perm())
		}
	}
	if fixture.manifest.Version != ManifestVersion1 {
		t.Fatalf("archive version=%d want=%d", fixture.manifest.Version, ManifestVersion1)
	}
	const expectedManifestID = "134f196109d61f7df0cc98d8d18320cc0edf4f38f9607b4eb069819ec4e22644"
	if fixture.manifestID.String() != expectedManifestID {
		t.Fatalf("manifest ID=%s want=%s", fixture.manifestID, expectedManifestID)
	}
	verified, err := VerifyArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedID, err := verified.ID(); err != nil || verifiedID != fixture.manifestID {
		t.Fatalf("verified manifest ID=%s want=%s err=%v", verifiedID, fixture.manifestID, err)
	}

	destination := filepath.Join(t.TempDir(), "restored-workchain")
	restoredManifest, err := RestoreDirectory(
		fixture.archivePath, destination, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, DefaultLimits(), workchain.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if restoredID, err := restoredManifest.ID(); err != nil || restoredID != fixture.manifestID {
		t.Fatalf("restored manifest ID=%s want=%s err=%v", restoredID, fixture.manifestID, err)
	}
	reopened, err := workchain.Open(destination, fixture.base, fixture.parameters)
	if err != nil {
		t.Fatal(err)
	}
	tip, err := reopened.Tip()
	if err != nil || !storage.EqualTips(tip, fixture.manifest.Anchor) {
		t.Fatalf("restored tip=%+v want=%+v err=%v", tip, fixture.manifest.Anchor, err)
	}
	ids, err := reopened.NodeIDs()
	if err != nil || len(ids) != 4 {
		t.Fatalf("restored node count=%d want=4 err=%v", len(ids), err)
	}
	next, _ := mineArchiveChild(
		t, reopened, tip.ID, tip.Timestamp+fixture.parameters.TargetSpacing, "restored-extension",
	)
	if _, _, err := reopened.Commit(next, next.Header.Seal.Timestamp); err != nil {
		t.Fatalf("restored chain extension: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreDirectory(
		fixture.archivePath, destination, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, DefaultLimits(), workchain.DefaultPolicy(),
	); !errors.Is(err, ErrArchiveExists) {
		t.Fatalf("existing restore destination error=%v", err)
	}
	if _, _, err := ExportDirectory(
		fixture.archivePath, fixture.binding, fixture.source, fixture.manifest.Anchor.ID,
		DefaultExportOptions(),
	); !errors.Is(err, ErrArchiveExists) {
		t.Fatalf("existing export destination error=%v", err)
	}
}

func TestArchiveVersionZeroRemainsVerifiableAndRestorable(t *testing.T) {
	fixture := newArchiveFixture(t)
	options := DefaultExportOptions()
	options.Version = ManifestVersion0
	options.BlocksPerChunk = 2
	archivePath := filepath.Join(t.TempDir(), "archive-v0")
	manifest, _, err := ExportDirectory(
		archivePath, fixture.binding, fixture.source, fixture.manifest.Anchor.ID, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != ManifestVersion0 {
		t.Fatalf("legacy manifest version=%d", manifest.Version)
	}
	firstChunk, err := DecodeChunk(mustReadArchiveFile(t, filepath.Join(archivePath, chunkFileName(0))))
	if err != nil || firstChunk.Version != ChunkVersion0 ||
		firstChunk.AnchorID != manifest.Anchor.ID {
		t.Fatalf("legacy chunk=%+v err=%v", firstChunk, err)
	}
	statement, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, statement, fixture.keys)
	if _, err := VerifyArchiveDirectory(
		archivePath, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreDirectory(
		archivePath, filepath.Join(t.TempDir(), "restore-v0"), checkpoint, fixture.policy,
		fixture.base, fixture.parameters, DefaultLimits(), workchain.DefaultPolicy(),
	); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveRejectsCorruptionUnexpectedFilesAndTightLimits(t *testing.T) {
	fixture := newArchiveFixture(t)

	corruptPath := filepath.Join(t.TempDir(), "corrupt")
	copyArchiveDirectory(t, fixture.archivePath, corruptPath)
	chunkPath := filepath.Join(corruptPath, chunkFileName(0))
	encoded, err := os.ReadFile(chunkPath)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-1] ^= 1
	if err := os.WriteFile(chunkPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchiveDirectory(
		corruptPath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err == nil {
		t.Fatal("corrupt archive chunk verified")
	}

	extraPath := filepath.Join(t.TempDir(), "extra")
	copyArchiveDirectory(t, fixture.archivePath, extraPath)
	if err := os.WriteFile(filepath.Join(extraPath, "uncommitted"), []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchiveDirectory(
		extraPath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); !errors.Is(err, ErrArchive) {
		t.Fatalf("unexpected archive file error=%v", err)
	}

	symlinkPath := filepath.Join(t.TempDir(), "symlink")
	copyArchiveDirectory(t, fixture.archivePath, symlinkPath)
	target := filepath.Join(symlinkPath, chunkFileName(0))
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(fixture.archivePath, chunkFileName(0)), target); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchiveDirectory(
		symlinkPath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); !errors.Is(err, ErrArchive) {
		t.Fatalf("symlink archive file error=%v", err)
	}

	limits := DefaultLimits()
	limits.MaximumBlocks = fixture.manifest.BlockCount - 1
	if _, err := VerifyArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, limits,
	); !errors.Is(err, ErrArchiveLimit) {
		t.Fatalf("archive block limit error=%v", err)
	}

	wrongStatement := fixture.checkpoint.Statement
	wrongStatement.ArchiveManifestID = types.DomainHash("test/workarchive/wrong-archive")
	wrongCheckpoint := signedCheckpoint(t, wrongStatement, fixture.keys)
	if _, err := VerifyArchiveDirectory(
		fixture.archivePath, wrongCheckpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); !errors.Is(err, ErrArchive) {
		t.Fatalf("wrong manifest statement error=%v", err)
	}
}

func TestArchiveCodecRejectsTrailingOversizeAndInvalidPolicy(t *testing.T) {
	manifestBytes, chunkBytes := archiveCodecSeeds(t)
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.ArchiveStatement(2, types.Hash{}); !errors.Is(err, ErrStatement) {
		t.Fatalf("archive statement missing predecessor error=%v", err)
	}
	if _, err := manifest.ArchiveStatement(
		1, types.DomainHash("test/workarchive/unexpected-previous"),
	); !errors.Is(err, ErrStatement) {
		t.Fatalf("first archive statement predecessor error=%v", err)
	}
	if _, err := DecodeManifest(append(manifestBytes, 0)); err == nil {
		t.Fatal("archive manifest decoder accepted trailing bytes")
	}
	if _, err := DecodeChunk(append(chunkBytes, 0)); err == nil {
		t.Fatal("archive chunk decoder accepted trailing bytes")
	}
	if _, err := DecodeManifest(make([]byte, MaximumManifestBytes+1)); !errors.Is(err, ErrManifest) {
		t.Fatalf("oversize archive manifest error=%v", err)
	}
	if _, err := DecodeChunk(make([]byte, MaximumChunkBytes+1)); !errors.Is(err, ErrChunk) {
		t.Fatalf("oversize archive chunk error=%v", err)
	}
	unknownManifest := append([]byte(nil), manifestBytes...)
	unknownManifest[len(manifestMagic)] = 0
	unknownManifest[len(manifestMagic)+1] = 3
	if _, err := DecodeManifest(unknownManifest); !errors.Is(err, ErrManifest) {
		t.Fatalf("unknown archive manifest version error=%v", err)
	}
	unknownChunk := append([]byte(nil), chunkBytes...)
	unknownChunk[len(chunkMagic)] = 0
	unknownChunk[len(chunkMagic)+1] = 2
	if _, err := DecodeChunk(unknownChunk); !errors.Is(err, ErrChunk) {
		t.Fatalf("unknown archive chunk version error=%v", err)
	}
	invalidLimits := DefaultLimits()
	invalidLimits.MaximumChunks = 0
	if err := invalidLimits.Validate(); !errors.Is(err, ErrArchiveLimit) {
		t.Fatalf("zero archive chunk policy error=%v", err)
	}
	invalidOptions := DefaultExportOptions()
	invalidOptions.BlocksPerChunk = MaximumChunkBlocks + 1
	if err := invalidOptions.Validate(); !errors.Is(err, ErrArchiveLimit) {
		t.Fatalf("over-maximum chunk target error=%v", err)
	}
	invalidOptions = DefaultExportOptions()
	invalidOptions.Version = ManifestVersion2 + 1
	if err := invalidOptions.Validate(); !errors.Is(err, ErrArchiveLimit) {
		t.Fatalf("unknown archive output version error=%v", err)
	}
	_, v1ChunkBytes := archiveCodecSeedsForVersion(t, ManifestVersion1)
	v1Chunk, err := DecodeChunk(v1ChunkBytes)
	if err != nil || v1Chunk.Version != ChunkVersion1 || !v1Chunk.AnchorID.IsZero() {
		t.Fatalf("v1 chunk=%+v err=%v", v1Chunk, err)
	}
	v1Chunk.AnchorID = types.DomainHash("test/workarchive/v1-forbidden-anchor")
	if _, err := v1Chunk.CanonicalBytes(); !errors.Is(err, ErrChunk) {
		t.Fatalf("v1 anchor-bound chunk error=%v", err)
	}
}

func TestArchiveExportRejectsReorgBeforePublication(t *testing.T) {
	fixture := newArchiveFixture(t)
	parent := t.TempDir()
	destination := filepath.Join(parent, "reorged")
	_, _, err := exportDirectory(
		destination, fixture.binding, fixture.source, fixture.manifest.Anchor.ID,
		DefaultExportOptions(), func() error {
			sideChild, _ := mineArchiveChild(
				t, fixture.source, fixture.sideActivationID,
				fixture.sideActivation.Header.Seal.Timestamp+60, "archive-reorg-side-child",
			)
			if _, _, err := fixture.source.Commit(sideChild, sideChild.Header.Seal.Timestamp); err != nil {
				return err
			}
			sideChildID, _ := sideChild.Header.ID()
			sideGrandchild, _ := mineArchiveChild(
				t, fixture.source, sideChildID,
				sideChild.Header.Seal.Timestamp+60, "archive-reorg-side-grandchild",
			)
			if _, _, err := fixture.source.Commit(
				sideGrandchild, sideGrandchild.Header.Seal.Timestamp,
			); err != nil {
				return err
			}
			sideGrandchildID, _ := sideGrandchild.Header.ID()
			sideWinner, _ := mineArchiveChild(
				t, fixture.source, sideGrandchildID,
				sideGrandchild.Header.Seal.Timestamp+60, "archive-reorg-side-winner",
			)
			_, _, err := fixture.source.Commit(sideWinner, sideWinner.Header.Seal.Timestamp)
			return err
		},
	)
	if !errors.Is(err, ErrChain) {
		t.Fatalf("reorged export error=%v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reorged archive was published: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("reorged export temporary entries=%d err=%v", len(entries), err)
	}
}

func TestArchiveRestoreFailureBeforePublishLeavesNoDestination(t *testing.T) {
	fixture := newArchiveFixture(t)
	parent := t.TempDir()
	destination := filepath.Join(parent, "restore")
	injected := errors.New("injected restore publication failure")
	_, err := restoreDirectory(
		fixture.archivePath, destination, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, DefaultLimits(), workchain.DefaultPolicy(),
		restoreHooks{beforePublish: func() error { return injected }},
	)
	if !errors.Is(err, injected) || !errors.Is(err, ErrArchivePublish) {
		t.Fatalf("injected restore error=%v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed restore destination exists: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed restore temporary entries=%d err=%v", len(entries), err)
	}
}

func FuzzDecodeArchiveManifestNeverPanics(f *testing.F) {
	manifestBytes, _ := archiveCodecSeeds(f)
	manifestV1Bytes, _ := archiveCodecSeedsForVersion(f, ManifestVersion1)
	f.Add(manifestBytes)
	f.Add(manifestV1Bytes)
	v2, err := DecodeManifest(manifestV1Bytes)
	if err != nil {
		f.Fatal(err)
	}
	v2.Version = ManifestVersion2
	v2.Binding.RadixActivationHeight = 10
	v2Bytes, err := v2.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(v2Bytes)
	f.Add([]byte("not-an-archive-manifest"))
	f.Fuzz(func(t *testing.T, input []byte) {
		manifest, err := DecodeManifest(input)
		if err != nil {
			return
		}
		encoded, err := manifest.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, encoded) {
			t.Fatal("accepted non-canonical archive manifest")
		}
	})
}

func FuzzDecodeArchiveChunkNeverPanics(f *testing.F) {
	_, chunkBytes := archiveCodecSeeds(f)
	_, chunkV1Bytes := archiveCodecSeedsForVersion(f, ManifestVersion1)
	f.Add(chunkBytes)
	f.Add(chunkV1Bytes)
	f.Add([]byte("not-an-archive-chunk"))
	f.Fuzz(func(t *testing.T, input []byte) {
		chunk, err := DecodeChunk(input)
		if err != nil {
			return
		}
		encoded, err := chunk.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, encoded) {
			t.Fatal("accepted non-canonical archive chunk")
		}
	})
}

type archiveFixture struct {
	source           *workchain.Store
	sourcePath       string
	archivePath      string
	base             workchain.Base
	parameters       workblock.Parameters
	binding          Binding
	manifest         Manifest
	manifestID       types.Hash
	checkpoint       Checkpoint
	policy           Policy
	keys             []ed25519.PrivateKey
	sideActivation   workblock.Block
	sideActivationID types.Hash
}

func newArchiveFixture(t testing.TB) archiveFixture {
	t.Helper()
	parameters := archiveTestParameters()
	base := archiveTestBase()
	workPolicy := workchain.DefaultPolicy()
	workPolicy.ForkRetention = 1
	workPolicy.CanonicalRetention = 1
	sourcePath := filepath.Join(t.TempDir(), "source")
	source, err := workchain.OpenWithPolicy(sourcePath, base, parameters, workPolicy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	activation, _ := mineArchiveChild(
		t, source, base.Tip.ID, base.Tip.Timestamp+60, "archive-main-activation",
	)
	if _, _, err := source.Commit(activation, activation.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	activationID, _ := activation.Header.ID()
	sideActivation, _ := mineArchiveChild(
		t, source, base.Tip.ID, base.Tip.Timestamp+60, "archive-side-activation",
	)
	if _, _, err := source.Commit(sideActivation, sideActivation.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	sideActivationID, _ := sideActivation.Header.ID()
	child, _ := mineArchiveChild(
		t, source, activationID, activation.Header.Seal.Timestamp+60, "archive-main-child",
	)
	if _, _, err := source.Commit(child, child.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	childID, _ := child.Header.ID()
	anchorBlock, _ := mineArchiveChild(
		t, source, childID, child.Header.Seal.Timestamp+60, "archive-main-anchor",
	)
	if _, _, err := source.Commit(anchorBlock, anchorBlock.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	anchor, err := source.Tip()
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{
		NetworkID: parameters.NetworkID, GenesisID: types.DomainHash("test/workarchive/archive-genesis"),
		ActivationHeight: parameters.ActivationHeight, BaseID: base.Tip.ID,
	}
	archivePath := filepath.Join(t.TempDir(), "archive")
	options := DefaultExportOptions()
	options.BlocksPerChunk = 2
	manifest, manifestID, err := ExportDirectory(
		archivePath, binding, source, anchor.ID, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PrivateKey{
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{52}, ed25519.SeedSize)),
	}
	checkpoint := signedCheckpoint(t, statement, keys)
	policy := Policy{
		Binding: binding, TrustedAttestors: sortedPublicKeys(keys), RequiredAttestations: 2,
	}
	if err := VerifyChain(checkpoint, policy, source); err != nil {
		t.Fatal(err)
	}
	return archiveFixture{
		source: source, sourcePath: sourcePath, archivePath: archivePath, base: base, parameters: parameters,
		binding: binding, manifest: manifest, manifestID: manifestID,
		checkpoint: checkpoint, policy: policy, keys: keys,
		sideActivation: sideActivation, sideActivationID: sideActivationID,
	}
}

func archiveCodecSeeds(t testing.TB) ([]byte, []byte) {
	return archiveCodecSeedsForVersion(t, ManifestVersion0)
}

func archiveCodecSeedsForVersion(t testing.TB, version uint16) ([]byte, []byte) {
	t.Helper()
	parameters := archiveTestParameters()
	base := archiveTestBase()
	chain, err := workchain.New(base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := mineArchiveChild(
		t, chain, base.Tip.ID, base.Tip.Timestamp+60, "archive-codec-seed",
	)
	if _, _, err := chain.Commit(block, block.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	tip, _ := chain.Tip()
	root, count, _ := chain.SelectedAncestryCommitment(tip.ID)
	binding := Binding{
		NetworkID: parameters.NetworkID, GenesisID: types.DomainHash("test/workarchive/codec-genesis"),
		ActivationHeight: parameters.ActivationHeight, BaseID: base.Tip.ID,
	}
	chunk := Chunk{
		Version: version, NetworkID: binding.NetworkID, BaseID: binding.BaseID,
		FirstHeight: parameters.ActivationHeight,
		Blocks:      []workblock.Block{block},
	}
	if version == ChunkVersion0 {
		chunk.AnchorID = tip.ID
	}
	chunkBytes, err := chunk.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	chunkID := types.DomainHash(chunkIDDomain, chunkBytes)
	manifest := Manifest{
		Version: version, Binding: binding, Anchor: tip,
		AncestryNodes: count, AncestryRoot: root, BlockCount: 1,
		TotalChunkBytes: uint64(len(chunkBytes)),
		Chunks: []ChunkDescriptor{{
			ID: chunkID, FirstHeight: parameters.ActivationHeight,
			LastHeight: parameters.ActivationHeight, BlockCount: 1,
			EncodedBytes: uint32(len(chunkBytes)),
		}},
	}
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return manifestBytes, chunkBytes
}

func archiveTestParameters() workblock.Parameters {
	return workblock.Parameters{
		NetworkID: 909, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: 1_699_999_940, DifficultyAnchorTarget: archiveTestTarget(),
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
}

func archiveTestBase() workchain.Base {
	initial := state.Empty()
	return workchain.Base{
		Tip: storage.Tip{
			ID: types.DomainHash("test/workarchive/archive-base"), Height: 0,
			Timestamp: 1_699_999_940, Target: archiveTestTarget(), StateRoot: initial.Root(),
		},
		State: initial, RecentTimestamps: []uint64{1_699_999_940},
	}
}

func archiveTestTarget() types.Hash {
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return target
}

func mineArchiveChild(
	t testing.TB,
	chain *workchain.Store,
	parentID types.Hash,
	timestamp uint64,
	label string,
) (workblock.Block, workblock.Result) {
	t.Helper()
	payload, _, err := chain.Prepare(parentID, timestamp, nil)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, _ := workgraph.InclusionRoot(nil)
	template, err := payload.SealTemplate(
		types.Address(types.DomainHash("test/workarchive/miner", []byte(label))), inclusion, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	block, result, err := payload.Finalize(anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	return block, result
}

func copyArchiveDirectory(t testing.TB, source, destination string) {
	t.Helper()
	if err := os.Mkdir(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		encoded, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, entry.Name()), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
