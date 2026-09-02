package workarchive

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestArchiveCompositionSupportsSuccessiveRetainedFloors(t *testing.T) {
	fixture, firstSuffixTip := preparePrunedArchiveFixture(t)
	secondSuffix, _ := mineArchiveChild(
		t, fixture.source, firstSuffixTip.ID,
		firstSuffixTip.Timestamp+fixture.parameters.TargetSpacing, "compose-second-suffix",
	)
	if _, _, err := fixture.source.Commit(
		secondSuffix, secondSuffix.Header.Seal.Timestamp,
	); err != nil {
		t.Fatal(err)
	}
	secondSuffixID := mustArchiveBlockID(t, secondSuffix)
	secondAnchor, err := fixture.source.TipByID(secondSuffixID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ExportDirectory(
		filepath.Join(t.TempDir(), "ordinary-export"), fixture.binding, fixture.source,
		secondAnchor.ID, DefaultExportOptions(),
	); !errors.Is(err, workchain.ErrHistoryPruned) {
		t.Fatalf("ordinary export from pruned store error=%v", err)
	}

	compositionPath := filepath.Join(t.TempDir(), "composed")
	options := DefaultExportOptions()
	options.BlocksPerChunk = 2
	manifest, manifestID, err := ComposeDirectory(
		compositionPath, fixture.archivePath, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, fixture.source, secondAnchor.ID, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	const expectedManifestID = "5b0f9d5355c49b60b1c95e1657c97aca1d9a4110beaed5b1f7a1550f5c861891"
	if manifestID.String() != expectedManifestID {
		t.Fatalf("composed manifest ID=%s want=%s", manifestID, expectedManifestID)
	}
	if manifest.BlockCount != fixture.manifest.BlockCount+2 || len(manifest.Chunks) != 3 ||
		manifest.Anchor.ID != secondAnchor.ID {
		t.Fatalf("composed archive=%+v", manifest)
	}
	if len(manifest.Chunks) < len(fixture.manifest.Chunks) {
		t.Fatalf("composed chunks=%d predecessor=%d", len(manifest.Chunks), len(fixture.manifest.Chunks))
	}
	for index, descriptor := range fixture.manifest.Chunks {
		if manifest.Chunks[index] != descriptor {
			t.Fatalf("composed prefix chunk %d changed: got=%+v want=%+v",
				index, manifest.Chunks[index], descriptor)
		}
	}
	previousStatementID := mustStatementID(t, fixture.checkpoint.Statement)
	statement, err := manifest.ArchiveStatement(2, previousStatementID)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, statement, fixture.keys)
	if err := VerifySuccessor(fixture.checkpoint, checkpoint, fixture.policy, fixture.source); err != nil {
		t.Fatalf("composed checkpoint successor: %v", err)
	}
	verified, err := VerifyArchiveDirectory(
		compositionPath, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedID, err := verified.ID(); err != nil || verifiedID != manifestID {
		t.Fatalf("verified composed manifest=%s want=%s err=%v", verifiedID, manifestID, err)
	}

	restorePath := filepath.Join(t.TempDir(), "composed-restore")
	if _, err := RestoreDirectory(
		compositionPath, restorePath, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(), workchain.DefaultPolicy(),
	); err != nil {
		t.Fatal(err)
	}
	restored, err := workchain.Open(restorePath, fixture.base, fixture.parameters)
	if err != nil {
		t.Fatal(err)
	}
	restoredTip, err := restored.Tip()
	if err != nil || !storage.EqualTips(restoredTip, secondAnchor) {
		_ = restored.Close()
		t.Fatalf("composed restore tip=%+v want=%+v err=%v", restoredTip, secondAnchor, err)
	}
	restoredExtension, _ := mineArchiveChild(
		t, restored, restoredTip.ID,
		restoredTip.Timestamp+fixture.parameters.TargetSpacing, "composed-restore-extension",
	)
	if _, _, err := restored.Commit(
		restoredExtension, restoredExtension.Header.Seal.Timestamp,
	); err != nil {
		_ = restored.Close()
		t.Fatalf("extend composed restore: %v", err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}

	postArchiveExtension, _ := mineArchiveChild(
		t, fixture.source, secondAnchor.ID,
		secondAnchor.Timestamp+fixture.parameters.TargetSpacing, "compose-next-floor-depth",
	)
	if _, _, err := fixture.source.Commit(
		postArchiveExtension, postArchiveExtension.Header.Seal.Timestamp,
	); err != nil {
		t.Fatal(err)
	}
	composedFixture := fixture
	composedFixture.archivePath = compositionPath
	composedFixture.manifest = manifest
	composedFixture.manifestID = manifestID
	composedFixture.checkpoint = checkpoint
	replicas, replicaPolicy := archiveReplicaFixture(t, composedFixture, 2_000, 30_000)
	result, err := PruneCanonicalPrefix(
		fixture.source, replicas, filepath.Join(t.TempDir(), "availability.omav"),
		checkpoint, fixture.policy, replicaPolicy, fixture.base, fixture.parameters,
		DefaultLimits(), 2_001,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.PreviousFloorID != fixture.manifest.Anchor.ID ||
		result.Report.FloorID != secondAnchor.ID || result.Report.RemovedNodes != 2 {
		t.Fatalf("second retained floor report=%+v", result.Report)
	}
	floor, err := fixture.source.CanonicalFloor()
	if err != nil || floor.Anchor.ID != secondAnchor.ID || floor.ManifestID != manifestID ||
		floor.StatementID != mustStatementID(t, statement) {
		t.Fatalf("second retained floor=%+v err=%v", floor, err)
	}
}

func TestArchiveCompositionRejectsInvalidSourcesAndNestedDestination(t *testing.T) {
	fixture, suffixTip := preparePrunedArchiveFixture(t)
	options := DefaultExportOptions()
	if _, _, err := ComposeDirectory(
		filepath.Join(t.TempDir(), "no-suffix"), fixture.archivePath, fixture.checkpoint,
		fixture.policy, fixture.base, fixture.parameters, fixture.source,
		fixture.manifest.Anchor.ID, options,
	); !errors.Is(err, ErrArchiveCompose) {
		t.Fatalf("composition without suffix error=%v", err)
	}
	if _, _, err := ComposeDirectory(
		filepath.Join(fixture.archivePath, "nested"), fixture.archivePath, fixture.checkpoint,
		fixture.policy, fixture.base, fixture.parameters, fixture.source, suffixTip.ID, options,
	); !errors.Is(err, ErrArchiveCompose) {
		t.Fatalf("nested composition destination error=%v", err)
	}
	entries, err := os.ReadDir(fixture.archivePath)
	if err != nil || len(entries) != len(fixture.manifest.Chunks)+1 {
		t.Fatalf("nested rejection changed source entries=%d err=%v", len(entries), err)
	}
	wrongStatement := fixture.checkpoint.Statement
	wrongStatement.Sequence = 2
	wrongStatement.PreviousID = types.DomainHash("test/workarchive/wrong-compose-predecessor")
	wrongCheckpoint := signedCheckpoint(t, wrongStatement, fixture.keys)
	wrongCheckpointDestination := filepath.Join(t.TempDir(), "wrong-floor-statement")
	if _, _, err := ComposeDirectory(
		wrongCheckpointDestination, fixture.archivePath, wrongCheckpoint,
		fixture.policy, fixture.base, fixture.parameters, fixture.source, suffixTip.ID, options,
	); !errors.Is(err, ErrArchiveCompose) {
		t.Fatalf("wrong retained-floor statement error=%v", err)
	}
	if _, err := os.Lstat(wrongCheckpointDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong retained-floor statement published destination: %v", err)
	}
	tooSmallChunks := DefaultExportOptions()
	tooSmallChunks.BlocksPerChunk = 1
	tooSmallDestination := filepath.Join(t.TempDir(), "split-stable-prefix")
	if _, _, err := ComposeDirectory(
		tooSmallDestination, fixture.archivePath, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, fixture.source, suffixTip.ID, tooSmallChunks,
	); !errors.Is(err, ErrArchiveCompose) {
		t.Fatalf("stable prefix split error=%v", err)
	}
	if _, err := os.Lstat(tooSmallDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stable prefix split published destination: %v", err)
	}

	corruptPath := filepath.Join(t.TempDir(), "corrupt-previous")
	copyArchiveDirectory(t, fixture.archivePath, corruptPath)
	chunkPath := filepath.Join(corruptPath, chunkFileName(0))
	encoded := mustReadArchiveFile(t, chunkPath)
	encoded[len(encoded)-1] ^= 1
	if err := os.WriteFile(chunkPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "from-corrupt")
	if _, _, err := ComposeDirectory(
		destination, corruptPath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, fixture.source, suffixTip.ID, options,
	); !errors.Is(err, ErrArchiveCompose) {
		t.Fatalf("corrupt composition source error=%v", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt composition published destination: %v", err)
	}
}

func TestArchiveCompositionRejectsReorgBeforePublication(t *testing.T) {
	fixture, firstSuffixTip := preparePrunedArchiveFixture(t)
	targetBlock, _ := mineArchiveChild(
		t, fixture.source, firstSuffixTip.ID,
		firstSuffixTip.Timestamp+fixture.parameters.TargetSpacing, "compose-reorg-target",
	)
	if _, _, err := fixture.source.Commit(targetBlock, targetBlock.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	targetID := mustArchiveBlockID(t, targetBlock)
	parent := filepath.Join(t.TempDir(), "publication")
	destination := filepath.Join(parent, "composed")
	_, _, err := composeDirectory(
		destination, fixture.archivePath, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, fixture.source, targetID, DefaultExportOptions(),
		func() error {
			parentID := fixture.manifest.Anchor.ID
			timestamp := fixture.manifest.Anchor.Timestamp
			for height := 0; height < 3; height++ {
				timestamp += fixture.parameters.TargetSpacing
				block, _ := mineArchiveChild(
					t, fixture.source, parentID, timestamp,
					"compose-reorg-winner-"+string(rune('a'+height)),
				)
				if _, _, err := fixture.source.Commit(block, block.Header.Seal.Timestamp); err != nil {
					return err
				}
				parentID = mustArchiveBlockID(t, block)
			}
			return nil
		},
	)
	if !errors.Is(err, ErrChain) || !errors.Is(err, ErrArchiveCompose) {
		t.Fatalf("reorged composition error=%v", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reorged composition was published: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("reorged composition temporary entries=%d err=%v", len(entries), err)
	}
}

func preparePrunedArchiveFixture(t testing.TB) (archiveFixture, storage.Tip) {
	t.Helper()
	fixture := newArchiveFixture(t)
	replicas, replicaPolicy := archiveReplicaFixture(t, fixture, 1_000, 20_000)
	extension, _ := mineArchiveChild(
		t, fixture.source, fixture.manifest.Anchor.ID,
		fixture.manifest.Anchor.Timestamp+fixture.parameters.TargetSpacing,
		"compose-first-suffix",
	)
	if _, _, err := fixture.source.Commit(extension, extension.Header.Seal.Timestamp); err != nil {
		t.Fatal(err)
	}
	if report, err := fixture.source.PruneStaleForks(); err != nil || report.RemovedNodes == 0 {
		t.Fatalf("composition stale-fork preparation report=%+v err=%v", report, err)
	}
	if _, err := PruneCanonicalPrefix(
		fixture.source, replicas, filepath.Join(t.TempDir(), "availability.omav"),
		fixture.checkpoint, fixture.policy, replicaPolicy, fixture.base,
		fixture.parameters, DefaultLimits(), 1_001,
	); err != nil {
		t.Fatal(err)
	}
	extensionID := mustArchiveBlockID(t, extension)
	tip, err := fixture.source.TipByID(extensionID)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, tip
}
