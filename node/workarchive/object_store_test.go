package workarchive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestArchiveObjectExchangeTransfersOnlyComposedSuffix(t *testing.T) {
	fixture, firstSuffixTip := preparePrunedArchiveFixture(t)
	secondSuffix, _ := mineArchiveChild(
		t, fixture.source, firstSuffixTip.ID,
		firstSuffixTip.Timestamp+fixture.parameters.TargetSpacing, "object-exchange-suffix",
	)
	if _, _, err := fixture.source.Commit(
		secondSuffix, secondSuffix.Header.Seal.Timestamp,
	); err != nil {
		t.Fatal(err)
	}
	secondAnchor, err := fixture.source.TipByID(mustArchiveBlockID(t, secondSuffix))
	if err != nil {
		t.Fatal(err)
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
	previousStatementID := mustStatementID(t, fixture.checkpoint.Statement)
	statement, err := manifest.ArchiveStatement(2, previousStatementID)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedCheckpoint(t, statement, fixture.keys)

	sourceStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "source-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstImport, err := sourceStore.ImportArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if err != nil || firstImport.AddedObjects != uint64(len(fixture.manifest.Chunks)) ||
		firstImport.ReusedObjects != 0 {
		t.Fatalf("first object import=%+v err=%v", firstImport, err)
	}
	composedImport, err := sourceStore.ImportArchiveDirectory(
		compositionPath, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if err != nil || composedImport.ManifestID != manifestID || composedImport.AddedObjects != 1 ||
		composedImport.ReusedObjects != uint64(len(fixture.manifest.Chunks)) {
		t.Fatalf("composed object import=%+v err=%v", composedImport, err)
	}

	destinationStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "destination-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destinationStore.ImportArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	request, complete, err := BuildChunkRequest(
		manifest, destinationStore, MaximumObjectRequestIDs,
	)
	if err != nil || complete || len(request.IDs) != 1 ||
		request.IDs[0] != manifest.Chunks[len(manifest.Chunks)-1].ID {
		t.Fatalf("suffix request=%+v complete=%t err=%v", request, complete, err)
	}
	requestBytes, err := request.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := DecodeChunkRequest(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ServeChunkRequest(sourceStore, manifest, decodedRequest)
	if err != nil || len(batch.Objects) != 1 || batch.Objects[0].ID != request.IDs[0] {
		t.Fatalf("suffix batch=%+v err=%v", batch, err)
	}
	batchBytes, err := batch.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decodedBatch, err := DecodeChunkBatch(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	applyReport, err := ApplyChunkBatch(destinationStore, manifest, decodedBatch)
	if err != nil || applyReport.AddedObjects != 1 || applyReport.ReusedObjects != 0 {
		t.Fatalf("suffix apply=%+v err=%v", applyReport, err)
	}
	if next, complete, err := BuildChunkRequest(
		manifest, destinationStore, MaximumObjectRequestIDs,
	); err != nil || !complete || len(next.IDs) != 0 {
		t.Fatalf("complete object store request=%+v complete=%t err=%v", next, complete, err)
	}
	objects, objectBytes, err := destinationStore.Usage()
	if err != nil || objects != uint64(len(manifest.Chunks)) || objectBytes != manifest.TotalChunkBytes {
		t.Fatalf("destination object usage=%d/%d want=%d/%d err=%v",
			objects, objectBytes, len(manifest.Chunks), manifest.TotalChunkBytes, err)
	}

	materializedPath := filepath.Join(t.TempDir(), "materialized")
	materialized, err := destinationStore.MaterializeDirectory(
		materializedPath, manifest, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if err != nil || materialized.ManifestID != manifestID ||
		materialized.Objects != uint64(len(manifest.Chunks)) ||
		materialized.Bytes != manifest.TotalChunkBytes {
		t.Fatalf("materialized archive=%+v err=%v", materialized, err)
	}
	verified, err := VerifyArchiveDirectory(
		materializedPath, checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedID, err := verified.ID(); err != nil || verifiedID != manifestID {
		t.Fatalf("materialized manifest=%s want=%s err=%v", verifiedID, manifestID, err)
	}
	restorePath := filepath.Join(t.TempDir(), "object-restore")
	if _, err := RestoreDirectory(
		materializedPath, restorePath, checkpoint, fixture.policy, fixture.base,
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
		t.Fatalf("object-restored tip=%+v want=%+v err=%v", restoredTip, secondAnchor, err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenObjectStore(destinationStore.path, DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if reopenedObjects, reopenedBytes, err := reopened.Usage(); err != nil ||
		reopenedObjects != objects || reopenedBytes != objectBytes {
		t.Fatalf("reopened object usage=%d/%d want=%d/%d err=%v",
			reopenedObjects, reopenedBytes, objects, objectBytes, err)
	}
}

func TestArchiveObjectStoreRejectsCorruptionBudgetAndInvalidExchange(t *testing.T) {
	fixture := newArchiveFixture(t)
	policy := DefaultObjectStorePolicy()
	policy.MaximumObjects = 1
	storePath := filepath.Join(t.TempDir(), "bounded-objects")
	store, err := OpenObjectStore(storePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	partialImport, err := store.ImportArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	)
	if !errors.Is(err, ErrObjectBudget) || partialImport.AddedObjects != 1 ||
		partialImport.ReusedObjects != 0 || partialImport.AddedBytes == 0 {
		t.Fatalf("partial object import=%+v error=%v", partialImport, err)
	}
	objects, _, err := store.Usage()
	if err != nil || objects != 1 {
		t.Fatalf("bounded object usage=%d err=%v", objects, err)
	}

	missingStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "missing-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	missingDestination := filepath.Join(t.TempDir(), "missing-materialization")
	if _, err := missingStore.MaterializeDirectory(
		missingDestination, fixture.manifest, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, DefaultLimits(),
	); err == nil {
		t.Fatal("missing objects materialized an archive")
	}
	if _, err := os.Lstat(missingDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-object destination exists: %v", err)
	}

	fullStore, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "full-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fullStore.ImportArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	tightLimits := DefaultLimits()
	tightLimits.MaximumBytes = fixture.manifest.TotalChunkBytes - 1
	tightDestination := filepath.Join(t.TempDir(), "tight-materialization")
	if _, err := fullStore.MaterializeDirectory(
		tightDestination, fixture.manifest, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, tightLimits,
	); !errors.Is(err, ErrArchiveLimit) {
		t.Fatalf("tight materialization error=%v", err)
	}
	if _, err := os.Lstat(tightDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tight-limit destination exists: %v", err)
	}
	nestedDestination := filepath.Join(fullStore.path, "nested-archive")
	if _, err := fullStore.MaterializeDirectory(
		nestedDestination, fixture.manifest, fixture.checkpoint, fixture.policy,
		fixture.base, fixture.parameters, DefaultLimits(),
	); !errors.Is(err, ErrObjectStore) {
		t.Fatalf("nested materialization error=%v", err)
	}
	if _, err := os.Lstat(nestedDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nested destination exists: %v", err)
	}
	request := ChunkRequest{
		Version:    ObjectExchangeVersion0,
		ManifestID: types.DomainHash("test/workarchive/wrong-object-manifest"),
		IDs:        []types.Hash{fixture.manifest.Chunks[0].ID},
	}
	if _, err := ServeChunkRequest(fullStore, fixture.manifest, request); !errors.Is(err, ErrObjectRequest) {
		t.Fatalf("wrong-manifest object request error=%v", err)
	}
	encoded, err := fullStore.Get(fixture.manifest.Chunks[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), encoded...)
	mutated[len(mutated)-1] ^= 1
	manifestID, _ := fixture.manifest.ID()
	batch := ChunkBatch{
		Version: ObjectExchangeVersion0, ManifestID: manifestID,
		Objects: []ChunkObject{{ID: fixture.manifest.Chunks[0].ID, Encoded: mutated}},
	}
	if _, err := ApplyChunkBatch(missingStore, fixture.manifest, batch); !errors.Is(err, ErrObjectBatch) {
		t.Fatalf("mutated object batch error=%v", err)
	}

	objectPath := filepath.Join(fullStore.path, objectFileName(fixture.manifest.Chunks[0].ID))
	objectBytes, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	objectBytes[len(objectBytes)-1] ^= 1
	if err := os.WriteFile(objectPath, objectBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObjectStore(fullStore.path, DefaultObjectStorePolicy()); !errors.Is(err, ErrObject) {
		t.Fatalf("corrupt object-store reopen error=%v", err)
	}
}

func TestArchiveObjectStoreRejectsNonCanonicalFileName(t *testing.T) {
	fixture := newArchiveFixture(t)
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "noncanonical-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveDirectory(
		fixture.archivePath, fixture.checkpoint, fixture.policy, fixture.base,
		fixture.parameters, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}
	id := fixture.manifest.Chunks[0].ID
	canonicalPath := filepath.Join(store.path, objectFileName(id))
	nonCanonicalName := "chunk-" + strings.ToUpper(id.String()) + ".omwc"
	if nonCanonicalName == objectFileName(id) {
		t.Fatal("test object ID has no hexadecimal letters")
	}
	if err := os.Rename(canonicalPath, filepath.Join(store.path, nonCanonicalName)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObjectStore(store.path, DefaultObjectStorePolicy()); !errors.Is(err, ErrObjectStore) {
		t.Fatalf("non-canonical object-store reopen error=%v", err)
	}
}

func TestArchiveObjectStoreConcurrentPutIsIdempotent(t *testing.T) {
	fixture := newArchiveFixture(t)
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "concurrent-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fixture.manifest.Chunks[0]
	encoded := mustReadArchiveFile(t, filepath.Join(fixture.archivePath, chunkFileName(0)))
	const workers = 16
	var wait sync.WaitGroup
	wait.Add(workers)
	errorsByWorker := make(chan error, workers)
	addedByWorker := make(chan bool, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			added, err := store.Put(fixture.manifest, descriptor.ID, encoded)
			errorsByWorker <- err
			addedByWorker <- added
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	close(addedByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
	added := 0
	for value := range addedByWorker {
		if value {
			added++
		}
	}
	if added != 1 {
		t.Fatalf("concurrent added objects=%d want=1", added)
	}
	if objects, objectBytes, err := store.Usage(); err != nil || objects != 1 ||
		objectBytes != uint64(len(encoded)) {
		t.Fatalf("concurrent object usage=%d/%d err=%v", objects, objectBytes, err)
	}
}

func TestArchiveObjectExchangeCodecsRejectMutationAndTrailingBytes(t *testing.T) {
	requestBytes, batchBytes := objectExchangeCodecSeeds(t)
	request, err := DecodeChunkRequest(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if canonical, err := request.CanonicalBytes(); err != nil || !bytes.Equal(canonical, requestBytes) {
		t.Fatalf("request canonical mismatch err=%v", err)
	}
	batch, err := DecodeChunkBatch(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	if canonical, err := batch.CanonicalBytes(); err != nil || !bytes.Equal(canonical, batchBytes) {
		t.Fatalf("batch canonical mismatch err=%v", err)
	}
	if _, err := DecodeChunkRequest(append(requestBytes, 0)); !errors.Is(err, ErrObjectRequest) {
		t.Fatalf("trailing object request error=%v", err)
	}
	if _, err := DecodeChunkBatch(append(batchBytes, 0)); !errors.Is(err, ErrObjectBatch) {
		t.Fatalf("trailing object batch error=%v", err)
	}
	duplicate := request
	duplicate.IDs = append(duplicate.IDs, duplicate.IDs[0])
	if _, err := duplicate.CanonicalBytes(); !errors.Is(err, ErrObjectRequest) {
		t.Fatalf("duplicate object request error=%v", err)
	}
	mutated := batch
	mutated.Objects = append([]ChunkObject(nil), batch.Objects...)
	mutated.Objects[0].Encoded = append([]byte(nil), batch.Objects[0].Encoded...)
	mutated.Objects[0].Encoded[len(mutated.Objects[0].Encoded)-1] ^= 1
	store, err := OpenObjectStore(
		filepath.Join(t.TempDir(), "codec-objects"), DefaultObjectStorePolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, _ := archiveCodecSeedsForVersion(t, ManifestVersion1)
	manifest, _ := DecodeManifest(manifestBytes)
	if _, err := ApplyChunkBatch(store, manifest, mutated); !errors.Is(err, ErrObjectBatch) {
		t.Fatalf("mutated canonical object error=%v", err)
	}
}

func FuzzDecodeChunkRequestNeverPanics(f *testing.F) {
	requestBytes, _ := objectExchangeCodecSeeds(f)
	f.Add(requestBytes)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeChunkRequest(input) })
}

func FuzzDecodeChunkBatchNeverPanics(f *testing.F) {
	_, batchBytes := objectExchangeCodecSeeds(f)
	f.Add(batchBytes)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = DecodeChunkBatch(input) })
}

func objectExchangeCodecSeeds(t testing.TB) ([]byte, []byte) {
	t.Helper()
	manifestBytes, chunkBytes := archiveCodecSeedsForVersion(t, ManifestVersion1)
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestID, _ := manifest.ID()
	request := ChunkRequest{
		Version: ObjectExchangeVersion0, ManifestID: manifestID,
		IDs: []types.Hash{manifest.Chunks[0].ID},
	}
	requestBytes, err := request.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	batch := ChunkBatch{
		Version: ObjectExchangeVersion0, ManifestID: manifestID,
		Objects: []ChunkObject{{ID: manifest.Chunks[0].ID, Encoded: chunkBytes}},
	}
	batchBytes, err := batch.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return requestBytes, batchBytes
}
