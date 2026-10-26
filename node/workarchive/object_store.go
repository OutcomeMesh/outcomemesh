package workarchive

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const (
	DefaultObjectStoreObjects uint64 = 262_144
	MaximumObjectStoreObjects uint64 = 4_194_304
)

var (
	ErrObjectStore  = errors.New("invalid WorkGraph archive object store")
	ErrObjectBudget = errors.New("WorkGraph archive object-store budget exceeded")
	ErrObject       = errors.New("invalid WorkGraph archive chunk object")
)

type ObjectStorePolicy struct {
	MaximumObjects uint64
	MaximumBytes   uint64
}

func DefaultObjectStorePolicy() ObjectStorePolicy {
	return ObjectStorePolicy{
		MaximumObjects: DefaultObjectStoreObjects,
		MaximumBytes:   MaximumArchiveBytes,
	}
}

func (policy ObjectStorePolicy) Validate() error {
	if policy.MaximumObjects == 0 || policy.MaximumObjects > MaximumObjectStoreObjects ||
		policy.MaximumBytes == 0 || policy.MaximumBytes > MaximumArchiveBytes {
		return ErrObjectBudget
	}
	return nil
}

type ObjectStore struct {
	mu         sync.Mutex
	path       string
	policy     ObjectStorePolicy
	objects    map[types.Hash]uint32
	totalBytes uint64
}

type ObjectImportReport struct {
	ManifestID    types.Hash
	AddedObjects  uint64
	ReusedObjects uint64
	AddedBytes    uint64
}

type ObjectMaterializeReport struct {
	ManifestID types.Hash
	Objects    uint64
	Bytes      uint64
}

// Directory returns the immutable object-store root configured when it was
// opened. It conveys placement only, not permission to read or remove objects.
func (store *ObjectStore) Directory() string {
	if store == nil {
		return ""
	}
	return store.path
}

func OpenObjectStore(path string, policy ObjectStorePolicy) (*ObjectStore, error) {
	if path == "" || policy.Validate() != nil {
		return nil, ErrObjectStore
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrObjectStore, err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	store := &ObjectStore{
		path: filepath.Clean(absolute), policy: policy,
		objects: make(map[types.Hash]uint32),
	}
	directory, err := os.Open(store.path)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			id, parseErr := parseObjectFileName(entry.Name())
			if parseErr != nil {
				return nil, parseErr
			}
			encoded, loadErr := loadChunkObjectFile(
				filepath.Join(store.path, entry.Name()), id,
			)
			if loadErr != nil {
				return nil, loadErr
			}
			if _, exists := store.objects[id]; exists ||
				uint64(len(store.objects)) >= policy.MaximumObjects ||
				uint64(len(encoded)) > policy.MaximumBytes-store.totalBytes {
				return nil, ErrObjectBudget
			}
			store.objects[id] = uint32(len(encoded))
			store.totalBytes += uint64(len(encoded))
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	return store, nil
}

func (store *ObjectStore) Usage() (uint64, uint64, error) {
	if store == nil {
		return 0, 0, ErrObjectStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return uint64(len(store.objects)), store.totalBytes, nil
}

func (store *ObjectStore) Missing(manifest Manifest) ([]types.Hash, error) {
	if store == nil || manifest.Validate() != nil {
		return nil, ErrObjectStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	missing := make([]types.Hash, 0)
	for _, descriptor := range manifest.Chunks {
		if _, exists := store.objects[descriptor.ID]; !exists {
			missing = append(missing, descriptor.ID)
			continue
		}
		encoded, err := loadChunkObjectFile(
			filepath.Join(store.path, objectFileName(descriptor.ID)), descriptor.ID,
		)
		if err != nil || len(encoded) != int(descriptor.EncodedBytes) {
			return nil, errors.Join(ErrObjectStore, err)
		}
	}
	return missing, nil
}

func (store *ObjectStore) Get(id types.Hash) ([]byte, error) {
	if store == nil || id.IsZero() {
		return nil, ErrObject
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	encodedBytes, exists := store.objects[id]
	if !exists {
		return nil, os.ErrNotExist
	}
	encoded, err := loadChunkObjectFile(filepath.Join(store.path, objectFileName(id)), id)
	if err != nil || len(encoded) != int(encodedBytes) {
		return nil, errors.Join(ErrObjectStore, err)
	}
	return encoded, nil
}

// Put accepts one exact chunk referenced by manifest. Publication uses an
// fsynced temporary file and an atomic no-replace hard link into the store.
func (store *ObjectStore) Put(
	manifest Manifest,
	id types.Hash,
	encoded []byte,
) (bool, error) {
	if store == nil || manifest.Validate() != nil || id.IsZero() {
		return false, ErrObject
	}
	descriptor, exists := manifestDescriptor(manifest, id)
	if !exists || validateChunkObject(manifest, descriptor, encoded) != nil {
		return false, ErrObject
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if expectedBytes, exists := store.objects[id]; exists {
		current, err := loadChunkObjectFile(filepath.Join(store.path, objectFileName(id)), id)
		if err != nil || len(current) != int(expectedBytes) || !bytes.Equal(current, encoded) {
			return false, errors.Join(ErrObjectStore, err)
		}
		return false, nil
	}
	if uint64(len(store.objects)) >= store.policy.MaximumObjects ||
		uint64(len(encoded)) > store.policy.MaximumBytes-store.totalBytes {
		return false, ErrObjectBudget
	}
	parent := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(parent, ".outcomemesh-work-object-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, err
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		return false, err
	}
	if written != len(encoded) {
		return false, io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	destination := filepath.Join(store.path, objectFileName(id))
	if err := os.Link(temporaryPath, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, err
		}
		current, loadErr := loadChunkObjectFile(destination, id)
		if loadErr != nil || !bytes.Equal(current, encoded) {
			return false, errors.Join(ErrObjectStore, loadErr)
		}
		store.objects[id] = uint32(len(current))
		store.totalBytes += uint64(len(current))
		return false, nil
	}
	if err := syncDirectory(store.path); err != nil {
		return false, err
	}
	store.objects[id] = uint32(len(encoded))
	store.totalBytes += uint64(len(encoded))
	return true, nil
}

func (store *ObjectStore) ImportArchiveDirectory(
	path string,
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
) (ObjectImportReport, error) {
	if store == nil {
		return ObjectImportReport{}, ErrObjectStore
	}
	manifest, err := VerifyArchiveDirectory(
		path, checkpoint, checkpointPolicy, base, parameters, limits,
	)
	if err != nil {
		return ObjectImportReport{}, err
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return ObjectImportReport{}, err
	}
	report := ObjectImportReport{ManifestID: manifestID}
	for index, descriptor := range manifest.Chunks {
		encoded, err := readRegularArchiveFile(
			filepath.Join(path, chunkFileName(uint32(index))), MaximumChunkBytes,
		)
		if err != nil {
			return report, err
		}
		added, err := store.Put(manifest, descriptor.ID, encoded)
		if err != nil {
			return report, err
		}
		if added {
			report.AddedObjects++
			report.AddedBytes += uint64(len(encoded))
		} else {
			report.ReusedObjects++
		}
	}
	return report, nil
}

func (store *ObjectStore) MaterializeDirectory(
	path string,
	manifest Manifest,
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
) (ObjectMaterializeReport, error) {
	if store == nil || path == "" {
		return ObjectMaterializeReport{}, ErrObjectStore
	}
	if err := limits.Validate(); err != nil {
		return ObjectMaterializeReport{}, err
	}
	if manifest.BlockCount > limits.MaximumBlocks ||
		uint32(len(manifest.Chunks)) > limits.MaximumChunks ||
		manifest.TotalChunkBytes > limits.MaximumBytes {
		return ObjectMaterializeReport{}, ErrArchiveLimit
	}
	if err := manifest.VerifyStatement(checkpoint.Statement); err != nil {
		return ObjectMaterializeReport{}, err
	}
	if err := checkpoint.Verify(checkpointPolicy); err != nil {
		return ObjectMaterializeReport{}, err
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return ObjectMaterializeReport{}, err
	}
	storeResolved, err := resolvedArchivePath(store.path)
	if err != nil {
		return ObjectMaterializeReport{}, err
	}
	destinationResolved, err := resolvedArchivePath(path)
	if err != nil || pathContains(storeResolved, destinationResolved) {
		return ObjectMaterializeReport{}, errors.Join(ErrObjectStore, err)
	}
	if _, err := os.Lstat(path); err == nil {
		return ObjectMaterializeReport{}, ErrArchiveExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return ObjectMaterializeReport{}, err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return ObjectMaterializeReport{}, err
	}
	temporaryPath, err := os.MkdirTemp(parent, ".outcomemesh-work-materialize-*")
	if err != nil {
		return ObjectMaterializeReport{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporaryPath)
		}
	}()
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		return ObjectMaterializeReport{}, err
	}
	if err := writeNewArchiveFile(filepath.Join(temporaryPath, manifestFileName), manifestBytes); err != nil {
		return ObjectMaterializeReport{}, err
	}
	report := ObjectMaterializeReport{
		ManifestID: manifestID, Objects: uint64(len(manifest.Chunks)),
	}
	for index, descriptor := range manifest.Chunks {
		encoded, err := store.Get(descriptor.ID)
		if err != nil || len(encoded) != int(descriptor.EncodedBytes) {
			return ObjectMaterializeReport{}, errors.Join(ErrObjectStore, err)
		}
		if err := writeNewArchiveFile(
			filepath.Join(temporaryPath, chunkFileName(uint32(index))), encoded,
		); err != nil {
			return ObjectMaterializeReport{}, err
		}
		report.Bytes += uint64(len(encoded))
	}
	if _, err := VerifyArchiveDirectory(
		temporaryPath, checkpoint, checkpointPolicy, base, parameters, limits,
	); err != nil {
		return ObjectMaterializeReport{}, err
	}
	if err := syncDirectory(temporaryPath); err != nil {
		return ObjectMaterializeReport{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		return ObjectMaterializeReport{}, ErrArchiveExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return ObjectMaterializeReport{}, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return ObjectMaterializeReport{}, err
	}
	published = true
	if err := syncDirectory(parent); err != nil {
		return ObjectMaterializeReport{}, errors.Join(ErrArchivePublish, err)
	}
	return report, nil
}

func manifestDescriptor(manifest Manifest, id types.Hash) (ChunkDescriptor, bool) {
	for _, descriptor := range manifest.Chunks {
		if descriptor.ID == id {
			return descriptor, true
		}
	}
	return ChunkDescriptor{}, false
}

func validateChunkObject(manifest Manifest, descriptor ChunkDescriptor, encoded []byte) error {
	if len(encoded) == 0 || len(encoded) != int(descriptor.EncodedBytes) ||
		len(encoded) > MaximumChunkBytes || types.DomainHash(chunkIDDomain, encoded) != descriptor.ID {
		return ErrObject
	}
	chunk, err := DecodeChunk(encoded)
	if err != nil {
		return ErrObject
	}
	canonical, err := chunk.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, encoded) || chunk.Version != manifest.Version ||
		chunk.Index != descriptor.Index || chunk.NetworkID != manifest.Binding.NetworkID ||
		chunk.BaseID != manifest.Binding.BaseID ||
		(manifest.Version == ManifestVersion0 && chunk.AnchorID != manifest.Anchor.ID) ||
		(manifest.Version == ManifestVersion1 && !chunk.AnchorID.IsZero()) ||
		chunk.FirstHeight != descriptor.FirstHeight ||
		len(chunk.Blocks) != int(descriptor.BlockCount) {
		return ErrObject
	}
	return nil
}

func loadChunkObjectFile(path string, id types.Hash) ([]byte, error) {
	encoded, err := readRegularArchiveFile(path, MaximumChunkBytes)
	if err != nil || types.DomainHash(chunkIDDomain, encoded) != id {
		return nil, errors.Join(ErrObject, err)
	}
	chunk, err := DecodeChunk(encoded)
	if err != nil {
		return nil, errors.Join(ErrObject, err)
	}
	canonical, err := chunk.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, errors.Join(ErrObject, err)
	}
	return encoded, nil
}

func objectFileName(id types.Hash) string { return "chunk-" + id.String() + ".omwc" }

func parseObjectFileName(name string) (types.Hash, error) {
	const prefix = "chunk-"
	const suffix = ".omwc"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) ||
		len(name) != len(prefix)+types.HashSize*2+len(suffix) {
		return types.Hash{}, ErrObjectStore
	}
	decoded, err := hex.DecodeString(name[len(prefix) : len(name)-len(suffix)])
	if err != nil || len(decoded) != types.HashSize {
		return types.Hash{}, errors.Join(ErrObjectStore, err)
	}
	var id types.Hash
	copy(id[:], decoded)
	if id.IsZero() || name != objectFileName(id) {
		return types.Hash{}, ErrObjectStore
	}
	return id, nil
}
