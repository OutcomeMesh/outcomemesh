package workarchive

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// OpenExistingObjectStore validates an already existing object directory without
// creating, importing, repairing or publishing any file. The returned handle has
// the same bounded object verification as OpenObjectStore. It does not acquire
// an exclusive process lock: callers must keep the root owner-controlled.
func OpenExistingObjectStore(path string, policy ObjectStorePolicy) (opened *ObjectStore, returnErr error) {
	return OpenExistingObjectStoreContext(context.Background(), path, policy)
}

// OpenExistingObjectStoreContext checks cancellation between bounded file reads;
// it cannot interrupt a synchronous filesystem call already in progress.
func OpenExistingObjectStoreContext(ctx context.Context, path string, policy ObjectStorePolicy) (opened *ObjectStore, returnErr error) {
	if ctx == nil || path == "" || policy.Validate() != nil {
		return nil, ErrObjectStore
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := os.Lstat(absolute)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrObjectStore, err)
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	directory, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			opened = nil
			returnErr = errors.Join(returnErr, closeErr)
		}
	}()
	checkRoot := func() error {
		opened, openedErr := directory.Stat()
		current, currentErr := os.Lstat(absolute)
		if openedErr != nil || currentErr != nil || !current.IsDir() ||
			current.Mode()&os.ModeSymlink != 0 || !os.SameFile(root, opened) || !os.SameFile(root, current) {
			return errors.Join(ErrObjectStore, openedErr, currentErr)
		}
		return nil
	}
	if err := checkRoot(); err != nil {
		return nil, err
	}
	store := &ObjectStore{path: absolute, policy: policy, objects: make(map[types.Hash]uint32)}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			id, err := parseObjectFileName(entry.Name())
			if err != nil {
				return nil, err
			}
			encoded, err := loadChunkObjectFile(filepath.Join(absolute, entry.Name()), id)
			if err != nil {
				return nil, err
			}
			if _, exists := store.objects[id]; exists || uint64(len(store.objects)) >= policy.MaximumObjects ||
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
	if err := checkRoot(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return store, nil
}
