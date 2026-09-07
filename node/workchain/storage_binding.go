package workchain

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

var ErrStorageBinding = errors.New("WorkChain storage incarnation does not match the independent pin")

// CreateBoundWithPolicy creates a NEW database with an independently selected
// nonzero incarnation ID. Generate a fresh random ID for each database and retain
// it outside that database before admitting work. It is local metadata, never a
// consensus input. Existing or partially initialized directories are refused.
//
// This detects another incarnation, not a copied database or a rollback that
// preserves the ID. It does not prove physical storage identity. Never recreate
// lost storage under an old ID or treat absent effects as permission to retry.
func CreateBoundWithPolicy(path string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash) (*Store, error) {
	return createBoundWithPolicy(path, base, parameters, policy, storageID, nil)
}

// Per-call initialization boundary used by local fault/process tests only.
func createBoundWithPolicy(path string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash, initializeCommit func(*pebble.Batch) error) (*Store, error) {
	if path == "" || storageID.IsZero() {
		return nil, ErrStorageBinding
	}
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	if _, err := New(base, parameters); err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncStorageDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return openWithPolicy(path, base, parameters, policy, storageID, false, initializeCommit)
}

// OpenBoundWithPolicy only reopens a previously initialized bound database. A
// missing database/identity, mismatched pin or legacy schema is never initialized
// or upgraded. Raw Open/OpenWithPolicy refuse this mode as well.
func OpenBoundWithPolicy(path string, base Base, parameters workblock.Parameters, policy Policy, expectedStorageID types.Hash) (*Store, error) {
	if path == "" || expectedStorageID.IsZero() {
		return nil, ErrStorageBinding
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, ErrStorageBinding
	}
	return openWithPolicy(path, base, parameters, policy, expectedStorageID, true, nil)
}

// VerifyStorageID checks the opened, immutable incarnation under the chain lock.
// Zero selects legacy unbound storage; it is not a wildcard or a freshness test.
func (store *Store) VerifyStorageID(expected types.Hash) error {
	if store == nil {
		return ErrStorageBinding
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return err
	}
	if store.persistence == nil || store.persistence.storageID != expected {
		return ErrStorageBinding
	}
	return nil
}

func syncStorageDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
