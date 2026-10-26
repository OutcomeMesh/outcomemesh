package pebblestore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/storage"
)

// OpenExistingReadOnly opens an already initialized ledger as an exclusive
// historical source. It never initializes genesis, repairs absent metadata,
// upgrades a schema or commits through the returned handle. A missing/empty
// directory or missing original LOCK is rejected before Pebble can create a
// lock file. Existing LOCK ownership still follows Pebble's platform behavior.
//
// The source paths must remain immutable and operator-controlled during open
// and use. This does not fence privileged path replacement, copied databases or
// rollback. Close this source before handing the detached base to another owner.
func OpenExistingReadOnly(path string, document genesis.Document, policy Policy) (_ *Store, err error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	if path == "" {
		return nil, storage.ErrCorrupt
	}
	path, err = filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	directory, err := os.Lstat(path)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(storage.ErrCorrupt, err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	lock, err := os.Lstat(filepath.Join(path, "LOCK"))
	if err != nil || !lock.Mode().IsRegular() || lock.Size() != 0 {
		return nil, errors.Join(storage.ErrCorrupt, err)
	}
	db, err := pebble.Open(path, &pebble.Options{
		FormatMajorVersion: pebble.FormatNewest, ReadOnly: true, ErrorIfNotExists: true,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, db.Close())
		}
	}()
	store := &Store{db: db, policy: policy, readOnly: true}
	storedGenesis, err := store.getCopy(keyGenesis)
	if err != nil {
		return nil, errors.Join(storage.ErrCorrupt, err)
	}
	if !bytes.Equal(storedGenesis, document.CanonicalBytes()) {
		return nil, storage.ErrGenesisMismatch
	}
	schema, err := store.getCopy(keySchema)
	if err != nil || len(schema) != 2 || binary.BigEndian.Uint16(schema) != storage.SchemaVersion {
		return nil, errors.Join(storage.ErrCorrupt, err)
	}
	if _, err := store.Snapshot(); err != nil {
		return nil, err
	}
	store.historyBytes, err = store.historyUsageUnlocked()
	if err != nil {
		return nil, err
	}
	tip, err := store.Tip()
	if err != nil {
		return nil, err
	}
	if _, err := store.SnapshotAt(tip.ID); err != nil {
		return nil, err
	}
	return store, nil
}
