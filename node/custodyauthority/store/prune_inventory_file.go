package store

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// SaveArchivePruneInventoryFile publishes a prepared package without replacing
// any existing destination. The dedicated parent must already exist and remain
// operator-controlled; this does not enroll a directory as a protected owner.
// Exact retries sync the same verified inode and its parent. An error after
// publication can leave a complete file; retry only with the same external pins.
// Inputs must not be mutated concurrently. No executor or authority is opened.
func SaveArchivePruneInventoryFile(path string, inventory ArchivePruneInventory, expectedInventoryID, expectedPolicyID types.Hash) error {
	return saveArchivePruneInventoryFile(path, inventory, expectedInventoryID, expectedPolicyID, storeHooks{})
}

func saveArchivePruneInventoryFile(path string, inventory ArchivePruneInventory, expectedInventoryID, expectedPolicyID types.Hash, hooks storeHooks) error {
	encoded, err := inventory.CanonicalBytes()
	if err != nil {
		return err
	}
	policyID, err := inventory.PolicyID()
	if err != nil || expectedInventoryID.IsZero() || expectedPolicyID.IsZero() ||
		archivePruneInventoryID(encoded) != expectedInventoryID || policyID != expectedPolicyID {
		return ErrPruneInventory
	}
	path, err = storePath(path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return syncArchivePruneInventory(path, encoded, hooks)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".outcomemesh-prune-inventory-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := writeAndSync(temporary, encoded, hooks); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := hooks.reach("inventory-published"); err != nil {
		return err
	}
	return syncArchivePruneInventory(path, encoded, hooks)
}

func syncArchivePruneInventory(path string, expected []byte, hooks storeHooks) (err error) {
	parent := filepath.Dir(path)
	directory, err := os.Lstat(parent)
	if err != nil || !directory.IsDir() {
		return errors.Join(ErrPruneInventory, err)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() != int64(len(expected)) {
		return errors.Join(ErrPruneInventory, err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.Join(ErrPruneInventory, err)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumArchivePruneInventoryBytes+1))
	if err != nil || !bytes.Equal(encoded, expected) {
		return errors.Join(ErrPruneInventory, err)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := hooks.reach("inventory-before-directory-sync"); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || current.Size() != before.Size() {
		return errors.Join(ErrPruneInventory, err)
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	openedDirectory, err := dir.Stat()
	if err != nil || !os.SameFile(directory, openedDirectory) {
		return errors.Join(ErrPruneInventory, err)
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	return hooks.reach("inventory-directory-synced")
}

// LoadArchivePruneInventoryFile is bounded, read-only and requires independently
// retained pins. Success authenticates preparation, not a latest authority head,
// historical lineage verification, physical durability or execution outcome.
func LoadArchivePruneInventoryFile(path string, expectedInventoryID, expectedPolicyID types.Hash) (ArchivePruneInventory, error) {
	if expectedInventoryID.IsZero() || expectedPolicyID.IsZero() {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	path, err := storePath(path)
	if err != nil {
		return ArchivePruneInventory{}, err
	}
	encoded, err := readRegular(path, MaximumArchivePruneInventoryBytes)
	if err != nil {
		return ArchivePruneInventory{}, errors.Join(ErrPruneInventory, err)
	}
	if archivePruneInventoryID(encoded) != expectedInventoryID {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	inventory, err := DecodeArchivePruneInventory(encoded)
	if err != nil {
		return ArchivePruneInventory{}, err
	}
	policyID, err := inventory.PolicyID()
	if err != nil || policyID != expectedPolicyID {
		return ArchivePruneInventory{}, ErrPruneInventory
	}
	return inventory, nil
}
