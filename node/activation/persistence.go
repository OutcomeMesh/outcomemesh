package activation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	workForestManifestName  = "FOREST"
	workForestPendingName   = "FOREST.pending"
	workForestSelectedName  = "SELECTED"
	workForestSelectPending = "SELECTED.pending"
)

var workForestManifest = []byte{
	'O', 'M', 'E', 'S', 'H', '/', 'w', 'o', 'r', 'k', 'f', 'o', 'r', 'e', 's', 't', 0, 1,
}

var workForestSelectedMagic = []byte{
	'O', 'M', 'E', 'S', 'H', '/', 's', 'e', 'l', 'e', 'c', 't', 'e', 'd', 0, 0,
}

func (router *Router) openPersistentTrees() error {
	var entries []os.DirEntry
	var err error
	if router.config.ReadOnly {
		entries, err = readWorkRoot(router.config.WorkRoot)
	} else {
		entries, err = prepareWorkRoot(router.config.WorkRoot)
	}
	if err != nil {
		return err
	}
	treeCount := 0
	manifestCount := 0
	for _, entry := range entries {
		switch entry.Name() {
		case workForestManifestName:
			manifestCount++
		case workForestSelectedName:
		default:
			treeCount++
		}
	}
	if manifestCount != 1 {
		return storage.ErrCorrupt
	}
	if treeCount > router.config.MaxWorkTrees {
		return ErrTreeLimit
	}
	for _, entry := range entries {
		if entry.Name() == workForestManifestName || entry.Name() == workForestSelectedName {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return storage.ErrCorrupt
		}
		baseID, err := decodeWorkBaseDirectory(entry.Name())
		if err != nil {
			return err
		}
		base, err := router.workBase(baseID)
		if err != nil {
			return fmt.Errorf("%w: persisted activation base %s: %v", storage.ErrCorrupt, baseID, err)
		}
		tree, err := router.openWorkTree(base)
		if err != nil {
			return err
		}
		if err := router.registerTreeLocked(baseID, tree); err != nil {
			_ = tree.Close()
			return err
		}
	}
	selected, exists, err := loadWorkForestSelection(router.config.WorkRoot)
	if err != nil {
		return err
	}
	if exists {
		router.selectedID = selected
	} else {
		// One-time migration reproduces the former deterministic choice from
		// verified tips before persisting the new arrival incumbent.
		router.selectedID = types.Hash{}
	}
	previous := router.selectedID
	if _, _, err := router.bestLocked(); err != nil {
		return err
	}
	if !exists || router.selectedID != previous {
		if router.config.ReadOnly {
			return storage.ErrCorrupt
		}
		if err := saveWorkForestSelection(router.config.WorkRoot, router.selectedID); err != nil {
			return err
		}
		router.selectDirty = false
	}
	return nil
}

func loadWorkForestSelection(root string) (types.Hash, bool, error) {
	path := filepath.Join(root, workForestSelectedName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return types.Hash{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() != int64(len(workForestSelectedMagic)+types.HashSize) {
		return types.Hash{}, false, storage.ErrCorrupt
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return types.Hash{}, false, err
	}
	selected, err := decodeWorkForestSelection(encoded)
	return selected, true, err
}

func decodeWorkForestSelection(encoded []byte) (types.Hash, error) {
	if len(encoded) != len(workForestSelectedMagic)+types.HashSize ||
		!bytes.Equal(encoded[:len(workForestSelectedMagic)], workForestSelectedMagic) {
		return types.Hash{}, storage.ErrCorrupt
	}
	var selected types.Hash
	copy(selected[:], encoded[len(workForestSelectedMagic):])
	if selected.IsZero() {
		return types.Hash{}, storage.ErrCorrupt
	}
	return selected, nil
}

func saveWorkForestSelection(root string, selected types.Hash) error {
	if selected.IsZero() {
		return storage.ErrCorrupt
	}
	encoded := make([]byte, 0, len(workForestSelectedMagic)+types.HashSize)
	encoded = append(encoded, workForestSelectedMagic...)
	encoded = append(encoded, selected[:]...)
	pendingPath := filepath.Join(root, workForestSelectPending)
	temporary, err := os.OpenFile(pendingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(pendingPath)
		}
	}()
	if err := writeAll(temporary, encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(pendingPath, filepath.Join(root, workForestSelectedName)); err != nil {
		return err
	}
	committed = true
	return syncDirectory(root)
}

func (router *Router) openWorkTree(base workchain.Base) (*workchain.Store, error) {
	if router.config.WorkRoot == "" {
		return workchain.New(base, router.config.Work)
	}
	if router.config.ReadOnly {
		policy := router.config.WorkPolicy
		policy.MaxHistoryBytes /= uint64(router.config.MaxWorkTrees)
		return workchain.OpenExistingReadOnly(filepath.Join(router.config.WorkRoot, base.Tip.ID.String()), base, router.config.Work, policy)
	}
	path, err := ensureWorkTreeDirectory(router.config.WorkRoot, base.Tip.ID)
	if err != nil {
		return nil, err
	}
	policy := router.config.WorkPolicy
	policy.MaxHistoryBytes /= uint64(router.config.MaxWorkTrees)
	return workchain.OpenWithPolicy(path, base, router.config.Work, policy)
}

func (router *Router) workBase(baseID types.Hash) (workchain.Base, error) {
	baseTip, err := router.ledger.TipByID(baseID)
	if err != nil {
		return workchain.Base{}, ErrParent
	}
	if baseTip.Height == ^uint64(0) || baseTip.Height+1 != router.config.Work.ActivationHeight {
		return workchain.Base{}, ErrBoundary
	}
	baseState, err := router.ledger.SnapshotAt(baseID)
	if err != nil {
		return workchain.Base{}, err
	}
	history, err := router.recentLegacyTimestampsLocked(baseTip)
	if err != nil {
		return workchain.Base{}, err
	}
	return workchain.Base{Tip: baseTip, State: baseState, RecentTimestamps: history}, nil
}

func prepareWorkRoot(root string) ([]os.DirEntry, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(os.PathSeparator) {
		return nil, ErrConfiguration
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, err
		}
		if err := syncDirectory(filepath.Dir(root)); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, ErrConfiguration
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	hasManifest := false
	hasPending := false
	hasSelectPending := false
	for _, entry := range entries {
		switch entry.Name() {
		case workForestManifestName:
			hasManifest = true
		case workForestPendingName:
			hasPending = true
		case workForestSelectPending:
			hasSelectPending = true
		}
	}
	manifestPath := filepath.Join(root, workForestManifestName)
	pendingPath := filepath.Join(root, workForestPendingName)
	switch {
	case hasManifest:
		if hasPending || validateWorkForestManifest(manifestPath) != nil {
			return nil, storage.ErrCorrupt
		}
	case hasPending:
		if len(entries) != 1 || validateWorkForestManifest(pendingPath) != nil {
			return nil, storage.ErrCorrupt
		}
		if err := os.Rename(pendingPath, manifestPath); err != nil {
			return nil, err
		}
		if err := syncDirectory(root); err != nil {
			return nil, err
		}
	case len(entries) != 0:
		return nil, storage.ErrCorrupt
	default:
		if err := createWorkForestManifest(pendingPath, manifestPath, root); err != nil {
			return nil, err
		}
	}
	if hasSelectPending {
		selectionPending := filepath.Join(root, workForestSelectPending)
		info, err := os.Lstat(selectionPending)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, storage.ErrCorrupt
		}
		// The selection is a restart hint; the durable tree tips remain the
		// source of work. Discard an interrupted hint and recompute it below.
		if err := os.Remove(selectionPending); err != nil {
			return nil, err
		}
		if err := syncDirectory(root); err != nil {
			return nil, err
		}
	}
	entries, err = os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func createWorkForestManifest(pendingPath, manifestPath, root string) error {
	file, err := os.OpenFile(pendingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeAll(file, workForestManifest)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(pendingPath, manifestPath); err != nil {
		return err
	}
	return syncDirectory(root)
}

func validateWorkForestManifest(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() != int64(len(workForestManifest)) {
		return storage.ErrCorrupt
	}
	encoded, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(encoded, workForestManifest) {
		return storage.ErrCorrupt
	}
	return nil
}

func ensureWorkTreeDirectory(root string, baseID types.Hash) (string, error) {
	path := filepath.Join(root, baseID.String())
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return "", err
		}
		if err := syncDirectory(root); err != nil {
			return "", err
		}
		return path, nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", storage.ErrCorrupt
	}
	return path, nil
}

func decodeWorkBaseDirectory(name string) (types.Hash, error) {
	if len(name) != types.HashSize*2 {
		return types.Hash{}, storage.ErrCorrupt
	}
	encoded, err := hex.DecodeString(name)
	if err != nil || len(encoded) != types.HashSize {
		return types.Hash{}, storage.ErrCorrupt
	}
	var result types.Hash
	copy(result[:], encoded)
	if result.String() != name {
		return types.Hash{}, storage.ErrCorrupt
	}
	return result, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
