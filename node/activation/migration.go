package activation

import (
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func readWorkRoot(root string) ([]os.DirEntry, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrConfiguration
	}
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(storage.ErrCorrupt, e)
	}
	if e = validateWorkForestManifest(filepath.Join(root, workForestManifestName)); e != nil {
		return nil, e
	}
	for _, name := range []string{workForestPendingName, workForestSelectPending} {
		if _, e = os.Lstat(filepath.Join(root, name)); !errors.Is(e, os.ErrNotExist) {
			return nil, errors.Join(storage.ErrCorrupt, e)
		}
	}
	return os.ReadDir(root)
}

// MigrationWorkBlocks orders the selected tree first and preserves each tree's
// incumbent. The caller must replay the complete legacy inventory before these.
func (r *Router) MigrationWorkBlocks(maxBytes uint64) ([]Block, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, storage.ErrClosed
	}
	tip, _, e := r.bestLocked()
	if e != nil {
		return nil, e
	}
	selectedBase := r.workBases[tip.ID]
	ids := make([]types.Hash, 0, len(r.trees))
	for id := range r.trees {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i] == ids[j] {
			return false
		}
		if ids[i] == selectedBase {
			return true
		}
		if ids[j] == selectedBase {
			return false
		}
		return types.CompareHash(ids[i], ids[j]) < 0
	})
	var result []Block
	var size uint64
	for _, id := range ids {
		blocks, e := r.trees[id].MigrationBlocks(maxBytes - size)
		if e != nil {
			return nil, e
		}
		for _, b := range blocks {
			v, e := Work(b, r.config.Work.ActivationHeight)
			if e != nil {
				return nil, e
			}
			size += uint64(len(v.CanonicalBytes()))
			result = append(result, v)
		}
	}
	return result, nil
}
