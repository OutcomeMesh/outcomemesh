package workchain

import (
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

// OpenExistingReadOnly holds the original database lock without bootstrap or repair.
// Bound operational stores still require their existing owner/pins and are refused.
func OpenExistingReadOnly(path string, base Base, p workblock.Parameters, policy Policy) (*Store, error) {
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(storage.ErrCorrupt, e)
	}
	lock, e := os.Lstat(filepath.Join(path, "LOCK"))
	if e != nil || !lock.Mode().IsRegular() || lock.Size() != 0 {
		return nil, errors.Join(storage.ErrCorrupt, e)
	}
	s, e := New(base, p)
	if e != nil {
		return nil, e
	}
	db, e := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest, ReadOnly: true, ErrorIfNotExists: true})
	if e != nil {
		return nil, e
	}
	persistence := &workPersistence{rootPath: path, db: db, policy: policy, checkpoints: make(map[types.Hash]struct{})}
	if e = persistence.initializeOrLoad(s, base, false); e != nil {
		db.Close()
		return nil, e
	}
	s.persistence = persistence
	return s, nil
}

// MigrationBlocks includes every retained fork, with the incumbent's ancestors
// first. Replaying this order retains first-seen equal-work selection.
func (s *Store) MigrationBlocks(maxBytes uint64) ([]workblock.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.openErrorLocked(); err != nil {
		return nil, err
	}
	if s.floor.Pruned || (s.persistence != nil && (s.persistence.effectSchema || !s.persistence.storageID.IsZero() || s.persistence.pins != nil)) {
		return nil, ErrCanonicalPrune
	}
	var order []*chainNode
	var path []*chainNode
	seen := map[types.Hash]bool{}
	for n := s.nodes[s.tipID]; n != nil && n.block != nil; n = s.nodes[n.block.Header.Seal.AnchorParent] {
		path = append(path, n)
	}
	for i := len(path) - 1; i >= 0; i-- {
		order = append(order, path[i])
		seen[path[i].tip.ID] = true
	}
	var forks []*chainNode
	for id, n := range s.nodes {
		if n.block != nil && !seen[id] {
			forks = append(forks, n)
		}
	}
	sort.Slice(forks, func(i, j int) bool {
		if forks[i].tip.Height != forks[j].tip.Height {
			return forks[i].tip.Height < forks[j].tip.Height
		}
		return types.CompareHash(forks[i].tip.ID, forks[j].tip.ID) < 0
	})
	order = append(order, forks...)
	var result []workblock.Block
	var size uint64
	for _, n := range order {
		b := n.block.CanonicalBytes()
		if uint64(len(b)) > maxBytes-size {
			return nil, storage.ErrHistoryLimit
		}
		size += uint64(len(b))
		v, e := workblock.Decode(b)
		if e != nil {
			return nil, e
		}
		result = append(result, v)
	}
	return result, nil
}

// Current archive/custody bindings do not encode the radix schedule.
func (s *Store) LegacyArchiveCompatible() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.closed && s.parameters.RadixActivationHeight == 0
}
