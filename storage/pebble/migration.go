package pebblestore

import (
	"sort"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

// MigrationBlocks detaches all retained blocks, not just the selected ancestry.
// The byte ceiling is enforced before decoding or retaining each block.
func (s *Store) MigrationBlocks(maxBytes uint64) ([]block.Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, storage.ErrClosed
	}
	it, e := s.db.NewIter(&pebble.IterOptions{LowerBound: []byte{blockIDPrefix}, UpperBound: []byte{blockIDPrefix + 1}})
	if e != nil {
		return nil, e
	}
	defer it.Close()
	var result []block.Block
	var size uint64
	for ok := it.First(); ok; ok = it.Next() {
		key := it.Key()
		if len(key) != 33 {
			return nil, storage.ErrCorrupt
		}
		raw := it.Value()
		if uint64(len(raw)) > maxBytes-size {
			return nil, storage.ErrHistoryLimit
		}
		size += uint64(len(raw))
		b, e := block.Decode(raw)
		if e != nil || b.Header.Version != s.protocolVersion {
			return nil, storage.ErrCorrupt
		}
		id, e := b.Header.ID()
		var want types.Hash
		copy(want[:], key[1:])
		if e != nil || id != want {
			return nil, storage.ErrCorrupt
		}
		result = append(result, b)
	}
	if e = it.Error(); e != nil {
		return nil, e
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Header.Height != result[j].Header.Height {
			return result[i].Header.Height < result[j].Header.Height
		}
		a, _ := result[i].Header.ID()
		b, _ := result[j].Header.ID()
		return types.CompareHash(a, b) < 0
	})
	return result, nil
}
