package workchain

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrStoragePosition   = errors.New("WorkChain database position does not match its independent journal")
	ErrStoragePinPending = errors.New("WorkChain storage position needs explicit recovery; missing work must not be retried")
	ErrStoragePinBusy    = errors.New("WorkChain storage position journal is already owned")
	ErrStoragePinLimit   = errors.New("WorkChain storage position journal reached its retention limit")
)

// MaximumStoragePositions bounds this local research journal. Records are never
// reset, compacted or discarded to make room. This is not a production WAL.
const MaximumStoragePositions uint64 = 65_536

// StoragePosition identifies one logical Pebble batch, not its content or physical
// device. CommitID is a fresh opaque token, NOT a state commitment or block ID.
type StoragePosition struct {
	Sequence uint64
	CommitID types.Hash
}

// StorageProtection is detached local evidence, not permission to execute work.
// Pending may equal Database (confirmation can be resumed) or follow Database
// (outcome unresolved, including the possibility of database rollback).
type StorageProtection struct {
	StorageID types.Hash
	PairID    types.Hash
	Database  StoragePosition
	Confirmed StoragePosition
	Pending   *StoragePosition
}

type storagePositionPins struct {
	path            string
	lock            *os.File
	identity        map[string]os.FileInfo
	encodedIdentity []byte
	pairID          types.Hash
	initial         StoragePosition
	confirmed       StoragePosition
	pending         *StoragePosition
	hook            func(string) error // per-instance local test seam, never an external flag
}

// CreatePositionPinnedWithPolicy creates TWO NEW disjoint trusted-owner roots.
// Retain pinsPath independently of the database and select/retain storageID
// before admitting work. Every logical batch receives an independent intent
// before commit and a confirmation afterwards. No migration or fresh-pin
// attachment to existing data is supported. Partial creation stays blocked.
//
// This detects database-only snapshot rollback. Copies of both roots, shared
// rollback, privileged rewriting and physical storage fencing remain outside
// this guarantee. Losing a pin journal is not permission to replace it.
func CreatePositionPinnedWithPolicy(path, pinsPath string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash) (*Store, error) {
	return createPositionPinnedWithPolicy(path, pinsPath, base, parameters, policy, storageID, nil)
}

func createPositionPinnedWithPolicy(path, pinsPath string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash, hook func(string) error) (_ *Store, err error) {
	path, pinsPath, err = positionPaths(path, pinsPath)
	if err != nil || storageID.IsZero() {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	if _, err := New(base, parameters); err != nil {
		return nil, err
	}
	for _, root := range []string{path, pinsPath} {
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrStoragePosition, err)
		}
	}
	pins, err := createPositionPins(pinsPath, storageID, workConfigHash(base, parameters), hook)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, pins.lock.Close())
		}
	}()
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncStorageDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	initialize := func(batch *pebble.Batch) error {
		if err := pins.reach("initialize-before"); err != nil {
			return err
		}
		if err := batch.Commit(pebble.Sync); err != nil {
			return err
		}
		return pins.reach("initialize-after")
	}
	chain, err := openWithPositionPins(path, base, parameters, policy, storageID, false, initialize, pins)
	if err != nil {
		return nil, err
	}
	// Until ready is durable, even a complete initialized database is unusable.
	if err := pins.publish("ready", pins.encodedIdentity, "ready"); err != nil {
		_ = chain.persistence.db.Close()
		return nil, err
	}
	if err := pins.captureIdentity(); err != nil {
		_ = chain.persistence.db.Close()
		return nil, err
	}
	return chain, nil
}

// OpenPositionPinnedWithPolicy verifies retained positions and the full database
// before returning. It never confirms or replays work. A valid one-intent gap
// returns a gated Store: only StorageProtection, ResumeStorageConfirmation and
// Close are available. An older, newer or conflicting database is refused.
func OpenPositionPinnedWithPolicy(path, pinsPath string, base Base, parameters workblock.Parameters, policy Policy, storageID types.Hash) (_ *Store, err error) {
	path, pinsPath, err = positionPaths(path, pinsPath)
	if err != nil || storageID.IsZero() {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	if policy.MaxHistoryBytes == 0 {
		return nil, storage.ErrHistoryLimit
	}
	if _, err := New(base, parameters); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	pins, err := openPositionPins(pinsPath, storageID, workConfigHash(base, parameters))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, pins.lock.Close())
		}
	}()
	return openWithPositionPins(path, base, parameters, policy, storageID, true, nil, pins)
}

// StorageProtection remains available while a recovered position is pending.
// An uncertain live commit requires closing/reopening before diagnostics.
func (store *Store) StorageProtection() (StorageProtection, error) {
	if store == nil {
		return StorageProtection{}, ErrStoragePosition
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.positionErrorLocked(); err != nil {
		return StorageProtection{}, err
	}
	p := store.persistence
	if err := p.pins.checkTail(); err != nil {
		return StorageProtection{}, err
	}
	result := StorageProtection{StorageID: p.storageID, PairID: p.pins.pairID, Database: p.position, Confirmed: p.pins.confirmed}
	if p.pins.pending != nil {
		copy := *p.pins.pending
		result.Pending = &copy
	}
	return result, nil
}

// ResumeStorageConfirmation ONLY confirms the exact pending position already
// present in the fully recovered database. It does not execute a batch, sign
// completion or resolve a missing effect. When the database is still at the
// previous position, no safe no-effect disposition is implemented.
func (store *Store) ResumeStorageConfirmation() error {
	if store == nil {
		return ErrStoragePosition
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.positionErrorLocked(); err != nil {
		return err
	}
	p := store.persistence
	if err := p.pins.checkTail(); err != nil {
		p.uncertain = true
		return errors.Join(ErrUncertain, err)
	}
	if p.pins.pending == nil {
		return nil
	}
	if p.position != *p.pins.pending {
		return ErrStoragePinPending
	}
	// Recovery may have replayed a surviving unsynced WAL. Make that existing
	// database state durable before publishing independent confirmation.
	if err := p.pins.reach("resume-before-flush"); err != nil {
		p.uncertain = true
		return errors.Join(ErrUncertain, err)
	}
	if err := p.db.Flush(); err != nil {
		p.uncertain = true
		return errors.Join(ErrUncertain, err)
	}
	if err := p.pins.reach("resume-after-flush"); err != nil {
		p.uncertain = true
		return errors.Join(ErrUncertain, err)
	}
	if err := p.pins.confirm(); err != nil {
		p.uncertain = true
		return errors.Join(ErrUncertain, err)
	}
	return nil
}

func (store *Store) positionErrorLocked() error {
	if store.closed {
		return storage.ErrClosed
	}
	if store.persistence == nil || store.persistence.pins == nil {
		return ErrStoragePosition
	}
	if store.persistence.uncertain {
		return ErrUncertain
	}
	return nil
}

// prepare performs the final authorization/fixed-width updates immediately
// before commit, AFTER the independent intent's I/O. Errors after intent may
// leave an unresolved gap; poison memory instead of guessing a safe retry.
func (p *workPersistence) commitBatch(batch *pebble.Batch, prepare func() error, commit func(*pebble.Batch) error) (err error) {
	if commit == nil {
		commit = func(batch *pebble.Batch) error { return batch.Commit(pebble.Sync) }
	}
	if p.pins != nil {
		defer func() {
			if err != nil {
				p.uncertain = true
				err = errors.Join(ErrUncertain, err)
			}
		}()
		next, err := p.pins.begin()
		if err != nil {
			return err
		}
		if err := batch.Set(workKeyPosition, encodeStoragePosition(next), nil); err != nil {
			return err
		}
	}
	if prepare != nil {
		if err := prepare(); err != nil {
			return err
		}
	}
	if p.pins != nil {
		if err := p.pins.reach("database-before"); err != nil {
			return err
		}
	}
	if err := commit(batch); err != nil {
		return err
	}
	if p.pins != nil {
		p.position = *p.pins.pending
		if err := p.pins.reach("database-after"); err != nil {
			return err
		}
		if err := p.pins.confirm(); err != nil {
			return err
		}
	}
	return nil
}

func positionPaths(path, pinsPath string) (string, string, error) {
	paths := []string{path, pinsPath}
	for i, value := range paths {
		if value == "" {
			return "", "", ErrStoragePosition
		}
		absolute, err := filepath.Abs(value)
		if err != nil {
			return "", "", err
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			return "", "", err
		}
		paths[i] = filepath.Join(parent, filepath.Base(absolute))
	}
	for i := range paths {
		rel, err := filepath.Rel(paths[i], paths[1-i])
		if err != nil || rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
			return "", "", ErrStoragePosition
		}
	}
	return paths[0], paths[1], nil
}

func encodeStoragePosition(p StoragePosition) []byte {
	encoded := make([]byte, 8+types.HashSize)
	binary.BigEndian.PutUint64(encoded, p.Sequence)
	copy(encoded[8:], p.CommitID[:])
	return encoded
}

func decodeStoragePosition(encoded []byte) (StoragePosition, error) {
	if len(encoded) != 8+types.HashSize {
		return StoragePosition{}, ErrStoragePosition
	}
	p := StoragePosition{Sequence: binary.BigEndian.Uint64(encoded)}
	copy(p.CommitID[:], encoded[8:])
	if p.CommitID.IsZero() || p.Sequence > MaximumStoragePositions {
		return StoragePosition{}, ErrStoragePosition
	}
	return p, nil
}

func (p *workPersistence) loadPosition(pinned bool) error {
	pair, pairErr := p.get(workKeyPositionPair)
	encoded, posErr := p.get(workKeyPosition)
	if !pinned {
		if !errors.Is(pairErr, pebble.ErrNotFound) || !errors.Is(posErr, pebble.ErrNotFound) {
			return errors.Join(ErrStoragePosition, storage.ErrCorrupt, pairErr, posErr)
		}
		return nil
	}
	if pairErr != nil || posErr != nil || !bytes.Equal(pair, p.pins.pairID[:]) {
		return errors.Join(ErrStoragePosition, pairErr, posErr)
	}
	position, err := decodeStoragePosition(encoded)
	if err != nil {
		return err
	}
	if position != p.pins.confirmed && (p.pins.pending == nil || position != *p.pins.pending) {
		return ErrStoragePosition
	}
	p.position = position
	return nil
}

func randomStorageToken() (types.Hash, error) {
	var token types.Hash
	_, err := rand.Read(token[:])
	if err != nil || token.IsZero() {
		return types.Hash{}, errors.Join(ErrStoragePosition, err)
	}
	return token, nil
}
