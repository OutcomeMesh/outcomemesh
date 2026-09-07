package workchain

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const positionRecordMaximum = 256

func positionIdentity(storageID, config, pair types.Hash) []byte {
	encoded := []byte("OMWP\x00I")
	encoded = append(encoded, storageID[:]...)
	encoded = append(encoded, config[:]...)
	return append(encoded, pair[:]...)
}

func newPositionPins(path string, storageID, config, pair types.Hash) *storagePositionPins {
	identity := positionIdentity(storageID, config, pair)
	initial := StoragePosition{CommitID: types.DomainHash("OMESH/workchain/storage-position/initial/v0", identity)}
	return &storagePositionPins{path: path, pairID: pair, encodedIdentity: identity, initial: initial, confirmed: initial}
}

func createPositionPins(path string, storageID, config types.Hash, hook func(string) error) (_ *storagePositionPins, err error) {
	pair, err := randomStorageToken()
	if err != nil {
		return nil, err
	}
	p := newPositionPins(path, storageID, config, pair)
	p.hook = hook
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncStorageDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	p.lock, err = openPositionLock(path, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.lock.Close())
		}
	}()
	for _, name := range []string{"intents", "confirmed", "pending"} {
		if err := os.Mkdir(filepath.Join(path, name), 0o700); err != nil {
			return nil, err
		}
		if err := syncStorageDirectory(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := p.publish("identity", p.encodedIdentity, "identity"); err != nil {
		return nil, err
	}
	return p, nil
}

func openPositionPins(path string, storageID, config types.Hash) (_ *storagePositionPins, err error) {
	lock, err := openPositionLock(path, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	identity, err := readPositionFile(filepath.Join(path, "identity"), positionRecordMaximum)
	if err != nil || len(identity) != 6+3*types.HashSize {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	var pair types.Hash
	copy(pair[:], identity[len(identity)-types.HashSize:])
	p := newPositionPins(path, storageID, config, pair)
	p.lock = lock
	if pair.IsZero() || !bytes.Equal(identity, p.encodedIdentity) {
		return nil, ErrStoragePosition
	}
	if err := p.captureIdentity(); err != nil {
		return nil, err
	}
	intents, err := positionNames(filepath.Join(path, "intents"), int(MaximumStoragePositions))
	if err != nil {
		return nil, err
	}
	confirmed, err := positionNames(filepath.Join(path, "confirmed"), int(MaximumStoragePositions))
	if err != nil {
		return nil, err
	}
	if len(confirmed) > len(intents) || len(intents)-len(confirmed) > 1 {
		return nil, ErrStoragePosition
	}
	for i, name := range intents {
		sequence := uint64(i + 1)
		if name != positionName(sequence) {
			return nil, ErrStoragePosition
		}
		encoded, err := readPositionFile(filepath.Join(path, "intents", name), positionRecordMaximum)
		if err != nil {
			return nil, err
		}
		previous, next, err := decodePositionRecord(encoded, p.encodedIdentity, false)
		if err != nil || previous != p.confirmed || next.Sequence != sequence {
			return nil, errors.Join(ErrStoragePosition, err)
		}
		p.pending = &next
		if i < len(confirmed) {
			if confirmed[i] != name {
				return nil, ErrStoragePosition
			}
			encoded, err := readPositionFile(filepath.Join(path, "confirmed", name), positionRecordMaximum)
			if err != nil {
				return nil, err
			}
			_, actual, err := decodePositionRecord(encoded, p.encodedIdentity, true)
			if err != nil || actual != next {
				return nil, errors.Join(ErrStoragePosition, err)
			}
			p.confirmed, p.pending = next, nil
		}
	}
	if err := p.checkTail(); err != nil {
		return nil, err
	}
	// A visible final link can have survived death before its directory barrier.
	// Stabilize the retained tail before allowing any new database mutation.
	for _, name := range []string{"identity", "ready"} {
		if err := syncPositionFile(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if p.confirmed.Sequence > 0 {
		name := positionName(p.confirmed.Sequence)
		for _, dir := range []string{"intents", "confirmed"} {
			if err := syncPositionFile(filepath.Join(path, dir, name)); err != nil {
				return nil, err
			}
		}
	}
	if p.pending != nil {
		if err := syncPositionFile(filepath.Join(path, "intents", positionName(p.pending.Sequence))); err != nil {
			return nil, err
		}
	}
	for _, dir := range []string{"intents", "confirmed", "pending", ""} {
		if err := syncStorageDirectory(filepath.Join(path, dir)); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func positionName(sequence uint64) string { return fmt.Sprintf("%020d", sequence) }

func encodePositionRecord(identity []byte, previous, next StoragePosition, confirmation bool) []byte {
	encoded := []byte("OMWP\x00T")
	if confirmation {
		encoded[5] = 'C'
	}
	context := types.DomainHash("OMESH/workchain/storage-position/identity/v0", identity)
	encoded = append(encoded, context[:]...)
	if !confirmation {
		encoded = append(encoded, encodeStoragePosition(previous)...)
	}
	encoded = append(encoded, encodeStoragePosition(next)...)
	checksum := types.DomainHash("OMESH/workchain/storage-position/record/v0", encoded)
	return append(encoded, checksum[:]...)
}

func decodePositionRecord(encoded, identity []byte, confirmation bool) (StoragePosition, StoragePosition, error) {
	var previous, next StoragePosition
	length := 6 + types.HashSize + 40 + types.HashSize
	if !confirmation {
		length += 40
	}
	if len(encoded) != length {
		return previous, next, ErrStoragePosition
	}
	var err error
	if !confirmation {
		previous, err = decodeStoragePosition(encoded[38:78])
		if err != nil {
			return previous, next, err
		}
	}
	next, err = decodeStoragePosition(encoded[length-72 : length-32])
	if err != nil || next.Sequence == 0 {
		return previous, next, ErrStoragePosition
	}
	if !confirmation && (previous.Sequence+1 != next.Sequence || previous.CommitID == next.CommitID) {
		return previous, next, ErrStoragePosition
	}
	if !bytes.Equal(encoded, encodePositionRecord(identity, previous, next, confirmation)) {
		return previous, next, ErrStoragePosition
	}
	return previous, next, nil
}

func (p *storagePositionPins) begin() (StoragePosition, error) {
	if err := p.checkTail(); err != nil {
		return StoragePosition{}, err
	}
	if p.pending != nil {
		return StoragePosition{}, ErrStoragePinPending
	}
	if p.confirmed.Sequence >= MaximumStoragePositions {
		return StoragePosition{}, ErrStoragePinLimit
	}
	token, err := randomStorageToken()
	if err != nil || token == p.confirmed.CommitID {
		return StoragePosition{}, errors.Join(ErrStoragePosition, err)
	}
	next := StoragePosition{Sequence: p.confirmed.Sequence + 1, CommitID: token}
	encoded := encodePositionRecord(p.encodedIdentity, p.confirmed, next, false)
	if err := p.publish(filepath.Join("intents", positionName(next.Sequence)), encoded, "intent"); err != nil {
		return StoragePosition{}, err
	}
	p.pending = &next
	return next, nil
}

func (p *storagePositionPins) confirm() error {
	if p.pending == nil {
		return ErrStoragePosition
	}
	if err := p.checkTail(); err != nil {
		return err
	}
	next := *p.pending
	encoded := encodePositionRecord(p.encodedIdentity, StoragePosition{}, next, true)
	if err := p.publish(filepath.Join("confirmed", positionName(next.Sequence)), encoded, "confirmation"); err != nil {
		return err
	}
	p.confirmed, p.pending = next, nil
	return nil
}

func (p *storagePositionPins) reach(stage string) error {
	if p.hook != nil {
		return p.hook(stage)
	}
	return nil
}

// Historical entries are immutable under the trusted-owner contract. Reopen
// verifies the full bounded chain; live checks verify permanent inodes, exact
// identity/ready bytes and the retained tail, not O(n) history on every block.
func (p *storagePositionPins) checkTail() error {
	if err := p.checkIdentity(); err != nil {
		return err
	}
	if p.confirmed.Sequence > 0 {
		name := positionName(p.confirmed.Sequence)
		encoded, err := readPositionFile(filepath.Join(p.path, "confirmed", name), positionRecordMaximum)
		if err != nil || !bytes.Equal(encoded, encodePositionRecord(p.encodedIdentity, StoragePosition{}, p.confirmed, true)) {
			return errors.Join(ErrStoragePosition, err)
		}
		encoded, err = readPositionFile(filepath.Join(p.path, "intents", name), positionRecordMaximum)
		if err != nil {
			return err
		}
		_, next, err := decodePositionRecord(encoded, p.encodedIdentity, false)
		if err != nil || next != p.confirmed {
			return errors.Join(ErrStoragePosition, err)
		}
	}
	if p.pending != nil {
		encoded, err := readPositionFile(filepath.Join(p.path, "intents", positionName(p.pending.Sequence)), positionRecordMaximum)
		if err != nil || !bytes.Equal(encoded, encodePositionRecord(p.encodedIdentity, p.confirmed, *p.pending, false)) {
			return errors.Join(ErrStoragePosition, err)
		}
	}
	return nil
}
