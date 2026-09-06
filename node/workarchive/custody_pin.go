package workarchive

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyBackupPinVersion0     uint16 = 0
	MaximumCustodyBackupPinBytes        = 8 + 2 + 8 + types.HashSize + MaximumCustodyCheckpointBytes
	custodyBackupPinIDDomain            = "OMESH/workgraph/archive/custody-backup-pin/id/v0"
)

var (
	ErrCustodyBackupPin         = errors.New("invalid custody backup pin journal")
	ErrCustodyBackupPinConflict = errors.New("custody pin head changed or the backup loses previously pinned evidence")
	custodyBackupPinMagic       = [8]byte{'O', 'M', 'W', 'A', 'C', 'P', 'I', 'N'}
)

// CustodyBackupPin links an operator-authorized backup checkpoint to the prior
// pin. Sequence counts backups, not custody cycles. This is an operational
// local trust record, not a signed receipt or a consensus finality claim.
type CustodyBackupPin struct {
	Version       uint16
	Sequence      uint64
	PreviousPinID types.Hash
	Checkpoint    CustodyCheckpoint
}

func (pin CustodyBackupPin) validate() error {
	if pin.Version != CustodyBackupPinVersion0 || pin.Sequence == 0 ||
		(pin.Sequence == 1) != pin.PreviousPinID.IsZero() || pin.Checkpoint.validate() != nil {
		return ErrCustodyBackupPin
	}
	return nil
}

func (pin CustodyBackupPin) CanonicalBytes() ([]byte, error) {
	if err := pin.validate(); err != nil {
		return nil, err
	}
	checkpoint, _ := pin.Checkpoint.CanonicalBytes()
	encoder := codec.NewEncoder(MaximumCustodyBackupPinBytes)
	encoder.Fixed(custodyBackupPinMagic[:])
	encoder.U16(pin.Version)
	encoder.U64(pin.Sequence)
	encoder.Fixed(pin.PreviousPinID[:])
	encoder.Fixed(checkpoint)
	return encoder.Bytes(), nil
}

func DecodeCustodyBackupPin(input []byte) (CustodyBackupPin, error) {
	if len(input) != MaximumCustodyBackupPinBytes {
		return CustodyBackupPin{}, ErrCustodyBackupPin
	}
	// Every field is fixed-width; the exact bound covers all decoder reads.
	decoder := codec.NewDecoder(input)
	magic, _ := decoder.Fixed(len(custodyBackupPinMagic))
	var pin CustodyBackupPin
	pin.Version, _ = decoder.U16()
	pin.Sequence, _ = decoder.U64()
	previous, _ := decoder.Fixed(types.HashSize)
	copy(pin.PreviousPinID[:], previous)
	checkpoint, _ := decoder.Fixed(MaximumCustodyCheckpointBytes)
	var err error
	pin.Checkpoint, err = DecodeCustodyCheckpoint(checkpoint)
	if err != nil || !bytes.Equal(magic, custodyBackupPinMagic[:]) || decoder.Finish() != nil || pin.validate() != nil {
		return CustodyBackupPin{}, errors.Join(ErrCustodyBackupPin, err)
	}
	return pin, nil
}

func (pin CustodyBackupPin) ID() (types.Hash, error) {
	encoded, err := pin.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyBackupPinIDDomain, encoded), nil
}

// Shape checks here are replayable without old payloads. Promotion additionally
// compares both verified backups to preserve historical bodies and intentions.
func custodyPinFollows(previous, next CustodyBackupPin) bool {
	previousID, err := previous.ID()
	old, current := previous.Checkpoint, next.Checkpoint
	return err == nil && next.validate() == nil && next.Sequence == previous.Sequence+1 &&
		next.PreviousPinID == previousID && current.HeaderID == old.HeaderID &&
		(current.Artifacts == (CustodyCheckpointTree{})) == (old.Artifacts == (CustodyCheckpointTree{})) &&
		current.Sequence >= old.Sequence && (current.Sequence != old.Sequence ||
		(current.HeadEntryID == old.HeadEntryID && current.ReceiptID == old.ReceiptID))
}
