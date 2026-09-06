package workarchive

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyHistoricalApplicationVersion0     uint16 = 0
	MaximumCustodyHistoricalApplicationBytes        = 8 + 2 + types.HashSize + MaximumCustodyCheckpointBytes
	custodyHistoricalApplicationIDDomain            = "OMESH/workgraph/archive/custody-historical-application/id/v0"
)

var (
	ErrCustodyHistoricalApplication   = errors.New("invalid custody historical application")
	ErrCustodyApplicationIncomplete   = errors.New("custody historical application is incomplete; preserve it and use a new destination")
	custodyHistoricalApplicationMagic = [8]byte{'O', 'M', 'W', 'A', 'C', 'A', 'P', 'L'}
)

// CustodyHistoricalApplication commits to a quarantined auditor reconstruction.
// The transfer binds the exact original checkpoints; Result binds the new
// historical-only header, preserved prefix, imported entry, and artifact tree.
// It is neither a new retention receipt nor authority to resume a participant.
type CustodyHistoricalApplication struct {
	Version    uint16
	TransferID types.Hash
	Result     CustodyCheckpoint
}

func (application CustodyHistoricalApplication) validate() error {
	if application.Version != CustodyHistoricalApplicationVersion0 || application.TransferID.IsZero() ||
		application.Result.validate() != nil || application.Result.Artifacts == (CustodyCheckpointTree{}) ||
		application.Result.Sequence == 0 {
		return ErrCustodyHistoricalApplication
	}
	return nil
}

func (application CustodyHistoricalApplication) CanonicalBytes() ([]byte, error) {
	if err := application.validate(); err != nil {
		return nil, err
	}
	checkpoint, _ := application.Result.CanonicalBytes()
	encoder := codec.NewEncoder(MaximumCustodyHistoricalApplicationBytes)
	encoder.Fixed(custodyHistoricalApplicationMagic[:])
	encoder.U16(application.Version)
	encoder.Fixed(application.TransferID[:])
	encoder.Fixed(checkpoint)
	return encoder.Bytes(), nil
}

func DecodeCustodyHistoricalApplication(input []byte) (CustodyHistoricalApplication, error) {
	if len(input) != MaximumCustodyHistoricalApplicationBytes {
		return CustodyHistoricalApplication{}, ErrCustodyHistoricalApplication
	}
	decoder := codec.NewDecoder(input)
	magic, _ := decoder.Fixed(len(custodyHistoricalApplicationMagic))
	var application CustodyHistoricalApplication
	application.Version, _ = decoder.U16()
	transferID, _ := decoder.Fixed(types.HashSize)
	copy(application.TransferID[:], transferID)
	checkpoint, _ := decoder.Fixed(MaximumCustodyCheckpointBytes)
	var err error
	application.Result, err = DecodeCustodyCheckpoint(checkpoint)
	if err != nil || !bytes.Equal(magic, custodyHistoricalApplicationMagic[:]) || decoder.Finish() != nil || application.validate() != nil {
		return CustodyHistoricalApplication{}, errors.Join(ErrCustodyHistoricalApplication, err)
	}
	return application, nil
}

func (application CustodyHistoricalApplication) ID() (types.Hash, error) {
	encoded, err := application.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyHistoricalApplicationIDDomain, encoded), nil
}
