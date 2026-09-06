package workarchive

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyParticipantRetirementVersion0     uint16 = 0
	MaximumCustodyParticipantRetirementBytes        = 8 + 2 + types.HashSize + MaximumCustodyCheckpointBytes + 8
	custodyRetirementIDDomain                       = "OMESH/workgraph/archive/custody-participant-retirement/id/v0"
	custodyRetirementPairIDDomain                   = "OMESH/workgraph/archive/custody-local-retirement-pair/id/v0"
)

var (
	ErrCustodyRetirement           = errors.New("invalid local custody retirement")
	ErrCustodyRetirementIncomplete = errors.New("local custody retirement is incomplete; preserve the committed retirement and retry the same reviewed decision")
	custodyRetirementMagic         = [8]byte{'O', 'M', 'W', 'A', 'C', 'R', 'E', 'T'}
)

// CustodyParticipantRetirement is a permanent LOCAL tombstone, not an operator
// signature or global revocation certificate. Before is the exact pinned tree
// before this sole addition. DecidedAt records the pair retirement intent, not
// the time every peer stopped. After the first marker commits, retry may finish
// that same intent even after the proposal's review window, never enable service.
type CustodyParticipantRetirement struct {
	Version    uint16
	ProposalID types.Hash
	Before     CustodyCheckpoint
	DecidedAt  uint64
}

func (retirement CustodyParticipantRetirement) validate() error {
	if retirement.Version != CustodyParticipantRetirementVersion0 || retirement.ProposalID.IsZero() ||
		retirement.Before.validate() != nil || retirement.DecidedAt == 0 {
		return ErrCustodyRetirement
	}
	return nil
}

func (retirement CustodyParticipantRetirement) CanonicalBytes() ([]byte, error) {
	if err := retirement.validate(); err != nil {
		return nil, err
	}
	before, _ := retirement.Before.CanonicalBytes()
	encoder := codec.NewEncoder(MaximumCustodyParticipantRetirementBytes)
	encoder.Fixed(custodyRetirementMagic[:])
	encoder.U16(retirement.Version)
	encoder.Fixed(retirement.ProposalID[:])
	encoder.Fixed(before)
	encoder.U64(retirement.DecidedAt)
	return encoder.Bytes(), nil
}

func DecodeCustodyParticipantRetirement(encoded []byte) (CustodyParticipantRetirement, error) {
	if len(encoded) != MaximumCustodyParticipantRetirementBytes {
		return CustodyParticipantRetirement{}, ErrCustodyRetirement
	}
	decoder := codec.NewDecoder(encoded)
	magic, _ := decoder.Fixed(len(custodyRetirementMagic))
	var result CustodyParticipantRetirement
	result.Version, _ = decoder.U16()
	id, _ := decoder.Fixed(types.HashSize)
	copy(result.ProposalID[:], id)
	before, _ := decoder.Fixed(MaximumCustodyCheckpointBytes)
	var err error
	result.Before, err = DecodeCustodyCheckpoint(before)
	result.DecidedAt, _ = decoder.U64()
	if err != nil || !bytes.Equal(magic, custodyRetirementMagic[:]) || decoder.Finish() != nil || result.validate() != nil {
		return CustodyParticipantRetirement{}, ErrCustodyRetirement
	}
	return result, nil
}

func (retirement CustodyParticipantRetirement) ID() (types.Hash, error) {
	encoded, err := retirement.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyRetirementIDDomain, encoded), nil
}

// CustodyLocalRetirementPair succeeds only after BOTH permanent local markers
// verify. It asserts no physical independence, remote revocation, stopped old
// binaries/copies, erased keys, fresh availability or active replacement.
type CustodyLocalRetirementPair struct {
	Auditor, Replica CustodyParticipantRetirement
}

func (pair CustodyLocalRetirementPair) ID() (types.Hash, error) {
	a, err := pair.Auditor.ID()
	r, rErr := pair.Replica.ID()
	if err != nil || rErr != nil || pair.Auditor.ProposalID != pair.Replica.ProposalID ||
		pair.Auditor.DecidedAt != pair.Replica.DecidedAt || pair.Auditor.Before.Artifacts == (CustodyCheckpointTree{}) ||
		pair.Replica.Before.Artifacts != (CustodyCheckpointTree{}) || pair.Auditor.Before.HeaderID != pair.Replica.Before.HeaderID ||
		pair.Auditor.Before.Sequence == ^uint64(0) || pair.Replica.Before.Sequence != pair.Auditor.Before.Sequence+1 {
		return types.Hash{}, ErrCustodyRetirement
	}
	return types.DomainHash(custodyRetirementPairIDDomain, a[:], r[:]), nil
}
