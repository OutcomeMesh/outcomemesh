package workblock

import (
	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func (p Parameters) Validate() error {
	if !p.valid() {
		return ErrParameters
	}
	return nil
}
func (p Parameters) VersionAt(height uint64) uint16 {
	if p.RadixActivationHeight != 0 && height >= p.RadixActivationHeight {
		return Version3
	}
	return Version1
}
func (p Parameters) CommitmentAt(height uint64) uint16 {
	if p.VersionAt(height) == Version3 {
		return state.CommitmentRadixV1
	}
	return state.CommitmentV0
}
func receiptVersion(commitment uint16) uint16 {
	if commitment == state.CommitmentRadixV1 {
		return legacyblock.Version2
	}
	return legacyblock.Version0
}
func stateForHeight(before *state.Memory, height uint64, p Parameters) (*state.Memory, error) {
	want := p.CommitmentAt(height)
	if before.CommitmentVersion() == state.CommitmentV0 && height == p.RadixActivationHeight {
		// Only the transition block rebuilds once, before paying its predecessor or executing transactions.
		return state.NewVersion(before.Resources(), state.CommitmentRadixV1)
	}
	if before.CommitmentVersion() != want || (height == p.RadixActivationHeight && height > p.ActivationHeight) {
		return nil, state.ErrCommitmentVersion
	}
	return before, nil
}
func payloadCommitment(version uint16, tx, receipt, stateRoot, previous, queue types.Hash, award uint64) (types.Hash, error) {
	switch version {
	case Version1:
		return workgraph.PayloadCommitmentV1(tx, receipt, stateRoot, previous, queue, award)
	case Version3:
		return workgraph.PayloadCommitmentV3(tx, receipt, stateRoot, previous, queue, award)
	default:
		return types.Hash{}, ErrParameters
	}
}
