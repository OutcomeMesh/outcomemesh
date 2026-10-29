package block

import (
	"github.com/outcomemesh/outcomemesh/core/difficulty"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	DefaultTargetSpacing  uint64 = 60
	DefaultASERTHalfLife  uint64 = 7_200
	DefaultRewardMaturity uint64 = 100
)

type Parameters struct {
	ProtocolVersion uint16
	NetworkID       uint32
	BlockSubsidy    uint64
	AnchorTimestamp uint64
	AnchorTarget    types.Hash
	TargetSpacing   uint64
	ASERTHalfLife   uint64
	RewardMaturity  uint64
}

func ParametersFromGenesis(document genesis.Document) Parameters {
	return Parameters{
		ProtocolVersion: document.Version,
		NetworkID:       document.NetworkID,
		BlockSubsidy:    document.BlockSubsidy,
		AnchorTimestamp: document.Timestamp,
		AnchorTarget:    document.Target,
		TargetSpacing:   DefaultTargetSpacing,
		ASERTHalfLife:   DefaultASERTHalfLife,
		RewardMaturity:  DefaultRewardMaturity,
	}
}

func (parameters Parameters) Target(height, timestamp uint64) (types.Hash, error) {
	return difficulty.ASERT(
		parameters.AnchorTarget,
		parameters.AnchorTimestamp,
		height,
		timestamp,
		parameters.TargetSpacing,
		parameters.ASERTHalfLife,
	)
}

func (parameters Parameters) valid() bool {
	return (parameters.ProtocolVersion == Version0 || parameters.ProtocolVersion == Version2) && parameters.NetworkID != 0 &&
		parameters.BlockSubsidy != 0 &&
		parameters.AnchorTimestamp != 0 &&
		!parameters.AnchorTarget.IsZero() &&
		parameters.TargetSpacing != 0 &&
		parameters.ASERTHalfLife != 0 &&
		parameters.RewardMaturity != 0
}

func (parameters Parameters) Validate() error {
	if !parameters.valid() {
		return ErrInvalidParameters
	}
	return nil
}

// StateCommitment is used only after validating Parameters.
func (parameters Parameters) StateCommitment() uint16 {
	if parameters.ProtocolVersion == Version2 {
		return state.CommitmentRadixV1
	}
	return state.CommitmentV0
}
