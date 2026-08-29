package tieproducer

import (
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

const (
	PairVersion0             uint16 = 0
	MaximumPairArtifactBytes        = 2*workblock.MaxCanonicalBytes + 1024
)

var ErrPairArtifact = errors.New("invalid controlled-tie pair artifact")

// Pair is a transport-neutral, role-labelled pair of proof-of-work blocks.
// It contains no observer signature or secret. An observer derives delivery
// order from the separately published plan, validates both blocks, and creates
// its own receipt only after local admission.
type Pair struct {
	Version  uint16
	PlanID   types.Hash
	Sequence uint64
	Tested   workblock.Block
	Control  workblock.Block
}

func (pair Pair) Validate(
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
) error {
	if pair.Version != PairVersion0 || pair.Sequence == 0 || expectedPlanID.IsZero() {
		return ErrPairArtifact
	}
	if err := plan.Verify(binding); err != nil {
		return err
	}
	if plan.Version != calibration.TiePlanVersion1 || pair.Sequence > uint64(len(plan.Slots)) {
		return ErrPairArtifact
	}
	planID, err := plan.ID()
	if err != nil {
		return err
	}
	if planID != expectedPlanID || pair.PlanID != planID {
		return ErrPairArtifact
	}
	if _, err := activation.Work(pair.Tested, plan.ActivationHeight); err != nil {
		return err
	}
	if _, err := activation.Work(pair.Control, plan.ActivationHeight); err != nil {
		return err
	}
	tested := pair.Tested.Header.Seal
	control := pair.Control.Header.Seal
	testedID, testedErr := pair.Tested.Header.ID()
	controlID, controlErr := pair.Control.Header.ID()
	if testedErr != nil || controlErr != nil || testedID.IsZero() || controlID.IsZero() || testedID == controlID ||
		tested.Miner != plan.TestedMiner || control.Miner != plan.ControlMiner ||
		tested.AnchorParent.IsZero() || tested.AnchorParent != control.AnchorParent ||
		tested.Height < plan.ActivationHeight || tested.Height != control.Height ||
		tested.Timestamp != control.Timestamp || tested.PayloadRoot != control.PayloadRoot {
		return ErrPairArtifact
	}
	return nil
}

func (pair Pair) CanonicalBytes(
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
) ([]byte, error) {
	if err := pair.Validate(plan, binding, expectedPlanID); err != nil {
		return nil, err
	}
	tested := pair.Tested.CanonicalBytes()
	control := pair.Control.CanonicalBytes()
	encoder := codec.NewEncoder(64 + len(tested) + len(control))
	encoder.U16(pair.Version)
	encoder.Fixed(pair.PlanID[:])
	encoder.U64(pair.Sequence)
	encoder.BytesField(tested)
	encoder.BytesField(control)
	encoded := encoder.Bytes()
	if len(encoded) > MaximumPairArtifactBytes {
		return nil, ErrPairArtifact
	}
	return encoded, nil
}

func (pair Pair) ID(
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
) (types.Hash, error) {
	encoded, err := pair.CanonicalBytes(plan, binding, expectedPlanID)
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/testnet/calibration/tie-pair/id/v0", encoded), nil
}

func DecodePair(
	input []byte,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	expectedPlanID types.Hash,
) (Pair, error) {
	if len(input) == 0 || len(input) > MaximumPairArtifactBytes {
		return Pair{}, ErrPairArtifact
	}
	decoder := codec.NewDecoder(input)
	var pair Pair
	var err error
	if pair.Version, err = decoder.U16(); err != nil {
		return Pair{}, err
	}
	planID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Pair{}, err
	}
	copy(pair.PlanID[:], planID)
	if pair.Sequence, err = decoder.U64(); err != nil {
		return Pair{}, err
	}
	tested, err := decoder.BytesField(workblock.MaxCanonicalBytes)
	if err != nil {
		return Pair{}, err
	}
	control, err := decoder.BytesField(workblock.MaxCanonicalBytes)
	if err != nil {
		return Pair{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Pair{}, err
	}
	if pair.Tested, err = workblock.Decode(tested); err != nil {
		return Pair{}, err
	}
	if pair.Control, err = workblock.Decode(control); err != nil {
		return Pair{}, err
	}
	if err := pair.Validate(plan, binding, expectedPlanID); err != nil {
		return Pair{}, err
	}
	return pair, nil
}
