package calibration

import (
	"crypto/ed25519"
	"errors"
	"io"
	"os"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	TiePairCheckpointVersion0 uint16 = 0
	TiePairCheckpointBytes           = 2 + types.HashSize + 8 + types.HashSize + ed25519.PublicKeySize + ed25519.SignatureSize
)

const (
	tiePairCheckpointSignatureDomain = "OMESH/testnet/calibration/tie-pair-checkpoint/signature/v0"
	tiePairCheckpointIDDomain        = "OMESH/testnet/calibration/tie-pair-checkpoint/id/v0"
)

var ErrTiePairCheckpoint = errors.New("invalid controlled-tie pair checkpoint")

// TiePairCheckpoint is the coordinator-signed publication unit created only
// after a portable pair exists. Publishing its ID outside the artifact path
// gives every observer the same plan/slot/pair binding without allowing pair
// IDs to influence mining or delivery order.
type TiePairCheckpoint struct {
	Version              uint16
	PlanID               types.Hash
	Sequence             uint64
	PairID               types.Hash
	CoordinatorPublicKey [ed25519.PublicKeySize]byte
	Signature            [ed25519.SignatureSize]byte
}

func SignTiePairCheckpoint(
	privateKey ed25519.PrivateKey,
	plan TiePlan,
	binding TiePlanBinding,
	expectedPlanID types.Hash,
	sequence uint64,
	pairID types.Hash,
) (TiePairCheckpoint, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return TiePairCheckpoint{}, ErrPublicKey
	}
	checkpoint := TiePairCheckpoint{
		Version: TiePairCheckpointVersion0, PlanID: expectedPlanID,
		Sequence: sequence, PairID: pairID,
	}
	copy(checkpoint.CoordinatorPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	if err := checkpoint.validateShape(plan, binding, expectedPlanID); err != nil {
		return TiePairCheckpoint{}, err
	}
	copy(checkpoint.Signature[:], ed25519.Sign(privateKey, checkpoint.signatureMessage()))
	return checkpoint, nil
}

func (checkpoint TiePairCheckpoint) Verify(
	plan TiePlan,
	binding TiePlanBinding,
	expectedPlanID types.Hash,
) error {
	if err := checkpoint.validateShape(plan, binding, expectedPlanID); err != nil {
		return err
	}
	if !ed25519.Verify(
		ed25519.PublicKey(checkpoint.CoordinatorPublicKey[:]),
		checkpoint.signatureMessage(), checkpoint.Signature[:],
	) {
		return ErrSignature
	}
	return nil
}

func (checkpoint TiePairCheckpoint) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(TiePairCheckpointBytes)
	checkpoint.encodeUnsigned(encoder)
	encoder.Fixed(checkpoint.Signature[:])
	return encoder.Bytes()
}

func (checkpoint TiePairCheckpoint) ID(
	plan TiePlan,
	binding TiePlanBinding,
	expectedPlanID types.Hash,
) (types.Hash, error) {
	if err := checkpoint.Verify(plan, binding, expectedPlanID); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(tiePairCheckpointIDDomain, checkpoint.CanonicalBytes()), nil
}

func DecodeTiePairCheckpoint(input []byte) (TiePairCheckpoint, error) {
	if len(input) != TiePairCheckpointBytes {
		return TiePairCheckpoint{}, ErrTiePairCheckpoint
	}
	decoder := codec.NewDecoder(input)
	var checkpoint TiePairCheckpoint
	var err error
	if checkpoint.Version, err = decoder.U16(); err != nil {
		return TiePairCheckpoint{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return TiePairCheckpoint{}, decodeErr
	} else {
		copy(checkpoint.PlanID[:], value)
	}
	if checkpoint.Sequence, err = decoder.U64(); err != nil {
		return TiePairCheckpoint{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return TiePairCheckpoint{}, decodeErr
	} else {
		copy(checkpoint.PairID[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
		return TiePairCheckpoint{}, decodeErr
	} else {
		copy(checkpoint.CoordinatorPublicKey[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.SignatureSize); decodeErr != nil {
		return TiePairCheckpoint{}, decodeErr
	} else {
		copy(checkpoint.Signature[:], value)
	}
	if err := decoder.Finish(); err != nil {
		return TiePairCheckpoint{}, err
	}
	if checkpoint.Version != TiePairCheckpointVersion0 || checkpoint.PlanID.IsZero() ||
		checkpoint.Sequence == 0 || checkpoint.PairID.IsZero() ||
		types.Hash(checkpoint.CoordinatorPublicKey).IsZero() {
		return TiePairCheckpoint{}, ErrTiePairCheckpoint
	}
	return checkpoint, nil
}

func SaveTiePairCheckpointFile(
	path string,
	checkpoint TiePairCheckpoint,
	plan TiePlan,
	binding TiePlanBinding,
	expectedPlanID types.Hash,
) (types.Hash, error) {
	if path == "" {
		return types.Hash{}, ErrTiePairCheckpoint
	}
	identifier, err := checkpoint.ID(plan, binding, expectedPlanID)
	if err != nil {
		return types.Hash{}, err
	}
	if err := savePrivateFile(path, ".outcomemesh-tie-pair-checkpoint-*", checkpoint.CanonicalBytes()); err != nil {
		return types.Hash{}, err
	}
	return identifier, nil
}

func LoadTiePairCheckpointFile(
	path string,
	plan TiePlan,
	binding TiePlanBinding,
	expectedPlanID types.Hash,
	expectedCheckpointID types.Hash,
) (TiePairCheckpoint, error) {
	if path == "" || expectedCheckpointID.IsZero() {
		return TiePairCheckpoint{}, ErrTiePairCheckpoint
	}
	file, err := os.Open(path)
	if err != nil {
		return TiePairCheckpoint{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, TiePairCheckpointBytes+1))
	if err != nil {
		return TiePairCheckpoint{}, err
	}
	checkpoint, err := DecodeTiePairCheckpoint(encoded)
	if err != nil {
		return TiePairCheckpoint{}, err
	}
	identifier, err := checkpoint.ID(plan, binding, expectedPlanID)
	if err != nil {
		return TiePairCheckpoint{}, err
	}
	if identifier != expectedCheckpointID {
		return TiePairCheckpoint{}, ErrTiePairCheckpoint
	}
	return checkpoint, nil
}

func (checkpoint TiePairCheckpoint) signatureMessage() []byte {
	encoder := codec.NewEncoder(TiePairCheckpointBytes - ed25519.SignatureSize)
	checkpoint.encodeUnsigned(encoder)
	hash := types.DomainHash(tiePairCheckpointSignatureDomain, encoder.Bytes())
	return hash[:]
}

func (checkpoint TiePairCheckpoint) encodeUnsigned(encoder *codec.Encoder) {
	encoder.U16(checkpoint.Version)
	encoder.Fixed(checkpoint.PlanID[:])
	encoder.U64(checkpoint.Sequence)
	encoder.Fixed(checkpoint.PairID[:])
	encoder.Fixed(checkpoint.CoordinatorPublicKey[:])
}

func (checkpoint TiePairCheckpoint) validateShape(
	plan TiePlan,
	binding TiePlanBinding,
	expectedPlanID types.Hash,
) error {
	if checkpoint.Version != TiePairCheckpointVersion0 || expectedPlanID.IsZero() ||
		checkpoint.PlanID != expectedPlanID || checkpoint.Sequence == 0 || checkpoint.PairID.IsZero() ||
		checkpoint.CoordinatorPublicKey != plan.CoordinatorPublicKey ||
		checkpoint.CoordinatorPublicKey != binding.CoordinatorPublicKey ||
		(plan.Version != TiePlanVersion1 && plan.Version != TiePlanVersion2) ||
		checkpoint.Sequence > uint64(len(plan.Slots)) {
		return ErrTiePairCheckpoint
	}
	if err := plan.Verify(binding); err != nil {
		return err
	}
	planID, err := plan.ID()
	if err != nil {
		return err
	}
	if planID != expectedPlanID {
		return ErrTiePairCheckpoint
	}
	return nil
}
