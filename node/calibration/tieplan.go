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
	TiePlanVersion0       uint16 = 0
	MaximumTiePlanSlots          = 10_000
	MaximumTiePlanBytes          = 256 * 1024
	MaximumTieSlotSeconds uint64 = 60 * 60
)

const (
	tiePlanSignatureDomain = "OMESH/testnet/calibration/tie-plan/signature/v0"
	tiePlanIDDomain        = "OMESH/testnet/calibration/tie-plan/id/v0"
)

var (
	ErrTiePlan      = errors.New("invalid controlled-tie plan")
	ErrTiePlanLimit = errors.New("controlled-tie plan exceeds limit")
)

// TiePlanSlot is one precommitted half-open experiment window. A slot must
// later have exactly one signed receipt, even if no valid pair was observed.
type TiePlanSlot struct {
	StartedAt uint64
	EndedAt   uint64
}

// TiePlan fixes the deployment, miner roles, timing, and observer before any
// candidate anchor IDs are known. The coordinator and observer are deliberately
// separate identities: the coordinator commits the experiment design, while
// the observer attests what it saw.
type TiePlan struct {
	Version                 uint16
	NetworkID               uint32
	GenesisID               types.Hash
	ActivationHeight        uint64
	TestedMiner             types.Address
	ControlMiner            types.Address
	MaximumPairDelaySeconds uint64
	Slots                   []TiePlanSlot
	ObserverPublicKey       [ed25519.PublicKeySize]byte
	CoordinatorPublicKey    [ed25519.PublicKeySize]byte
	Signature               [ed25519.SignatureSize]byte
}

// TiePlanBinding is supplied independently by a verifier. In particular, a
// public key merely embedded in a self-signed plan is not a trust anchor.
type TiePlanBinding struct {
	NetworkID            uint32
	GenesisID            types.Hash
	ActivationHeight     uint64
	ObserverPublicKey    [ed25519.PublicKeySize]byte
	CoordinatorPublicKey [ed25519.PublicKeySize]byte
}

func SignTiePlan(privateKey ed25519.PrivateKey, plan TiePlan) (TiePlan, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return TiePlan{}, ErrPublicKey
	}
	plan.Slots = append([]TiePlanSlot(nil), plan.Slots...)
	copy(plan.CoordinatorPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	plan.Signature = [ed25519.SignatureSize]byte{}
	if err := plan.validateShape(); err != nil {
		return TiePlan{}, err
	}
	copy(plan.Signature[:], ed25519.Sign(privateKey, plan.signatureMessage()))
	return plan, nil
}

func (plan TiePlan) Validate() error {
	if err := plan.validateShape(); err != nil {
		return err
	}
	if !ed25519.Verify(
		ed25519.PublicKey(plan.CoordinatorPublicKey[:]),
		plan.signatureMessage(),
		plan.Signature[:],
	) {
		return ErrSignature
	}
	return nil
}

func (plan TiePlan) Verify(expected TiePlanBinding) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if !validTiePlanBinding(expected) || plan.Binding() != expected {
		return ErrBinding
	}
	return nil
}

func (plan TiePlan) Binding() TiePlanBinding {
	return TiePlanBinding{
		NetworkID: plan.NetworkID, GenesisID: plan.GenesisID,
		ActivationHeight: plan.ActivationHeight, ObserverPublicKey: plan.ObserverPublicKey,
		CoordinatorPublicKey: plan.CoordinatorPublicKey,
	}
}

func (plan TiePlan) ID() (types.Hash, error) {
	if err := plan.Validate(); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(tiePlanIDDomain, plan.CanonicalBytes()), nil
}

func (plan TiePlan) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(256 + len(plan.Slots)*16)
	plan.encodeUnsigned(encoder)
	encoder.Fixed(plan.Signature[:])
	return encoder.Bytes()
}

func DecodeTiePlan(input []byte) (TiePlan, error) {
	if len(input) == 0 || len(input) > MaximumTiePlanBytes {
		return TiePlan{}, ErrTiePlanLimit
	}
	decoder := codec.NewDecoder(input)
	var plan TiePlan
	var err error
	if plan.Version, err = decoder.U16(); err != nil {
		return TiePlan{}, err
	}
	if plan.Version != TiePlanVersion0 {
		return TiePlan{}, ErrVersion
	}
	if plan.NetworkID, err = decoder.U32(); err != nil {
		return TiePlan{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return TiePlan{}, decodeErr
	} else {
		copy(plan.GenesisID[:], value)
	}
	if plan.ActivationHeight, err = decoder.U64(); err != nil {
		return TiePlan{}, err
	}
	if value, decodeErr := decoder.Fixed(types.AddressSize); decodeErr != nil {
		return TiePlan{}, decodeErr
	} else {
		copy(plan.TestedMiner[:], value)
	}
	if value, decodeErr := decoder.Fixed(types.AddressSize); decodeErr != nil {
		return TiePlan{}, decodeErr
	} else {
		copy(plan.ControlMiner[:], value)
	}
	if plan.MaximumPairDelaySeconds, err = decoder.U64(); err != nil {
		return TiePlan{}, err
	}
	count, err := decoder.ListLength(MaximumTiePlanSlots)
	if err != nil {
		return TiePlan{}, err
	}
	plan.Slots = make([]TiePlanSlot, count)
	for index := range plan.Slots {
		if plan.Slots[index].StartedAt, err = decoder.U64(); err != nil {
			return TiePlan{}, err
		}
		if plan.Slots[index].EndedAt, err = decoder.U64(); err != nil {
			return TiePlan{}, err
		}
	}
	if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
		return TiePlan{}, decodeErr
	} else {
		copy(plan.ObserverPublicKey[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
		return TiePlan{}, decodeErr
	} else {
		copy(plan.CoordinatorPublicKey[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.SignatureSize); decodeErr != nil {
		return TiePlan{}, decodeErr
	} else {
		copy(plan.Signature[:], value)
	}
	if err := decoder.Finish(); err != nil {
		return TiePlan{}, err
	}
	return plan, nil
}

func SaveTiePlanFile(path string, plan TiePlan, expected TiePlanBinding) error {
	if path == "" {
		return ErrTiePlan
	}
	if err := plan.Verify(expected); err != nil {
		return err
	}
	encoded := plan.CanonicalBytes()
	if len(encoded) > MaximumTiePlanBytes {
		return ErrTiePlanLimit
	}
	return savePrivateFile(path, ".outcomemesh-tie-plan-*", encoded)
}

func LoadTiePlanFile(path string, expected TiePlanBinding) (TiePlan, error) {
	file, err := os.Open(path)
	if err != nil {
		return TiePlan{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumTiePlanBytes+1))
	if err != nil {
		return TiePlan{}, err
	}
	if len(encoded) > MaximumTiePlanBytes {
		return TiePlan{}, ErrTiePlanLimit
	}
	plan, err := DecodeTiePlan(encoded)
	if err != nil {
		return TiePlan{}, err
	}
	if err := plan.Verify(expected); err != nil {
		return TiePlan{}, err
	}
	return plan, nil
}

func (plan TiePlan) signatureMessage() []byte {
	encoder := codec.NewEncoder(192 + len(plan.Slots)*16)
	plan.encodeUnsigned(encoder)
	hash := types.DomainHash(tiePlanSignatureDomain, encoder.Bytes())
	return hash[:]
}

func (plan TiePlan) encodeUnsigned(encoder *codec.Encoder) {
	encoder.U16(plan.Version)
	encoder.U32(plan.NetworkID)
	encoder.Fixed(plan.GenesisID[:])
	encoder.U64(plan.ActivationHeight)
	encoder.Fixed(plan.TestedMiner[:])
	encoder.Fixed(plan.ControlMiner[:])
	encoder.U64(plan.MaximumPairDelaySeconds)
	encoder.Uvarint(uint64(len(plan.Slots)))
	for _, slot := range plan.Slots {
		encoder.U64(slot.StartedAt)
		encoder.U64(slot.EndedAt)
	}
	encoder.Fixed(plan.ObserverPublicKey[:])
	encoder.Fixed(plan.CoordinatorPublicKey[:])
}

func (plan TiePlan) validateShape() error {
	if plan.Version != TiePlanVersion0 {
		return ErrVersion
	}
	if plan.NetworkID == 0 || plan.GenesisID.IsZero() || plan.ActivationHeight == 0 {
		return ErrNetwork
	}
	if plan.TestedMiner.IsZero() || plan.ControlMiner.IsZero() || plan.TestedMiner == plan.ControlMiner {
		return ErrTiePlan
	}
	if plan.ObserverPublicKey == [ed25519.PublicKeySize]byte{} ||
		plan.CoordinatorPublicKey == [ed25519.PublicKeySize]byte{} {
		return ErrPublicKey
	}
	if len(plan.Slots) == 0 {
		return ErrTiePlan
	}
	if len(plan.Slots) > MaximumTiePlanSlots {
		return ErrTiePlanLimit
	}
	if plan.MaximumPairDelaySeconds == 0 || plan.MaximumPairDelaySeconds > MaximumTieSlotSeconds {
		return ErrTiePlan
	}
	for index, slot := range plan.Slots {
		if slot.StartedAt == 0 || slot.EndedAt <= slot.StartedAt ||
			slot.EndedAt-slot.StartedAt > MaximumTieSlotSeconds ||
			plan.MaximumPairDelaySeconds > slot.EndedAt-slot.StartedAt ||
			(index > 0 && slot.StartedAt < plan.Slots[index-1].EndedAt) {
			return ErrTiePlan
		}
	}
	return nil
}

func validTiePlanBinding(binding TiePlanBinding) bool {
	return binding.NetworkID != 0 && !binding.GenesisID.IsZero() && binding.ActivationHeight != 0 &&
		binding.ObserverPublicKey != [ed25519.PublicKeySize]byte{} &&
		binding.CoordinatorPublicKey != [ed25519.PublicKeySize]byte{}
}
