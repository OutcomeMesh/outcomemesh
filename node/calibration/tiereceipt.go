package calibration

import (
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	TieReceiptVersion0     uint16 = 0
	TieReceiptVersion1     uint16 = 1
	TieReceiptVersion2     uint16 = 2
	MaximumTieReceiptBytes        = 1024
)

const (
	tieReceiptSignatureDomain = "OMESH/testnet/calibration/tie-receipt/signature/v0"
	tieReceiptIDDomain        = "OMESH/testnet/calibration/tie-receipt/id/v0"
)

var (
	ErrTieReceipt      = errors.New("invalid controlled-tie receipt")
	ErrTieReceiptLimit = errors.New("controlled-tie receipt exceeds limit")
)

type TieTrialStatus uint8

type TieTrialRole uint8

const (
	TieRoleUnspecified TieTrialRole = iota
	TieRoleTested
	TieRoleControl
)

const (
	// TieTrialNoPair explicitly closes a precommitted slot without a valid pair.
	// It is evidence of completeness, not a successful statistical trial.
	TieTrialNoPair TieTrialStatus = iota
	TieTrialCompleted
)

// TieTrialReceipt is the observer's signed raw account of one planned slot.
// TestedAnchorID and ControlAnchorID are role-labelled before Adopted is
// derived, preventing a caller from submitting a mutable success counter.
type TieTrialReceipt struct {
	Version               uint16
	PlanID                types.Hash
	Sequence              uint64
	Status                TieTrialStatus
	PreviousID            types.Hash
	ParentID              types.Hash
	Height                uint64
	TestedAnchorID        types.Hash
	ControlAnchorID       types.Hash
	TestedObservedAt      uint64
	ControlObservedAt     uint64
	SelectedAnchorID      types.Hash
	FirstObservedAnchorID types.Hash
	ObserverPublicKey     [ed25519.PublicKeySize]byte
	Signature             [ed25519.SignatureSize]byte
}

func SignTieTrialReceipt(privateKey ed25519.PrivateKey, receipt TieTrialReceipt, plan TiePlan) (TieTrialReceipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return TieTrialReceipt{}, ErrPublicKey
	}
	planID, err := plan.ID()
	if err != nil {
		return TieTrialReceipt{}, err
	}
	receipt.PlanID = planID
	copy(receipt.ObserverPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	receipt.Signature = [ed25519.SignatureSize]byte{}
	if err := receipt.validateShape(plan, planID); err != nil {
		return TieTrialReceipt{}, err
	}
	copy(receipt.Signature[:], ed25519.Sign(privateKey, receipt.signatureMessage()))
	return receipt, nil
}

func (receipt TieTrialReceipt) Validate(plan TiePlan) error {
	planID, err := plan.ID()
	if err != nil {
		return err
	}
	return receipt.validate(plan, planID)
}

func (receipt TieTrialReceipt) validate(plan TiePlan, planID types.Hash) error {
	if err := receipt.validateShape(plan, planID); err != nil {
		return err
	}
	if !ed25519.Verify(
		ed25519.PublicKey(receipt.ObserverPublicKey[:]),
		receipt.signatureMessage(),
		receipt.Signature[:],
	) {
		return ErrSignature
	}
	return nil
}

func (receipt TieTrialReceipt) ID(plan TiePlan) (types.Hash, error) {
	if err := receipt.Validate(plan); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(receipt.idDomain(), receipt.CanonicalBytes()), nil
}

func (receipt TieTrialReceipt) Adopted() (bool, error) {
	if receipt.Status != TieTrialCompleted || receipt.TestedAnchorID.IsZero() ||
		receipt.ControlAnchorID.IsZero() || receipt.TestedAnchorID == receipt.ControlAnchorID ||
		(receipt.SelectedAnchorID != receipt.TestedAnchorID && receipt.SelectedAnchorID != receipt.ControlAnchorID) {
		return false, ErrTieReceipt
	}
	return receipt.SelectedAnchorID == receipt.TestedAnchorID, nil
}

func (receipt TieTrialReceipt) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(352)
	receipt.encodeUnsigned(encoder)
	encoder.Fixed(receipt.Signature[:])
	return encoder.Bytes()
}

func DecodeTieTrialReceipt(input []byte) (TieTrialReceipt, error) {
	if len(input) == 0 || len(input) > MaximumTieReceiptBytes {
		return TieTrialReceipt{}, ErrTieReceiptLimit
	}
	decoder := codec.NewDecoder(input)
	var receipt TieTrialReceipt
	var err error
	if receipt.Version, err = decoder.U16(); err != nil {
		return TieTrialReceipt{}, err
	}
	if receipt.Version != TieReceiptVersion0 && receipt.Version != TieReceiptVersion1 &&
		receipt.Version != TieReceiptVersion2 {
		return TieTrialReceipt{}, ErrVersion
	}
	if err := decodeTieReceiptHash(decoder, &receipt.PlanID); err != nil {
		return TieTrialReceipt{}, err
	}
	if receipt.Sequence, err = decoder.U64(); err != nil {
		return TieTrialReceipt{}, err
	}
	status, err := decoder.U8()
	if err != nil {
		return TieTrialReceipt{}, err
	}
	receipt.Status = TieTrialStatus(status)
	for _, target := range []*types.Hash{
		&receipt.PreviousID, &receipt.ParentID, &receipt.TestedAnchorID,
		&receipt.ControlAnchorID,
	} {
		if err := decodeTieReceiptHash(decoder, target); err != nil {
			return TieTrialReceipt{}, err
		}
	}
	if receipt.Height, err = decoder.U64(); err != nil {
		return TieTrialReceipt{}, err
	}
	if receipt.TestedObservedAt, err = decoder.U64(); err != nil {
		return TieTrialReceipt{}, err
	}
	if receipt.ControlObservedAt, err = decoder.U64(); err != nil {
		return TieTrialReceipt{}, err
	}
	if err := decodeTieReceiptHash(decoder, &receipt.SelectedAnchorID); err != nil {
		return TieTrialReceipt{}, err
	}
	if receipt.Version == TieReceiptVersion1 || receipt.Version == TieReceiptVersion2 {
		if err := decodeTieReceiptHash(decoder, &receipt.FirstObservedAnchorID); err != nil {
			return TieTrialReceipt{}, err
		}
	}
	if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
		return TieTrialReceipt{}, decodeErr
	} else {
		copy(receipt.ObserverPublicKey[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.SignatureSize); decodeErr != nil {
		return TieTrialReceipt{}, decodeErr
	} else {
		copy(receipt.Signature[:], value)
	}
	if err := decoder.Finish(); err != nil {
		return TieTrialReceipt{}, err
	}
	return receipt, nil
}

func decodeTieReceiptHash(decoder *codec.Decoder, target *types.Hash) error {
	value, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return err
	}
	copy(target[:], value)
	return nil
}

func (receipt TieTrialReceipt) signatureMessage() []byte {
	encoder := codec.NewEncoder(288)
	receipt.encodeUnsigned(encoder)
	hash := types.DomainHash(receipt.signatureDomain(), encoder.Bytes())
	return hash[:]
}

func (receipt TieTrialReceipt) encodeUnsigned(encoder *codec.Encoder) {
	encoder.U16(receipt.Version)
	encoder.Fixed(receipt.PlanID[:])
	encoder.U64(receipt.Sequence)
	encoder.U8(uint8(receipt.Status))
	encoder.Fixed(receipt.PreviousID[:])
	encoder.Fixed(receipt.ParentID[:])
	encoder.Fixed(receipt.TestedAnchorID[:])
	encoder.Fixed(receipt.ControlAnchorID[:])
	encoder.U64(receipt.Height)
	encoder.U64(receipt.TestedObservedAt)
	encoder.U64(receipt.ControlObservedAt)
	encoder.Fixed(receipt.SelectedAnchorID[:])
	if receipt.Version == TieReceiptVersion1 || receipt.Version == TieReceiptVersion2 {
		encoder.Fixed(receipt.FirstObservedAnchorID[:])
	}
	encoder.Fixed(receipt.ObserverPublicKey[:])
}

func (receipt TieTrialReceipt) validateShape(plan TiePlan, planID types.Hash) error {
	if receipt.Version != TieReceiptVersion0 && receipt.Version != TieReceiptVersion1 &&
		receipt.Version != TieReceiptVersion2 {
		return ErrVersion
	}
	if (plan.Version == TiePlanVersion0 && receipt.Version != TieReceiptVersion0) ||
		(plan.Version == TiePlanVersion1 && receipt.Version != TieReceiptVersion1) ||
		(plan.Version == TiePlanVersion2 && receipt.Version != TieReceiptVersion2) {
		return ErrVersion
	}
	if receipt.PlanID != planID || !plan.AllowsObserver(receipt.ObserverPublicKey) {
		return ErrBinding
	}
	if receipt.Sequence == 0 || receipt.Sequence > uint64(len(plan.Slots)) ||
		(receipt.Sequence == 1) != receipt.PreviousID.IsZero() {
		return ErrSequence
	}
	if receipt.Status == TieTrialNoPair {
		if !receipt.ParentID.IsZero() || receipt.Height != 0 ||
			!receipt.TestedAnchorID.IsZero() || !receipt.ControlAnchorID.IsZero() ||
			receipt.TestedObservedAt != 0 || receipt.ControlObservedAt != 0 ||
			!receipt.SelectedAnchorID.IsZero() || !receipt.FirstObservedAnchorID.IsZero() {
			return ErrTieReceipt
		}
		return nil
	}
	if receipt.Status != TieTrialCompleted || receipt.ParentID.IsZero() ||
		receipt.Height < plan.ActivationHeight || receipt.TestedAnchorID.IsZero() ||
		receipt.ControlAnchorID.IsZero() || receipt.TestedAnchorID == receipt.ControlAnchorID ||
		receipt.ParentID == receipt.TestedAnchorID || receipt.ParentID == receipt.ControlAnchorID ||
		(receipt.SelectedAnchorID != receipt.TestedAnchorID && receipt.SelectedAnchorID != receipt.ControlAnchorID) {
		return ErrTieReceipt
	}
	slot := plan.Slots[receipt.Sequence-1]
	if receipt.TestedObservedAt < slot.StartedAt || receipt.TestedObservedAt >= slot.EndedAt ||
		receipt.ControlObservedAt < slot.StartedAt || receipt.ControlObservedAt >= slot.EndedAt ||
		absoluteDifference(receipt.TestedObservedAt, receipt.ControlObservedAt) > plan.MaximumPairDelaySeconds {
		return ErrTieReceipt
	}
	if receipt.Version == TieReceiptVersion0 {
		if !receipt.FirstObservedAnchorID.IsZero() {
			return ErrTieReceipt
		}
	} else {
		expectedFirst := receipt.TestedAnchorID
		if slot.FirstRole == TieRoleControl {
			expectedFirst = receipt.ControlAnchorID
		}
		if receipt.FirstObservedAnchorID != expectedFirst {
			return ErrTieReceipt
		}
	}
	return nil
}

func (receipt TieTrialReceipt) signatureDomain() string {
	if receipt.Version == TieReceiptVersion1 {
		return "OMESH/testnet/calibration/tie-receipt/signature/v1"
	}
	if receipt.Version == TieReceiptVersion2 {
		return "OMESH/testnet/calibration/tie-receipt/signature/v2"
	}
	return tieReceiptSignatureDomain
}

func (receipt TieTrialReceipt) idDomain() string {
	if receipt.Version == TieReceiptVersion1 {
		return "OMESH/testnet/calibration/tie-receipt/id/v1"
	}
	if receipt.Version == TieReceiptVersion2 {
		return "OMESH/testnet/calibration/tie-receipt/id/v2"
	}
	return tieReceiptIDDomain
}

func absoluteDifference(left, right uint64) uint64 {
	if left >= right {
		return left - right
	}
	return right - left
}
