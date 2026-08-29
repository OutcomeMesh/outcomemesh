package calibration

import (
	"io"
	"os"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	tiePendingVersion      uint16 = 1
	MaximumTiePendingBytes        = 1024
)

var tiePendingMagic = [8]byte{'O', 'M', 'T', 'I', 'E', 'P', 'N', 'D'}

type tieCandidate struct {
	Present    bool
	ID         types.Hash
	ParentID   types.Hash
	Height     uint64
	ObservedAt uint64
	SelectedID types.Hash
}

type tiePendingState struct {
	PlanID           types.Hash
	Sequence         uint64
	PreviousID       types.Hash
	Invalid          bool
	FirstRole        TieTrialRole
	LatestSelectedID types.Hash
	Tested           tieCandidate
	Control          tieCandidate
}

func newTiePending(planID types.Hash, sequence uint64, previousID types.Hash) tiePendingState {
	return tiePendingState{PlanID: planID, Sequence: sequence, PreviousID: previousID}
}

func (pending tiePendingState) canonicalBytes(plan TiePlan, planID types.Hash) ([]byte, error) {
	if err := pending.validate(plan, planID); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(384)
	encoder.Fixed(tiePendingMagic[:])
	encoder.U16(tiePendingVersion)
	encoder.Fixed(pending.PlanID[:])
	encoder.U64(pending.Sequence)
	encoder.Fixed(pending.PreviousID[:])
	encodeTiePendingBool(encoder, pending.Invalid)
	encoder.U8(uint8(pending.FirstRole))
	encoder.Fixed(pending.LatestSelectedID[:])
	encodeTieCandidate(encoder, pending.Tested)
	encodeTieCandidate(encoder, pending.Control)
	encoded := encoder.Bytes()
	if len(encoded) > MaximumTiePendingBytes {
		return nil, ErrPending
	}
	return encoded, nil
}

func decodeTiePending(input []byte, plan TiePlan, planID types.Hash) (tiePendingState, error) {
	if len(input) == 0 || len(input) > MaximumTiePendingBytes {
		return tiePendingState{}, ErrPending
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(tiePendingMagic))
	if err != nil || string(magic) != string(tiePendingMagic[:]) {
		return tiePendingState{}, ErrPending
	}
	version, err := decoder.U16()
	if err != nil || version != tiePendingVersion {
		return tiePendingState{}, ErrPending
	}
	var pending tiePendingState
	if err := decodeTieReceiptHash(decoder, &pending.PlanID); err != nil {
		return tiePendingState{}, err
	}
	if pending.Sequence, err = decoder.U64(); err != nil {
		return tiePendingState{}, err
	}
	if err := decodeTieReceiptHash(decoder, &pending.PreviousID); err != nil {
		return tiePendingState{}, err
	}
	if pending.Invalid, err = decodeTiePendingBool(decoder); err != nil {
		return tiePendingState{}, err
	}
	role, err := decoder.U8()
	if err != nil {
		return tiePendingState{}, err
	}
	pending.FirstRole = TieTrialRole(role)
	if err := decodeTieReceiptHash(decoder, &pending.LatestSelectedID); err != nil {
		return tiePendingState{}, err
	}
	if pending.Tested, err = decodeTieCandidate(decoder); err != nil {
		return tiePendingState{}, err
	}
	if pending.Control, err = decodeTieCandidate(decoder); err != nil {
		return tiePendingState{}, err
	}
	if err := decoder.Finish(); err != nil {
		return tiePendingState{}, err
	}
	if err := pending.validate(plan, planID); err != nil {
		return tiePendingState{}, err
	}
	return pending, nil
}

func encodeTiePendingBool(encoder *codec.Encoder, value bool) {
	if value {
		encoder.U8(1)
	} else {
		encoder.U8(0)
	}
}

func decodeTiePendingBool(decoder *codec.Decoder) (bool, error) {
	value, err := decoder.U8()
	if err != nil || value > 1 {
		return false, ErrPending
	}
	return value == 1, nil
}

func encodeTieCandidate(encoder *codec.Encoder, candidate tieCandidate) {
	encodeTiePendingBool(encoder, candidate.Present)
	encoder.Fixed(candidate.ID[:])
	encoder.Fixed(candidate.ParentID[:])
	encoder.U64(candidate.Height)
	encoder.U64(candidate.ObservedAt)
	encoder.Fixed(candidate.SelectedID[:])
}

func decodeTieCandidate(decoder *codec.Decoder) (tieCandidate, error) {
	var candidate tieCandidate
	var err error
	if candidate.Present, err = decodeTiePendingBool(decoder); err != nil {
		return tieCandidate{}, err
	}
	if err := decodeTieReceiptHash(decoder, &candidate.ID); err != nil {
		return tieCandidate{}, err
	}
	if err := decodeTieReceiptHash(decoder, &candidate.ParentID); err != nil {
		return tieCandidate{}, err
	}
	if candidate.Height, err = decoder.U64(); err != nil {
		return tieCandidate{}, err
	}
	if candidate.ObservedAt, err = decoder.U64(); err != nil {
		return tieCandidate{}, err
	}
	if err := decodeTieReceiptHash(decoder, &candidate.SelectedID); err != nil {
		return tieCandidate{}, err
	}
	return candidate, nil
}

func (pending tiePendingState) validate(plan TiePlan, planID types.Hash) error {
	if pending.PlanID != planID || pending.Sequence == 0 ||
		pending.Sequence > uint64(len(plan.Slots))+1 ||
		(pending.Sequence == 1) != pending.PreviousID.IsZero() {
		return ErrPending
	}
	if pending.Sequence == uint64(len(plan.Slots))+1 {
		if pending.Invalid || pending.FirstRole != TieRoleUnspecified || !pending.LatestSelectedID.IsZero() ||
			pending.Tested != (tieCandidate{}) || pending.Control != (tieCandidate{}) {
			return ErrPending
		}
		return nil
	}
	slot := plan.Slots[pending.Sequence-1]
	if err := validateTieCandidate(pending.Tested, plan, slot); err != nil {
		return err
	}
	if err := validateTieCandidate(pending.Control, plan, slot); err != nil {
		return err
	}
	if !pending.Tested.Present && !pending.Control.Present {
		if pending.FirstRole != TieRoleUnspecified || !pending.LatestSelectedID.IsZero() {
			return ErrPending
		}
	} else if pending.FirstRole != TieRoleTested && pending.FirstRole != TieRoleControl {
		return ErrPending
	}
	return nil
}

func validateTieCandidate(candidate tieCandidate, plan TiePlan, slot TiePlanSlot) error {
	if !candidate.Present {
		if candidate != (tieCandidate{}) {
			return ErrPending
		}
		return nil
	}
	if candidate.ID.IsZero() || candidate.ParentID.IsZero() || candidate.ID == candidate.ParentID ||
		candidate.Height < plan.ActivationHeight || candidate.ObservedAt < slot.StartedAt ||
		candidate.ObservedAt >= slot.EndedAt {
		return ErrPending
	}
	return nil
}

func saveTiePending(path string, pending tiePendingState, plan TiePlan, planID types.Hash) error {
	if path == "" {
		return ErrPending
	}
	encoded, err := pending.canonicalBytes(plan, planID)
	if err != nil {
		return err
	}
	return savePrivateFile(path, ".outcomemesh-tie-pending-*", encoded)
}

func loadTiePending(path string, plan TiePlan, planID types.Hash) (tiePendingState, error) {
	file, err := os.Open(path)
	if err != nil {
		return tiePendingState{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumTiePendingBytes+1))
	if err != nil {
		return tiePendingState{}, err
	}
	if len(encoded) > MaximumTiePendingBytes {
		return tiePendingState{}, ErrPending
	}
	return decodeTiePending(encoded, plan, planID)
}
