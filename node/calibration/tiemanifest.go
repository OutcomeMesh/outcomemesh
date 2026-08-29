package calibration

import (
	"io"
	"os"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	tieManifestVersion      uint16 = 0
	MaximumTieManifestBytes        = 8 * 1024 * 1024
)

var tieManifestMagic = [8]byte{'O', 'M', 'T', 'I', 'E', 'R', 'A', 'W'}

type TieReceiptAggregate struct {
	PlanID                types.Hash
	FirstReceiptID        types.Hash
	LastReceiptID         types.Hash
	PlannedSlots          uint64
	ReceiptCount          uint64
	CompletedTrials       uint64
	NoPairSlots           uint64
	TestedAdoptions       uint64
	ConservativeAdoptions uint64
	Complete              bool
}

// EvidenceCounters returns the fail-closed inputs intended for ER-5. A missing
// or explicitly unsuccessful pair is charged as a tested-branch adoption, so
// selective completion cannot improve the result. Live prefixes are rejected.
func (aggregate TieReceiptAggregate) EvidenceCounters() (adoptions, trials uint64, err error) {
	if !aggregate.Complete || aggregate.ReceiptCount != aggregate.PlannedSlots ||
		aggregate.CompletedTrials+aggregate.NoPairSlots != aggregate.ReceiptCount ||
		aggregate.TestedAdoptions > aggregate.CompletedTrials ||
		aggregate.ConservativeAdoptions != aggregate.TestedAdoptions+aggregate.NoPairSlots {
		return 0, 0, ErrManifest
	}
	return aggregate.ConservativeAdoptions, aggregate.PlannedSlots, nil
}

// ValidateTieReceiptManifest accepts an exact prefix while an experiment is
// live. Complete becomes true only when every precommitted slot has one signed
// receipt; only that state is suitable for a final statistical report.
func ValidateTieReceiptManifest(plan TiePlan, receipts []TieTrialReceipt, expected TiePlanBinding) (TieReceiptAggregate, error) {
	if err := plan.Verify(expected); err != nil {
		return TieReceiptAggregate{}, err
	}
	if len(receipts) == 0 {
		return TieReceiptAggregate{}, ErrManifest
	}
	if len(receipts) > len(plan.Slots) || len(receipts) > MaximumTiePlanSlots {
		return TieReceiptAggregate{}, ErrManifestLimit
	}
	// Verify above authenticates these exact canonical bytes. Hash once so a
	// 10,000-slot manifest remains O(N), not O(N^2) in plan slots.
	planID := types.DomainHash(tiePlanIDDomain, plan.CanonicalBytes())
	result := TieReceiptAggregate{
		PlanID: planID, PlannedSlots: uint64(len(plan.Slots)),
		ReceiptCount: uint64(len(receipts)), Complete: len(receipts) == len(plan.Slots),
	}
	var previousID types.Hash
	for index, receipt := range receipts {
		if receipt.Sequence != uint64(index)+1 {
			return TieReceiptAggregate{}, ErrSequence
		}
		if index == 0 {
			if !receipt.PreviousID.IsZero() {
				return TieReceiptAggregate{}, ErrPrevious
			}
		} else if receipt.PreviousID != previousID {
			return TieReceiptAggregate{}, ErrPrevious
		}
		if err := receipt.validate(plan, planID); err != nil {
			return TieReceiptAggregate{}, err
		}
		identifier := types.DomainHash(tieReceiptIDDomain, receipt.CanonicalBytes())
		if index == 0 {
			result.FirstReceiptID = identifier
		}
		previousID = identifier
		result.LastReceiptID = identifier
		if receipt.Status == TieTrialCompleted {
			result.CompletedTrials++
			adopted, err := receipt.Adopted()
			if err != nil {
				return TieReceiptAggregate{}, err
			}
			if adopted {
				result.TestedAdoptions++
			}
		} else {
			result.NoPairSlots++
		}
	}
	result.ConservativeAdoptions = result.TestedAdoptions + result.NoPairSlots
	return result, nil
}

func EncodeTieReceiptManifest(plan TiePlan, receipts []TieTrialReceipt, expected TiePlanBinding) ([]byte, TieReceiptAggregate, error) {
	aggregate, err := ValidateTieReceiptManifest(plan, receipts, expected)
	if err != nil {
		return nil, TieReceiptAggregate{}, err
	}
	encoder := codec.NewEncoder(512 + len(receipts)*352)
	encoder.Fixed(tieManifestMagic[:])
	encoder.U16(tieManifestVersion)
	encoder.BytesField(plan.CanonicalBytes())
	encoder.Uvarint(uint64(len(receipts)))
	for _, receipt := range receipts {
		encoder.BytesField(receipt.CanonicalBytes())
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumTieManifestBytes {
		return nil, TieReceiptAggregate{}, ErrManifestLimit
	}
	return encoded, aggregate, nil
}

func DecodeTieReceiptManifest(input []byte, expected TiePlanBinding) (TiePlan, []TieTrialReceipt, TieReceiptAggregate, error) {
	if len(input) == 0 || len(input) > MaximumTieManifestBytes {
		return TiePlan{}, nil, TieReceiptAggregate{}, ErrManifestLimit
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(tieManifestMagic))
	if err != nil || string(magic) != string(tieManifestMagic[:]) {
		return TiePlan{}, nil, TieReceiptAggregate{}, ErrManifest
	}
	version, err := decoder.U16()
	if err != nil || version != tieManifestVersion {
		return TiePlan{}, nil, TieReceiptAggregate{}, ErrManifest
	}
	encodedPlan, err := decoder.BytesField(MaximumTiePlanBytes)
	if err != nil {
		return TiePlan{}, nil, TieReceiptAggregate{}, err
	}
	plan, err := DecodeTiePlan(encodedPlan)
	if err != nil {
		return TiePlan{}, nil, TieReceiptAggregate{}, err
	}
	count, err := decoder.ListLength(MaximumTiePlanSlots)
	if err != nil || count == 0 {
		return TiePlan{}, nil, TieReceiptAggregate{}, ErrManifest
	}
	receipts := make([]TieTrialReceipt, count)
	for index := range receipts {
		encodedReceipt, err := decoder.BytesField(MaximumTieReceiptBytes)
		if err != nil {
			return TiePlan{}, nil, TieReceiptAggregate{}, err
		}
		receipts[index], err = DecodeTieTrialReceipt(encodedReceipt)
		if err != nil {
			return TiePlan{}, nil, TieReceiptAggregate{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return TiePlan{}, nil, TieReceiptAggregate{}, err
	}
	aggregate, err := ValidateTieReceiptManifest(plan, receipts, expected)
	if err != nil {
		return TiePlan{}, nil, TieReceiptAggregate{}, err
	}
	return plan, receipts, aggregate, nil
}

func SaveTieReceiptFile(path string, plan TiePlan, receipts []TieTrialReceipt, expected TiePlanBinding) (TieReceiptAggregate, error) {
	if path == "" {
		return TieReceiptAggregate{}, ErrManifest
	}
	encoded, aggregate, err := EncodeTieReceiptManifest(plan, receipts, expected)
	if err != nil {
		return TieReceiptAggregate{}, err
	}
	if err := savePrivateFile(path, ".outcomemesh-tie-receipts-*", encoded); err != nil {
		return TieReceiptAggregate{}, err
	}
	return aggregate, nil
}

func LoadTieReceiptFile(path string, expected TiePlanBinding) (TiePlan, []TieTrialReceipt, TieReceiptAggregate, error) {
	file, err := os.Open(path)
	if err != nil {
		return TiePlan{}, nil, TieReceiptAggregate{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumTieManifestBytes+1))
	if err != nil {
		return TiePlan{}, nil, TieReceiptAggregate{}, err
	}
	if len(encoded) > MaximumTieManifestBytes {
		return TiePlan{}, nil, TieReceiptAggregate{}, ErrManifestLimit
	}
	return DecodeTieReceiptManifest(encoded, expected)
}
