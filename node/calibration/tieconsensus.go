package calibration

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var ErrTieConsensus = errors.New("invalid multi-observer controlled-tie consensus")

// TieObserverCheckpoint is independently published for one observer. Entries
// are kept in the same canonical public-key order committed by a version-2
// plan, so a verifier cannot silently select a favorable observer subset.
type TieObserverCheckpoint struct {
	ObserverPublicKey  [ed25519.PublicKeySize]byte
	PublishedReceiptID types.Hash
}

// TieObserverView contains one complete, separately signed receipt chain and
// the trust binding supplied by its verifier.
type TieObserverView struct {
	Binding            TiePlanBinding
	Receipts           []TieTrialReceipt
	PublishedReceiptID types.Hash
}

// TieConsensusAggregate counts campaign slots, never observer signatures, as
// trials. Observer views are correlated witnesses of the same planned race.
type TieConsensusAggregate struct {
	PlanID                types.Hash
	ObserverCount         uint64
	PlannedSlots          uint64
	ValidatedReceipts     uint64
	CompletedTrials       uint64
	NoPairSlots           uint64
	DisagreementSlots     uint64
	TestedAdoptions       uint64
	ConservativeAdoptions uint64
	ObserverCheckpoints   []TieObserverCheckpoint
}

// EvidenceCounters returns the fail-closed Bernoulli inputs. Every unavailable
// or disagreeing slot counts as a tested-branch adoption, but still contributes
// exactly one trial regardless of the observer count.
func (aggregate TieConsensusAggregate) EvidenceCounters() (uint64, uint64, error) {
	if aggregate.PlanID.IsZero() || aggregate.ObserverCount < 2 ||
		aggregate.ObserverCount > MaximumTieObservers || aggregate.PlannedSlots == 0 ||
		aggregate.PlannedSlots > MaximumTiePlanSlots ||
		aggregate.CompletedTrials > aggregate.PlannedSlots ||
		aggregate.NoPairSlots != aggregate.PlannedSlots-aggregate.CompletedTrials ||
		aggregate.DisagreementSlots > aggregate.NoPairSlots ||
		aggregate.TestedAdoptions > aggregate.CompletedTrials ||
		aggregate.ConservativeAdoptions < aggregate.NoPairSlots ||
		aggregate.ConservativeAdoptions-aggregate.NoPairSlots != aggregate.TestedAdoptions ||
		aggregate.ValidatedReceipts%aggregate.ObserverCount != 0 ||
		aggregate.ValidatedReceipts/aggregate.ObserverCount != aggregate.PlannedSlots ||
		uint64(len(aggregate.ObserverCheckpoints)) != aggregate.ObserverCount {
		return 0, 0, ErrTieConsensus
	}
	for index, checkpoint := range aggregate.ObserverCheckpoints {
		if types.Hash(checkpoint.ObserverPublicKey).IsZero() || checkpoint.PublishedReceiptID.IsZero() ||
			(index > 0 && bytes.Compare(
				aggregate.ObserverCheckpoints[index-1].ObserverPublicKey[:], checkpoint.ObserverPublicKey[:],
			) >= 0) {
			return 0, 0, ErrTieConsensus
		}
	}
	return aggregate.ConservativeAdoptions, aggregate.PlannedSlots, nil
}

// CheckpointID commits the complete canonical observer/tail set into the one
// evidence-tail field used by the ER-5 report. It does not replace publication
// of each constituent observer tail.
func (aggregate TieConsensusAggregate) CheckpointID() (types.Hash, error) {
	if _, _, err := aggregate.EvidenceCounters(); err != nil {
		return types.Hash{}, err
	}
	encoder := codec.NewEncoder(64 + len(aggregate.ObserverCheckpoints)*64)
	encoder.U16(0)
	encoder.Fixed(aggregate.PlanID[:])
	encoder.Uvarint(uint64(len(aggregate.ObserverCheckpoints)))
	for _, checkpoint := range aggregate.ObserverCheckpoints {
		encoder.Fixed(checkpoint.ObserverPublicKey[:])
		encoder.Fixed(checkpoint.PublishedReceiptID[:])
	}
	return types.DomainHash("OMESH/testnet/calibration/tie-consensus/checkpoint/v0", encoder.Bytes()), nil
}

// ValidateTieObserverViews verifies every observer committed by a version-2
// plan exactly once. Valid per-observer chains are mandatory. A disagreement
// about one slot is not pooled or majority-voted: that campaign slot is
// conservatively classified as NoPair.
func ValidateTieObserverViews(
	plan TiePlan,
	expectedPlanID types.Hash,
	views []TieObserverView,
) (TieConsensusAggregate, error) {
	if expectedPlanID.IsZero() || plan.Version != TiePlanVersion2 ||
		len(views) != len(plan.ObserverPublicKeys) || len(views) < 2 {
		return TieConsensusAggregate{}, ErrTieConsensus
	}
	if err := plan.Validate(); err != nil {
		return TieConsensusAggregate{}, err
	}
	planID, err := plan.ID()
	if err != nil {
		return TieConsensusAggregate{}, err
	}
	if planID != expectedPlanID {
		return TieConsensusAggregate{}, ErrTieConsensus
	}

	result := TieConsensusAggregate{
		PlanID: planID, ObserverCount: uint64(len(views)), PlannedSlots: uint64(len(plan.Slots)),
		ObserverCheckpoints: make([]TieObserverCheckpoint, len(views)),
	}
	for index, view := range views {
		expectedObserver := plan.ObserverPublicKeys[index]
		if view.Binding.ObserverPublicKey != expectedObserver || view.PublishedReceiptID.IsZero() {
			return TieConsensusAggregate{}, ErrTieConsensus
		}
		tie, err := ValidateTieReceiptManifest(plan, view.Receipts, view.Binding)
		if err != nil {
			return TieConsensusAggregate{}, err
		}
		if !tie.Complete || tie.PlanID != planID || tie.LastReceiptID != view.PublishedReceiptID ||
			len(view.Receipts) != len(plan.Slots) {
			return TieConsensusAggregate{}, ErrTieConsensus
		}
		result.ValidatedReceipts += uint64(len(view.Receipts))
		result.ObserverCheckpoints[index] = TieObserverCheckpoint{
			ObserverPublicKey: expectedObserver, PublishedReceiptID: view.PublishedReceiptID,
		}
	}

	for slotIndex := range plan.Slots {
		first := views[0].Receipts[slotIndex]
		allNoPair := first.Status == TieTrialNoPair
		agreeCompleted := first.Status == TieTrialCompleted
		for viewIndex := 1; viewIndex < len(views); viewIndex++ {
			candidate := views[viewIndex].Receipts[slotIndex]
			allNoPair = allNoPair && candidate.Status == TieTrialNoPair
			agreeCompleted = agreeCompleted && candidate.Status == TieTrialCompleted &&
				sameCompletedTieObservation(first, candidate)
		}
		switch {
		case agreeCompleted:
			result.CompletedTrials++
			if first.SelectedAnchorID == first.TestedAnchorID {
				result.TestedAdoptions++
			}
		case allNoPair:
			result.NoPairSlots++
		default:
			result.NoPairSlots++
			result.DisagreementSlots++
		}
	}
	result.ConservativeAdoptions = result.TestedAdoptions + result.NoPairSlots
	if _, _, err := result.EvidenceCounters(); err != nil {
		return TieConsensusAggregate{}, err
	}
	return result, nil
}

func sameCompletedTieObservation(left, right TieTrialReceipt) bool {
	return left.ParentID == right.ParentID && left.Height == right.Height &&
		left.TestedAnchorID == right.TestedAnchorID && left.ControlAnchorID == right.ControlAnchorID &&
		left.SelectedAnchorID == right.SelectedAnchorID &&
		left.FirstObservedAnchorID == right.FirstObservedAnchorID
}
