package calibration

import (
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
)

var ErrEvidence = errors.New("invalid calibration evidence bundle")

// EvidenceBinding contains only independently obtained trust anchors and
// externally published rollback/precommit checkpoints. None of these values is
// learned from the evidence files being verified.
type EvidenceBinding struct {
	Telemetry             Binding
	TiePlan               TiePlanBinding
	TelemetryTailID       types.Hash
	PublishedTiePlanID    types.Hash
	PublishedTieReceiptID types.Hash
}

// EvidenceAggregate is the only evidence-mode input intended for ER-5. The
// telemetry manifest supplies work observations; the complete raw tie chain
// supplies conservative tie counters. Legacy/manual tie counters in hourly
// records are rejected instead of being combined or silently ignored.
type EvidenceAggregate struct {
	Telemetry              Aggregate
	Tie                    TieReceiptAggregate
	ControlledTieAdoptions uint64
	ControlledTieTrials    uint64
}

func ValidateEvidenceBundle(
	records []Record,
	plan TiePlan,
	receipts []TieTrialReceipt,
	expected EvidenceBinding,
) (EvidenceAggregate, error) {
	telemetry, err := ValidateManifest(records, expected.Telemetry)
	if err != nil {
		return EvidenceAggregate{}, err
	}
	tie, err := ValidateTieReceiptManifest(plan, receipts, expected.TiePlan)
	if err != nil {
		return EvidenceAggregate{}, err
	}
	return validateEvidenceAggregates(telemetry, plan, tie, expected)
}

func LoadEvidenceFiles(telemetryPath, tieReceiptPath string, expected EvidenceBinding) (EvidenceAggregate, error) {
	if telemetryPath == "" || tieReceiptPath == "" || telemetryPath == tieReceiptPath {
		return EvidenceAggregate{}, ErrEvidence
	}
	_, telemetry, err := LoadFile(telemetryPath, expected.Telemetry)
	if err != nil {
		return EvidenceAggregate{}, err
	}
	plan, _, tie, err := LoadTieReceiptFile(tieReceiptPath, expected.TiePlan)
	if err != nil {
		return EvidenceAggregate{}, err
	}
	return validateEvidenceAggregates(telemetry, plan, tie, expected)
}

func validateEvidenceAggregates(
	telemetry Aggregate,
	plan TiePlan,
	tie TieReceiptAggregate,
	expected EvidenceBinding,
) (EvidenceAggregate, error) {
	if !validEvidenceBinding(expected) || telemetry.Binding != expected.Telemetry {
		return EvidenceAggregate{}, ErrEvidence
	}
	if err := plan.Verify(expected.TiePlan); err != nil {
		return EvidenceAggregate{}, ErrEvidence
	}
	if telemetry.ControlledTieAdoptions != 0 || telemetry.ControlledTieTrials != 0 {
		return EvidenceAggregate{}, ErrEvidence
	}
	if plan.Version != TiePlanVersion1 && plan.Version != TiePlanVersion2 {
		return EvidenceAggregate{}, ErrEvidence
	}
	if telemetry.LastRecordID != expected.TelemetryTailID ||
		tie.PlanID != expected.PublishedTiePlanID ||
		tie.LastReceiptID != expected.PublishedTieReceiptID {
		return EvidenceAggregate{}, ErrEvidence
	}
	if !tie.Complete || len(plan.Slots) == 0 || plan.Slots[0].StartedAt < telemetry.StartedAt ||
		plan.Slots[len(plan.Slots)-1].EndedAt > telemetry.EndedAt {
		return EvidenceAggregate{}, ErrEvidence
	}
	adoptions, trials, err := tie.EvidenceCounters()
	if err != nil {
		return EvidenceAggregate{}, err
	}
	return EvidenceAggregate{
		Telemetry: telemetry, Tie: tie,
		ControlledTieAdoptions: adoptions, ControlledTieTrials: trials,
	}, nil
}

func validEvidenceBinding(binding EvidenceBinding) bool {
	return validBinding(binding.Telemetry) && validTiePlanBinding(binding.TiePlan) &&
		binding.Telemetry.NetworkID == binding.TiePlan.NetworkID &&
		binding.Telemetry.GenesisID == binding.TiePlan.GenesisID &&
		binding.Telemetry.ActivationHeight == binding.TiePlan.ActivationHeight &&
		binding.Telemetry.ObserverPublicKey == binding.TiePlan.ObserverPublicKey &&
		!binding.TelemetryTailID.IsZero() && !binding.PublishedTiePlanID.IsZero() &&
		!binding.PublishedTieReceiptID.IsZero()
}
