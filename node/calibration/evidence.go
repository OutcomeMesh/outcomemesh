package calibration

import (
	"bytes"
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

// MultiEvidenceBinding precommits every receipt-chain tail for one shared
// version-2 plan. ObserverCheckpoints must exactly match the plan's canonical
// observer set; omitting an inconvenient view is invalid evidence.
type MultiEvidenceBinding struct {
	Telemetry           Binding
	TiePlan             TiePlanBinding
	TelemetryTailID     types.Hash
	PublishedTiePlanID  types.Hash
	ObserverCheckpoints []TieObserverCheckpoint
}

type MultiEvidenceAggregate struct {
	Telemetry              Aggregate
	Tie                    TieConsensusAggregate
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

func ValidateMultiObserverEvidenceBundle(
	records []Record,
	plan TiePlan,
	receiptViews [][]TieTrialReceipt,
	expected MultiEvidenceBinding,
) (MultiEvidenceAggregate, error) {
	telemetry, err := ValidateManifest(records, expected.Telemetry)
	if err != nil {
		return MultiEvidenceAggregate{}, err
	}
	if len(receiptViews) != len(expected.ObserverCheckpoints) {
		return MultiEvidenceAggregate{}, ErrEvidence
	}
	views := make([]TieObserverView, len(receiptViews))
	for index, receipts := range receiptViews {
		binding := expected.TiePlan
		binding.ObserverPublicKey = expected.ObserverCheckpoints[index].ObserverPublicKey
		views[index] = TieObserverView{
			Binding: binding, Receipts: receipts,
			PublishedReceiptID: expected.ObserverCheckpoints[index].PublishedReceiptID,
		}
	}
	return validateMultiEvidenceAggregates(telemetry, plan, views, expected)
}

func LoadMultiObserverEvidenceFiles(
	telemetryPath string,
	tieReceiptPaths []string,
	expected MultiEvidenceBinding,
) (MultiEvidenceAggregate, error) {
	if telemetryPath == "" || len(tieReceiptPaths) != len(expected.ObserverCheckpoints) {
		return MultiEvidenceAggregate{}, ErrEvidence
	}
	seen := map[string]struct{}{telemetryPath: {}}
	_, telemetry, err := LoadFile(telemetryPath, expected.Telemetry)
	if err != nil {
		return MultiEvidenceAggregate{}, err
	}
	var plan TiePlan
	views := make([]TieObserverView, len(tieReceiptPaths))
	for index, path := range tieReceiptPaths {
		if path == "" {
			return MultiEvidenceAggregate{}, ErrEvidence
		}
		if _, duplicate := seen[path]; duplicate {
			return MultiEvidenceAggregate{}, ErrEvidence
		}
		seen[path] = struct{}{}
		binding := expected.TiePlan
		binding.ObserverPublicKey = expected.ObserverCheckpoints[index].ObserverPublicKey
		loadedPlan, receipts, _, err := LoadTieReceiptFile(path, binding)
		if err != nil {
			return MultiEvidenceAggregate{}, err
		}
		if index == 0 {
			plan = loadedPlan
		} else if !bytes.Equal(plan.CanonicalBytes(), loadedPlan.CanonicalBytes()) {
			return MultiEvidenceAggregate{}, ErrEvidence
		}
		views[index] = TieObserverView{
			Binding: binding, Receipts: receipts,
			PublishedReceiptID: expected.ObserverCheckpoints[index].PublishedReceiptID,
		}
	}
	return validateMultiEvidenceAggregates(telemetry, plan, views, expected)
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
	if plan.Version != TiePlanVersion1 {
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

func validateMultiEvidenceAggregates(
	telemetry Aggregate,
	plan TiePlan,
	views []TieObserverView,
	expected MultiEvidenceBinding,
) (MultiEvidenceAggregate, error) {
	if !validMultiEvidenceBinding(expected) || telemetry.Binding != expected.Telemetry ||
		telemetry.ControlledTieAdoptions != 0 || telemetry.ControlledTieTrials != 0 ||
		telemetry.LastRecordID != expected.TelemetryTailID {
		return MultiEvidenceAggregate{}, ErrEvidence
	}
	if err := plan.Verify(expected.TiePlan); err != nil {
		return MultiEvidenceAggregate{}, err
	}
	tie, err := ValidateTieObserverViews(plan, expected.PublishedTiePlanID, views)
	if err != nil {
		return MultiEvidenceAggregate{}, err
	}
	if len(tie.ObserverCheckpoints) != len(expected.ObserverCheckpoints) {
		return MultiEvidenceAggregate{}, ErrEvidence
	}
	for index := range tie.ObserverCheckpoints {
		if tie.ObserverCheckpoints[index] != expected.ObserverCheckpoints[index] {
			return MultiEvidenceAggregate{}, ErrEvidence
		}
	}
	if len(plan.Slots) == 0 || plan.Slots[0].StartedAt < telemetry.StartedAt ||
		plan.Slots[len(plan.Slots)-1].EndedAt > telemetry.EndedAt {
		return MultiEvidenceAggregate{}, ErrEvidence
	}
	adoptions, trials, err := tie.EvidenceCounters()
	if err != nil {
		return MultiEvidenceAggregate{}, err
	}
	return MultiEvidenceAggregate{
		Telemetry: telemetry, Tie: tie,
		ControlledTieAdoptions: adoptions, ControlledTieTrials: trials,
	}, nil
}

func validMultiEvidenceBinding(binding MultiEvidenceBinding) bool {
	if !validBinding(binding.Telemetry) || !validTiePlanBinding(binding.TiePlan) ||
		binding.Telemetry.NetworkID != binding.TiePlan.NetworkID ||
		binding.Telemetry.GenesisID != binding.TiePlan.GenesisID ||
		binding.Telemetry.ActivationHeight != binding.TiePlan.ActivationHeight ||
		binding.Telemetry.ObserverPublicKey != binding.TiePlan.ObserverPublicKey ||
		binding.TelemetryTailID.IsZero() || binding.PublishedTiePlanID.IsZero() ||
		len(binding.ObserverCheckpoints) < 2 || len(binding.ObserverCheckpoints) > MaximumTieObservers {
		return false
	}
	for index, checkpoint := range binding.ObserverCheckpoints {
		if types.Hash(checkpoint.ObserverPublicKey).IsZero() || checkpoint.PublishedReceiptID.IsZero() ||
			(index > 0 && bytes.Compare(
				binding.ObserverCheckpoints[index-1].ObserverPublicKey[:], checkpoint.ObserverPublicKey[:],
			) >= 0) {
			return false
		}
	}
	return true
}
