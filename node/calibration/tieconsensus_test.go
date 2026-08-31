package calibration

import (
	"crypto/ed25519"
	"errors"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestMultiObserverTieConsensusCountsCampaignSlotsOnce(t *testing.T) {
	plan, keys, views := tieConsensusFixture(t)
	planID, _ := plan.ID()
	aggregate, err := ValidateTieObserverViews(plan, planID, views)
	if err != nil {
		t.Fatal(err)
	}
	adoptions, trials, err := aggregate.EvidenceCounters()
	checkpoint, checkpointErr := aggregate.CheckpointID()
	if err != nil || aggregate.ObserverCount != uint64(len(keys)) || aggregate.ValidatedReceipts != 9 ||
		aggregate.CompletedTrials != 2 || aggregate.NoPairSlots != 1 || aggregate.DisagreementSlots != 0 ||
		aggregate.TestedAdoptions != 1 || adoptions != 2 || trials != 3 || checkpointErr != nil ||
		checkpoint.String() != "204d727d275051b20564e6c8d4afdcff35fecd83519aec27c744919d90969e38" {
		t.Fatalf("aggregate=%+v adoptions=%d trials=%d checkpoint=%s err=%v checkpoint_err=%v",
			aggregate, adoptions, trials, checkpoint, err, checkpointErr)
	}
}

func TestMultiObserverTieConsensusDowngradesConflictsWithoutMajorityVote(t *testing.T) {
	plan, keys, views := tieConsensusFixture(t)
	planID, _ := plan.ID()
	views[1].Receipts = resignTieConsensusReceipts(t, plan, keys[1], views[1].Receipts, func(receipts []TieTrialReceipt) {
		receipts[0].SelectedAnchorID = receipts[0].ControlAnchorID
	})
	views[1].PublishedReceiptID, _ = views[1].Receipts[len(views[1].Receipts)-1].ID(plan)
	aggregate, err := ValidateTieObserverViews(plan, planID, views)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.CompletedTrials != 1 || aggregate.NoPairSlots != 2 || aggregate.DisagreementSlots != 1 ||
		aggregate.TestedAdoptions != 0 || aggregate.ConservativeAdoptions != 2 {
		t.Fatalf("selection-conflict aggregate=%+v", aggregate)
	}

	plan, keys, views = tieConsensusFixture(t)
	views[1].Receipts = resignTieConsensusReceipts(t, plan, keys[1], views[1].Receipts, func(receipts []TieTrialReceipt) {
		receipts[1] = TieTrialReceipt{Version: TieReceiptVersion2, Sequence: 2, Status: TieTrialNoPair}
	})
	views[1].PublishedReceiptID, _ = views[1].Receipts[len(views[1].Receipts)-1].ID(plan)
	aggregate, err = ValidateTieObserverViews(plan, planID, views)
	if err != nil || aggregate.DisagreementSlots != 1 || aggregate.NoPairSlots != 2 {
		t.Fatalf("availability-conflict aggregate=%+v err=%v", aggregate, err)
	}
}

func TestMultiObserverTieConsensusRequiresEveryCanonicalViewAndCheckpoint(t *testing.T) {
	plan, _, views := tieConsensusFixture(t)
	planID, _ := plan.ID()
	if _, err := ValidateTieObserverViews(plan, planID, views[:1]); !errors.Is(err, ErrTieConsensus) {
		t.Fatalf("missing observer error=%v", err)
	}
	swapped := append([]TieObserverView(nil), views...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if _, err := ValidateTieObserverViews(plan, planID, swapped); !errors.Is(err, ErrTieConsensus) {
		t.Fatalf("noncanonical observer order error=%v", err)
	}
	wrongTail := append([]TieObserverView(nil), views...)
	wrongTail[0].PublishedReceiptID[0] ^= 1
	if _, err := ValidateTieObserverViews(plan, planID, wrongTail); !errors.Is(err, ErrTieConsensus) {
		t.Fatalf("unpublished tail error=%v", err)
	}
}

func TestMultiObserverTieConsensusRejectsOverflowedAggregateCounts(t *testing.T) {
	plan, _, views := tieConsensusFixture(t)
	planID, _ := plan.ID()
	aggregate, err := ValidateTieObserverViews(plan, planID, views)
	if err != nil {
		t.Fatal(err)
	}
	aggregate.ObserverCount = 2
	aggregate.PlannedSlots = 1 << 63
	aggregate.ValidatedReceipts = 0
	aggregate.CompletedTrials = 1 << 63
	aggregate.NoPairSlots = 0
	aggregate.TestedAdoptions = 0
	aggregate.ConservativeAdoptions = 0
	aggregate.ObserverCheckpoints = aggregate.ObserverCheckpoints[:2]
	if _, _, err := aggregate.EvidenceCounters(); !errors.Is(err, ErrTieConsensus) {
		t.Fatalf("overflowed observer receipt count error=%v", err)
	}
}

func tieConsensusFixture(t testing.TB) (TiePlan, []ed25519.PrivateKey, []TieObserverView) {
	t.Helper()
	type keyedObserver struct {
		public [ed25519.PublicKeySize]byte
		key    ed25519.PrivateKey
	}
	observers := make([]keyedObserver, 3)
	for index, label := range []string{"a", "b", "c"} {
		seed := types.DomainHash("test/calibration/tie-consensus/observer", []byte(label))
		observers[index].key = ed25519.NewKeyFromSeed(seed[:])
		copy(observers[index].public[:], observers[index].key.Public().(ed25519.PublicKey))
	}
	sort.Slice(observers, func(left, right int) bool {
		return string(observers[left].public[:]) < string(observers[right].public[:])
	})
	plan := TiePlan{
		Version: TiePlanVersion2, NetworkID: 909, GenesisID: types.DomainHash("test/calibration/tie-consensus/genesis"),
		ActivationHeight:        2,
		TestedMiner:             types.Address(types.DomainHash("test/calibration/tie-consensus/tested")),
		ControlMiner:            types.Address(types.DomainHash("test/calibration/tie-consensus/control")),
		MaximumPairDelaySeconds: 5,
		ObserverPublicKeys:      make([][ed25519.PublicKeySize]byte, len(observers)),
		Slots: []TiePlanSlot{
			{StartedAt: 100, EndedAt: 110, FirstRole: TieRoleTested},
			{StartedAt: 120, EndedAt: 130, FirstRole: TieRoleControl},
			{StartedAt: 140, EndedAt: 150, FirstRole: TieRoleTested},
		},
	}
	for index := range observers {
		plan.ObserverPublicKeys[index] = observers[index].public
	}
	coordinatorSeed := types.DomainHash("test/calibration/tie-consensus/coordinator")
	var err error
	plan, err = SignTiePlan(ed25519.NewKeyFromSeed(coordinatorSeed[:]), plan)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]ed25519.PrivateKey, len(observers))
	for index := range observers {
		keys[index] = observers[index].key
	}
	views := make([]TieObserverView, len(keys))
	for index, key := range keys {
		receipts := []TieTrialReceipt{
			{
				Version: TieReceiptVersion2, Sequence: 1, Status: TieTrialCompleted,
				ParentID: types.DomainHash("test/calibration/tie-consensus/parent-1"), Height: 2,
				TestedAnchorID:   types.DomainHash("test/calibration/tie-consensus/tested-1"),
				ControlAnchorID:  types.DomainHash("test/calibration/tie-consensus/control-1"),
				TestedObservedAt: 102 + uint64(index), ControlObservedAt: 103 + uint64(index),
				SelectedAnchorID:      types.DomainHash("test/calibration/tie-consensus/tested-1"),
				FirstObservedAnchorID: types.DomainHash("test/calibration/tie-consensus/tested-1"),
			},
			{
				Version: TieReceiptVersion2, Sequence: 2, Status: TieTrialCompleted,
				ParentID: types.DomainHash("test/calibration/tie-consensus/parent-2"), Height: 3,
				TestedAnchorID:   types.DomainHash("test/calibration/tie-consensus/tested-2"),
				ControlAnchorID:  types.DomainHash("test/calibration/tie-consensus/control-2"),
				TestedObservedAt: 123 + uint64(index), ControlObservedAt: 122 + uint64(index),
				SelectedAnchorID:      types.DomainHash("test/calibration/tie-consensus/control-2"),
				FirstObservedAnchorID: types.DomainHash("test/calibration/tie-consensus/control-2"),
			},
			{Version: TieReceiptVersion2, Sequence: 3, Status: TieTrialNoPair},
		}
		receipts = resignTieConsensusReceipts(t, plan, key, receipts, nil)
		binding := plan.Binding()
		binding.ObserverPublicKey = observers[index].public
		tail, _ := receipts[len(receipts)-1].ID(plan)
		views[index] = TieObserverView{Binding: binding, Receipts: receipts, PublishedReceiptID: tail}
	}
	return plan, keys, views
}

func resignTieConsensusReceipts(
	t testing.TB,
	plan TiePlan,
	key ed25519.PrivateKey,
	receipts []TieTrialReceipt,
	mutate func([]TieTrialReceipt),
) []TieTrialReceipt {
	t.Helper()
	result := append([]TieTrialReceipt(nil), receipts...)
	if mutate != nil {
		mutate(result)
	}
	var previous types.Hash
	for index := range result {
		result[index].PreviousID = previous
		result[index].PlanID = types.Hash{}
		result[index].ObserverPublicKey = [ed25519.PublicKeySize]byte{}
		result[index].Signature = [ed25519.SignatureSize]byte{}
		signed, err := SignTieTrialReceipt(key, result[index], plan)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = signed
		previous, err = signed.ID(plan)
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}
