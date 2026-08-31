package tieproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestCampaignPersistsEveryPublicationAndObserverBoundary(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	statePath := filepath.Join(t.TempDir(), "campaign.state")
	campaign, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := campaign.Status()
	if err != nil || status.Phase != CampaignAwaitingPair || status.NextSequence != 1 ||
		status.ObserverCount != 2 || status.AcknowledgedCount != 0 {
		t.Fatalf("initial status=%+v err=%v", status, err)
	}

	pair, checkpoint := campaignPair(t, plan, binding, keys.coordinator, 1)
	checkpointID, _ := checkpoint.ID(plan, binding, planID)
	if err := campaign.StagePair(pair, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := campaign.StagePair(pair, checkpoint); err != nil {
		t.Fatalf("idempotent stage: %v", err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignAwaitingPublication || status.CheckpointID != checkpointID ||
		status.PairID != checkpoint.PairID || len(status.ObserverReceiptTails) != 2 {
		t.Fatalf("staged status=%+v", status)
	}
	if err := campaign.Close(); err != nil {
		t.Fatal(err)
	}

	campaign, err = OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongCheckpoint := checkpointID
	wrongCheckpoint[0] ^= 1
	if err := campaign.ConfirmPublication(1, wrongCheckpoint); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("wrong publication error=%v", err)
	}
	if err := campaign.ConfirmPublication(1, checkpointID); err != nil {
		t.Fatal(err)
	}
	if err := campaign.ConfirmPublication(1, checkpointID); err != nil {
		t.Fatalf("idempotent publication: %v", err)
	}

	secondTail := types.DomainHash("test/tieproducer/campaign/second-tail")
	if err := campaign.Acknowledge(1, keys.observers[1], secondTail); err != nil {
		t.Fatal(err)
	}
	if err := campaign.Close(); err != nil {
		t.Fatal(err)
	}
	campaign, err = OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignDelivering || status.AcknowledgedCount != 1 ||
		status.ObserverReceiptTails[1] != secondTail {
		t.Fatalf("reopened delivery status=%+v", status)
	}
	if err := campaign.Acknowledge(1, keys.observers[1], secondTail); err != nil {
		t.Fatalf("idempotent acknowledgement: %v", err)
	}
	conflictingTail := secondTail
	conflictingTail[0] ^= 1
	if err := campaign.Acknowledge(1, keys.observers[1], conflictingTail); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("conflicting acknowledgement error=%v", err)
	}
	unknownObserver := [ed25519.PublicKeySize]byte(types.DomainHash("test/tieproducer/campaign/unknown"))
	if err := campaign.Acknowledge(1, unknownObserver, conflictingTail); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("unknown observer error=%v", err)
	}
	firstTail := types.DomainHash("test/tieproducer/campaign/first-tail")
	if err := campaign.Acknowledge(1, keys.observers[0], firstTail); err != nil {
		t.Fatal(err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignAwaitingAdvance || status.AcknowledgedCount != 2 ||
		status.ObserverReceiptTails[0] != firstTail || status.ObserverReceiptTails[1] != secondTail {
		t.Fatalf("acknowledged status=%+v", status)
	}
	if err := campaign.Advance(1); err != nil {
		t.Fatal(err)
	}
	if err := campaign.Advance(1); err != nil {
		t.Fatalf("idempotent intermediate advance: %v", err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignAwaitingPair || status.NextSequence != 2 ||
		!status.PairID.IsZero() || !status.CheckpointID.IsZero() || len(status.ObserverReceiptTails) != 0 {
		t.Fatalf("advanced status=%+v", status)
	}

	pair, checkpoint = campaignPair(t, plan, binding, keys.coordinator, 2)
	checkpointID, _ = checkpoint.ID(plan, binding, planID)
	if err := campaign.StagePair(pair, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := campaign.ConfirmPublication(2, checkpointID); err != nil {
		t.Fatal(err)
	}
	for index, observer := range keys.observers {
		if err := campaign.Acknowledge(
			2, observer, types.DomainHash("test/tieproducer/campaign/final-tail", []byte{byte(index)}),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := campaign.Advance(2); err != nil {
		t.Fatal(err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignComplete || status.NextSequence != 3 {
		t.Fatalf("complete status=%+v", status)
	}
	if err := campaign.Advance(2); err != nil {
		t.Fatalf("idempotent final advance: %v", err)
	}
}

func TestCampaignRejectsConflictingPairAndCorruptState(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	statePath := filepath.Join(t.TempDir(), "campaign.state")
	campaign, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	pair, checkpoint := campaignPair(t, plan, binding, keys.coordinator, 1)
	if err := campaign.StagePair(pair, checkpoint); err != nil {
		t.Fatal(err)
	}
	otherCheckpoint := checkpoint
	otherCheckpoint.PairID = types.DomainHash("test/tieproducer/campaign/conflicting-pair")
	otherCheckpoint, err = calibration.SignTiePairCheckpoint(
		keys.coordinator, plan, binding, planID, 1, otherCheckpoint.PairID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := campaign.StagePair(pair, otherCheckpoint); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("pair/checkpoint mismatch error=%v", err)
	}
	if err := campaign.Advance(1); !errors.Is(err, ErrCampaignPhase) {
		t.Fatalf("advance before acknowledgements error=%v", err)
	}
	if err := campaign.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-1] ^= 1
	if err := os.WriteFile(statePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	}); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("corrupt campaign state error=%v", err)
	}
	if err := os.WriteFile(statePath, make([]byte, MaximumCampaignStateBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, StatePath: statePath,
	}); !errors.Is(err, ErrCampaignState) {
		t.Fatalf("oversize campaign state error=%v", err)
	}
}

func FuzzDecodeCampaignStateNeverPanics(f *testing.F) {
	plan, _, _ := campaignPlan(f)
	planID, _ := plan.ID()
	state := campaignState{
		Version: CampaignStateVersion0, PlanID: planID,
		NextSequence: 1, Phase: CampaignAwaitingPair,
	}
	encoded, err := encodeCampaignState(state, plan, planID)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decodeCampaignState(input, plan, planID)
	})
}

type campaignKeys struct {
	coordinator ed25519.PrivateKey
	observers   [][ed25519.PublicKeySize]byte
}

func campaignPlan(t testing.TB) (calibration.TiePlan, calibration.TiePlanBinding, campaignKeys) {
	t.Helper()
	coordinator := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	observerA := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	observerB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	observers := make([][ed25519.PublicKeySize]byte, 2)
	copy(observers[0][:], observerA.Public().(ed25519.PublicKey))
	copy(observers[1][:], observerB.Public().(ed25519.PublicKey))
	sort.Slice(observers, func(left, right int) bool {
		return bytes.Compare(observers[left][:], observers[right][:]) < 0
	})
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion2, NetworkID: 71,
		GenesisID: types.DomainHash("test/tieproducer/genesis"), ActivationHeight: 1,
		TestedMiner:             types.Address(types.DomainHash("test/tieproducer/tested")),
		ControlMiner:            types.Address(types.DomainHash("test/tieproducer/control")),
		MaximumPairDelaySeconds: 5, ObserverPublicKeys: observers,
		Slots: []calibration.TiePlanSlot{
			{StartedAt: 1_700_000_000, EndedAt: 1_700_000_060, FirstRole: calibration.TieRoleTested},
			{StartedAt: 1_700_000_120, EndedAt: 1_700_000_180, FirstRole: calibration.TieRoleControl},
		},
	}
	plan, err := calibration.SignTiePlan(coordinator, plan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, plan.Binding(), campaignKeys{coordinator: coordinator, observers: observers}
}

func campaignPair(
	t testing.TB,
	plan calibration.TiePlan,
	binding calibration.TiePlanBinding,
	coordinator ed25519.PrivateKey,
	sequence uint64,
) (Pair, calibration.TiePairCheckpoint) {
	t.Helper()
	planID, _ := plan.ID()
	source := producerFixture(t, plan)
	source.now = plan.Slots[sequence-1].StartedAt
	pair, _, err := MinePair(context.Background(), source, Config{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: sequence,
	})
	if err != nil {
		t.Fatal(err)
	}
	pairID, _ := pair.ID(plan, binding, planID)
	checkpoint, err := calibration.SignTiePairCheckpoint(
		coordinator, plan, binding, planID, sequence, pairID,
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair, checkpoint
}
