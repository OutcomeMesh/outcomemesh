package tieproducer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/difficulty"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestDriveCampaignResumesPublicationAndDeliveryAcrossTwoSlots(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	campaign, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		StatePath: t.TempDir() + "/campaign.state",
	})
	if err != nil {
		t.Fatal(err)
	}
	source := newCampaignDriverSource(t, plan)
	artifacts := &memoryCampaignArtifacts{pairs: make(map[uint64]Pair), checkpoints: make(map[uint64]calibration.TiePairCheckpoint)}
	publicationFailure := errors.New("publication channel unavailable")
	publication := &campaignPublicationFixture{failSequence: 1, failErr: publicationFailure}
	deliveryFailure := errors.New("observer unavailable")
	deliverer := &campaignDeliveryFixture{failSequence: 1, failObserver: keys.observers[1], failErr: deliveryFailure}
	clock := campaignDriverClock{source: source}
	config := CampaignDriverConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		CoordinatorPrivateKey: keys.coordinator, Campaign: campaign, Source: source,
		Artifacts: artifacts, Publication: publication, Deliverer: deliverer, Clock: clock,
	}

	if err := DriveCampaign(context.Background(), config); !errors.Is(err, publicationFailure) {
		t.Fatalf("publication failure error=%v", err)
	}
	status, _ := campaign.Status()
	if status.Phase != CampaignAwaitingPublication || status.NextSequence != 1 ||
		len(artifacts.pairs) != 1 || len(source.submissions) != 0 {
		t.Fatalf("post-publication-failure status=%+v artifacts=%d submissions=%+v",
			status, len(artifacts.pairs), source.submissions)
	}
	publication.failErr = nil
	if err := DriveCampaign(context.Background(), config); !errors.Is(err, deliveryFailure) {
		t.Fatalf("delivery failure error=%v", err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignDelivering || status.AcknowledgedCount != 1 ||
		status.ObserverReceiptTails[0].IsZero() || !status.ObserverReceiptTails[1].IsZero() ||
		len(source.submissions) != 0 {
		t.Fatalf("post-delivery-failure status=%+v submissions=%+v", status, source.submissions)
	}

	deliverer.failErr = nil
	if err := DriveCampaign(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignComplete || status.NextSequence != 3 || len(artifacts.pairs) != 2 ||
		source.tip.Height != 2 || len(source.submissions) != 4 {
		t.Fatalf("complete status=%+v tip=%+v artifacts=%d submissions=%+v",
			status, source.tip, len(artifacts.pairs), source.submissions)
	}
	wantMiners := []types.Address{
		plan.TestedMiner, plan.ControlMiner,
		plan.ControlMiner, plan.TestedMiner,
	}
	for index, submission := range source.submissions {
		if submission.miner != wantMiners[index] {
			t.Fatalf("submission %d miner=%s want=%s", index, submission.miner, wantMiners[index])
		}
	}
	if publication.calls[1] != 2 || publication.calls[2] != 1 {
		t.Fatalf("publication calls=%v", publication.calls)
	}
	if deliverer.calls[campaignDeliveryKey{sequence: 1, observer: keys.observers[0]}] != 1 ||
		deliverer.calls[campaignDeliveryKey{sequence: 1, observer: keys.observers[1]}] != 2 {
		t.Fatalf("delivery calls=%v", deliverer.calls)
	}
}

func TestDriveCampaignRejectsWrongCoordinatorBeforeWork(t *testing.T) {
	plan, binding, _ := campaignPlan(t)
	planID, _ := plan.ID()
	campaign, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		StatePath: t.TempDir() + "/campaign.state",
	})
	if err != nil {
		t.Fatal(err)
	}
	source := newCampaignDriverSource(t, plan)
	wrongSeed := types.DomainHash("test/tieproducer/campaign-driver/wrong-coordinator")
	err = DriveCampaign(context.Background(), CampaignDriverConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		CoordinatorPrivateKey: ed25519.NewKeyFromSeed(wrongSeed[:]),
		Campaign:              campaign, Source: source,
		Artifacts: &memoryCampaignArtifacts{}, Publication: &campaignPublicationFixture{},
		Deliverer: &campaignDeliveryFixture{}, Clock: campaignDriverClock{source: source},
	})
	if !errors.Is(err, ErrCampaignDriver) || source.prepareCalls != 0 {
		t.Fatalf("wrong coordinator error=%v prepare_calls=%d", err, source.prepareCalls)
	}
}

func TestDriveCampaignSkipsExpiredUnpublishedSlotBeforeAnyDelivery(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	campaign, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		StatePath: t.TempDir() + "/campaign.state",
	})
	if err != nil {
		t.Fatal(err)
	}
	source := newCampaignDriverSource(t, plan)
	artifacts := &memoryCampaignArtifacts{}
	publication := &campaignSlotExpiryPublication{
		source: source, expireSequence: 1, expiredAt: plan.Slots[0].EndedAt,
	}
	deliverer := &campaignDeliveryFixture{}
	config := CampaignDriverConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		CoordinatorPrivateKey: keys.coordinator, Campaign: campaign, Source: source,
		Artifacts: artifacts, Publication: publication, Deliverer: deliverer,
		Clock: campaignDriverClock{source: source},
	}
	if err := DriveCampaign(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	status, err := campaign.Status()
	if err != nil || status.Phase != CampaignComplete || status.NextSequence != 3 ||
		status.SkippedSlots != 1 || !slices.Equal(status.SkippedSequences, []uint64{1}) {
		t.Fatalf("complete skipped status=%+v err=%v", status, err)
	}
	if source.tip.Height != 1 || len(source.submissions) != 2 {
		t.Fatalf("source tip=%+v submissions=%+v", source.tip, source.submissions)
	}
	for key := range deliverer.calls {
		if key.sequence != 2 {
			t.Fatalf("expired sequence delivered: calls=%v", deliverer.calls)
		}
	}
	if len(artifacts.pairs) != 2 || publication.calls[1] != 1 || publication.calls[2] != 1 {
		t.Fatalf("artifacts=%d publication_calls=%v", len(artifacts.pairs), publication.calls)
	}
}

func TestDriveCampaignNeverSkipsAfterObserverDeliveryBegins(t *testing.T) {
	plan, binding, keys := campaignPlan(t)
	planID, _ := plan.ID()
	campaign, err := OpenCampaign(CampaignConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		StatePath: t.TempDir() + "/campaign.state",
	})
	if err != nil {
		t.Fatal(err)
	}
	source := newCampaignDriverSource(t, plan)
	deliveryFailure := errors.New("observer unavailable")
	deliverer := &campaignDeliveryFixture{
		failSequence: 1, failObserver: keys.observers[1], failErr: deliveryFailure,
	}
	config := CampaignDriverConfig{
		Plan: plan, Binding: binding, ExpectedPlanID: planID,
		CoordinatorPrivateKey: keys.coordinator, Campaign: campaign, Source: source,
		Artifacts: &memoryCampaignArtifacts{}, Publication: &campaignPublicationFixture{},
		Deliverer: deliverer, Clock: campaignDriverClock{source: source},
	}
	if err := DriveCampaign(context.Background(), config); !errors.Is(err, deliveryFailure) {
		t.Fatalf("delivery error=%v", err)
	}
	status, _ := campaign.Status()
	if status.Phase != CampaignDelivering || status.AcknowledgedCount != 1 {
		t.Fatalf("partial delivery status=%+v", status)
	}
	source.now = plan.Slots[0].EndedAt + calibration.TieReceiptClosureGraceSeconds
	if err := DriveCampaign(context.Background(), config); !errors.Is(err, ErrOutsideSlot) {
		t.Fatalf("expired partial-delivery error=%v", err)
	}
	status, _ = campaign.Status()
	if status.Phase != CampaignDelivering || status.NextSequence != 1 ||
		status.AcknowledgedCount != 1 || status.SkippedSlots != 0 {
		t.Fatalf("unsafe skip status=%+v", status)
	}
}

type memoryCampaignArtifacts struct {
	mu          sync.Mutex
	pairs       map[uint64]Pair
	checkpoints map[uint64]calibration.TiePairCheckpoint
}

func (store *memoryCampaignArtifacts) Store(pair Pair, checkpoint calibration.TiePairCheckpoint) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.pairs == nil {
		store.pairs = make(map[uint64]Pair)
	}
	if store.checkpoints == nil {
		store.checkpoints = make(map[uint64]calibration.TiePairCheckpoint)
	}
	if current, exists := store.checkpoints[pair.Sequence]; exists {
		if current != checkpoint {
			return ErrCampaignState
		}
		return nil
	}
	store.pairs[pair.Sequence] = pair
	store.checkpoints[pair.Sequence] = checkpoint
	return nil
}

func (store *memoryCampaignArtifacts) Load(sequence uint64) (Pair, calibration.TiePairCheckpoint, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pair, exists := store.pairs[sequence]
	if !exists {
		return Pair{}, calibration.TiePairCheckpoint{}, osErrNotExist
	}
	return pair, store.checkpoints[sequence], nil
}

var osErrNotExist = errors.New("campaign artifact does not exist")

type campaignPublicationFixture struct {
	failSequence uint64
	failErr      error
	calls        map[uint64]int
}

type campaignSlotExpiryPublication struct {
	source         *campaignDriverSource
	expireSequence uint64
	expiredAt      uint64
	calls          map[uint64]int
}

func (fixture *campaignSlotExpiryPublication) WaitPublished(
	_ context.Context,
	sequence uint64,
	checkpointID types.Hash,
) error {
	if checkpointID.IsZero() || fixture.source == nil {
		return ErrCampaignDriver
	}
	if fixture.calls == nil {
		fixture.calls = make(map[uint64]int)
	}
	fixture.calls[sequence]++
	if sequence == fixture.expireSequence {
		fixture.source.now = fixture.expiredAt
		return context.DeadlineExceeded
	}
	return nil
}

func (fixture *campaignPublicationFixture) WaitPublished(
	_ context.Context,
	sequence uint64,
	checkpointID types.Hash,
) error {
	if checkpointID.IsZero() {
		return ErrCampaignDriver
	}
	if fixture.calls == nil {
		fixture.calls = make(map[uint64]int)
	}
	fixture.calls[sequence]++
	if fixture.failErr != nil && sequence == fixture.failSequence {
		return fixture.failErr
	}
	return nil
}

type campaignDeliveryKey struct {
	sequence uint64
	observer [ed25519.PublicKeySize]byte
}

type campaignDeliveryFixture struct {
	mu           sync.Mutex
	failSequence uint64
	failObserver [ed25519.PublicKeySize]byte
	failErr      error
	calls        map[campaignDeliveryKey]int
}

func (fixture *campaignDeliveryFixture) Deliver(
	_ context.Context,
	observer [ed25519.PublicKeySize]byte,
	pair Pair,
	checkpoint calibration.TiePairCheckpoint,
) (types.Hash, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if checkpoint.PairID.IsZero() || checkpoint.Sequence != pair.Sequence {
		return types.Hash{}, ErrCampaignDriver
	}
	if fixture.calls == nil {
		fixture.calls = make(map[campaignDeliveryKey]int)
	}
	key := campaignDeliveryKey{sequence: pair.Sequence, observer: observer}
	fixture.calls[key]++
	if fixture.failErr != nil && pair.Sequence == fixture.failSequence && observer == fixture.failObserver {
		return types.Hash{}, fixture.failErr
	}
	return types.DomainHash(
		"test/tieproducer/campaign-driver/receipt-tail",
		[]byte{byte(pair.Sequence)}, observer[:],
	), nil
}

type campaignDriverClock struct {
	source *campaignDriverSource
}

func (clock campaignDriverClock) WaitUntil(ctx context.Context, unixSeconds uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.source.now = unixSeconds
	return nil
}

func (clock campaignDriverClock) Now() (uint64, error) {
	if clock.source == nil || clock.source.now == 0 {
		return 0, ErrCampaignDriver
	}
	return clock.source.now, nil
}

type campaignDriverSource struct {
	now          uint64
	tip          storage.Tip
	parameters   workblock.Parameters
	currentState *state.Memory
	previous     *workblock.Earning
	feeQueue     *workgraph.FeeQueue
	position     workblock.Position
	prepareCalls int
	submissions  []producerSubmission
}

func newCampaignDriverSource(t testing.TB, plan calibration.TiePlan) *campaignDriverSource {
	t.Helper()
	parentID := types.DomainHash("test/tieproducer/campaign-driver/parent")
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return &campaignDriverSource{
		tip:          storage.Tip{ID: parentID, Height: 0, Timestamp: 1_699_999_940},
		currentState: state.Empty(),
		parameters: workblock.Parameters{
			NetworkID: plan.NetworkID, BlockSubsidy: 10_220, RewardMaturity: 100,
			ActivationHeight: plan.ActivationHeight, DifficultyAnchorTimestamp: 1_699_999_940,
			DifficultyAnchorTarget: target, TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
		},
	}
}

func (source *campaignDriverSource) AdmissionTime() (uint64, error) {
	return source.now, nil
}

func (source *campaignDriverSource) Tip() (storage.Tip, error) {
	return source.tip, nil
}

func (source *campaignDriverSource) PrepareWork(
	parent types.Hash,
	timestamp uint64,
	_ []outcome.Transaction,
) (*workblock.Payload, workblock.Position, error) {
	source.prepareCalls++
	if parent != source.tip.ID || source.tip.Height == ^uint64(0) {
		return nil, workblock.Position{}, ErrCampaignDriver
	}
	target, err := difficulty.ASERT(
		source.parameters.DifficultyAnchorTarget,
		source.parameters.DifficultyAnchorTimestamp,
		source.tip.Height+1,
		source.tip.Timestamp+source.parameters.TargetSpacing,
		source.parameters.TargetSpacing,
		source.parameters.ASERTHalfLife,
	)
	if err != nil {
		return nil, workblock.Position{}, err
	}
	source.position = workblock.Position{
		Height: source.tip.Height + 1, ParentID: parent,
		ParentTimestamp: source.tip.Timestamp, MedianTimePast: source.tip.Timestamp,
		Timestamp: timestamp, Target: target, FeeQueue: source.feeQueue,
	}
	payload, err := workblock.PreparePayload(
		source.currentState, source.position, source.previous, nil, source.parameters,
	)
	return payload, source.position, err
}

func (source *campaignDriverSource) Submit(candidate activation.Block) (storage.Tip, error) {
	block, ok := candidate.WorkBlock()
	if !ok {
		return storage.Tip{}, ErrCampaignDriver
	}
	id, err := candidate.ID()
	if err != nil {
		return storage.Tip{}, err
	}
	seal := block.Header.Seal
	source.submissions = append(source.submissions, producerSubmission{id: id, miner: seal.Miner})
	if seal.AnchorParent == source.tip.ID && seal.Height == source.tip.Height+1 {
		result, err := workblock.ValidateAndExecute(
			source.currentState, source.position, source.previous, block, source.parameters,
		)
		if err != nil {
			return storage.Tip{}, err
		}
		source.currentState = result.State
		source.feeQueue = result.FeeQueue
		source.previous = &workblock.Earning{
			Seal: seal, Shares: append([]workgraph.Share(nil), block.Shares...), FeeAward: result.FeeAward,
			ParentTimestamp: source.position.ParentTimestamp, MedianTimePast: source.position.MedianTimePast,
		}
		source.tip = storage.Tip{ID: id, Height: seal.Height, Timestamp: seal.Timestamp}
		return source.tip, nil
	}
	if seal.Height == source.tip.Height {
		return source.tip, nil
	}
	return storage.Tip{}, ErrCampaignDriver
}
