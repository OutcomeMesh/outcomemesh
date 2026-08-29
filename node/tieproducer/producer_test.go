package tieproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestProduceSubmitsOnlyInPrecommittedRoleOrder(t *testing.T) {
	for _, firstRole := range []calibration.TieTrialRole{
		calibration.TieRoleTested,
		calibration.TieRoleControl,
	} {
		t.Run(roleName(firstRole), func(t *testing.T) {
			plan, binding := producerPlan(t, firstRole)
			planID, err := plan.ID()
			if err != nil {
				t.Fatal(err)
			}
			source := producerFixture(t, plan)
			result, err := Produce(context.Background(), source, Config{
				Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			wantFirst := plan.TestedMiner
			wantSecond := plan.ControlMiner
			wantFirstID := result.Tested.ID
			wantFinalID := result.Control.ID
			if firstRole == calibration.TieRoleControl {
				wantFirst, wantSecond = wantSecond, wantFirst
				wantFirstID, wantFinalID = wantFinalID, wantFirstID
			}
			if len(source.submissions) != 2 || source.submissions[0].miner != wantFirst ||
				source.submissions[1].miner != wantSecond {
				t.Fatalf("submission order=%+v want=%s,%s", source.submissions, wantFirst, wantSecond)
			}
			if result.FirstRole != firstRole || result.ParentID != source.tip.ID || result.Height != 1 ||
				result.Tested.ID.IsZero() || result.Control.ID.IsZero() || result.Tested.ID == result.Control.ID ||
				result.FirstSelected != wantFirstID || result.FinalSelected != wantFinalID {
				t.Fatalf("production result=%+v", result)
			}
			if source.preparedParent != source.tip.ID || source.preparedTimestamp != source.now {
				t.Fatalf("prepared parent=%s timestamp=%d", source.preparedParent, source.preparedTimestamp)
			}
		})
	}
}

func TestProduceRejectsSubstitutedPlanAndClosedSlotBeforeMining(t *testing.T) {
	plan, binding := producerPlan(t, calibration.TieRoleTested)
	planID, _ := plan.ID()
	source := producerFixture(t, plan)
	wrongID := types.DomainHash("test/tieproducer/wrong-plan")
	_, err := Produce(context.Background(), source, Config{
		Plan: plan, Binding: binding, ExpectedPlanID: wrongID, Sequence: 1,
	})
	if !errors.Is(err, ErrConfiguration) || source.prepareCalls != 0 {
		t.Fatalf("substituted plan error=%v prepare_calls=%d", err, source.prepareCalls)
	}
	source.now = plan.Slots[0].EndedAt
	_, err = Produce(context.Background(), source, Config{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: 1,
	})
	if !errors.Is(err, ErrOutsideSlot) || source.prepareCalls != 0 {
		t.Fatalf("closed slot error=%v prepare_calls=%d", err, source.prepareCalls)
	}
}

func TestPortablePairRoundTripsBeforeIndependentAdmission(t *testing.T) {
	plan, binding := producerPlan(t, calibration.TieRoleControl)
	planID, _ := plan.ID()
	coordinatorSource := producerFixture(t, plan)
	pair, mined, err := MinePair(context.Background(), coordinatorSource, Config{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(coordinatorSource.submissions) != 0 {
		t.Fatalf("coordinator admitted portable pair locally: %+v", coordinatorSource.submissions)
	}
	encoded, err := pair.CanonicalBytes(plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	pairID, err := pair.ID(plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pairID.String(), "ae313ca7a0a3c9614c14c5d9347090eddcec8dda6f4a26361543a5262be3ac0d"; got != want {
		t.Fatalf("pair ID=%s want=%s", got, want)
	}
	decoded, err := DecodePair(encoded, plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := decoded.CanonicalBytes(plan, binding, planID)
	if err != nil || !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("pair round trip equal=%t err=%v", bytes.Equal(roundTrip, encoded), err)
	}
	observerSource := producerFixture(t, plan)
	admitted, err := AdmitPair(context.Background(), observerSource, Config{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: 1,
	}, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(observerSource.submissions) != 2 || observerSource.submissions[0].miner != plan.ControlMiner ||
		observerSource.submissions[1].miner != plan.TestedMiner || admitted.Tested.ID != mined.Tested.ID ||
		admitted.Control.ID != mined.Control.ID {
		t.Fatalf("portable admission=%+v submissions=%+v mined=%+v", admitted, observerSource.submissions, mined)
	}
	if _, err := DecodePair(append(encoded, 0), plan, binding, planID); err == nil {
		t.Fatal("pair artifact with trailing bytes was accepted")
	}
	if _, err := DecodePair(make([]byte, MaximumPairArtifactBytes+1), plan, binding, planID); !errors.Is(err, ErrPairArtifact) {
		t.Fatalf("oversize pair error=%v", err)
	}
	swapped := pair
	swapped.Tested, swapped.Control = swapped.Control, swapped.Tested
	if err := swapped.Validate(plan, binding, planID); !errors.Is(err, ErrPairArtifact) {
		t.Fatalf("role-swapped pair error=%v", err)
	}
}

func FuzzDecodePairNeverPanics(f *testing.F) {
	plan, binding := producerPlan(f, calibration.TieRoleControl)
	planID, _ := plan.ID()
	source := producerFixture(f, plan)
	pair, _, err := MinePair(context.Background(), source, Config{
		Plan: plan, Binding: binding, ExpectedPlanID: planID, Sequence: 1,
	})
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := pair.CanonicalBytes(plan, binding, planID)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodePair(input, plan, binding, planID)
	})
}

type producerSubmission struct {
	id    types.Hash
	miner types.Address
}

type producerSource struct {
	now               uint64
	tip               storage.Tip
	payload           *workblock.Payload
	position          workblock.Position
	prepareCalls      int
	preparedParent    types.Hash
	preparedTimestamp uint64
	submissions       []producerSubmission
}

func (source *producerSource) AdmissionTime() (uint64, error) {
	return source.now, nil
}

func (source *producerSource) Tip() (storage.Tip, error) {
	return source.tip, nil
}

func (source *producerSource) PrepareWork(
	parent types.Hash,
	timestamp uint64,
	_ []outcome.Transaction,
) (*workblock.Payload, workblock.Position, error) {
	source.prepareCalls++
	source.preparedParent = parent
	source.preparedTimestamp = timestamp
	return source.payload, source.position, nil
}

func (source *producerSource) Submit(candidate activation.Block) (storage.Tip, error) {
	block, ok := candidate.WorkBlock()
	if !ok {
		return storage.Tip{}, errors.New("not a WorkGraph block")
	}
	id, err := candidate.ID()
	if err != nil {
		return storage.Tip{}, err
	}
	source.submissions = append(source.submissions, producerSubmission{id: id, miner: block.Header.Seal.Miner})
	return storage.Tip{ID: id, Height: block.Header.Seal.Height, Timestamp: block.Header.Seal.Timestamp}, nil
}

func producerFixture(t testing.TB, plan calibration.TiePlan) *producerSource {
	t.Helper()
	parentID := types.DomainHash("test/tieproducer/parent")
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	parameters := workblock.Parameters{
		NetworkID: plan.NetworkID, BlockSubsidy: 10_220, RewardMaturity: 100,
		ActivationHeight: plan.ActivationHeight, DifficultyAnchorTimestamp: 1_699_999_940,
		DifficultyAnchorTarget: target, TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
	position := workblock.Position{
		Height: 1, ParentID: parentID, ParentTimestamp: parameters.DifficultyAnchorTimestamp,
		MedianTimePast: parameters.DifficultyAnchorTimestamp, Timestamp: plan.Slots[0].StartedAt,
		Target: target,
	}
	payload, err := workblock.PreparePayload(state.Empty(), position, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	return &producerSource{
		now:     plan.Slots[0].StartedAt,
		tip:     storage.Tip{ID: parentID, Height: 0, Timestamp: parameters.DifficultyAnchorTimestamp},
		payload: payload, position: position,
	}
}

func producerPlan(t testing.TB, firstRole calibration.TieTrialRole) (calibration.TiePlan, calibration.TiePlanBinding) {
	t.Helper()
	coordinator := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	observer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion1, NetworkID: 71,
		GenesisID: types.DomainHash("test/tieproducer/genesis"), ActivationHeight: 1,
		TestedMiner:             types.Address(types.DomainHash("test/tieproducer/tested")),
		ControlMiner:            types.Address(types.DomainHash("test/tieproducer/control")),
		MaximumPairDelaySeconds: 5,
		Slots: []calibration.TiePlanSlot{{
			StartedAt: 1_700_000_000, EndedAt: 1_700_000_060, FirstRole: firstRole,
		}},
	}
	copy(plan.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	plan, err := calibration.SignTiePlan(coordinator, plan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, plan.Binding()
}

func roleName(role calibration.TieTrialRole) string {
	if role == calibration.TieRoleControl {
		return "control-first"
	}
	return "tested-first"
}
