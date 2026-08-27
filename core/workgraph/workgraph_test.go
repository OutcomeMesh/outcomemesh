package workgraph

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestDerivedTargetUsesExactRatioAndSaturates(t *testing.T) {
	t.Parallel()

	var tiny types.Hash
	tiny[len(tiny)-1] = 1
	target, err := DerivedTarget(tiny)
	if err != nil {
		t.Fatal(err)
	}
	var want types.Hash
	want[len(want)-2] = 0x03
	want[len(want)-1] = 0xff
	if target != want {
		t.Fatalf("derived target = %s, want %s", target, want)
	}
	maximum := maximumTarget()
	target, err = DerivedTarget(maximum)
	if err != nil || target != maximum {
		t.Fatalf("saturated target = %s err=%v", target, err)
	}
	if _, err := DerivedTarget(types.Hash{}); !errors.Is(err, ErrTarget) {
		t.Fatalf("zero anchor target error = %v", err)
	}
	limit := exactRatioLimitTarget()
	if !ExactShareRatio(limit) {
		t.Fatal("largest exact-ratio target was rejected")
	}
	above := limit
	above[0] = 1
	if ExactShareRatio(above) || ExactShareRatio(types.Hash{}) || ExactShareRatio(maximum) {
		t.Fatal("saturated or zero target was accepted for WorkGraph rewards")
	}
	unsupported := testTemplate(t, testContext(), "saturated-mining", nil)
	unsupported.Target = maximum
	if _, _, err := Mine(context.Background(), unsupported, 0); !errors.Is(err, ErrTarget) {
		t.Fatalf("saturated mining target error = %v", err)
	}
}

func TestShareRoundTripCanonicalDAGAndDetachedBatch(t *testing.T) {
	t.Parallel()

	validation := testContext()
	first := testShare(t, validation, "first", nil)
	firstID, _ := first.ID()
	dependent := testShare(t, validation, "dependent", []types.Hash{firstID})
	independent := testShare(t, validation, "independent", nil)
	canonical, err := Canonicalize(validation, []Share{dependent, independent, first})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ValidateBatch(validation, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Len() != 3 || batch.Root().IsZero() || len(batch.IDs()) != 3 {
		t.Fatalf("invalid validated batch len=%d root=%s", batch.Len(), batch.Root())
	}
	for index, share := range canonical {
		decoded, err := Decode(share.CanonicalBytes())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded.CanonicalBytes(), share.CanonicalBytes()) {
			t.Fatalf("share %d changed after round trip", index)
		}
	}
	detached := batch.Shares()
	detached[0].Parents = append(detached[0].Parents, types.DomainHash("mutated"))
	if reflect.DeepEqual(detached, batch.Shares()) {
		t.Fatal("validated batch exposed mutable share storage")
	}

	reordered := append([]Share(nil), canonical...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := ValidateBatch(validation, reordered); !errors.Is(err, ErrCanonicalOrder) {
		t.Fatalf("reordered batch error = %v", err)
	}
	duplicated := append(append([]Share(nil), canonical...), canonical[0])
	if _, err := ValidateBatch(validation, duplicated); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate batch error = %v", err)
	}
	missing := testShare(t, validation, "missing", []types.Hash{types.DomainHash("missing-parent")})
	if _, err := ValidateBatch(validation, []Share{missing}); !errors.Is(err, ErrParents) {
		t.Fatalf("missing parent error = %v", err)
	}
}

func TestWinningAnchorParentsCommitExactPayoutClosure(t *testing.T) {
	t.Parallel()

	validation := testContext()
	first := testShare(t, validation, "closure-first", nil)
	firstID, _ := first.ID()
	dependent := testShare(t, validation, "closure-dependent", []types.Hash{firstID})
	dependentID, _ := dependent.ID()
	independent := testShare(t, validation, "closure-independent", nil)
	independentID, _ := independent.ID()
	canonical, err := Canonicalize(validation, []Share{dependent, independent, first})
	if err != nil {
		t.Fatal(err)
	}
	anchorParents := []types.Hash{dependentID, independentID}
	if types.CompareHash(anchorParents[0], anchorParents[1]) > 0 {
		anchorParents[0], anchorParents[1] = anchorParents[1], anchorParents[0]
	}
	anchorTemplate := testTemplate(t, validation, "unused-anchor-label", anchorParents)
	anchorTemplate.Miner = validation.AnchorMiner
	anchor, _, err := MineAnchor(context.Background(), anchorTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ValidateCommittedBatch(validation, anchor, canonical)
	if err != nil || batch.Len() != 3 {
		t.Fatalf("committed closure len=%d err=%v", batch.Len(), err)
	}
	withoutAncestor := make([]Share, 0, 2)
	for _, share := range canonical {
		id, _ := share.ID()
		if id != firstID {
			withoutAncestor = append(withoutAncestor, share)
		}
	}
	if _, err := ValidateCommittedBatch(validation, anchor, withoutAncestor); !errors.Is(err, ErrParents) {
		t.Fatalf("missing committed ancestor error = %v", err)
	}
	extra := testShare(t, validation, "closure-unreferenced", nil)
	withExtra, err := Canonicalize(validation, append(append([]Share(nil), canonical...), extra))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateCommittedBatch(validation, anchor, withExtra); !errors.Is(err, ErrParents) {
		t.Fatalf("unreferenced extra share error = %v", err)
	}
}

func TestCommittedSharesAllowBoundedTimestampVariation(t *testing.T) {
	t.Parallel()

	validation := testContext()
	shareTemplate := testTemplate(t, validation, "timestamp-window", nil)
	shareTemplate.Timestamp = validation.AnchorTimestamp - 50
	share, shareID, err := Mine(context.Background(), shareTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	anchorTemplate := testTemplate(t, validation, "timestamp-window-anchor", []types.Hash{shareID})
	anchorTemplate.Miner = validation.AnchorMiner
	anchor, _, err := MineAnchor(context.Background(), anchorTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateCommittedBatch(validation, anchor, []Share{share}); err != nil {
		t.Fatalf("bounded timestamp variation rejected: %v", err)
	}
	wrongAnchorTime := anchor
	wrongAnchorTime.Timestamp--
	if _, err := ValidateCommittedBatch(validation, wrongAnchorTime, []Share{share}); !errors.Is(err, ErrTimestamp) {
		t.Fatalf("anchor timestamp mismatch error = %v", err)
	}
}

func TestShareListCodecRoundTripAndStrictBounds(t *testing.T) {
	t.Parallel()

	validation := testContext()
	shares := []Share{testShare(t, validation, "codec-a", nil), testShare(t, validation, "codec-b", nil)}
	encoded, err := EncodeShares(shares)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeShares(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(shares) {
		t.Fatalf("decoded %d shares, want %d", len(decoded), len(shares))
	}
	for index := range shares {
		if !reflect.DeepEqual(decoded[index].CanonicalBytes(), shares[index].CanonicalBytes()) {
			t.Fatalf("share %d changed after list round trip", index)
		}
	}
	if _, err := DecodeShares(append(encoded, 0)); err == nil {
		t.Fatal("share list accepted trailing bytes")
	}
	if _, err := EncodeShares(make([]Share, MaxShares+1)); !errors.Is(err, ErrShareCount) {
		t.Fatalf("oversize share list error = %v", err)
	}
}

func TestShareValidationRejectsContextAndProofMismatch(t *testing.T) {
	t.Parallel()

	validation := testContext()
	share := testShare(t, validation, "valid", nil)
	if err := ValidateShare(validation, share); err != nil {
		t.Fatal(err)
	}
	wrongNetwork := share
	wrongNetwork.NetworkID++
	if err := ValidateShare(validation, wrongNetwork); !errors.Is(err, ErrNetwork) {
		t.Fatalf("network mismatch error = %v", err)
	}
	wrongTarget := share
	wrongTarget.Target[0]--
	if err := ValidateShare(validation, wrongTarget); !errors.Is(err, ErrTarget) {
		t.Fatalf("target mismatch error = %v", err)
	}
	late := share
	late.Timestamp = validation.AnchorTimestamp + MaxShareTimestampLead + 1
	if err := ValidateShare(validation, late); !errors.Is(err, ErrTimestamp) {
		t.Fatalf("timestamp mismatch error = %v", err)
	}
	earlier := share
	earlier.Timestamp--
	if err := ValidateShare(validation, earlier); err != nil {
		t.Fatalf("valid timestamp variation rejected: %v", err)
	}

	var hardAnchor types.Hash
	hardAnchor[len(hardAnchor)-1] = 1
	hardContext := validation
	hardContext.AnchorTarget = hardAnchor
	hardShare := share
	hardShare.Target = hardAnchor
	hardShare.Nonce = 0
	if err := ValidateShare(hardContext, hardShare); !errors.Is(err, ErrProofOfWork) {
		t.Fatalf("invalid share proof error = %v", err)
	}
}

func TestSameWorkSealCanBecomeWeakShareOrHardAnchor(t *testing.T) {
	t.Parallel()

	validation := testContext()
	var hardTarget types.Hash
	hardTarget[1] = 0x0f
	for index := 2; index < len(hardTarget); index++ {
		hardTarget[index] = 0xff
	}
	validation.AnchorTarget = hardTarget
	template := testTemplate(t, validation, "dual-use", nil)
	weak, weakID, err := Mine(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	shareTarget, _ := DerivedTarget(hardTarget)
	if types.CompareHash(weakID, shareTarget) > 0 {
		t.Fatal("weak miner returned work above derived threshold")
	}
	anchor, anchorID, err := MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	if types.CompareHash(anchorID, hardTarget) > 0 {
		t.Fatal("anchor miner returned work above hard threshold")
	}
	meets, err := MeetsAnchor(anchor)
	if err != nil || !meets {
		t.Fatalf("hard work did not meet anchor through same seal: meets=%t err=%v", meets, err)
	}
	if err := ValidateShare(validation, anchor); err != nil {
		t.Fatalf("hard anchor was not also a valid weak share: %v", err)
	}
	if weak.Target != anchor.Target || weak.PayloadRoot != anchor.PayloadRoot || weak.AnchorParent != anchor.AnchorParent {
		t.Fatal("weak and hard mining changed committed template fields")
	}
}

func TestPayloadCommitmentBindsEveryExecutionRoot(t *testing.T) {
	t.Parallel()

	values := [4]types.Hash{
		types.DomainHash("test/workgraph/payload/tx"), types.DomainHash("test/workgraph/payload/receipt"),
		types.DomainHash("test/workgraph/payload/state"), types.DomainHash("test/workgraph/payload/previous-work"),
	}
	commitment, err := PayloadCommitment(values[0], values[1], values[2], values[3])
	if err != nil || commitment.IsZero() {
		t.Fatalf("payload commitment=%s err=%v", commitment, err)
	}
	for index := range values {
		mutated := values
		mutated[index][0] ^= 1
		other, err := PayloadCommitment(mutated[0], mutated[1], mutated[2], mutated[3])
		if err != nil || other == commitment {
			t.Fatalf("payload field %d was not committed", index)
		}
	}
	if _, err := PayloadCommitment(types.Hash{}, values[1], values[2], values[3]); !errors.Is(err, ErrPayload) {
		t.Fatalf("zero payload field error = %v", err)
	}
}

func TestPayloadCommitmentV1BindsFeeStateAndAward(t *testing.T) {
	t.Parallel()

	values := [5]types.Hash{
		types.DomainHash("test/workgraph/payload-v1/tx"),
		types.DomainHash("test/workgraph/payload-v1/receipt"),
		types.DomainHash("test/workgraph/payload-v1/state"),
		types.DomainHash("test/workgraph/payload-v1/previous-work"),
		types.DomainHash("test/workgraph/payload-v1/fee-queue"),
	}
	commitment, err := PayloadCommitmentV1(values[0], values[1], values[2], values[3], values[4], 17)
	if err != nil || commitment.IsZero() {
		t.Fatalf("payload-v1 commitment=%s err=%v", commitment, err)
	}
	for index := range values {
		mutated := values
		mutated[index][0] ^= 1
		other, err := PayloadCommitmentV1(
			mutated[0], mutated[1], mutated[2], mutated[3], mutated[4], 17,
		)
		if err != nil || other == commitment {
			t.Fatalf("payload-v1 field %d was not committed", index)
		}
	}
	other, err := PayloadCommitmentV1(values[0], values[1], values[2], values[3], values[4], 18)
	if err != nil || other == commitment {
		t.Fatal("payload-v1 fee award was not committed")
	}
	if _, err := PayloadCommitmentV1(
		values[0], values[1], values[2], values[3], types.Hash{}, 17,
	); !errors.Is(err, ErrPayload) {
		t.Fatalf("zero fee queue root error = %v", err)
	}
}

func TestFixedRewardRatesAreDeterministicAndRemoveOmissionGain(t *testing.T) {
	t.Parallel()

	const subsidy uint64 = 10_220
	const fees uint64 = 7
	anchorSubsidy, shareReward, err := RewardRates(subsidy)
	if err != nil || anchorSubsidy != 5_110 || shareReward != 10 {
		t.Fatalf("reward rates anchor=%d share=%d err=%v", anchorSubsidy, shareReward, err)
	}
	if _, _, err := RewardRates(2*ExpectedSharesPerAnchor - 1); !errors.Is(err, ErrReward) {
		t.Fatalf("sub-unit share policy error = %v", err)
	}
	if _, _, err := RewardRates(^uint64(0)); !errors.Is(err, ErrReward) {
		t.Fatalf("unsafe maximum policy error = %v", err)
	}

	validation := testContext()
	first := testShare(t, validation, "reward-a", nil)
	second := testShare(t, validation, "reward-b", nil)
	third := testShare(t, validation, "reward-c", nil)
	second.Miner = first.Miner
	second.Nonce++
	canonical, err := Canonicalize(validation, []Share{third, first, second})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ValidateBatch(validation, canonical)
	if err != nil {
		t.Fatal(err)
	}
	rewards, err := AllocateRewards(subsidy, fees, validation.AnchorMiner, batch)
	if err != nil {
		t.Fatal(err)
	}
	wantAmounts := map[types.Address]uint64{validation.AnchorMiner: anchorSubsidy + fees}
	for _, share := range canonical {
		wantAmounts[share.Miner] += shareReward
	}
	var distributed uint64
	for index, reward := range rewards {
		if index > 0 && types.CompareAddress(rewards[index-1].Miner, reward.Miner) >= 0 {
			t.Fatal("reward order is not canonical")
		}
		if reward.Amount != wantAmounts[reward.Miner] {
			t.Fatalf("reward for %s = %d, want %d", reward.Miner, reward.Amount, wantAmounts[reward.Miner])
		}
		distributed += reward.Amount
		delete(wantAmounts, reward.Miner)
	}
	if len(wantAmounts) != 0 || distributed != anchorSubsidy+fees+3*shareReward {
		t.Fatalf("missing rewards=%v distributed=%d", wantAmounts, distributed)
	}
	empty, err := ValidateBatch(validation, nil)
	if err != nil {
		t.Fatal(err)
	}
	rewards, err = AllocateRewards(subsidy, fees, validation.AnchorMiner, empty)
	if err != nil || len(rewards) != 1 || rewards[0].Amount != anchorSubsidy+fees || rewards[0].Miner != validation.AnchorMiner {
		t.Fatalf("empty batch rewards=%+v err=%v", rewards, err)
	}
	if _, err := AllocateRewards(subsidy, fees, types.Address(types.DomainHash("wrong-anchor-miner")), empty); !errors.Is(err, ErrReward) {
		t.Fatalf("mismatched anchor miner error = %v", err)
	}

	own := testShare(t, validation, "anchor-owned-share", nil)
	own.Miner = validation.AnchorMiner
	foreign := testShare(t, validation, "foreign-share", nil)
	fullShares, err := Canonicalize(validation, []Share{own, foreign})
	if err != nil {
		t.Fatal(err)
	}
	full, err := ValidateBatch(validation, fullShares)
	if err != nil {
		t.Fatal(err)
	}
	ownShares, err := Canonicalize(validation, []Share{own})
	if err != nil {
		t.Fatal(err)
	}
	ownOnly, err := ValidateBatch(validation, ownShares)
	if err != nil {
		t.Fatal(err)
	}
	fullRewards, err := AllocateRewards(subsidy, fees, validation.AnchorMiner, full)
	if err != nil {
		t.Fatal(err)
	}
	ownRewards, err := AllocateRewards(subsidy, fees, validation.AnchorMiner, ownOnly)
	if err != nil {
		t.Fatal(err)
	}
	if rewardFor(fullRewards, validation.AnchorMiner) != rewardFor(ownRewards, validation.AnchorMiner) {
		t.Fatal("omitting a foreign share increased the anchor miner's payout")
	}
}

func rewardFor(rewards []Reward, miner types.Address) uint64 {
	for _, reward := range rewards {
		if reward.Miner == miner {
			return reward.Amount
		}
	}
	return 0
}

func TestBatchCapsDistinctRewardMiners(t *testing.T) {
	t.Parallel()

	validation := testContext()
	shares := make([]Share, MaxRewardMiners)
	for index := range shares {
		shares[index] = testShare(t, validation, string(rune(index+1)), nil)
		shares[index].Miner = types.Address(types.DomainHash("test/workgraph/unique-miner", []byte{byte(index), byte(index >> 8)}))
	}
	if _, err := Canonicalize(validation, shares); !errors.Is(err, ErrRewardMiners) {
		t.Fatalf("reward miner cap error = %v", err)
	}
}

func TestDelayedRewardResourcesAreCanonicalMatureAndConserved(t *testing.T) {
	t.Parallel()

	validation := testContext()
	share := testShare(t, validation, "resource-share", nil)
	canonical, err := Canonicalize(validation, []Share{share})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ValidateBatch(validation, canonical)
	if err != nil {
		t.Fatal(err)
	}
	const subsidy uint64 = 10_220
	rewards, err := AllocateRewards(subsidy, 0, validation.AnchorMiner, batch)
	if err != nil {
		t.Fatal(err)
	}
	anchorID := types.DomainHash("test/workgraph/reward-anchor")
	resources, err := RewardResources(validation.NetworkID, validation.Height, validation.Height+1, anchorID, rewards, 100)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for index, value := range resources {
		if value.Owner != rewards[index].Miner || value.Amount != rewards[index].Amount ||
			value.SpendAfter != validation.Height+101 {
			t.Fatalf("reward resource %d = %+v reward=%+v", index, value, rewards[index])
		}
		total += value.Amount
	}
	anchorSubsidy, shareReward, _ := RewardRates(subsidy)
	if total != anchorSubsidy+shareReward {
		t.Fatalf("reward resources total = %d", total)
	}
	left, err := state.New(resources)
	if err != nil {
		t.Fatal(err)
	}
	rightResources := append([]resource.Resource(nil), resources...)
	for leftIndex, rightIndex := 0, len(rightResources)-1; leftIndex < rightIndex; leftIndex, rightIndex = leftIndex+1, rightIndex-1 {
		rightResources[leftIndex], rightResources[rightIndex] = rightResources[rightIndex], rightResources[leftIndex]
	}
	right, err := state.New(rightResources)
	if err != nil || left.Root() != right.Root() {
		t.Fatalf("reward resource root changed with insertion order: err=%v", err)
	}
	if _, err := RewardResources(validation.NetworkID, validation.Height, validation.Height, anchorID, rewards, 100); !errors.Is(err, ErrReward) {
		t.Fatalf("same-height payout error = %v", err)
	}
}

func TestGoldenShareVectors(t *testing.T) {
	validation := testContext()
	share := testShare(t, validation, "golden", nil)
	share.Nonce = 7
	id, err := share.ID()
	if err != nil {
		t.Fatal(err)
	}
	batchShares, err := Canonicalize(validation, []Share{share})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ValidateBatch(validation, batchShares)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(share.CanonicalBytes()), "00000000004d00000000000000096cbf201defd160bae5a8f83d09a0ab1b5d96dae4a67be8d6048a51dd4b2447a9000000006553f101007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff30437bb9bcd7a8f9e102e80d36db384da29954bf43eb12ee33b9b537f6789e5faddd6d5ae0229cd6dc8308ca52b8973246ecf2e27b2224af2d28a75f7857f621052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c000000000000000007"; got != want {
		t.Fatalf("canonical share = %s, want %s", got, want)
	}
	if id.String() != "d602d67c610d3f45e3db5a19c5899aaab8a6c9b792dde021c097749338d061fe" {
		t.Fatalf("share ID = %s", id)
	}
	if share.InclusionRoot.String() != "052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c" {
		t.Fatalf("empty inclusion root = %s", share.InclusionRoot)
	}
	if batch.Root().String() != "468ddfa28a83db3d8dcd144bb2b95a22fa2083fc7820cb85f8dd85b4b0f91e7a" {
		t.Fatalf("batch root = %s", batch.Root())
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	validation := testContext()
	share := testShare(f, validation, "fuzz", nil)
	f.Add(share.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Decode(input)
	})
}

func FuzzDecodeSharesNeverPanics(f *testing.F) {
	validation := testContext()
	share := testShare(f, validation, "batch-fuzz", nil)
	encoded, err := EncodeShares([]Share{share})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeShares(input)
	})
}

func testContext() Context {
	return Context{
		NetworkID: 77, Height: 9, AnchorParent: types.DomainHash("test/workgraph/anchor"), AnchorTarget: exactRatioLimitTarget(),
		PayloadRoot:     types.DomainHash("test/workgraph/payload"),
		AnchorMiner:     types.Address(types.DomainHash("test/workgraph/anchor-miner")),
		AnchorTimestamp: 1_700_000_001,
		MedianTimePast:  1_699_999_900,
	}
}

func testShare(t testing.TB, validation Context, label string, parents []types.Hash) Share {
	t.Helper()
	template := testTemplate(t, validation, label, parents)
	mined, _, err := Mine(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	return mined
}

func testTemplate(t testing.TB, validation Context, label string, parents []types.Hash) Share {
	t.Helper()
	inclusion, err := InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	template := Share{
		Version: Version0, NetworkID: validation.NetworkID, Height: validation.Height, AnchorParent: validation.AnchorParent,
		Timestamp: validation.AnchorTimestamp, Target: validation.AnchorTarget, PayloadRoot: validation.PayloadRoot,
		Miner: types.Address(types.DomainHash("test/workgraph/miner", []byte(label))), InclusionRoot: inclusion,
		Parents: append([]types.Hash(nil), parents...),
	}
	return template
}

func maximumTarget() types.Hash {
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	return target
}

func exactRatioLimitTarget() types.Hash {
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return target
}
