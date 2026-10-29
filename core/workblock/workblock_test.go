package workblock

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/difficulty"
	"github.com/outcomemesh/outcomemesh/core/guardvm"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func TestActivationThenDelayedWorkGraphPayout(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	initialResource := resource.Resource{
		ID:      types.ResourceID(types.DomainHash("test/workblock/initial-resource")),
		Version: resource.Version0,
		Owner:   testAddress("initial-owner"),
		Asset:   types.NativeAssetID(),
		Amount:  7,
	}
	initialState, err := state.New([]resource.Resource{initialResource})
	if err != nil {
		t.Fatal(err)
	}
	activation := Position{
		Height:          parameters.ActivationHeight,
		ParentID:        types.DomainHash("test/workblock/version-zero-parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp,
		MedianTimePast:  parameters.DifficultyAnchorTimestamp,
		Timestamp:       1_700_000_000,
		Target:          parameters.DifficultyAnchorTarget,
	}
	payload1, err := PreparePayload(initialState, activation, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	firstTemplate, err := payload1.SealTemplate(testAddress("share-miner-a"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, firstID, err := workgraph.Mine(context.Background(), firstTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	secondTemplate, err := payload1.SealTemplate(testAddress("share-miner-b"), inclusion, []types.Hash{firstID})
	if err != nil {
		t.Fatal(err)
	}
	second, secondID, err := workgraph.Mine(context.Background(), secondTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	shareContext := contextFromSeal(first, activation.MedianTimePast)
	shareContext.AnchorMiner = testAddress("anchor-miner")
	shares, err := workgraph.Canonicalize(shareContext, []workgraph.Share{second, first})
	if err != nil {
		t.Fatal(err)
	}
	anchorTemplate, err := payload1.SealTemplate(shareContext.AnchorMiner, inclusion, []types.Hash{secondID})
	if err != nil {
		t.Fatal(err)
	}
	anchor1, anchor1ID, err := workgraph.MineAnchor(context.Background(), anchorTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	block1, result1, err := payload1.Finalize(anchor1, shares)
	if err != nil {
		t.Fatal(err)
	}
	if result1.BlockID != anchor1ID || result1.State.Root() != initialState.Root() ||
		len(result1.PayoutResources) != 0 || result1.PayoutBatch != nil ||
		result1.FeeQueue == nil || result1.FeeAward != 0 {
		t.Fatalf("activation result unexpectedly issued a current-height reward: %+v", result1)
	}
	if headerID, err := block1.Header.ID(); err != nil || headerID != anchor1ID {
		t.Fatalf("unified header ID = %s err=%v, want anchor %s", headerID, err, anchor1ID)
	}
	encoded1 := block1.CanonicalBytes()
	decoded1, err := Decode(encoded1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded1.CanonicalBytes(), encoded1) {
		t.Fatal("version-1 block changed after canonical round trip")
	}
	if _, err := Decode(append(encoded1, 0)); err == nil {
		t.Fatal("version-1 block decoder accepted trailing bytes")
	}
	decodedHeader, err := DecodeHeader(block1.Header.CanonicalBytes())
	if err != nil || !reflect.DeepEqual(decodedHeader.CanonicalBytes(), block1.Header.CanonicalBytes()) {
		t.Fatalf("version-1 header round trip failed: %v", err)
	}
	replayed1, err := ValidateAndExecute(initialState, activation, nil, block1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if replayed1.State.Root() != result1.State.Root() || replayed1.BlockID != result1.BlockID {
		t.Fatal("activation replay changed its state or block ID")
	}
	if err := ValidateHeaderAt(activation, block1.Header, parameters, activation.Timestamp); err != nil {
		t.Fatalf("valid header-first proof rejected: %v", err)
	}
	if _, err := ValidateAndExecuteAt(
		initialState, activation, nil, block1, parameters,
		activation.Timestamp-legacyblock.MaxFutureDrift-1,
	); !errors.Is(err, ErrFutureTime) {
		t.Fatalf("future timestamp admission error = %v", err)
	}

	earning1 := &Earning{
		Seal: anchor1, Shares: shares, FeeAward: result1.FeeAward,
		ParentTimestamp: activation.ParentTimestamp, MedianTimePast: activation.MedianTimePast,
	}
	position2 := Position{
		Height:          activation.Height + 1,
		ParentID:        anchor1ID,
		ParentTimestamp: activation.Timestamp,
		MedianTimePast:  activation.Timestamp,
		Timestamp:       activation.Timestamp + parameters.TargetSpacing,
		Target:          parameters.DifficultyAnchorTarget,
		FeeQueue:        result1.FeeQueue,
	}
	payload2, err := PreparePayload(result1.State, position2, earning1, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if payload2.result.PayoutBatch == nil || payload2.result.PayoutBatch.Len() != 2 {
		t.Fatalf("payout batch len = %d, want 2", payload2.result.PayoutBatch.Len())
	}
	if payload2.header.PreviousWorkRoot != payload2.result.PayoutBatch.Root() {
		t.Fatal("second payload does not commit the predecessor payout batch")
	}
	if len(payload2.result.PayoutResources) != 3 {
		t.Fatalf("payout resources = %d, want anchor plus two share miners", len(payload2.result.PayoutResources))
	}
	var distributed uint64
	for index, payout := range payload2.result.PayoutResources {
		distributed += payout.Amount
		if payout.SpendAfter != position2.Height+parameters.RewardMaturity {
			t.Fatalf("payout %d spend-after = %d", index, payout.SpendAfter)
		}
		if index > 0 && types.CompareAddress(payload2.result.PayoutResources[index-1].Owner, payout.Owner) >= 0 {
			t.Fatal("payout resources are not in canonical recipient order")
		}
	}
	anchorSubsidy, shareReward, err := workgraph.RewardRates(parameters.BlockSubsidy)
	if err != nil {
		t.Fatal(err)
	}
	if distributed != anchorSubsidy+2*shareReward || payload2.result.State.Len() != initialState.Len()+3 {
		t.Fatalf("distributed=%d state-len=%d", distributed, payload2.result.State.Len())
	}
	anchor2Template, err := payload2.SealTemplate(testAddress("second-anchor-miner"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchor2, _, err := workgraph.MineAnchor(context.Background(), anchor2Template, 0)
	if err != nil {
		t.Fatal(err)
	}
	block2, result2, err := payload2.Finalize(anchor2, nil)
	if err != nil {
		t.Fatal(err)
	}
	replayed2, err := ValidateAndExecute(result1.State, position2, earning1, block2, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if replayed2.State.Root() != result2.State.Root() || replayed2.BlockID != result2.BlockID {
		t.Fatal("second block replay changed its state or block ID")
	}

	tamperedRoot := block2
	tamperedRoot.Header.PreviousWorkRoot = types.DomainHash("test/workblock/tampered-root")
	if _, err := ValidateAndExecute(result1.State, position2, earning1, tamperedRoot, parameters); !errors.Is(err, ErrRoot) {
		t.Fatalf("tampered previous-work root error = %v", err)
	}
	tamperedClosure := block1
	tamperedClosure.Shares = tamperedClosure.Shares[1:]
	if _, err := ValidateAndExecute(initialState, activation, nil, tamperedClosure, parameters); !errors.Is(err, workgraph.ErrParents) {
		t.Fatalf("omitted committed ancestor error = %v", err)
	}
}

func TestActivationBoundaryCannotSkipPreviousPayout(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	position := Position{
		Height:          parameters.ActivationHeight + 1,
		ParentID:        types.DomainHash("test/workblock/parent"),
		ParentTimestamp: 1_700_000_000,
		MedianTimePast:  1_700_000_000,
		Timestamp:       1_700_000_060,
		Target:          parameters.DifficultyAnchorTarget,
	}
	if _, err := PreparePayload(state.Empty(), position, nil, nil, parameters); !errors.Is(err, ErrPrevious) {
		t.Fatalf("missing post-activation earning error = %v", err)
	}
	position.Height = parameters.ActivationHeight
	parameters.ActivationHeight = 0
	if _, err := PreparePayload(state.Empty(), position, nil, nil, parameters); !errors.Is(err, ErrParameters) {
		t.Fatalf("zero activation height error = %v", err)
	}
}

func TestCollectedFeeIsPaidToFutureAnchorAfterExactDelay(t *testing.T) {
	t.Parallel()
	for _, h := range []uint64{0, 1, 2, 3, 4} {
		t.Run(fmt.Sprint(h), func(t *testing.T) { checkDelayedFeeAcrossRadix(t, h) })
	}
}
func checkDelayedFeeAcrossRadix(t *testing.T, radixHeight uint64) {
	parameters := testParameters()
	parameters.RadixActivationHeight = radixHeight
	parameters.FeeDelay = 2
	seed := types.DomainHash("test/workblock/fee-owner")
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	input := resource.Resource{
		ID: types.ResourceID(types.DomainHash("test/workblock/fee-input")), Version: resource.Version0,
		Owner: owner, Asset: types.NativeAssetID(), Amount: 100,
	}
	current, err := state.New([]resource.Resource{input})
	if err != nil {
		t.Fatal(err)
	}
	transaction := outcome.Transaction{
		Version: outcome.Version0, NetworkID: parameters.NetworkID,
		Inputs:  []resource.Ref{{ID: input.ID, Version: input.Version}},
		Outputs: []resource.Output{{Owner: testAddress("fee-recipient"), Asset: input.Asset, Amount: 95}},
		Guard: guardvm.Program{
			Version: guardvm.Version0, Instructions: []guardvm.Instruction{{Op: guardvm.OpHalt}},
		},
		Fee: 5, ValidUntil: parameters.ActivationHeight + 10, Nonce: [32]byte{9, 9, 9},
	}
	if err := transaction.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	position := Position{
		Height: parameters.ActivationHeight, ParentID: types.DomainHash("test/workblock/fee-parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp,
		MedianTimePast:  parameters.DifficultyAnchorTimestamp,
		Timestamp:       parameters.DifficultyAnchorTimestamp + parameters.TargetSpacing,
		Target:          parameters.DifficultyAnchorTarget,
	}
	inclusion, _ := workgraph.InclusionRoot(nil)
	var previous *Earning
	var third Result
	for height := 0; height < 3; height++ {
		transactions := []outcome.Transaction(nil)
		if height == 0 {
			transactions = []outcome.Transaction{transaction}
		}
		payload, err := PreparePayload(current, position, previous, transactions, parameters)
		if err != nil {
			t.Fatalf("prepare height %d: %v", position.Height, err)
		}
		template, err := payload.SealTemplate(testAddress("fee-anchor"), inclusion, nil)
		if err != nil {
			t.Fatal(err)
		}
		anchor, anchorID, err := workgraph.MineAnchor(context.Background(), template, 0)
		if err != nil {
			t.Fatal(err)
		}
		block, result, err := payload.Finalize(anchor, nil)
		if err != nil {
			t.Fatal(err)
		}
		if block.Header.Version != parameters.VersionAt(position.Height) || result.State.CommitmentVersion() != parameters.CommitmentAt(position.Height) {
			t.Fatal("wrong scheduled commitment")
		}
		replay, err := ValidateAndExecute(current, position, previous, block, parameters)
		if err != nil || replay.State.Root() != result.State.Root() {
			t.Fatal("transition replay", err)
		}
		for _, receipt := range result.Receipts {
			if receipt.Version != receiptVersion(parameters.CommitmentAt(position.Height)) {
				t.Fatal("wrong receipt version")
			}
		}
		if block.Header.FeeAward != result.FeeAward {
			t.Fatal("header does not commit derived fee award")
		}
		if height == 0 && (result.Fees != 5 || result.FeeAward != 0 || result.FeeQueue.Balance() != 5) {
			t.Fatalf("fee deposit result=%+v", result)
		}
		if height == 2 {
			third = result
		}
		previous = &Earning{
			Seal: anchor, Shares: block.Shares, FeeAward: result.FeeAward,
			ParentTimestamp: position.ParentTimestamp, MedianTimePast: position.MedianTimePast,
		}
		current = result.State
		position = Position{
			Height: position.Height + 1, ParentID: anchorID,
			ParentTimestamp: position.Timestamp, MedianTimePast: position.Timestamp,
			Timestamp: position.Timestamp + parameters.TargetSpacing,
			Target:    parameters.DifficultyAnchorTarget, FeeQueue: result.FeeQueue,
		}
	}
	if third.FeeAward != 5 || third.FeeQueue.Balance() != 0 {
		t.Fatalf("mature fee award=%d queue_balance=%d", third.FeeAward, third.FeeQueue.Balance())
	}
	fourth, err := PreparePayload(current, position, previous, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if len(fourth.result.PayoutResources) != 1 {
		t.Fatalf("future fee payout resources=%d", len(fourth.result.PayoutResources))
	}
	anchorSubsidy, _, _ := workgraph.RewardRates(parameters.BlockSubsidy)
	if fourth.result.PayoutResources[0].Amount != anchorSubsidy+5 {
		t.Fatalf("future anchor payout=%d want=%d", fourth.result.PayoutResources[0].Amount, anchorSubsidy+5)
	}
}

func TestLaggedASERTLocksTargetBeforeCurrentTimestamp(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	parameters.DifficultyAnchorTarget = types.Hash{}
	parameters.DifficultyAnchorTarget[1] = 0x0f
	for index := 2; index < len(parameters.DifficultyAnchorTarget); index++ {
		parameters.DifficultyAnchorTarget[index] = 0xff
	}
	target, err := difficulty.ASERT(
		parameters.DifficultyAnchorTarget, parameters.DifficultyAnchorTimestamp, 1,
		parameters.DifficultyAnchorTimestamp+parameters.TargetSpacing,
		parameters.TargetSpacing, parameters.ASERTHalfLife,
	)
	if err != nil {
		t.Fatal(err)
	}
	base := Position{
		Height: 1, ParentID: types.DomainHash("test/workblock/lagged-parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp,
		MedianTimePast:  parameters.DifficultyAnchorTimestamp,
		Timestamp:       parameters.DifficultyAnchorTimestamp + 1,
		Target:          target,
	}
	early, err := PreparePayload(state.Empty(), base, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	latePosition := base
	latePosition.Timestamp += workgraph.MaxShareTimestampLead
	late, err := PreparePayload(state.Empty(), latePosition, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if early.header.Seal.Target != late.header.Seal.Target ||
		early.header.Seal.PayloadRoot != late.header.Seal.PayloadRoot {
		t.Fatal("current miner timestamp changed the precommitted target or executable payload")
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	invalidSeal, err := early.SealTemplate(testAddress("invalid-hard-proof"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	for {
		meets, err := workgraph.MeetsAnchor(invalidSeal)
		if err != nil {
			t.Fatal(err)
		}
		if !meets {
			break
		}
		invalidSeal.Nonce++
	}
	invalidHeader := early.header
	invalidHeader.Seal = invalidSeal
	if err := ValidateHeaderAt(base, invalidHeader, parameters, base.Timestamp); !errors.Is(err, workgraph.ErrProofOfWork) {
		t.Fatalf("invalid header-first hard proof error = %v", err)
	}
	forged := base
	forged.Target[0]++
	if _, err := PreparePayload(state.Empty(), forged, nil, nil, parameters); !errors.Is(err, ErrPosition) {
		t.Fatalf("miner-selected easier target error = %v", err)
	}
	changedParent := base
	changedParent.ParentTimestamp -= parameters.TargetSpacing * 10
	changedParent.MedianTimePast = changedParent.ParentTimestamp
	changedParent.Timestamp = changedParent.ParentTimestamp + 1
	changedTarget, err := difficulty.ASERT(
		parameters.DifficultyAnchorTarget, parameters.DifficultyAnchorTimestamp, changedParent.Height,
		changedParent.ParentTimestamp+parameters.TargetSpacing,
		parameters.TargetSpacing, parameters.ASERTHalfLife,
	)
	if err != nil {
		t.Fatal(err)
	}
	if changedTarget == target {
		t.Fatal("lagged ASERT did not react to the committed parent timestamp")
	}
	changedParent.Target = changedTarget
	if _, err := PreparePayload(state.Empty(), changedParent, nil, nil, parameters); err != nil {
		t.Fatalf("parent-derived target rejected: %v", err)
	}
}

func TestCompetingBranchesDoNotLeakOrRepeatDelayedPayouts(t *testing.T) {
	t.Parallel()

	parameters := testParameters()
	initialState := state.Empty()
	activation := Position{
		Height: parameters.ActivationHeight, ParentID: types.DomainHash("test/workblock/fork-parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp, MedianTimePast: parameters.DifficultyAnchorTimestamp,
		Timestamp: 1_700_001_000, Target: parameters.DifficultyAnchorTarget,
	}
	payload, err := PreparePayload(initialState, activation, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, resultA, earningA := buildActivationBranch(t, payload, inclusion, "branch-a")
	_, resultB, earningB := buildActivationBranch(t, payload, inclusion, "branch-b")
	if resultA.BlockID == resultB.BlockID || resultA.State.Root() != resultB.State.Root() {
		t.Fatal("competing activation blocks must have distinct IDs over the same pre-payout state")
	}
	positionA2 := Position{
		Height: activation.Height + 1, ParentID: resultA.BlockID,
		ParentTimestamp: activation.Timestamp, MedianTimePast: activation.Timestamp,
		Timestamp: activation.Timestamp + parameters.TargetSpacing, Target: parameters.DifficultyAnchorTarget,
		FeeQueue: resultA.FeeQueue,
	}
	positionB2 := positionA2
	positionB2.ParentID = resultB.BlockID
	positionB2.FeeQueue = resultB.FeeQueue
	payoutA, err := PreparePayload(resultA.State, positionA2, earningA, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	payoutB, err := PreparePayload(resultB.State, positionB2, earningB, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if payoutA.result.State.Root() == payoutB.result.State.Root() {
		t.Fatal("fork-specific delayed payouts unexpectedly produced one state root")
	}
	idsA := make(map[types.ResourceID]struct{}, len(payoutA.result.PayoutResources))
	for _, payout := range payoutA.result.PayoutResources {
		idsA[payout.ID] = struct{}{}
		if _, exists := payoutB.result.State.Get(payout.ID); exists {
			t.Fatal("abandoned branch payout leaked into competing branch state")
		}
	}
	for _, payout := range payoutB.result.PayoutResources {
		if _, exists := idsA[payout.ID]; exists {
			t.Fatal("fork-specific payout ID was reused by a competing anchor")
		}
		if _, exists := payoutA.result.State.Get(payout.ID); exists {
			t.Fatal("competing branch payout leaked into the first branch state")
		}
	}
	replayedA, err := PreparePayload(resultA.State, positionA2, earningA, nil, parameters)
	if err != nil || replayedA.result.State.Root() != payoutA.result.State.Root() {
		t.Fatalf("same branch replay is not deterministic: err=%v", err)
	}
	positionA3 := positionA2
	positionA3.Height++
	positionA3.ParentID = types.DomainHash("test/workblock/not-the-height-two-anchor")
	if _, err := PreparePayload(payoutA.result.State, positionA3, earningA, nil, parameters); !errors.Is(err, ErrPrevious) {
		t.Fatalf("height-one earning reused at height three: %v", err)
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	parameters := testParameters()
	position := Position{
		Height: parameters.ActivationHeight, ParentID: types.DomainHash("test/workblock/fuzz-parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp, MedianTimePast: parameters.DifficultyAnchorTimestamp,
		Timestamp: 1_700_002_000, Target: parameters.DifficultyAnchorTarget,
	}
	payload, err := PreparePayload(state.Empty(), position, nil, nil, parameters)
	if err != nil {
		f.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		f.Fatal(err)
	}
	template, err := payload.SealTemplate(testAddress("fuzz-anchor"), inclusion, nil)
	if err != nil {
		f.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		f.Fatal(err)
	}
	block, _, err := payload.Finalize(anchor, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(block.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := Decode(input)
		if err == nil && !bytes.Equal(decoded.CanonicalBytes(), input) {
			t.Fatal("successful decode did not preserve canonical bytes")
		}
	})
}

func TestGoldenVersion1BlockVector(t *testing.T) {
	parameters := testParameters()
	position := Position{
		Height: parameters.ActivationHeight, ParentID: types.DomainHash("test/workblock/golden-parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp, MedianTimePast: parameters.DifficultyAnchorTimestamp,
		Timestamp: 1_700_000_000, Target: parameters.DifficultyAnchorTarget,
	}
	payload, err := PreparePayload(state.Empty(), position, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	template, err := payload.SealTemplate(testAddress("golden-anchor"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	block, result, err := payload.Finalize(anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	const headerHex = "000100000000004d0000000000000001c03ea83b20b7f068ecf378fe3dde1662213fb410c87757e466b0314b05a0c14a000000006553f100007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffde688a7e3502cfc2ce9c832eee98e4cd3d107e0aafd1c5253a273e74f217f650ace6904f805047b8675a3129f84d0916fa60cfc9516bfca85033202e1a3852a7052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c0000000000000000e4c1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a84a725e151beb9dd0fba579c14cc511895301f6a632142e7294f88f783891222531199c8b262bb18f7820ba0f7c1156b81940f52cebb9c205c946f2e7b57ca020d44be30322640c368aff4cf516cd220bf70227f9f1558f65166116387cdd61ae0000000000000000"
	if got := hex.EncodeToString(block.Header.CanonicalBytes()); got != headerHex {
		t.Fatalf("canonical version-1 header = %s", got)
	}
	if got := hex.EncodeToString(block.CanonicalBytes()); got != headerHex+"0000" {
		t.Fatalf("canonical version-1 block = %s", got)
	}
	if result.BlockID.String() != "002fd4201ce8009bee8176585ab086affdb1a5b5e3b5ad77c7a29f76af3f0619" {
		t.Fatalf("version-1 block ID = %s", result.BlockID)
	}
	if len(block.Header.CanonicalBytes()) != 361 || len(block.CanonicalBytes()) != 363 {
		t.Fatalf("golden sizes header=%d block=%d", len(block.Header.CanonicalBytes()), len(block.CanonicalBytes()))
	}
}

func buildActivationBranch(
	t *testing.T,
	payload *Payload,
	inclusion types.Hash,
	label string,
) (Block, Result, *Earning) {
	t.Helper()
	shareTemplate, err := payload.SealTemplate(testAddress(label+"-share"), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	share, shareID, err := workgraph.Mine(context.Background(), shareTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	anchorTemplate, err := payload.SealTemplate(testAddress(label+"-anchor"), inclusion, []types.Hash{shareID})
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), anchorTemplate, 0)
	if err != nil {
		t.Fatal(err)
	}
	block, result, err := payload.Finalize(anchor, []workgraph.Share{share})
	if err != nil {
		t.Fatal(err)
	}
	return block, result, &Earning{
		Seal: anchor, Shares: block.Shares, FeeAward: result.FeeAward,
		ParentTimestamp: payload.position.ParentTimestamp, MedianTimePast: payload.position.MedianTimePast,
	}
}

func testParameters() Parameters {
	return Parameters{
		NetworkID: 77, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: 1_699_999_940, DifficultyAnchorTarget: testAnchorTarget(),
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
}

func testAddress(label string) types.Address {
	return types.Address(types.DomainHash("test/workblock/address", []byte(label)))
}

func testAnchorTarget() types.Hash {
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	return target
}
