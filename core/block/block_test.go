package block

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/guardvm"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func easyTarget() types.Hash {
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	return target
}

func testParent() Parent {
	return Parent{
		ID:             types.DomainHash("test/block/parent"),
		Height:         0,
		Timestamp:      1_700_000_000,
		MedianTimePast: 1_700_000_000,
		Target:         easyTarget(),
	}
}

func testMiner() types.Address {
	return types.Address(types.DomainHash("test/block/miner"))
}

func testParameters(networkID uint32) Parameters {
	parent := testParent()
	return Parameters{
		NetworkID:       networkID,
		BlockSubsidy:    50,
		AnchorTimestamp: parent.Timestamp,
		AnchorTarget:    parent.Target,
		TargetSpacing:   1,
		ASERTHalfLife:   DefaultASERTHalfLife,
		RewardMaturity:  DefaultRewardMaturity,
	}
}

func TestPrepareMineValidateEmptyBlock(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parameters := testParameters(9)
	candidate, prepared, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, minedID, err := Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ValidateAndExecuteAt(state.Empty(), parent, mined, parameters, mined.Header.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if result.BlockID != minedID {
		t.Fatalf("block ID: got %s want %s", result.BlockID, minedID)
	}
	if result.FinalRoot != prepared.FinalRoot {
		t.Fatalf("root: got %s want %s", result.FinalRoot, prepared.FinalRoot)
	}
	if balance, err := result.State.Balance(testMiner(), types.NativeAssetID()); err != nil || balance != 50 {
		t.Fatalf("miner balance = %d, %v; want 50", balance, err)
	}
	if result.Reward.SpendAfter != 1+parameters.RewardMaturity {
		t.Fatalf("reward spend-after = %d, want %d", result.Reward.SpendAfter, 1+parameters.RewardMaturity)
	}
	decoded, err := Decode(mined.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.CanonicalBytes()) != string(mined.CanonicalBytes()) {
		t.Fatal("block changed during canonical round trip")
	}
	const canonicalHex = "0000000000090000000000000001243fc993547ba2a9ffab93a9e926f91977e2b8fcfc15bd6b4e7a822e0ba77770000000006553f101ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a838f137f4680f1bb8da88e859511438286cbdda3b926c08907d158a6a6b2154a6ed7b941fc24bf386993c2db1dd82afaa552bfc358c1230d7d0bec36edf1769f7000000000000000000"
	if got := hex.EncodeToString(mined.CanonicalBytes()); got != canonicalHex {
		t.Fatalf("canonical block changed:\n got %s\nwant %s", got, canonicalHex)
	}
	if got, want := minedID.String(), "8c63485ab8a8a8fcf43d69b0fbd938133112185fe47a0cc93a52366f9d225874"; got != want {
		t.Fatalf("block ID changed: got %s want %s", got, want)
	}
	if got, want := mined.Header.TxRoot.String(), "c1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da8"; got != want {
		t.Fatalf("transaction root changed: got %s want %s", got, want)
	}
	if got, want := mined.Header.ReceiptRoot.String(), "6672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a8"; got != want {
		t.Fatalf("receipt root changed: got %s want %s", got, want)
	}
	if got, want := mined.Header.StateRoot.String(), "38f137f4680f1bb8da88e859511438286cbdda3b926c08907d158a6a6b2154a6"; got != want {
		t.Fatalf("block state root changed: got %s want %s", got, want)
	}
}

func TestBlockExecutesTransactionAndCreditsFees(t *testing.T) {
	t.Parallel()

	preState, transaction := testTransaction(t)
	parent := testParent()
	parameters := testParameters(transaction.NetworkID)
	candidate, _, err := Prepare(preState, parent, []outcome.Transaction{transaction}, testMiner(), parent.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ValidateAndExecuteAt(preState, parent, mined, parameters, mined.Header.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if result.Fees != transaction.Fee || result.Reward.Amount != parameters.BlockSubsidy+transaction.Fee {
		t.Fatalf("fees=%d reward=%d", result.Fees, result.Reward.Amount)
	}
	txID, err := transaction.ID()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Receipts) != 1 || result.Receipts[0].TxID != txID {
		t.Fatal("missing transaction receipt")
	}
	if result.State.Len() != 3 {
		t.Fatalf("post-state resources = %d, want 3", result.State.Len())
	}
}

func TestValidateRejectsCommittedRootMismatch(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parameters := testParameters(9)
	candidate, _, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Header.StateRoot[0] ^= 0xff
	_, err = ValidateAndExecuteAt(state.Empty(), parent, candidate, parameters, candidate.Header.Timestamp)
	if !errors.Is(err, ErrStateRoot) {
		t.Fatalf("got %v, want state-root mismatch", err)
	}
}

func TestValidateRejectsUnexpectedASERTTarget(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parameters := testParameters(9)
	candidate, _, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Header.Target[31] ^= 1
	if _, err := ValidateAndExecuteAt(state.Empty(), parent, candidate, parameters, candidate.Header.Timestamp); !errors.Is(err, ErrUnexpectedTarget) {
		t.Fatalf("got %v, want unexpected target", err)
	}
}

func TestValidateRejectsForeignNetworkEvenWithValidProof(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parameters := testParameters(9)
	candidate, _, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Header.NetworkID++
	if _, err := ValidateAndExecuteAt(state.Empty(), parent, candidate, parameters, candidate.Header.Timestamp); !errors.Is(err, ErrUnexpectedNetwork) {
		t.Fatalf("foreign network error = %v", err)
	}
}

func TestHeaderHasFixedCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	candidate, _, err := Prepare(state.Empty(), testParent(), nil, testMiner(), testParent().Timestamp+1, testParameters(9))
	if err != nil {
		t.Fatal(err)
	}
	encoded := candidate.Header.CanonicalBytes()
	if len(encoded) != HeaderCanonicalBytes {
		t.Fatalf("header length = %d, want %d", len(encoded), HeaderCanonicalBytes)
	}
	decoded, err := DecodeHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != candidate.Header {
		t.Fatal("header changed during canonical round trip")
	}
	if _, err := DecodeHeader(append(encoded, 0)); !errors.Is(err, ErrBlockSize) {
		t.Fatalf("trailing header byte error = %v", err)
	}
}

func TestMedianTimePastAllowsTimestampBelowDirectParent(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parent.MedianTimePast = parent.Timestamp - 100
	parameters := testParameters(9)
	timestamp := parent.Timestamp - 50
	candidate, _, err := Prepare(state.Empty(), parent, nil, testMiner(), timestamp, parameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAndExecuteAt(state.Empty(), parent, mined, parameters, timestamp); err != nil {
		t.Fatalf("valid median-time-past block rejected: %v", err)
	}

	if _, _, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.MedianTimePast, parameters); !errors.Is(err, ErrMedianTimePast) {
		t.Fatalf("got %v, want median-time-past rejection", err)
	}
}

func TestFutureTimestampBound(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parameters := testParameters(9)
	candidate, _, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.Timestamp+1, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAndExecuteAt(state.Empty(), parent, candidate, parameters, candidate.Header.Timestamp-MaxFutureDrift); err != nil {
		t.Fatalf("future-boundary block rejected: %v", err)
	}
	if _, err := ValidateAndExecuteAt(state.Empty(), parent, candidate, parameters, candidate.Header.Timestamp-MaxFutureDrift-1); !errors.Is(err, ErrFutureTimestamp) {
		t.Fatalf("got %v, want future timestamp rejection", err)
	}
}

func TestPrepareRejectsRewardCollision(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parameters := testParameters(9)
	reward := resource.Resource{
		ID:      RewardID(parameters.NetworkID, 1, parent.ID, testMiner()),
		Version: resource.Version0,
		Owner:   testMiner(),
		Asset:   types.NativeAssetID(),
		Amount:  1,
	}
	preState, err := state.New([]resource.Resource{reward})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Prepare(preState, parent, nil, testMiner(), parent.Timestamp+1, parameters); !errors.Is(err, ErrRewardCollision) {
		t.Fatalf("got %v, want reward collision", err)
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	parent := testParent()
	candidate, _, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.Timestamp+1, testParameters(9))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append(candidate.CanonicalBytes(), 0)); err == nil {
		t.Fatal("decoder accepted trailing bytes")
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	parent := testParent()
	candidate, _, err := Prepare(state.Empty(), parent, nil, testMiner(), parent.Timestamp+1, testParameters(9))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(candidate.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Decode(input)
	})
}

func testTransaction(t testing.TB) (*state.Memory, outcome.Transaction) {
	t.Helper()
	seed := types.DomainHash("test/block/private-key")
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	input := resource.Resource{
		ID:      types.ResourceID(types.DomainHash("test/block/input")),
		Version: resource.Version0,
		Owner:   owner,
		Asset:   types.NativeAssetID(),
		Amount:  1_000,
	}
	preState, err := state.New([]resource.Resource{input})
	if err != nil {
		t.Fatal(err)
	}
	recipient := types.Address(types.DomainHash("test/block/recipient"))
	transaction := outcome.Transaction{
		Version:   outcome.Version0,
		NetworkID: 9,
		Inputs:    []resource.Ref{{ID: input.ID, Version: input.Version}},
		Outputs: []resource.Output{
			{Owner: recipient, Asset: input.Asset, Amount: 900},
			{Owner: owner, Asset: input.Asset, Amount: 95},
		},
		Guard:      guardvm.Program{Version: guardvm.Version0, Instructions: []guardvm.Instruction{{Op: guardvm.OpHalt}}},
		Fee:        5,
		ValidUntil: 100,
		Nonce:      [32]byte{7},
	}
	if err := transaction.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return preState, transaction
}
