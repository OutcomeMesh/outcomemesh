package workgraphmodel

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func TestActivationReviewCorpus(t *testing.T) {
	document, err := RunActivationReview(CanonicalActivationReviewConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Result.SelfishMining.Points) != 155 ||
		len(document.Result.FeeFragmentation.Points) != 72 {
		t.Fatalf("review dimensions: selfish=%d fees=%d",
			len(document.Result.SelfishMining.Points), len(document.Result.FeeFragmentation.Points))
	}
	wantSelfish := []SelfishProfitThreshold{
		{TieAdoptionPPM: 0, FirstProfitableHashPPM: 340_000, Found: true},
		{TieAdoptionPPM: 250_000, FirstProfitableHashPPM: 330_000, Found: true},
		{TieAdoptionPPM: 500_000, FirstProfitableHashPPM: 270_000, Found: true},
		{TieAdoptionPPM: 750_000, FirstProfitableHashPPM: 230_000, Found: true},
		{TieAdoptionPPM: 1_000_000, FirstProfitableHashPPM: 160_000, Found: true},
	}
	if !reflect.DeepEqual(document.Result.SelfishMining.Thresholds, wantSelfish) {
		t.Fatalf("selfish thresholds:\n got: %+v\nwant: %+v",
			document.Result.SelfishMining.Thresholds, wantSelfish)
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "083a21ff5b3e06a9cddcf5f00203e4ec173b35f1bffed71ebeb70af7b9c0fd2c"
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("review digest = %s, want %s", got, wantDigest)
	}
	invalid := document
	invalid.Schema = ""
	if _, err := invalid.CanonicalJSON(); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("invalid review schema error = %v, want ErrConfiguration", err)
	}
	t.Logf("selfish_thresholds=%+v", document.Result.SelfishMining.Thresholds)
	t.Logf("fee_thresholds=%+v", document.Result.FeeFragmentation.Thresholds)
	t.Logf("review_sha256=%s", hex.EncodeToString(digest[:]))
}

func TestFeeFragmentationSweepActivationGrid(t *testing.T) {
	t.Parallel()

	result, err := RunFeeFragmentationSweep(activationFeeSweepConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantThresholds := []FeeFragmentationThreshold{
		{MinerHashPPM: 10_000, DirectFirstFee: 2_500_000_000, DirectFound: true, SmoothedFirstFee: 250_000_000_000, SmoothedFound: true},
		{MinerHashPPM: 50_000, DirectFirstFee: 2_500_000_000, DirectFound: true, SmoothedFirstFee: 50_000_000_000, SmoothedFound: true},
		{MinerHashPPM: 100_000, DirectFirstFee: 2_500_000_000, DirectFound: true, SmoothedFirstFee: 25_000_000_000, SmoothedFound: true},
		{MinerHashPPM: 200_000, DirectFirstFee: 2_000_000_000, DirectFound: true, SmoothedFirstFee: 10_000_000_000, SmoothedFound: true},
		{MinerHashPPM: 300_000, DirectFirstFee: 2_000_000_000, DirectFound: true, SmoothedFirstFee: 6_000_000_000, SmoothedFound: true},
		{MinerHashPPM: 400_000, DirectFirstFee: 2_000_000_000, DirectFound: true, SmoothedFirstFee: 4_000_000_000, SmoothedFound: true},
	}
	if !reflect.DeepEqual(result.Thresholds, wantThresholds) {
		t.Fatalf("fragmentation thresholds:\n got: %+v\nwant: %+v", result.Thresholds, wantThresholds)
	}
	if len(result.Points) != 72 {
		t.Fatalf("point count = %d, want 72", len(result.Points))
	}

	directPoint := feeSweepPoint(t, result, 100_000, 3_000_000_000)
	if !directPoint.DirectFragmented || directPoint.SmoothedFragmented ||
		directPoint.DirectIncludedSharePPM != 820_000 ||
		directPoint.SmoothedIncludedSharePPM != uint64(PartsPerMillion) {
		t.Fatalf("10%%/3 coin point = %+v", directPoint)
	}
	smoothedPoint := feeSweepPoint(t, result, 100_000, 25_000_000_000)
	if !smoothedPoint.DirectFragmented || !smoothedPoint.SmoothedFragmented ||
		smoothedPoint.DirectIncludedSharePPM != 820_000 ||
		smoothedPoint.SmoothedIncludedSharePPM != 820_000 {
		t.Fatalf("10%%/25 coin point = %+v", smoothedPoint)
	}
	t.Logf("fee_fragmentation_thresholds=%+v", result.Thresholds)
}

func TestFeeFragmentationSweepRejectsNonCanonicalOrUnboundedGrid(t *testing.T) {
	t.Parallel()

	tests := []FeeFragmentationSweepConfig{
		{},
		{
			BlockSubsidy:  5_000_000_000,
			HashSharesPPM: []uint32{100_000, 100_000},
			PrivateFees:   []uint64{1}, MaxPasses: 1,
		},
		{
			BlockSubsidy:  5_000_000_000,
			HashSharesPPM: []uint32{100_000},
			PrivateFees:   []uint64{2, 1}, MaxPasses: 1,
		},
		{
			BlockSubsidy:  5_000_000_000,
			HashSharesPPM: make([]uint32, MaxFeeSweepHashShares),
			PrivateFees:   make([]uint64, MaxFeeSweepFees), MaxPasses: 1,
		},
	}
	for index, config := range tests {
		if _, err := RunFeeFragmentationSweep(config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("case %d error = %v, want ErrConfiguration", index, err)
		}
	}
}

func activationFeeSweepConfig() FeeFragmentationSweepConfig {
	return CanonicalActivationReviewConfig().FeeFragmentation
}

func feeSweepPoint(
	t *testing.T,
	result FeeFragmentationSweepResult,
	hashShare uint32,
	privateFee uint64,
) FeeFragmentationPoint {
	t.Helper()
	for _, point := range result.Points {
		if point.MinerHashPPM == hashShare && point.PrivateFee == privateFee {
			return point
		}
	}
	t.Fatalf("missing point hash=%d fee=%d", hashShare, privateFee)
	return FeeFragmentationPoint{}
}
