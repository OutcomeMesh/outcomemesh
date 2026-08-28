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
		len(document.Result.TrailDepths) != int(MaxTrailDepth) ||
		len(document.Result.FeeFragmentation.Points) != 72 ||
		document.Result.RejectedGlobalTie != (GlobalTieBreakGrindingResult{
			PotentialRaces: 10_000, PublishedRaces: 4_959, SuppressedRaces: 5_041,
			PublishedAdoptions: 4_959, FavorableIDPPM: 495_900, PublishedAdoptionPPM: 1_000_000,
		}) {
		t.Fatalf("review dimensions: selfish=%d trail_depths=%d fees=%d global_tie=%+v",
			len(document.Result.SelfishMining.Points), len(document.Result.TrailDepths),
			len(document.Result.FeeFragmentation.Points), document.Result.RejectedGlobalTie)
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
	for index, trail := range document.Result.TrailDepths {
		wantDepth := uint8(index + 1)
		wantTrail := activationTrailThresholds(wantDepth)
		if trail.Depth != wantDepth || !reflect.DeepEqual(trail.Sweep.Thresholds, wantTrail) ||
			len(trail.Sweep.Points) != 155 {
			t.Fatalf("trail depth %d result:\n got: %+v\nwant thresholds: %+v",
				wantDepth, trail, wantTrail)
		}
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "8d20c51d815a2149d505b361b14840c087e587fdcdaa203060a9ff1c69c3bc16"
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("review digest = %s, want %s", got, wantDigest)
	}
	invalid := document
	invalid.Schema = ""
	if _, err := invalid.CanonicalJSON(); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("invalid review schema error = %v, want ErrConfiguration", err)
	}
	t.Logf("selfish_thresholds=%+v", document.Result.SelfishMining.Thresholds)
	for _, trail := range document.Result.TrailDepths {
		t.Logf("trail_depth_%d_thresholds=%+v", trail.Depth, trail.Sweep.Thresholds)
	}
	t.Logf("fee_thresholds=%+v", document.Result.FeeFragmentation.Thresholds)
	t.Logf("review_sha256=%s", hex.EncodeToString(digest[:]))
}

func activationTrailThresholds(depth uint8) []SelfishProfitThreshold {
	values := map[uint8][]uint32{
		1: {370_000, 330_000, 270_000, 230_000, 160_000},
		2: {380_000, 340_000, 310_000, 250_000, 160_000},
		3: {380_000, 360_000, 330_000, 250_000, 160_000},
		4: {400_000, 380_000, 360_000, 250_000, 160_000},
	}
	hashes := values[depth]
	ties := []uint32{0, 250_000, 500_000, 750_000, 1_000_000}
	result := make([]SelfishProfitThreshold, len(ties))
	for index, tie := range ties {
		result[index] = SelfishProfitThreshold{
			TieAdoptionPPM: tie, FirstProfitableHashPPM: hashes[index], Found: true,
		}
	}
	return result
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
