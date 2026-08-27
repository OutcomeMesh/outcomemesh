package workgraphmodel

import (
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func TestHonestSharesAreProportionalAndProductionCapHasHeadroom(t *testing.T) {
	t.Parallel()

	config := Config{
		Rounds: 5_000, Seed: 0x6a09e667f3bcc909, ShareRatio: workgraph.ShareDifficultyRatio,
		MaxIncludedShares: workgraph.MaxShares, AverageShareBytes: 183, BlockSubsidy: 5_000_000_000,
		Miners: []Miner{{HashUnits: 70}, {HashUnits: 20}, {HashUnits: 10}},
	}
	result, err := Run(config)
	if err != nil {
		t.Fatal(err)
	}
	if result.OverflowRounds != 0 || result.CanonicalAnchors != uint64(config.Rounds) {
		t.Fatalf("unexpected cap/orphan result: %+v", result)
	}
	t.Logf("honest rounds=%d shares=%d max_round=%d bytes=%d overflow=%d issuance=%d schedule=%d",
		result.Rounds, result.IncludedShares, result.MaxPublishedInRound, result.IncludedBytes,
		result.OverflowRounds, result.IssuedSubsidy, result.ScheduledSubsidy)
	wantAverage := uint64(workgraph.ShareDifficultyRatio - 1)
	average := result.IncludedShares / result.CanonicalAnchors
	if average < wantAverage*9/10 || average > wantAverage*11/10 {
		t.Fatalf("average shares/anchor = %d, want near %d", average, wantAverage)
	}
	if result.IncludedBytes/result.CanonicalAnchors > 128<<10 {
		t.Fatalf("average WorkGraph bytes/anchor = %d", result.IncludedBytes/result.CanonicalAnchors)
	}
	if result.IssuedSubsidy*100 < result.ScheduledSubsidy*98 ||
		result.IssuedSubsidy*100 > result.ScheduledSubsidy*102 {
		t.Fatalf("honest issuance=%d schedule=%d", result.IssuedSubsidy, result.ScheduledSubsidy)
	}
	var totalHash uint64 = 100
	for index, miner := range config.Miners {
		deviation, err := DeviationPPM(result.Miners[index].RewardedShares, result.IncludedShares, miner.HashUnits, totalHash)
		if err != nil {
			t.Fatal(err)
		}
		if deviation > 20_000 {
			t.Fatalf("miner %d proportional deviation = %d ppm", index, deviation)
		}
	}
}

func TestWithholdingLosesShareCreditWithoutChangingHashOwnership(t *testing.T) {
	t.Parallel()

	config := Config{
		Rounds: 5_000, Seed: 0xbb67ae8584caa73b, ShareRatio: 64,
		MaxIncludedShares: workgraph.MaxShares, AverageShareBytes: 183,
		AnchorOrphanPPM: 100_000,
		Miners:          []Miner{{HashUnits: 50, WithholdPPM: 500_000}, {HashUnits: 50}},
	}
	result, err := Run(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("withholding withholder=%+v honest=%+v orphans=%d", result.Miners[0], result.Miners[1], result.OrphanAnchors)
	withholder := result.Miners[0]
	honest := result.Miners[1]
	if withholder.DiscoveredShares*9/10 > honest.DiscoveredShares || withholder.DiscoveredShares < honest.DiscoveredShares*9/10 {
		t.Fatalf("equal hash did not discover comparable work: withholder=%+v honest=%+v", withholder, honest)
	}
	if withholder.RewardedShares*3 > honest.RewardedShares*2 {
		t.Fatalf("50%% withholding retained too much share credit: withholder=%d honest=%d", withholder.RewardedShares, honest.RewardedShares)
	}
	if withholder.AnchorWins*9/10 > honest.AnchorWins || withholder.AnchorWins < honest.AnchorWins*9/10 {
		t.Fatalf("share withholding changed anchor ownership: withholder=%d honest=%d", withholder.AnchorWins, honest.AnchorWins)
	}
	if result.OrphanAnchors < 400 || result.OrphanAnchors > 600 {
		t.Fatalf("orphan anchors = %d, want near 500", result.OrphanAnchors)
	}
}

func TestUndersizedCapProducesMeasurableOverflow(t *testing.T) {
	t.Parallel()

	result, err := Run(Config{
		Rounds: 2_000, Seed: 0x3c6ef372fe94f82b, ShareRatio: workgraph.ShareDifficultyRatio,
		MaxIncludedShares: 2_048, AverageShareBytes: 183, Miners: []Miner{{HashUnits: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("undersized_cap overflow_rounds=%d max_round=%d", result.OverflowRounds, result.MaxPublishedInRound)
	if result.OverflowRounds < 20 {
		t.Fatalf("fourfold cap overflowed only %d/2000 rounds; expected geometric tail near 1.8%%", result.OverflowRounds)
	}
}

func TestCompetingPayloadTemplatesLoseOtherwiseValidShareWork(t *testing.T) {
	t.Parallel()

	result, err := Run(Config{
		Rounds: 5_000, Seed: 0xa54ff53a5f1d36f1, ShareRatio: 64,
		MaxIncludedShares: workgraph.MaxShares, AverageShareBytes: 183,
		Miners: []Miner{{HashUnits: 50, Template: 1}, {HashUnits: 50, Template: 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var published uint64
	for _, miner := range result.Miners {
		published += miner.PublishedShares
	}
	if result.TemplateMismatchShares < published*4/10 || result.TemplateMismatchShares > published*6/10 {
		t.Fatalf("template mismatch shares=%d published=%d", result.TemplateMismatchShares, published)
	}
	if result.IncludedShares+result.TemplateMismatchShares != published {
		t.Fatalf("template accounting included=%d mismatch=%d published=%d", result.IncludedShares, result.TemplateMismatchShares, published)
	}
	t.Logf("split_templates included=%d mismatched=%d", result.IncludedShares, result.TemplateMismatchShares)
}

func TestFixedRatesTrackHonestScheduleAndBurnFragmentedWork(t *testing.T) {
	t.Parallel()

	result, err := Run(Config{
		Rounds: 2_000, Seed: 0x9b05688c2b3e6c1f, ShareRatio: workgraph.ShareDifficultyRatio,
		MaxIncludedShares: workgraph.MaxShares, AverageShareBytes: 183, BlockSubsidy: 5_000_000_000,
		Miners: []Miner{{HashUnits: 50, Template: 1}, {HashUnits: 50, Template: 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IssuedSubsidy*100 < result.ScheduledSubsidy*70 ||
		result.IssuedSubsidy*100 > result.ScheduledSubsidy*80 {
		t.Fatalf("split-template issuance=%d schedule=%d", result.IssuedSubsidy, result.ScheduledSubsidy)
	}
	t.Logf("fixed_rate_fragmentation issued=%d schedule=%d", result.IssuedSubsidy, result.ScheduledSubsidy)
}

func TestRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := Run(Config{}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("empty configuration error = %v", err)
	}
}
