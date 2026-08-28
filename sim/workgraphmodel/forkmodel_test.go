package workgraphmodel

import "testing"

func TestImmediatePublicationTracksHashShareWithoutForkDuplicates(t *testing.T) {
	t.Parallel()

	result, err := RunSelfish(testSelfishConfig(250_000, false))
	if err != nil {
		t.Fatal(err)
	}
	share, err := RewardSharePPM(result.AttackerReward, result.HonestReward)
	if err != nil {
		t.Fatal(err)
	}
	if result.OrphanAnchors != 0 || result.CanonicalBlocks != result.HardDiscoveries ||
		result.IncludedShares > result.DiscoveredShares || share < 240_000 || share > 260_000 {
		t.Fatalf("honest publication result=%+v reward_share=%d", result, share)
	}
	t.Logf("publish_now reward_ppm=%d canonical=%d shares=%d", share, result.CanonicalBlocks, result.IncludedShares)
}

func TestQuarterHashSelfishStrategyDoesNotBeatImmediatePublication(t *testing.T) {
	t.Parallel()

	baselineConfig := testSelfishConfig(250_000, false)
	selfishConfig := baselineConfig
	selfishConfig.WithholdAnchors = true
	baseline, err := RunSelfish(baselineConfig)
	if err != nil {
		t.Fatal(err)
	}
	selfish, err := RunSelfish(selfishConfig)
	if err != nil {
		t.Fatal(err)
	}
	baselineShare, _ := RewardSharePPM(baseline.AttackerReward, baseline.HonestReward)
	selfishShare, _ := RewardSharePPM(selfish.AttackerReward, selfish.HonestReward)
	if selfishShare > baselineShare+5_000 || selfish.OrphanAnchors == 0 {
		t.Fatalf("25%% selfish strategy unexpectedly profitable baseline=%d selfish=%d result=%+v",
			baselineShare, selfishShare, selfish)
	}
	t.Logf("selfish_25 baseline_ppm=%d selfish_ppm=%d orphans=%d", baselineShare, selfishShare, selfish.OrphanAnchors)
}

func TestThirtyFivePercentSelfishStrategyWithTieAdoptionIsProfitable(t *testing.T) {
	t.Parallel()

	baselineConfig := testSelfishConfig(350_000, false)
	baselineConfig.TieAdoptionPPM = 500_000
	selfishConfig := baselineConfig
	selfishConfig.WithholdAnchors = true
	baseline, err := RunSelfish(baselineConfig)
	if err != nil {
		t.Fatal(err)
	}
	selfish, err := RunSelfish(selfishConfig)
	if err != nil {
		t.Fatal(err)
	}
	baselineShare, _ := RewardSharePPM(baseline.AttackerReward, baseline.HonestReward)
	selfishShare, _ := RewardSharePPM(selfish.AttackerReward, selfish.HonestReward)
	if selfishShare <= baselineShare+10_000 || selfish.OrphanAnchors == 0 {
		t.Fatalf("35%% selfish strategy did not gain baseline=%d selfish=%d result=%+v",
			baselineShare, selfishShare, selfish)
	}
	t.Logf("selfish_35 baseline_ppm=%d selfish_ppm=%d orphans=%d", baselineShare, selfishShare, selfish.OrphanAnchors)
}

func TestOmittingHonestSharesCannotIncreaseAttackerAbsoluteReward(t *testing.T) {
	t.Parallel()

	includeConfig := testSelfishConfig(350_000, true)
	includeConfig.TieAdoptionPPM = 500_000
	omitConfig := includeConfig
	omitConfig.OmitHonestShares = true
	included, err := RunSelfish(includeConfig)
	if err != nil {
		t.Fatal(err)
	}
	omitted, err := RunSelfish(omitConfig)
	if err != nil {
		t.Fatal(err)
	}
	if omitted.AttackerReward != included.AttackerReward || omitted.HonestReward >= included.HonestReward ||
		omitted.TotalIssued >= included.TotalIssued {
		t.Fatalf("omission changed winner absolute reward incorrectly include=%+v omit=%+v", included, omitted)
	}
	t.Logf("omission attacker_reward=%d honest_include=%d honest_omit=%d issued_include=%d issued_omit=%d",
		included.AttackerReward, included.HonestReward, omitted.HonestReward,
		included.TotalIssued, omitted.TotalIssued)
}

func TestOneBlockTrailRetryPreservesAccounting(t *testing.T) {
	t.Parallel()

	standardConfig := testSelfishConfig(250_000, true)
	standardConfig.TieAdoptionPPM = 500_000
	trailConfig := standardConfig
	trailConfig.TrailRetry = true
	standard, err := RunSelfish(standardConfig)
	if err != nil {
		t.Fatal(err)
	}
	trail, err := RunSelfish(trailConfig)
	if err != nil {
		t.Fatal(err)
	}
	standardShare, err := RewardSharePPM(standard.AttackerReward, standard.HonestReward)
	if err != nil {
		t.Fatal(err)
	}
	trailShare, err := RewardSharePPM(trail.AttackerReward, trail.HonestReward)
	if err != nil {
		t.Fatal(err)
	}
	if standardShare != 256_406 || trailShare != 256_770 ||
		standard.OrphanAnchors != 1_814 || trail.OrphanAnchors != 1_809 ||
		trail.IncludedShares > trail.DiscoveredShares ||
		trail.CanonicalBlocks+trail.OrphanAnchors > trail.HardDiscoveries ||
		trail.OrphanAnchors == 0 {
		t.Fatalf("trail accounting result=%+v", trail)
	}
	t.Logf("trail_retry standard_ppm=%d trail_ppm=%d standard_orphans=%d trail_orphans=%d standard_unresolved=%d trail_unresolved=%d",
		standardShare, trailShare, standard.OrphanAnchors, trail.OrphanAnchors,
		standard.UnresolvedPrivateLead, trail.UnresolvedPrivateLead)
}

func TestTrailRetryRequiresWithholding(t *testing.T) {
	t.Parallel()

	config := testSelfishConfig(250_000, false)
	config.TrailRetry = true
	if _, err := RunSelfish(config); err != ErrConfiguration {
		t.Fatalf("trail without withholding error = %v, want ErrConfiguration", err)
	}
}

func FuzzRunSelfishStrategiesNeverBreakAccounting(f *testing.F) {
	f.Add(uint64(1), uint32(250_000), uint32(500_000), uint16(32), byte(0b0111))
	f.Add(uint64(0xcbbb9d5dc1059ed8), uint32(450_000), uint32(0), uint16(16), byte(0b0011))
	f.Fuzz(func(
		t *testing.T,
		seed uint64,
		attackerHash uint32,
		tieAdoption uint32,
		discoveries uint16,
		flags byte,
	) {
		attackerHash = attackerHash%999_999 + 1
		tieAdoption %= uint32(PartsPerMillion) + 1
		withhold := flags&1 != 0
		config := SelfishConfig{
			HardDiscoveries:  int(discoveries%32) + 1,
			Seed:             seed,
			ShareRatio:       512,
			AttackerHashPPM:  attackerHash,
			TieAdoptionPPM:   tieAdoption,
			BlockSubsidy:     5_000_000_000,
			FeesPerBlock:     100_000,
			WithholdAnchors:  withhold,
			TrailRetry:       withhold && flags&2 != 0,
			OmitHonestShares: flags&4 != 0,
		}
		if _, err := RunSelfish(config); err != nil {
			t.Fatalf("valid bounded strategy config failed: %+v: %v", config, err)
		}
	})
}

func testSelfishConfig(attackerHash uint32, withhold bool) SelfishConfig {
	return SelfishConfig{
		HardDiscoveries: 10_000,
		Seed:            0xcbbb9d5dc1059ed8,
		ShareRatio:      512,
		AttackerHashPPM: attackerHash,
		BlockSubsidy:    5_000_000_000,
		FeesPerBlock:    100_000,
		WithholdAnchors: withhold,
	}
}
