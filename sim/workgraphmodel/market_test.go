package workgraphmodel

import (
	"errors"
	"testing"
)

func TestTemplateMarketLowPrivateFeePreservesCommonPayload(t *testing.T) {
	t.Parallel()

	config := privateFeeMarket(500_000_000)
	result, err := RunTemplateMarket(config)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Stable || result.Switches != 0 || result.TemplateHashUnits[0] != 10 ||
		result.ExpectedIncludedSharePPM != uint64(PartsPerMillion) ||
		result.ExpectedSubsidyPPMOfSchedule != uint64(PartsPerMillion) {
		t.Fatalf("low private fee fragmented common payload: %+v", result)
	}
	t.Logf("market_low_fee inclusion_ppm=%d attacker_reward_ppm=%d",
		result.ExpectedIncludedSharePPM, result.MinerRewardPPM[0])
}

func TestTemplateMarketHighPrivateFeeCausesMeasurableFragmentation(t *testing.T) {
	t.Parallel()

	config := privateFeeMarket(3_000_000_000)
	result, err := RunTemplateMarket(config)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Stable || result.Assignments[0] != 1 || result.TemplateHashUnits[0] != 9 ||
		result.TemplateHashUnits[1] != 1 || result.ExpectedIncludedSharePPM != 820_000 ||
		result.ExpectedSubsidyPPMOfSchedule < 909_999 ||
		result.ExpectedSubsidyPPMOfSchedule > 910_001 || result.ExpectedFeesPerAnchor != 300_000_000 {
		t.Fatalf("high private fee market result: %+v", result)
	}
	if result.MinerRewardPPM[0] <= 100_000 {
		t.Fatalf("private fee did not motivate miner: %+v", result)
	}
	t.Logf("market_high_fee inclusion_ppm=%d subsidy_ppm=%d expected_fees=%d attacker_reward_ppm=%d",
		result.ExpectedIncludedSharePPM, result.ExpectedSubsidyPPMOfSchedule,
		result.ExpectedFeesPerAnchor, result.MinerRewardPPM[0])
}

func TestTemplateMarketSmoothedFeesPreventTestedPrivateFragmentation(t *testing.T) {
	t.Parallel()

	config := privateFeeMarket(3_000_000_000)
	config.SmoothFees = true
	result, err := RunTemplateMarket(config)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Stable || result.Switches != 0 || result.TemplateHashUnits[0] != 10 ||
		result.ExpectedIncludedSharePPM != uint64(PartsPerMillion) ||
		result.ExpectedSubsidyPPMOfSchedule != uint64(PartsPerMillion) {
		t.Fatalf("smoothed fees fragmented common payload: %+v", result)
	}
	t.Logf("market_smoothed_fee inclusion_ppm=%d attacker_reward_ppm=%d",
		result.ExpectedIncludedSharePPM, result.MinerRewardPPM[0])
}

func TestTemplateMarketNetworkEffectConvergesSplitEqualFeeTemplates(t *testing.T) {
	t.Parallel()

	miners := make([]MarketMiner, 10)
	for index := range miners {
		miners[index] = MarketMiner{
			HashUnits: 1, InitialTemplate: index / 5, AllowedTemplates: []int{0, 1},
		}
	}
	result, err := RunTemplateMarket(MarketConfig{
		BlockSubsidy: 5_000_000_000,
		Templates:    []MarketTemplate{{}, {}},
		Miners:       miners,
		MaxPasses:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Stable || result.ExpectedIncludedSharePPM != uint64(PartsPerMillion) ||
		(result.TemplateHashUnits[0] != 10 && result.TemplateHashUnits[1] != 10) {
		t.Fatalf("equal-fee templates did not converge: %+v", result)
	}
	t.Logf("market_coordination assignments=%v switches=%d passes=%d",
		result.Assignments, result.Switches, result.Passes)
}

func TestTemplateMarketRejectsUnavailableInitialTemplate(t *testing.T) {
	t.Parallel()

	_, err := RunTemplateMarket(MarketConfig{
		BlockSubsidy: 5_000_000_000,
		Templates:    []MarketTemplate{{}, {}},
		Miners: []MarketMiner{{
			HashUnits: 1, InitialTemplate: 1, AllowedTemplates: []int{0},
		}},
		MaxPasses: 1,
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("unavailable template error = %v", err)
	}
}

func privateFeeMarket(privateFee uint64) MarketConfig {
	miners := make([]MarketMiner, 10)
	miners[0] = MarketMiner{HashUnits: 1, InitialTemplate: 0, AllowedTemplates: []int{0, 1}}
	for index := 1; index < len(miners); index++ {
		miners[index] = MarketMiner{HashUnits: 1, InitialTemplate: 0, AllowedTemplates: []int{0}}
	}
	return MarketConfig{
		BlockSubsidy: 5_000_000_000,
		Templates:    []MarketTemplate{{}, {Fees: privateFee}},
		Miners:       miners,
		MaxPasses:    100,
	}
}
