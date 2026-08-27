package workgraphmodel

import (
	"errors"
	"testing"
)

func TestSelfishSweepMapsProfitabilityBoundary(t *testing.T) {
	config := testSelfishSweepConfig()
	result, err := RunSelfishSweep(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Points) != len(config.HashSharesPPM)*len(config.TieAdoptionsPPM) ||
		len(result.Thresholds) != len(config.TieAdoptionsPPM) {
		t.Fatalf("unexpected result dimensions: %+v", result)
	}
	expectedThresholds := []uint32{350_000, 350_000, 250_000, 250_000, 150_000}
	for index, threshold := range result.Thresholds {
		if !threshold.Found || threshold.TieAdoptionPPM != config.TieAdoptionsPPM[index] ||
			threshold.FirstProfitableHashPPM != expectedThresholds[index] {
			t.Fatalf("threshold[%d]=%+v, want tie=%d hash=%d",
				index, threshold, config.TieAdoptionsPPM[index], expectedThresholds[index])
		}
		t.Logf("threshold tie_ppm=%d found=%t first_hash_ppm=%d",
			threshold.TieAdoptionPPM, threshold.Found, threshold.FirstProfitableHashPPM)
	}
	expectedBaseline := []uint64{151_799, 203_539, 253_119, 303_403, 353_084, 403_928, 452_174}
	expectedOrphanRate := []uint64{117_500, 146_833, 185_166, 216_000, 250_666, 303_500, 370_333}
	expectedSelfish := [][]uint64{
		{104_386, 146_940, 222_674, 291_484, 376_451, 503_163, 662_836},
		{117_638, 166_186, 241_875, 314_158, 400_411, 521_017, 675_772},
		{132_964, 183_802, 261_310, 333_918, 417_657, 534_452, 684_012},
		{145_585, 200_712, 278_240, 350_226, 432_622, 543_856, 692_769},
		{160_946, 216_463, 293_111, 362_837, 443_473, 554_064, 698_828},
	}
	expectedWinningSeeds := [][]uint32{
		{0, 0, 0, 1, 3, 3, 3},
		{0, 0, 0, 2, 3, 3, 3},
		{0, 0, 3, 3, 3, 3, 3},
		{0, 0, 3, 3, 3, 3, 3},
		{3, 3, 3, 3, 3, 3, 3},
	}
	for tieIndex := range config.TieAdoptionsPPM {
		for hashIndex := range config.HashSharesPPM {
			pointIndex := tieIndex*len(config.HashSharesPPM) + hashIndex
			point := result.Points[pointIndex]
			advantage := int64(expectedSelfish[tieIndex][hashIndex]) - int64(expectedBaseline[hashIndex])
			profitable := advantage >= int64(config.ProfitMarginPPM) && expectedWinningSeeds[tieIndex][hashIndex] == 3
			if point.AttackerHashPPM != config.HashSharesPPM[hashIndex] ||
				point.TieAdoptionPPM != config.TieAdoptionsPPM[tieIndex] ||
				point.BaselineRewardPPM != expectedBaseline[hashIndex] ||
				point.SelfishRewardPPM != expectedSelfish[tieIndex][hashIndex] ||
				point.AdvantagePPM != advantage || point.WinningSeeds != expectedWinningSeeds[tieIndex][hashIndex] ||
				point.SeedCount != 3 || point.HardDiscoveries != 6_000 ||
				point.OrphanRatePPM != expectedOrphanRate[hashIndex] || point.Profitable != profitable {
				t.Fatalf("point[%d]=%+v", pointIndex, point)
			}
		}
	}
}

func TestSelfishSweepRejectsNonCanonicalOrExcessiveInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SelfishSweepConfig)
	}{
		{name: "no seeds", mutate: func(config *SelfishSweepConfig) { config.Seeds = nil }},
		{name: "zero seed", mutate: func(config *SelfishSweepConfig) { config.Seeds[0] = 0 }},
		{name: "duplicate seed", mutate: func(config *SelfishSweepConfig) { config.Seeds[1] = config.Seeds[0] }},
		{name: "unordered hash", mutate: func(config *SelfishSweepConfig) { config.HashSharesPPM[1] = config.HashSharesPPM[0] }},
		{name: "unordered tie", mutate: func(config *SelfishSweepConfig) { config.TieAdoptionsPPM[1] = config.TieAdoptionsPPM[0] }},
		{name: "invalid margin", mutate: func(config *SelfishSweepConfig) { config.ProfitMarginPPM = 1_000_001 }},
		{name: "excessive corpus", mutate: func(config *SelfishSweepConfig) { config.HardDiscoveries = 100_000 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testSelfishSweepConfig()
			test.mutate(&config)
			if _, err := RunSelfishSweep(config); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("RunSelfishSweep error=%v, want %v", err, ErrConfiguration)
			}
		})
	}
}

func testSelfishSweepConfig() SelfishSweepConfig {
	return SelfishSweepConfig{
		HardDiscoveries: 2_000,
		Seeds: []uint64{
			0x243f6a8885a308d3,
			0x9e3779b97f4a7c15,
			0xcbbb9d5dc1059ed8,
		},
		HashSharesPPM: []uint32{
			150_000,
			200_000,
			250_000,
			300_000,
			350_000,
			400_000,
			450_000,
		},
		TieAdoptionsPPM: []uint32{
			0,
			250_000,
			500_000,
			750_000,
			1_000_000,
		},
		ShareRatio:      512,
		BlockSubsidy:    5_000_000_000,
		FeesPerBlock:    100_000,
		ProfitMarginPPM: 5_000,
	}
}
