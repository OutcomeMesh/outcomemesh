package workgraphmodel

import (
	"math"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

const (
	maxSelfishSweepHashes      = 32
	maxSelfishSweepTies        = 16
	maxSelfishSweepSeeds       = 16
	maxSelfishSweepDiscoveries = 1_000_000
)

// SelfishSweepConfig defines a deterministic cartesian sweep. HashSharesPPM
// and TieAdoptionsPPM must be strictly increasing so Points and Thresholds have
// one canonical order. Seeds must be non-zero and unique.
type SelfishSweepConfig struct {
	HardDiscoveries int
	Seeds           []uint64
	HashSharesPPM   []uint32
	TieAdoptionsPPM []uint32
	ShareRatio      uint64
	BlockSubsidy    uint64
	FeesPerBlock    uint64
	ProfitMarginPPM uint64
}

// SelfishSweepPoint aggregates paired honest/selfish runs over every seed.
// Profitable is deliberately conservative: the aggregate advantage must reach
// ProfitMarginPPM and the selfish strategy must beat its paired baseline on
// every seed.
type SelfishSweepPoint struct {
	AttackerHashPPM   uint32
	TieAdoptionPPM    uint32
	BaselineRewardPPM uint64
	SelfishRewardPPM  uint64
	AdvantagePPM      int64
	WinningSeeds      uint32
	SeedCount         uint32
	OrphanAnchors     uint64
	HardDiscoveries   uint64
	OrphanRatePPM     uint64
	Profitable        bool
}

// SelfishProfitThreshold records the first tested hash-share point that meets
// the conservative profitability rule. Found is false when no tested point
// reached the threshold.
type SelfishProfitThreshold struct {
	TieAdoptionPPM         uint32
	FirstProfitableHashPPM uint32
	Found                  bool
}

type SelfishSweepResult struct {
	Points     []SelfishSweepPoint
	Thresholds []SelfishProfitThreshold
}

type selfishBaseline struct {
	attackerReward uint64
	honestReward   uint64
	seedShares     []uint64
}

// RunSelfishSweep compares immediate publication and anchor withholding with
// common random seeds. Baselines are reused across tie-adoption values because
// an immediate publisher never creates a tie in this model.
func RunSelfishSweep(config SelfishSweepConfig) (SelfishSweepResult, error) {
	return runSelfishStrategySweep(config, 0)
}

// RunTrailRetrySweep applies the same paired profitability rule to a bounded
// one-block trail-stubborn strategy. After losing a published tie, the attacker
// mines the stale branch for one more anchor; a catch-up creates one final
// equal-height race, while another honest anchor ends the attempt.
func RunTrailRetrySweep(config SelfishSweepConfig) (SelfishSweepResult, error) {
	return runSelfishStrategySweep(config, 1)
}

// RunTrailDepthSweep keeps mining a losing fork while its anchor deficit is at
// most depth. Depth is consensus-analysis input, not a protocol parameter.
func RunTrailDepthSweep(config SelfishSweepConfig, depth uint8) (SelfishSweepResult, error) {
	if depth == 0 || depth > MaxTrailDepth {
		return SelfishSweepResult{}, ErrConfiguration
	}
	return runSelfishStrategySweep(config, depth)
}

func runSelfishStrategySweep(config SelfishSweepConfig, trailDepth uint8) (SelfishSweepResult, error) {
	if err := validateSelfishSweep(config); err != nil {
		return SelfishSweepResult{}, err
	}
	baselines := make([]selfishBaseline, len(config.HashSharesPPM))
	for hashIndex, hashShare := range config.HashSharesPPM {
		baseline := selfishBaseline{seedShares: make([]uint64, len(config.Seeds))}
		for seedIndex, seed := range config.Seeds {
			result, err := RunSelfish(sweepRunConfig(config, hashShare, 0, seed, false, 0))
			if err != nil {
				return SelfishSweepResult{}, err
			}
			if baseline.attackerReward, err = addSweepAmount(baseline.attackerReward, result.AttackerReward); err != nil {
				return SelfishSweepResult{}, err
			}
			if baseline.honestReward, err = addSweepAmount(baseline.honestReward, result.HonestReward); err != nil {
				return SelfishSweepResult{}, err
			}
			baseline.seedShares[seedIndex], err = RewardSharePPM(result.AttackerReward, result.HonestReward)
			if err != nil {
				return SelfishSweepResult{}, err
			}
		}
		baselines[hashIndex] = baseline
	}

	result := SelfishSweepResult{
		Points:     make([]SelfishSweepPoint, 0, len(config.HashSharesPPM)*len(config.TieAdoptionsPPM)),
		Thresholds: make([]SelfishProfitThreshold, 0, len(config.TieAdoptionsPPM)),
	}
	for _, tieAdoption := range config.TieAdoptionsPPM {
		threshold := SelfishProfitThreshold{TieAdoptionPPM: tieAdoption}
		for hashIndex, hashShare := range config.HashSharesPPM {
			point, err := runSelfishSweepPoint(
				config, baselines[hashIndex], hashShare, tieAdoption, trailDepth,
			)
			if err != nil {
				return SelfishSweepResult{}, err
			}
			result.Points = append(result.Points, point)
			if point.Profitable && !threshold.Found {
				threshold.FirstProfitableHashPPM = hashShare
				threshold.Found = true
			}
		}
		result.Thresholds = append(result.Thresholds, threshold)
	}
	return result, nil
}

func runSelfishSweepPoint(
	config SelfishSweepConfig,
	baseline selfishBaseline,
	hashShare uint32,
	tieAdoption uint32,
	trailDepth uint8,
) (SelfishSweepPoint, error) {
	point := SelfishSweepPoint{
		AttackerHashPPM: hashShare,
		TieAdoptionPPM:  tieAdoption,
		SeedCount:       uint32(len(config.Seeds)),
	}
	var attackerReward uint64
	var honestReward uint64
	for seedIndex, seed := range config.Seeds {
		result, err := RunSelfish(sweepRunConfig(
			config, hashShare, tieAdoption, seed, true, trailDepth,
		))
		if err != nil {
			return SelfishSweepPoint{}, err
		}
		if attackerReward, err = addSweepAmount(attackerReward, result.AttackerReward); err != nil {
			return SelfishSweepPoint{}, err
		}
		if honestReward, err = addSweepAmount(honestReward, result.HonestReward); err != nil {
			return SelfishSweepPoint{}, err
		}
		if point.OrphanAnchors, err = addSweepAmount(point.OrphanAnchors, result.OrphanAnchors); err != nil {
			return SelfishSweepPoint{}, err
		}
		if point.HardDiscoveries, err = addSweepAmount(point.HardDiscoveries, result.HardDiscoveries); err != nil {
			return SelfishSweepPoint{}, err
		}
		seedShare, err := RewardSharePPM(result.AttackerReward, result.HonestReward)
		if err != nil {
			return SelfishSweepPoint{}, err
		}
		if seedShare > baseline.seedShares[seedIndex] {
			point.WinningSeeds++
		}
	}
	var err error
	point.BaselineRewardPPM, err = RewardSharePPM(baseline.attackerReward, baseline.honestReward)
	if err != nil {
		return SelfishSweepPoint{}, err
	}
	point.SelfishRewardPPM, err = RewardSharePPM(attackerReward, honestReward)
	if err != nil {
		return SelfishSweepPoint{}, err
	}
	point.AdvantagePPM = int64(point.SelfishRewardPPM) - int64(point.BaselineRewardPPM)
	var ok bool
	point.OrphanRatePPM, ok = multiplyDivide(point.OrphanAnchors, uint64(PartsPerMillion), point.HardDiscoveries)
	if !ok {
		return SelfishSweepPoint{}, ErrConfiguration
	}
	point.Profitable = point.AdvantagePPM >= int64(config.ProfitMarginPPM) &&
		point.WinningSeeds == point.SeedCount
	return point, nil
}

func sweepRunConfig(
	config SelfishSweepConfig,
	hashShare uint32,
	tieAdoption uint32,
	seed uint64,
	withhold bool,
	trailDepth uint8,
) SelfishConfig {
	return SelfishConfig{
		HardDiscoveries: config.HardDiscoveries,
		Seed:            seed,
		ShareRatio:      config.ShareRatio,
		AttackerHashPPM: hashShare,
		TieAdoptionPPM:  tieAdoption,
		BlockSubsidy:    config.BlockSubsidy,
		FeesPerBlock:    config.FeesPerBlock,
		WithholdAnchors: withhold,
		TrailDepth:      trailDepth,
	}
}

func validateSelfishSweep(config SelfishSweepConfig) error {
	if config.HardDiscoveries <= 0 || config.HardDiscoveries > 100_000 ||
		len(config.Seeds) == 0 || len(config.Seeds) > maxSelfishSweepSeeds ||
		len(config.HashSharesPPM) == 0 || len(config.HashSharesPPM) > maxSelfishSweepHashes ||
		len(config.TieAdoptionsPPM) == 0 || len(config.TieAdoptionsPPM) > maxSelfishSweepTies ||
		config.ShareRatio != workgraph.ShareDifficultyRatio ||
		config.ProfitMarginPPM > uint64(PartsPerMillion) {
		return ErrConfiguration
	}
	if config.BlockSubsidy > math.MaxUint64-config.FeesPerBlock {
		return ErrConfiguration
	}
	for index, value := range config.HashSharesPPM {
		if value == 0 || value >= PartsPerMillion || (index > 0 && value <= config.HashSharesPPM[index-1]) {
			return ErrConfiguration
		}
	}
	for index, value := range config.TieAdoptionsPPM {
		if value > PartsPerMillion || (index > 0 && value <= config.TieAdoptionsPPM[index-1]) {
			return ErrConfiguration
		}
	}
	for index, seed := range config.Seeds {
		if seed == 0 {
			return ErrConfiguration
		}
		for earlier := 0; earlier < index; earlier++ {
			if seed == config.Seeds[earlier] {
				return ErrConfiguration
			}
		}
	}
	runs := int64(len(config.HashSharesPPM)) * int64(len(config.Seeds)) *
		int64(len(config.TieAdoptionsPPM)+1) * int64(config.HardDiscoveries)
	if runs > maxSelfishSweepDiscoveries {
		return ErrConfiguration
	}
	return nil
}

func addSweepAmount(left, right uint64) (uint64, error) {
	value, err := types.AddAmount(left, right)
	if err != nil {
		return 0, ErrConfiguration
	}
	return value, nil
}
