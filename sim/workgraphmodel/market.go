package workgraphmodel

import (
	"math"
	"math/big"

	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

const (
	MaxMarketTemplates  = 32
	MaxMarketIterations = 10_000
)

type MarketTemplate struct {
	Fees uint64
}

type MarketMiner struct {
	HashUnits        uint64
	InitialTemplate  int
	AllowedTemplates []int
}

type MarketConfig struct {
	BlockSubsidy uint64
	Templates    []MarketTemplate
	Miners       []MarketMiner
	MaxPasses    int
	SmoothFees   bool
}

type MarketResult struct {
	Assignments                  []int
	TemplateHashUnits            []uint64
	MinerRewardPPM               []uint64
	Passes                       uint64
	Switches                     uint64
	Stable                       bool
	ExpectedIncludedSharePPM     uint64
	ExpectedSubsidyPPMOfSchedule uint64
	ExpectedFeesPerAnchor        uint64
}

// RunTemplateMarket applies deterministic sequential best responses to exact
// expected WorkGraph revenue. For miner i on template t, the choice-dependent
// score (with common positive factors removed) is:
//
//	(anchor_subsidy + fees[t]) * total_hash
//	  + expected_share_pool * hash_on_template_after_choice
//
// The second term is the chance that i's weak shares match the next anchor.
// All comparisons and reported expectation ratios use integer big arithmetic.
func RunTemplateMarket(config MarketConfig) (MarketResult, error) {
	anchorSubsidy, shareReward, err := workgraph.RewardRates(config.BlockSubsidy)
	if err != nil || len(config.Templates) == 0 || len(config.Templates) > MaxMarketTemplates ||
		len(config.Miners) == 0 || len(config.Miners) > workgraph.MaxRewardMiners ||
		config.MaxPasses <= 0 || config.MaxPasses > MaxMarketIterations {
		return MarketResult{}, ErrConfiguration
	}
	for _, template := range config.Templates {
		if template.Fees > math.MaxUint64-anchorSubsidy {
			return MarketResult{}, ErrConfiguration
		}
	}
	result := MarketResult{
		Assignments:       append([]int(nil), make([]int, len(config.Miners))...),
		TemplateHashUnits: make([]uint64, len(config.Templates)),
		MinerRewardPPM:    make([]uint64, len(config.Miners)),
	}
	allowed := make([][]int, len(config.Miners))
	var totalHash uint64
	for index, miner := range config.Miners {
		if miner.HashUnits == 0 || miner.InitialTemplate < 0 ||
			miner.InitialTemplate >= len(config.Templates) || len(miner.AllowedTemplates) == 0 ||
			totalHash > math.MaxUint64-miner.HashUnits {
			return MarketResult{}, ErrConfiguration
		}
		totalHash += miner.HashUnits
		seen := make(map[int]struct{}, len(miner.AllowedTemplates))
		containsInitial := false
		for _, template := range miner.AllowedTemplates {
			if template < 0 || template >= len(config.Templates) {
				return MarketResult{}, ErrConfiguration
			}
			if _, exists := seen[template]; exists {
				return MarketResult{}, ErrConfiguration
			}
			seen[template] = struct{}{}
			allowed[index] = append(allowed[index], template)
			containsInitial = containsInitial || template == miner.InitialTemplate
		}
		if !containsInitial {
			return MarketResult{}, ErrConfiguration
		}
		result.Assignments[index] = miner.InitialTemplate
		if result.TemplateHashUnits[miner.InitialTemplate] > math.MaxUint64-miner.HashUnits {
			return MarketResult{}, ErrConfiguration
		}
		result.TemplateHashUnits[miner.InitialTemplate] += miner.HashUnits
	}

	sharePool := new(big.Int).SetUint64(shareReward)
	sharePool.Mul(sharePool, new(big.Int).SetUint64(workgraph.ExpectedSharesPerAnchor))
	for pass := 1; pass <= config.MaxPasses; pass++ {
		changed := false
		for minerIndex, miner := range config.Miners {
			current := result.Assignments[minerIndex]
			best := current
			bestScore := marketChoiceScore(
				current, current, miner.HashUnits, totalHash, result.TemplateHashUnits,
				config.Templates, anchorSubsidy, sharePool, config.SmoothFees,
			)
			for _, candidate := range allowed[minerIndex] {
				score := marketChoiceScore(
					candidate, current, miner.HashUnits, totalHash, result.TemplateHashUnits,
					config.Templates, anchorSubsidy, sharePool, config.SmoothFees,
				)
				if score.Cmp(bestScore) > 0 {
					best = candidate
					bestScore = score
				}
			}
			if best == current {
				continue
			}
			result.TemplateHashUnits[current] -= miner.HashUnits
			result.TemplateHashUnits[best] += miner.HashUnits
			result.Assignments[minerIndex] = best
			result.Switches++
			changed = true
		}
		result.Passes = uint64(pass)
		if !changed {
			result.Stable = true
			break
		}
	}
	if err := calculateMarketExpectations(
		config, totalHash, anchorSubsidy, sharePool, &result,
	); err != nil {
		return MarketResult{}, err
	}
	return result, nil
}

func marketChoiceScore(
	candidate int,
	current int,
	minerHash uint64,
	totalHash uint64,
	templateHash []uint64,
	templates []MarketTemplate,
	anchorSubsidy uint64,
	sharePool *big.Int,
	smoothFees bool,
) *big.Int {
	hashAfter := templateHash[candidate]
	if candidate != current {
		hashAfter += minerHash
	}
	anchor := new(big.Int).Mul(
		new(big.Int).SetUint64(anchorSubsidy), new(big.Int).SetUint64(totalHash),
	)
	feeMultiplier := totalHash
	if smoothFees {
		// A candidate-specific fee is first won with this miner's hash and is
		// later earned back only in proportion to the same hash share.
		feeMultiplier = minerHash
	}
	fees := new(big.Int).Mul(
		new(big.Int).SetUint64(templates[candidate].Fees), new(big.Int).SetUint64(feeMultiplier),
	)
	anchor.Add(anchor, fees)
	shares := new(big.Int).Mul(new(big.Int).Set(sharePool), new(big.Int).SetUint64(hashAfter))
	return anchor.Add(anchor, shares)
}

func calculateMarketExpectations(
	config MarketConfig,
	totalHash uint64,
	anchorSubsidy uint64,
	sharePool *big.Int,
	result *MarketResult,
) error {
	total := new(big.Int).SetUint64(totalHash)
	totalSquared := new(big.Int).Mul(new(big.Int).Set(total), total)
	sumHashSquared := new(big.Int)
	weightedFees := new(big.Int)
	for template, hash := range result.TemplateHashUnits {
		hashValue := new(big.Int).SetUint64(hash)
		sumHashSquared.Add(sumHashSquared, new(big.Int).Mul(hashValue, hashValue))
		feeTerm := new(big.Int).Mul(
			new(big.Int).SetUint64(hash), new(big.Int).SetUint64(config.Templates[template].Fees),
		)
		weightedFees.Add(weightedFees, feeTerm)
	}
	value, ok := marketRatio(sumHashSquared, totalSquared, uint64(PartsPerMillion))
	if !ok {
		return ErrConfiguration
	}
	result.ExpectedIncludedSharePPM = value

	subsidyNumerator := new(big.Int).Mul(new(big.Int).SetUint64(anchorSubsidy), totalSquared)
	subsidyNumerator.Add(subsidyNumerator, new(big.Int).Mul(new(big.Int).Set(sharePool), sumHashSquared))
	subsidyDenominator := new(big.Int).Mul(new(big.Int).SetUint64(config.BlockSubsidy), totalSquared)
	value, ok = marketRatio(subsidyNumerator, subsidyDenominator, uint64(PartsPerMillion))
	if !ok {
		return ErrConfiguration
	}
	result.ExpectedSubsidyPPMOfSchedule = value
	fees := new(big.Int).Quo(weightedFees, total)
	if !fees.IsUint64() {
		return ErrConfiguration
	}
	result.ExpectedFeesPerAnchor = fees.Uint64()

	rewardNumerators := make([]*big.Int, len(config.Miners))
	totalRewards := new(big.Int)
	for index, miner := range config.Miners {
		template := result.Assignments[index]
		var score *big.Int
		if config.SmoothFees {
			score = new(big.Int).Mul(
				new(big.Int).SetUint64(anchorSubsidy), new(big.Int).SetUint64(totalHash),
			)
			score.Add(score, new(big.Int).Mul(
				new(big.Int).Set(sharePool), new(big.Int).SetUint64(result.TemplateHashUnits[template]),
			))
			// Every miner receives its hash-proportional future share of all fees
			// deposited by the equilibrium template mix.
			score.Add(score, weightedFees)
		} else {
			score = marketChoiceScore(
				template, template, miner.HashUnits, totalHash, result.TemplateHashUnits,
				config.Templates, anchorSubsidy, sharePool, false,
			)
		}
		rewardNumerators[index] = score.Mul(score, new(big.Int).SetUint64(miner.HashUnits))
		totalRewards.Add(totalRewards, rewardNumerators[index])
	}
	if totalRewards.Sign() == 0 {
		return ErrConfiguration
	}
	for index, reward := range rewardNumerators {
		value, ok := marketRatio(reward, totalRewards, uint64(PartsPerMillion))
		if !ok {
			return ErrConfiguration
		}
		result.MinerRewardPPM[index] = value
	}
	return nil
}

func marketRatio(numerator, denominator *big.Int, scale uint64) (uint64, bool) {
	if numerator == nil || denominator == nil || numerator.Sign() < 0 || denominator.Sign() <= 0 {
		return 0, false
	}
	value := new(big.Int).Mul(new(big.Int).Set(numerator), new(big.Int).SetUint64(scale))
	value.Quo(value, denominator)
	return value.Uint64(), value.IsUint64()
}
