// Package workgraphmodel provides a deterministic integer-only Monte Carlo
// model for weak-share proportionality, withholding, propagation, orphaning,
// bandwidth, batch-cap tails, local-view DAG topology, bounded gossip queues,
// and multi-round public/private forks.
package workgraphmodel

import (
	"errors"
	"math/bits"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

const PartsPerMillion uint32 = 1_000_000

var ErrConfiguration = errors.New("invalid WorkGraph simulation configuration")

type Miner struct {
	HashUnits   uint64
	WithholdPPM uint32
	Template    uint16
}

type Config struct {
	Rounds             int
	Seed               uint64
	ShareRatio         uint64
	MaxIncludedShares  int
	AverageShareBytes  uint64
	PropagationLossPPM uint32
	AnchorOrphanPPM    uint32
	BlockSubsidy       uint64
	Miners             []Miner
}

type MinerResult struct {
	DiscoveredShares uint64
	PublishedShares  uint64
	RewardedShares   uint64
	AnchorWins       uint64
}

type Result struct {
	Rounds                 uint64
	CanonicalAnchors       uint64
	OrphanAnchors          uint64
	OverflowRounds         uint64
	TemplateMismatchShares uint64
	IncludedShares         uint64
	IncludedBytes          uint64
	ScheduledSubsidy       uint64
	IssuedSubsidy          uint64
	MaxPublishedInRound    uint64
	Miners                 []MinerResult
}

type publishedShare struct {
	miner    int
	template uint16
	order    uint64
}

func Run(config Config) (Result, error) {
	if config.Rounds <= 0 || config.Rounds > 100_000 || config.ShareRatio == 0 || config.ShareRatio > 1_000_000 ||
		config.MaxIncludedShares <= 0 || config.MaxIncludedShares > workgraph.MaxShares ||
		config.AverageShareBytes == 0 || config.AverageShareBytes > workgraph.MaxShareCanonicalBytes ||
		config.PropagationLossPPM > PartsPerMillion || config.AnchorOrphanPPM > PartsPerMillion ||
		len(config.Miners) == 0 || len(config.Miners) > workgraph.MaxRewardMiners {
		return Result{}, ErrConfiguration
	}
	var totalHash uint64
	for _, miner := range config.Miners {
		if miner.HashUnits == 0 || miner.WithholdPPM > PartsPerMillion || totalHash > ^uint64(0)-miner.HashUnits {
			return Result{}, ErrConfiguration
		}
		totalHash += miner.HashUnits
	}
	if totalHash == 0 {
		return Result{}, ErrConfiguration
	}
	var anchorSubsidy uint64
	var shareReward uint64
	if config.BlockSubsidy != 0 {
		var err error
		anchorSubsidy, shareReward, err = workgraph.RewardRates(config.BlockSubsidy)
		if err != nil {
			return Result{}, ErrConfiguration
		}
	}
	random := prng{state: config.Seed}
	if random.state == 0 {
		random.state = 0x9e3779b97f4a7c15
	}
	result := Result{Rounds: uint64(config.Rounds), Miners: make([]MinerResult, len(config.Miners))}
	maxEvents := config.ShareRatio * 128
	if maxEvents < uint64(config.MaxIncludedShares)*2 {
		maxEvents = uint64(config.MaxIncludedShares) * 2
	}
	for range config.Rounds {
		published := make([]publishedShare, 0, min(int(config.ShareRatio), config.MaxIncludedShares))
		anchorMiner := -1
		for event := uint64(0); event < maxEvents; event++ {
			miner := chooseMiner(random.next(), totalHash, config.Miners)
			if random.next()%config.ShareRatio == 0 {
				anchorMiner = miner
				break
			}
			result.Miners[miner].DiscoveredShares++
			if uint32(random.next()%uint64(PartsPerMillion)) < config.Miners[miner].WithholdPPM {
				continue
			}
			if uint32(random.next()%uint64(PartsPerMillion)) < config.PropagationLossPPM {
				continue
			}
			result.Miners[miner].PublishedShares++
			published = append(published, publishedShare{
				miner: miner, template: config.Miners[miner].Template, order: random.next(),
			})
		}
		if anchorMiner < 0 {
			return Result{}, ErrConfiguration
		}
		result.Miners[anchorMiner].AnchorWins++
		if uint64(len(published)) > result.MaxPublishedInRound {
			result.MaxPublishedInRound = uint64(len(published))
		}
		if uint32(random.next()%uint64(PartsPerMillion)) < config.AnchorOrphanPPM {
			result.OrphanAnchors++
			continue
		}
		result.CanonicalAnchors++
		winningTemplate := config.Miners[anchorMiner].Template
		eligible := published[:0]
		for _, share := range published {
			if share.template != winningTemplate {
				result.TemplateMismatchShares++
				continue
			}
			eligible = append(eligible, share)
		}
		published = eligible
		if len(published) > config.MaxIncludedShares {
			result.OverflowRounds++
			sort.Slice(published, func(left, right int) bool {
				if published[left].order != published[right].order {
					return published[left].order < published[right].order
				}
				return published[left].miner < published[right].miner
			})
			published = published[:config.MaxIncludedShares]
		}
		for _, share := range published {
			result.Miners[share.miner].RewardedShares++
		}
		result.IncludedShares += uint64(len(published))
		bytes, err := types.AddAmount(result.IncludedBytes, uint64(len(published))*config.AverageShareBytes)
		if err != nil {
			return Result{}, ErrConfiguration
		}
		result.IncludedBytes = bytes
		if config.BlockSubsidy != 0 {
			result.ScheduledSubsidy, err = types.AddAmount(result.ScheduledSubsidy, config.BlockSubsidy)
			if err != nil {
				return Result{}, ErrConfiguration
			}
			roundIssuance := anchorSubsidy + uint64(len(published))*shareReward
			result.IssuedSubsidy, err = types.AddAmount(result.IssuedSubsidy, roundIssuance)
			if err != nil {
				return Result{}, ErrConfiguration
			}
		}
	}
	return result, nil
}

// DeviationPPM returns the absolute deviation between an observed count and a
// hash-proportional expected count, divided by the expected count.
func DeviationPPM(observed, totalObserved, minerHash, totalHash uint64) (uint64, error) {
	if totalObserved == 0 || minerHash == 0 || totalHash == 0 || minerHash > totalHash {
		return 0, ErrConfiguration
	}
	expected, ok := multiplyDivide(totalObserved, minerHash, totalHash)
	if !ok {
		return 0, ErrConfiguration
	}
	if expected == 0 {
		return 0, ErrConfiguration
	}
	var difference uint64
	if observed >= expected {
		difference = observed - expected
	} else {
		difference = expected - observed
	}
	deviation, ok := multiplyDivide(difference, uint64(PartsPerMillion), expected)
	if !ok {
		return ^uint64(0), nil
	}
	return deviation, nil
}

func chooseMiner(value, total uint64, miners []Miner) int {
	selected := value % total
	var cumulative uint64
	for index, miner := range miners {
		cumulative += miner.HashUnits
		if selected < cumulative {
			return index
		}
	}
	return len(miners) - 1
}

func multiplyDivide(left, right, divisor uint64) (uint64, bool) {
	if divisor == 0 {
		return 0, false
	}
	high, low := bits.Mul64(left, right)
	if high >= divisor {
		return 0, false
	}
	quotient, _ := bits.Div64(high, low, divisor)
	return quotient, true
}

type prng struct{ state uint64 }

func (random *prng) next() uint64 {
	random.state ^= random.state << 13
	random.state ^= random.state >> 7
	random.state ^= random.state << 17
	return random.state
}
