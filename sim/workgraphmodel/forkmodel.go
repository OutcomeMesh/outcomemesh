package workgraphmodel

import (
	"math"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

type SelfishConfig struct {
	HardDiscoveries  int
	Seed             uint64
	ShareRatio       uint64
	AttackerHashPPM  uint32
	TieAdoptionPPM   uint32
	BlockSubsidy     uint64
	FeesPerBlock     uint64
	WithholdAnchors  bool
	OmitHonestShares bool
}

type SelfishResult struct {
	HardDiscoveries       uint64
	CanonicalBlocks       uint64
	AttackerCanonical     uint64
	HonestCanonical       uint64
	OrphanAnchors         uint64
	DiscoveredShares      uint64
	AttackerFoundShares   uint64
	HonestFoundShares     uint64
	IncludedShares        uint64
	AttackerIncluded      uint64
	HonestIncluded        uint64
	AttackerReward        uint64
	HonestReward          uint64
	TotalIssued           uint64
	OverCapCandidates     uint64
	UnresolvedPrivateLead uint64
}

type forkPool []bool // true is attacker work; false is honest work.

type forkCandidate struct {
	attacker bool
	shares   forkPool
}

type tieRace struct {
	attacker forkCandidate
	honest   forkCandidate
}

// RunSelfish models adaptive hard-anchor withholding across multiple rounds.
// Work shares remain tied to the branch parent on which they were found. A
// public and private candidate may commit the same pre-fork shares, but only
// the finally canonical candidate is passed to reward accounting.
func RunSelfish(config SelfishConfig) (SelfishResult, error) {
	if config.HardDiscoveries <= 0 || config.HardDiscoveries > 100_000 ||
		config.ShareRatio != workgraph.ShareDifficultyRatio ||
		config.AttackerHashPPM == 0 || config.AttackerHashPPM >= PartsPerMillion ||
		config.TieAdoptionPPM > PartsPerMillion {
		return SelfishResult{}, ErrConfiguration
	}
	anchorSubsidy, shareReward, err := workgraph.RewardRates(config.BlockSubsidy)
	if err != nil {
		return SelfishResult{}, ErrConfiguration
	}
	if anchorSubsidy > math.MaxUint64-config.FeesPerBlock {
		return SelfishResult{}, ErrConfiguration
	}
	random := prng{state: config.Seed}
	if random.state == 0 {
		random.state = 0xa4093822299f31d0
	}
	result := SelfishResult{}
	private := make([]forkCandidate, 0, 8)
	var publicPool forkPool
	var privatePool forkPool
	var tie *tieRace

	for discovery := 0; discovery < config.HardDiscoveries; discovery++ {
		result.HardDiscoveries++
		if tie != nil {
			resolver, attackBranch, err := mineTieRace(config, &random, &result)
			if err != nil {
				return SelfishResult{}, err
			}
			if attackBranch {
				if err := commitForkCandidate(&result, tie.attacker, anchorSubsidy, shareReward, config.FeesPerBlock); err != nil {
					return SelfishResult{}, err
				}
				if err := commitForkCandidate(&result, resolver, anchorSubsidy, shareReward, config.FeesPerBlock); err != nil {
					return SelfishResult{}, err
				}
				result.OrphanAnchors++
			} else {
				if err := commitForkCandidate(&result, tie.honest, anchorSubsidy, shareReward, config.FeesPerBlock); err != nil {
					return SelfishResult{}, err
				}
				if err := commitForkCandidate(&result, resolver, anchorSubsidy, shareReward, config.FeesPerBlock); err != nil {
					return SelfishResult{}, err
				}
				result.OrphanAnchors++
			}
			tie = nil
			publicPool = nil
			privatePool = nil
			private = private[:0]
			continue
		}

		if len(private) == 0 {
			attackerWon, err := mineSharedForkRound(config, &random, &result, &publicPool)
			if err != nil {
				return SelfishResult{}, err
			}
			candidate := makeForkCandidate(attackerWon, publicPool, config.OmitHonestShares && attackerWon, &result)
			if attackerWon && config.WithholdAnchors {
				private = append(private, candidate)
				privatePool = nil
				continue
			}
			if err := commitForkCandidate(&result, candidate, anchorSubsidy, shareReward, config.FeesPerBlock); err != nil {
				return SelfishResult{}, err
			}
			publicPool = nil
			continue
		}

		attackerWon, err := mineSplitForkRound(config, &random, &result, &publicPool, &privatePool)
		if err != nil {
			return SelfishResult{}, err
		}
		if attackerWon {
			private = append(private, makeForkCandidate(true, privatePool, false, &result))
			privatePool = nil
			continue
		}

		honestCandidate := makeForkCandidate(false, publicPool, false, &result)
		switch len(private) {
		case 1:
			tie = &tieRace{attacker: private[0], honest: honestCandidate}
			publicPool = nil
			privatePool = nil
			private = private[:0]
		case 2:
			for _, candidate := range private {
				if err := commitForkCandidate(&result, candidate, anchorSubsidy, shareReward, config.FeesPerBlock); err != nil {
					return SelfishResult{}, err
				}
			}
			result.OrphanAnchors++
			private = private[:0]
			publicPool = nil
			privatePool = nil
		default:
			if err := commitForkCandidate(&result, private[0], anchorSubsidy, shareReward, config.FeesPerBlock); err != nil {
				return SelfishResult{}, err
			}
			result.OrphanAnchors++
			private = append(private[:0], private[1:]...)
			publicPool = nil
		}
	}
	result.UnresolvedPrivateLead = uint64(len(private))
	if tie != nil {
		result.UnresolvedPrivateLead++
	}
	if result.IncludedShares > result.DiscoveredShares {
		return SelfishResult{}, ErrConfiguration
	}
	return result, nil
}

func mineSharedForkRound(
	config SelfishConfig,
	random *prng,
	result *SelfishResult,
	pool *forkPool,
) (bool, error) {
	return mineForkHashes(config, random, result, func(attacker bool) {
		*pool = append(*pool, attacker)
	})
}

func mineSplitForkRound(
	config SelfishConfig,
	random *prng,
	result *SelfishResult,
	publicPool *forkPool,
	privatePool *forkPool,
) (bool, error) {
	return mineForkHashes(config, random, result, func(attacker bool) {
		if attacker {
			*privatePool = append(*privatePool, true)
		} else {
			*publicPool = append(*publicPool, false)
		}
	})
}

func mineForkHashes(
	config SelfishConfig,
	random *prng,
	result *SelfishResult,
	onShare func(attacker bool),
) (bool, error) {
	maximum := config.ShareRatio * 128
	for event := uint64(0); event < maximum; event++ {
		attacker := uint32(random.next()%uint64(PartsPerMillion)) < config.AttackerHashPPM
		if random.next()%config.ShareRatio == 0 {
			return attacker, nil
		}
		onShare(attacker)
		result.DiscoveredShares++
		if attacker {
			result.AttackerFoundShares++
		} else {
			result.HonestFoundShares++
		}
	}
	return false, ErrConfiguration
}

func mineTieRace(
	config SelfishConfig,
	random *prng,
	result *SelfishResult,
) (resolver forkCandidate, attackBranch bool, err error) {
	var attackPool forkPool
	var honestPool forkPool
	maximum := config.ShareRatio * 128
	for event := uint64(0); event < maximum; event++ {
		attacker := uint32(random.next()%uint64(PartsPerMillion)) < config.AttackerHashPPM
		branch := attacker || uint32(random.next()%uint64(PartsPerMillion)) < config.TieAdoptionPPM
		if random.next()%config.ShareRatio == 0 {
			resolver = makeForkCandidate(attacker, mapTiePool(branch, attackPool, honestPool),
				config.OmitHonestShares && attacker, result)
			return resolver, branch, nil
		}
		result.DiscoveredShares++
		if attacker {
			result.AttackerFoundShares++
			attackPool = append(attackPool, true)
		} else {
			result.HonestFoundShares++
			if branch {
				attackPool = append(attackPool, false)
			} else {
				honestPool = append(honestPool, false)
			}
		}
	}
	return forkCandidate{}, false, ErrConfiguration
}

func mapTiePool(attackBranch bool, attackPool, honestPool forkPool) forkPool {
	if attackBranch {
		return attackPool
	}
	return honestPool
}

func makeForkCandidate(attacker bool, pool forkPool, omitHonest bool, result *SelfishResult) forkCandidate {
	bounded := make(forkPool, 0, min(len(pool), workgraph.MaxShares))
	for _, owner := range pool {
		if omitHonest && !owner {
			continue
		}
		if len(bounded) == workgraph.MaxShares {
			result.OverCapCandidates++
			break
		}
		bounded = append(bounded, owner)
	}
	return forkCandidate{attacker: attacker, shares: bounded}
}

func commitForkCandidate(
	result *SelfishResult,
	candidate forkCandidate,
	anchorSubsidy uint64,
	shareReward uint64,
	fees uint64,
) error {
	result.CanonicalBlocks++
	anchorReward, err := types.AddAmount(anchorSubsidy, fees)
	if err != nil {
		return ErrConfiguration
	}
	if candidate.attacker {
		result.AttackerCanonical++
		result.AttackerReward, err = types.AddAmount(result.AttackerReward, anchorReward)
	} else {
		result.HonestCanonical++
		result.HonestReward, err = types.AddAmount(result.HonestReward, anchorReward)
	}
	if err != nil {
		return ErrConfiguration
	}
	for _, attackerShare := range candidate.shares {
		result.IncludedShares++
		if attackerShare {
			result.AttackerIncluded++
			result.AttackerReward, err = types.AddAmount(result.AttackerReward, shareReward)
		} else {
			result.HonestIncluded++
			result.HonestReward, err = types.AddAmount(result.HonestReward, shareReward)
		}
		if err != nil {
			return ErrConfiguration
		}
	}
	result.TotalIssued, err = types.AddAmount(result.AttackerReward, result.HonestReward)
	if err != nil {
		return ErrConfiguration
	}
	return nil
}

func RewardSharePPM(attackerReward, honestReward uint64) (uint64, error) {
	total, err := types.AddAmount(attackerReward, honestReward)
	if err != nil || total == 0 {
		return 0, ErrConfiguration
	}
	value, ok := multiplyDivide(attackerReward, uint64(PartsPerMillion), total)
	if !ok {
		return 0, ErrConfiguration
	}
	return value, nil
}
