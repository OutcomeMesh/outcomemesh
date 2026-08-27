package powmodel

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/difficulty"
	"github.com/outcomemesh/outcomemesh/core/pow"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var (
	ErrConfiguration = errors.New("invalid proof-of-work simulation configuration")
	ErrNoSolution    = errors.New("simulation solve time exceeds configured bound")
)

type Ratio struct {
	Numerator   uint64
	Denominator uint64
}

type Phase struct {
	Blocks        uint64
	HashRate      Ratio
	TimestampBias int64
}

type Config struct {
	AnchorTarget    types.Hash
	AnchorTimestamp uint64
	TargetSpacing   uint64
	HalfLife        uint64
	MaxSolveSeconds uint64
}

type Observation struct {
	Height         uint64
	WallTime       uint64
	Timestamp      uint64
	SolveSeconds   uint64
	Target         types.Hash
	Work           []byte
	CumulativeWork []byte
}

// Run evaluates expected-work crossings rather than sampling random nonces.
// For a candidate duration d, enough work exists when:
//
//	hash_rate * d >= target_difficulty
//
// Both sides are cross-multiplied as integers using the exact target ratio.
func Run(config Config, phases []Phase) ([]Observation, error) {
	if err := validate(config, phases); err != nil {
		return nil, err
	}
	totalBlocks := uint64(0)
	for _, phase := range phases {
		if totalBlocks > math.MaxUint64-phase.Blocks {
			return nil, ErrConfiguration
		}
		totalBlocks += phase.Blocks
	}
	if totalBlocks > uint64(math.MaxInt) {
		return nil, ErrConfiguration
	}

	observations := make([]Observation, 0, int(totalBlocks))
	wallTime := config.AnchorTimestamp
	timestamps := make([]uint64, 0, 11)
	cumulativeWork := new(big.Int)
	height := uint64(0)
	for _, phase := range phases {
		for range phase.Blocks {
			height++
			mtp := medianTimePast(config.AnchorTimestamp, timestamps)
			duration, timestamp, target, err := solve(config, phase, height, wallTime, mtp)
			if err != nil {
				return nil, fmt.Errorf("height %d: %w", height, err)
			}
			wallTime += duration
			blockWork, err := pow.Work(target)
			if err != nil {
				return nil, err
			}
			cumulativeWork.Add(cumulativeWork, blockWork)
			observations = append(observations, Observation{
				Height:         height,
				WallTime:       wallTime,
				Timestamp:      timestamp,
				SolveSeconds:   duration,
				Target:         target,
				Work:           append([]byte(nil), blockWork.Bytes()...),
				CumulativeWork: append([]byte(nil), cumulativeWork.Bytes()...),
			})
			timestamps = append(timestamps, timestamp)
			if len(timestamps) > 11 {
				timestamps = append(timestamps[:0], timestamps[len(timestamps)-11:]...)
			}
		}
	}
	return observations, nil
}

// RunLagged models the experimental version-1 rule. Target(h) is calculated
// once from the committed parent timestamp plus one ideal spacing before any
// current-height timestamp or solve duration is chosen.
func RunLagged(config Config, phases []Phase) ([]Observation, error) {
	if err := validate(config, phases); err != nil {
		return nil, err
	}
	var totalBlocks uint64
	for _, phase := range phases {
		if totalBlocks > math.MaxUint64-phase.Blocks {
			return nil, ErrConfiguration
		}
		totalBlocks += phase.Blocks
	}
	if totalBlocks > uint64(math.MaxInt) {
		return nil, ErrConfiguration
	}

	observations := make([]Observation, 0, int(totalBlocks))
	wallTime := config.AnchorTimestamp
	parentTimestamp := config.AnchorTimestamp
	timestamps := make([]uint64, 0, 11)
	cumulativeWork := new(big.Int)
	var height uint64
	for _, phase := range phases {
		for range phase.Blocks {
			height++
			if parentTimestamp > math.MaxUint64-config.TargetSpacing {
				return nil, fmt.Errorf("height %d: %w", height, ErrConfiguration)
			}
			target, err := difficulty.ASERT(
				config.AnchorTarget, config.AnchorTimestamp, height,
				parentTimestamp+config.TargetSpacing, config.TargetSpacing, config.HalfLife,
			)
			if err != nil {
				return nil, fmt.Errorf("height %d: %w", height, err)
			}
			mtp := medianTimePast(config.AnchorTimestamp, timestamps)
			duration, timestamp, err := solveLagged(config, phase, wallTime, mtp, target)
			if err != nil {
				return nil, fmt.Errorf("height %d: %w", height, err)
			}
			wallTime += duration
			blockWork, err := pow.Work(target)
			if err != nil {
				return nil, err
			}
			cumulativeWork.Add(cumulativeWork, blockWork)
			observations = append(observations, Observation{
				Height: height, WallTime: wallTime, Timestamp: timestamp, SolveSeconds: duration, Target: target,
				Work:           append([]byte(nil), blockWork.Bytes()...),
				CumulativeWork: append([]byte(nil), cumulativeWork.Bytes()...),
			})
			parentTimestamp = timestamp
			timestamps = append(timestamps, timestamp)
			if len(timestamps) > 11 {
				timestamps = append(timestamps[:0], timestamps[len(timestamps)-11:]...)
			}
		}
	}
	return observations, nil
}

func validate(config Config, phases []Phase) error {
	if config.AnchorTarget.IsZero() || config.AnchorTimestamp == 0 || config.TargetSpacing == 0 ||
		config.HalfLife == 0 || config.MaxSolveSeconds == 0 || len(phases) == 0 {
		return ErrConfiguration
	}
	for _, phase := range phases {
		if phase.Blocks == 0 || phase.HashRate.Numerator == 0 || phase.HashRate.Denominator == 0 ||
			phase.TimestampBias > int64(block.MaxFutureDrift) {
			return ErrConfiguration
		}
	}
	return nil
}

func solve(config Config, phase Phase, height, wallTime, median uint64) (uint64, uint64, types.Hash, error) {
	predicate := func(duration uint64) (bool, uint64, types.Hash, error) {
		if duration == 0 || wallTime > math.MaxUint64-duration {
			return false, 0, types.Hash{}, nil
		}
		foundAt := wallTime + duration
		timestamp := biasedTimestamp(foundAt, phase.TimestampBias)
		if median == math.MaxUint64 {
			return false, 0, types.Hash{}, nil
		}
		if timestamp <= median {
			timestamp = median + 1
		}
		maxFuture := foundAt
		if maxFuture <= math.MaxUint64-block.MaxFutureDrift {
			maxFuture += block.MaxFutureDrift
		} else {
			maxFuture = math.MaxUint64
		}
		if timestamp > maxFuture {
			return false, timestamp, types.Hash{}, nil
		}
		target, err := difficulty.ASERT(
			config.AnchorTarget,
			config.AnchorTimestamp,
			height,
			timestamp,
			config.TargetSpacing,
			config.HalfLife,
		)
		if err != nil {
			return false, 0, types.Hash{}, err
		}
		return enoughExpectedWork(config, phase.HashRate, duration, target), timestamp, target, nil
	}

	upper := uint64(1)
	for {
		enough, _, _, err := predicate(upper)
		if err != nil {
			return 0, 0, types.Hash{}, err
		}
		if enough {
			break
		}
		if upper >= config.MaxSolveSeconds {
			return 0, 0, types.Hash{}, ErrNoSolution
		}
		if upper > config.MaxSolveSeconds/2 {
			upper = config.MaxSolveSeconds
		} else {
			upper *= 2
		}
	}

	lower := uint64(1)
	for lower < upper {
		mid := lower + (upper-lower)/2
		enough, _, _, err := predicate(mid)
		if err != nil {
			return 0, 0, types.Hash{}, err
		}
		if enough {
			upper = mid
		} else {
			lower = mid + 1
		}
	}
	enough, timestamp, target, err := predicate(lower)
	if err != nil {
		return 0, 0, types.Hash{}, err
	}
	if !enough {
		return 0, 0, types.Hash{}, ErrNoSolution
	}
	return lower, timestamp, target, nil
}

func solveLagged(
	config Config,
	phase Phase,
	wallTime uint64,
	median uint64,
	target types.Hash,
) (uint64, uint64, error) {
	predicate := func(duration uint64) (bool, uint64) {
		if duration == 0 || wallTime > math.MaxUint64-duration {
			return false, 0
		}
		foundAt := wallTime + duration
		timestamp := biasedTimestamp(foundAt, phase.TimestampBias)
		if median == math.MaxUint64 {
			return false, 0
		}
		if timestamp <= median {
			timestamp = median + 1
		}
		maximum := foundAt
		if maximum <= math.MaxUint64-block.MaxFutureDrift {
			maximum += block.MaxFutureDrift
		} else {
			maximum = math.MaxUint64
		}
		if timestamp > maximum {
			return false, timestamp
		}
		return enoughExpectedWork(config, phase.HashRate, duration, target), timestamp
	}

	upper := uint64(1)
	for {
		enough, _ := predicate(upper)
		if enough {
			break
		}
		if upper >= config.MaxSolveSeconds {
			return 0, 0, ErrNoSolution
		}
		if upper > config.MaxSolveSeconds/2 {
			upper = config.MaxSolveSeconds
		} else {
			upper *= 2
		}
	}
	lower := uint64(1)
	for lower < upper {
		middle := lower + (upper-lower)/2
		enough, _ := predicate(middle)
		if enough {
			upper = middle
		} else {
			lower = middle + 1
		}
	}
	enough, timestamp := predicate(lower)
	if !enough {
		return 0, 0, ErrNoSolution
	}
	return lower, timestamp, nil
}

func enoughExpectedWork(config Config, hashRate Ratio, duration uint64, target types.Hash) bool {
	// Relative difficulty is (anchor_target + 1) / (target + 1). Cross
	// multiplication preserves the fractional part that integer chain work
	// intentionally floors.
	available := new(big.Int).SetUint64(hashRate.Numerator)
	available.Mul(available, new(big.Int).SetUint64(duration))
	available.Mul(available, hashPlusOne(target))
	required := new(big.Int).SetUint64(hashRate.Denominator)
	required.Mul(required, new(big.Int).SetUint64(config.TargetSpacing))
	required.Mul(required, hashPlusOne(config.AnchorTarget))
	return available.Cmp(required) >= 0
}

func hashPlusOne(value types.Hash) *big.Int {
	result := new(big.Int).SetBytes(value[:])
	return result.Add(result, big.NewInt(1))
}

func biasedTimestamp(wallTime uint64, bias int64) uint64 {
	if bias >= 0 {
		value := uint64(bias)
		if wallTime > math.MaxUint64-value {
			return math.MaxUint64
		}
		return wallTime + value
	}
	// -(MinInt64) cannot be represented as int64, so convert without negating.
	magnitude := uint64(-(bias + 1)) + 1
	if magnitude > wallTime {
		return 0
	}
	return wallTime - magnitude
}

func medianTimePast(anchor uint64, timestamps []uint64) uint64 {
	if len(timestamps) == 0 {
		return anchor
	}
	ordered := append([]uint64(nil), timestamps...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	return ordered[len(ordered)/2]
}
