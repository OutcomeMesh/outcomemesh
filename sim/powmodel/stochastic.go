package powmodel

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"math/big"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/difficulty"
	"github.com/outcomemesh/outcomemesh/core/pow"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	MaxStochasticBlocks       = 100_000
	MaxStochasticSolveSeconds = 30 * 24 * 60 * 60
	observationDigestDomain   = "OMESH/powmodel/observations/v1"
)

// DigestObservations commits every reported field in canonical big-endian
// order. It lets review fixtures detect a path change even when aggregate
// averages happen to remain equal.
func DigestObservations(observations []Observation) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(observationDigestDomain))
	writeStochasticUint64(digest, uint64(len(observations)))
	for _, observation := range observations {
		writeStochasticUint64(digest, observation.Height)
		writeStochasticUint64(digest, observation.WallTime)
		writeStochasticUint64(digest, observation.Timestamp)
		writeStochasticUint64(digest, observation.SolveSeconds)
		_, _ = digest.Write(observation.Target[:])
		writeStochasticBytes(digest, observation.Work)
		writeStochasticBytes(digest, observation.CumulativeWork)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

// RunStochastic samples a deterministic, fixed-seed geometric solve process in
// whole-second buckets. At each second the success probability is the exact
// expected-work fraction for the current ASERT target and configured hash rate,
// capped at one. It adds discovery variance to Run without using floating point
// or iterating individual hashes.
func RunStochastic(config Config, phases []Phase, seed uint64) ([]Observation, error) {
	if err := validateStochastic(config, phases, seed); err != nil {
		return nil, err
	}
	totalBlocks, err := stochasticBlockCount(phases)
	if err != nil {
		return nil, err
	}
	observations := make([]Observation, 0, totalBlocks)
	random := stochasticPRNG{state: seed}
	wallTime := config.AnchorTimestamp
	timestamps := make([]uint64, 0, 11)
	cumulativeWork := new(big.Int)
	var height uint64
	for _, phase := range phases {
		for range phase.Blocks {
			height++
			mtp := medianTimePast(config.AnchorTimestamp, timestamps)
			duration, timestamp, target, err := solveStochastic(
				config, phase, height, wallTime, mtp, &random,
			)
			if err != nil {
				return nil, fmt.Errorf("height %d: %w", height, err)
			}
			wallTime += duration
			observation, err := stochasticObservation(height, wallTime, timestamp, duration, target, cumulativeWork)
			if err != nil {
				return nil, err
			}
			observations = append(observations, observation)
			timestamps = appendStochasticTimestamp(timestamps, timestamp)
		}
	}
	return observations, nil
}

// RunStochasticLagged applies the same fixed-seed discovery process to the
// version-1 parent-timestamp target rule. The current block's random duration
// and timestamp cannot change its already fixed target.
func RunStochasticLagged(config Config, phases []Phase, seed uint64) ([]Observation, error) {
	if err := validateStochastic(config, phases, seed); err != nil {
		return nil, err
	}
	totalBlocks, err := stochasticBlockCount(phases)
	if err != nil {
		return nil, err
	}
	observations := make([]Observation, 0, totalBlocks)
	random := stochasticPRNG{state: seed}
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
			duration, timestamp, err := solveStochasticLagged(
				config, phase, wallTime, mtp, target, &random,
			)
			if err != nil {
				return nil, fmt.Errorf("height %d: %w", height, err)
			}
			wallTime += duration
			observation, err := stochasticObservation(height, wallTime, timestamp, duration, target, cumulativeWork)
			if err != nil {
				return nil, err
			}
			observations = append(observations, observation)
			parentTimestamp = timestamp
			timestamps = appendStochasticTimestamp(timestamps, timestamp)
		}
	}
	return observations, nil
}

func validateStochastic(config Config, phases []Phase, seed uint64) error {
	if seed == 0 || config.MaxSolveSeconds > MaxStochasticSolveSeconds {
		return ErrConfiguration
	}
	return validate(config, phases)
}

func stochasticBlockCount(phases []Phase) (int, error) {
	var total uint64
	for _, phase := range phases {
		if total > math.MaxUint64-phase.Blocks {
			return 0, ErrConfiguration
		}
		total += phase.Blocks
	}
	if total > uint64(math.MaxInt) {
		return 0, ErrConfiguration
	}
	if total > MaxStochasticBlocks {
		return 0, ErrConfiguration
	}
	return int(total), nil
}

func solveStochastic(
	config Config,
	phase Phase,
	height uint64,
	wallTime uint64,
	median uint64,
	random *stochasticPRNG,
) (uint64, uint64, types.Hash, error) {
	for duration := uint64(1); duration <= config.MaxSolveSeconds; duration++ {
		timestamp, valid := stochasticCandidateTimestamp(wallTime, duration, median, phase.TimestampBias)
		if !valid {
			continue
		}
		target, err := difficulty.ASERT(
			config.AnchorTarget, config.AnchorTimestamp, height, timestamp,
			config.TargetSpacing, config.HalfLife,
		)
		if err != nil {
			return 0, 0, types.Hash{}, err
		}
		if stochasticSuccess(config, phase.HashRate, target, random) {
			return duration, timestamp, target, nil
		}
		if duration == math.MaxUint64 {
			break
		}
	}
	return 0, 0, types.Hash{}, ErrNoSolution
}

func solveStochasticLagged(
	config Config,
	phase Phase,
	wallTime uint64,
	median uint64,
	target types.Hash,
	random *stochasticPRNG,
) (uint64, uint64, error) {
	for duration := uint64(1); duration <= config.MaxSolveSeconds; duration++ {
		timestamp, valid := stochasticCandidateTimestamp(wallTime, duration, median, phase.TimestampBias)
		if valid && stochasticSuccess(config, phase.HashRate, target, random) {
			return duration, timestamp, nil
		}
		if duration == math.MaxUint64 {
			break
		}
	}
	return 0, 0, ErrNoSolution
}

func stochasticCandidateTimestamp(wallTime, duration, median uint64, bias int64) (uint64, bool) {
	if duration == 0 || wallTime > math.MaxUint64-duration || median == math.MaxUint64 {
		return 0, false
	}
	foundAt := wallTime + duration
	timestamp := biasedTimestamp(foundAt, bias)
	if timestamp <= median {
		timestamp = median + 1
	}
	maximum := foundAt
	if maximum <= math.MaxUint64-block.MaxFutureDrift {
		maximum += block.MaxFutureDrift
	} else {
		maximum = math.MaxUint64
	}
	return timestamp, timestamp <= maximum
}

func stochasticSuccess(config Config, hashRate Ratio, target types.Hash, random *stochasticPRNG) bool {
	numerator := new(big.Int).SetUint64(hashRate.Numerator)
	numerator.Mul(numerator, hashPlusOne(target))
	denominator := new(big.Int).SetUint64(hashRate.Denominator)
	denominator.Mul(denominator, new(big.Int).SetUint64(config.TargetSpacing))
	denominator.Mul(denominator, hashPlusOne(config.AnchorTarget))
	if numerator.Cmp(denominator) >= 0 {
		return true
	}

	// Uniform is a deterministic 256-bit integer. The cross-multiplied
	// comparison samples numerator/denominator to 256-bit resolution.
	uniform := new(big.Int)
	for range 4 {
		uniform.Lsh(uniform, 64)
		uniform.Or(uniform, new(big.Int).SetUint64(random.next()))
	}
	left := new(big.Int).Mul(uniform, denominator)
	right := new(big.Int).Lsh(numerator, 256)
	return left.Cmp(right) < 0
}

func stochasticObservation(
	height uint64,
	wallTime uint64,
	timestamp uint64,
	duration uint64,
	target types.Hash,
	cumulativeWork *big.Int,
) (Observation, error) {
	blockWork, err := pow.Work(target)
	if err != nil {
		return Observation{}, err
	}
	cumulativeWork.Add(cumulativeWork, blockWork)
	return Observation{
		Height:         height,
		WallTime:       wallTime,
		Timestamp:      timestamp,
		SolveSeconds:   duration,
		Target:         target,
		Work:           append([]byte(nil), blockWork.Bytes()...),
		CumulativeWork: append([]byte(nil), cumulativeWork.Bytes()...),
	}, nil
}

func appendStochasticTimestamp(timestamps []uint64, timestamp uint64) []uint64 {
	timestamps = append(timestamps, timestamp)
	if len(timestamps) > 11 {
		timestamps = append(timestamps[:0], timestamps[len(timestamps)-11:]...)
	}
	return timestamps
}

type stochasticPRNG struct {
	state uint64
}

func (random *stochasticPRNG) next() uint64 {
	random.state += 0x9e3779b97f4a7c15
	value := random.state
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	return value ^ (value >> 31)
}

func writeStochasticUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func writeStochasticBytes(digest hash.Hash, value []byte) {
	writeStochasticUint64(digest, uint64(len(value)))
	_, _ = digest.Write(value)
}
