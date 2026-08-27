package powmodel

import (
	"errors"
	"math/big"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func testConfig() Config {
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	return Config{
		AnchorTarget:    target,
		AnchorTimestamp: 1_700_000_000,
		TargetSpacing:   block.DefaultTargetSpacing,
		HalfLife:        block.DefaultASERTHalfLife,
		MaxSolveSeconds: 30 * 24 * 60 * 60,
	}
}

func TestBaselineHashRateTracksExactSchedule(t *testing.T) {
	t.Parallel()

	config := testConfig()
	observations, err := Run(config, []Phase{{
		Blocks:   200,
		HashRate: Ratio{Numerator: 1, Denominator: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range observations {
		if observation.SolveSeconds != config.TargetSpacing {
			t.Fatalf("height %d solve time = %d, want %d", observation.Height, observation.SolveSeconds, config.TargetSpacing)
		}
		if observation.Target != config.AnchorTarget {
			t.Fatalf("height %d target drifted on schedule", observation.Height)
		}
	}
}

func TestASERTConvergesAfterFourfoldHashRateStep(t *testing.T) {
	t.Parallel()

	config := testConfig()
	observations, err := Run(config, []Phase{
		{Blocks: 100, HashRate: Ratio{Numerator: 1, Denominator: 1}},
		{Blocks: 700, HashRate: Ratio{Numerator: 4, Denominator: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observations[100].SolveSeconds >= config.TargetSpacing/2 {
		t.Fatalf("hash-rate step did not initially shorten blocks: %d", observations[100].SolveSeconds)
	}
	average := averageSolveTime(observations[len(observations)-100:])
	t.Logf("4x step: first=%ds final-100-average=%ds final-target=%s final-work=%s",
		observations[100].SolveSeconds, average, observations[len(observations)-1].Target,
		new(big.Int).SetBytes(observations[len(observations)-1].Work))
	if average < 55 || average > 65 {
		t.Fatalf("ASERT did not reconverge near 60 seconds: final average=%d", average)
	}
	if new(big.Int).SetBytes(observations[len(observations)-1].Work).Cmp(big.NewInt(3)) < 0 {
		t.Fatal("fourfold hash rate did not produce proportionally harder chain work")
	}
}

func TestFutureTimestampBiasHasBoundedTargetEffect(t *testing.T) {
	t.Parallel()

	config := testConfig()
	honest, err := Run(config, []Phase{{
		Blocks:   800,
		HashRate: Ratio{Numerator: 4, Denominator: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	biased, err := Run(config, []Phase{{
		Blocks:        800,
		HashRate:      Ratio{Numerator: 4, Denominator: 1},
		TimestampBias: int64(block.MaxFutureDrift),
	}})
	if err != nil {
		t.Fatal(err)
	}
	honestTarget := new(big.Int).SetBytes(honest[len(honest)-1].Target[:])
	biasedTarget := new(big.Int).SetBytes(biased[len(biased)-1].Target[:])
	if biasedTarget.Cmp(honestTarget) < 0 {
		t.Fatal("maximum future bias unexpectedly made the target harder")
	}
	ratioBasisPoints := new(big.Int).Mul(biasedTarget, big.NewInt(10_000))
	ratioBasisPoints.Div(ratioBasisPoints, honestTarget)
	t.Logf("+120s target ratio=%s basis points", ratioBasisPoints)
	if ratioBasisPoints.Cmp(big.NewInt(10_120)) > 0 {
		t.Fatalf("120-second bias changed target by more than 1.2%%: %s bp", ratioBasisPoints)
	}
}

func TestASERTEasesAfterHashRateReturnsToBaseline(t *testing.T) {
	t.Parallel()

	config := testConfig()
	observations, err := Run(config, []Phase{
		{Blocks: 100, HashRate: Ratio{Numerator: 1, Denominator: 1}},
		{Blocks: 700, HashRate: Ratio{Numerator: 4, Denominator: 1}},
		{Blocks: 1_000, HashRate: Ratio{Numerator: 1, Denominator: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observations[800].SolveSeconds <= config.TargetSpacing*2 {
		t.Fatalf("hash-rate drop did not initially lengthen blocks: %d", observations[800].SolveSeconds)
	}
	average := averageSolveTime(observations[len(observations)-100:])
	if average < 58 || average > 62 {
		t.Fatalf("ASERT did not ease back to baseline: final average=%d", average)
	}
	t.Logf("4x -> 1x: first=%ds final-100-average=%ds final-target=%s",
		observations[800].SolveSeconds, average, observations[len(observations)-1].Target)
}

func TestSlowTimestampManipulationPaysMoreWorkPerBlock(t *testing.T) {
	t.Parallel()

	config := testConfig()
	honest, err := Run(config, []Phase{{
		Blocks:   300,
		HashRate: Ratio{Numerator: 4, Denominator: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	slow, err := Run(config, []Phase{{
		Blocks:        300,
		HashRate:      Ratio{Numerator: 4, Denominator: 1},
		TimestampBias: -3_600,
	}})
	if err != nil {
		t.Fatal(err)
	}
	honestWork := new(big.Int).SetBytes(honest[len(honest)-1].CumulativeWork)
	slowWork := new(big.Int).SetBytes(slow[len(slow)-1].CumulativeWork)
	t.Logf("slow timestamp: honest-work=%s slow-work=%s honest-elapsed=%d slow-elapsed=%d",
		honestWork, slowWork,
		honest[len(honest)-1].WallTime-config.AnchorTimestamp,
		slow[len(slow)-1].WallTime-config.AnchorTimestamp)
	if slowWork.Cmp(honestWork) <= 0 {
		t.Fatal("slow timestamps created the same block count without more committed work")
	}
	if slow[len(slow)-1].WallTime <= honest[len(honest)-1].WallTime {
		t.Fatal("slow timestamps did not increase physical time needed for the same block count")
	}
}

func TestRejectsBiasBeyondFutureAdmissionBound(t *testing.T) {
	t.Parallel()

	_, err := Run(testConfig(), []Phase{{
		Blocks:        1,
		HashRate:      Ratio{Numerator: 1, Denominator: 1},
		TimestampBias: int64(block.MaxFutureDrift) + 1,
	}})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("got %v, want invalid configuration", err)
	}
}

func averageSolveTime(observations []Observation) uint64 {
	var total uint64
	for _, observation := range observations {
		total += observation.SolveSeconds
	}
	return total / uint64(len(observations))
}
