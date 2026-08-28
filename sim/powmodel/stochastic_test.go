package powmodel

import (
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
)

func TestStochasticASERTBaselineHasExpectedNonceVariance(t *testing.T) {
	t.Parallel()

	config := testConfig()
	observations, err := RunStochastic(config, []Phase{{
		Blocks: 2_048, HashRate: Ratio{Numerator: 1, Denominator: 1},
	}}, 0x3c6ef372fe94f82b)
	if err != nil {
		t.Fatal(err)
	}
	minimum, mean, p50, p95, p99, maximum := stochasticDistribution(observations)
	if minimum != 1 || mean != 62 || p50 != 43 || p95 != 184 || p99 != 271 || maximum != 464 {
		t.Fatalf("unexpected v0 solve distribution: min=%d mean=%d p50=%d p95=%d p99=%d max=%d",
			minimum, mean, p50, p95, p99, maximum)
	}
	t.Logf("stochastic_v0_baseline min=%d mean=%d p50=%d p95=%d p99=%d max=%d elapsed=%d",
		minimum, mean, p50, p95, p99, maximum,
		observations[len(observations)-1].WallTime-config.AnchorTimestamp)
	digest := DigestObservations(observations)
	const wantDigest = "be7e802166596c6c5bd6f226561056e412f623738462da910b5c89ec2956e8aa"
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("stochastic v0 digest = %s, want %s", got, wantDigest)
	}
	t.Logf("stochastic_v0_sha256=%s", hex.EncodeToString(digest[:]))
}

func TestStochasticLaggedBaselineIsDeterministicWithSolveVariance(t *testing.T) {
	t.Parallel()

	config := testConfig()
	phases := []Phase{{
		Blocks: 4_096, HashRate: Ratio{Numerator: 1, Denominator: 1},
	}}
	const seed = 0x6a09e667f3bcc909
	first, err := RunStochasticLagged(config, phases, seed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RunStochasticLagged(config, phases, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("fixed seed did not reproduce the same stochastic chain")
	}
	different, err := RunStochasticLagged(config, phases, seed+1)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first, different) {
		t.Fatal("different seeds produced identical stochastic chains")
	}

	minimum, mean, p50, p95, p99, maximum := stochasticDistribution(first)
	if minimum != 1 || mean != 59 || p50 != 41 || p95 != 179 || p99 != 269 || maximum != 560 {
		t.Fatalf("unexpected solve distribution: min=%d mean=%d p50=%d p95=%d p99=%d max=%d",
			minimum, mean, p50, p95, p99, maximum)
	}
	t.Logf("stochastic_lagged_baseline min=%d mean=%d p50=%d p95=%d p99=%d max=%d elapsed=%d",
		minimum, mean, p50, p95, p99, maximum,
		first[len(first)-1].WallTime-config.AnchorTimestamp)
	digest := DigestObservations(first)
	const wantDigest = "34be269d5b978372e5bc183bf46c46e2a27bf2a37216defb80b56d5413bcd187"
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("stochastic lagged digest = %s, want %s", got, wantDigest)
	}
	t.Logf("stochastic_lagged_sha256=%s", hex.EncodeToString(digest[:]))
}

func TestStochasticLaggedHashStepReconverges(t *testing.T) {
	t.Parallel()

	config := testConfig()
	observations, err := RunStochasticLagged(config, []Phase{
		{Blocks: 100, HashRate: Ratio{Numerator: 1, Denominator: 1}},
		{Blocks: 700, HashRate: Ratio{Numerator: 4, Denominator: 1}},
	}, 0xa54ff53a5f1d36f1)
	if err != nil {
		t.Fatal(err)
	}
	finalMean := averageSolveTime(observations[len(observations)-100:])
	if observations[100].SolveSeconds != 15 || finalMean != 55 ||
		observations[len(observations)-1].WallTime-config.AnchorTimestamp != 33_830 ||
		new(big.Int).SetBytes(observations[len(observations)-1].CumulativeWork).Cmp(big.NewInt(1_633)) != 0 {
		t.Fatalf("stochastic 4x step did not reconverge: final mean=%d", finalMean)
	}
	t.Logf("stochastic_lagged_4x first=%d final_100_mean=%d elapsed=%d final_work=%s",
		observations[100].SolveSeconds, finalMean,
		observations[len(observations)-1].WallTime-config.AnchorTimestamp,
		new(big.Int).SetBytes(observations[len(observations)-1].CumulativeWork))
}

func TestStochasticLaggedSlowTimestampStillCostsMoreWorkAndTime(t *testing.T) {
	t.Parallel()

	config := testConfig()
	const seed = 0x510e527fade682d1
	honest, err := RunStochasticLagged(config, []Phase{{
		Blocks: 300, HashRate: Ratio{Numerator: 4, Denominator: 1},
	}}, seed)
	if err != nil {
		t.Fatal(err)
	}
	slow, err := RunStochasticLagged(config, []Phase{{
		Blocks: 300, HashRate: Ratio{Numerator: 4, Denominator: 1}, TimestampBias: -3_600,
	}}, seed)
	if err != nil {
		t.Fatal(err)
	}
	honestWork := new(big.Int).SetBytes(honest[len(honest)-1].CumulativeWork)
	slowWork := new(big.Int).SetBytes(slow[len(slow)-1].CumulativeWork)
	if honestWork.Cmp(big.NewInt(423)) != 0 || slowWork.Cmp(big.NewInt(534)) != 0 ||
		honest[len(honest)-1].WallTime-config.AnchorTimestamp != 7_474 ||
		slow[len(slow)-1].WallTime-config.AnchorTimestamp != 9_718 {
		t.Fatalf("stochastic slow timestamps created cheap height: honest_work=%s slow_work=%s honest_time=%d slow_time=%d",
			honestWork, slowWork, honest[len(honest)-1].WallTime, slow[len(slow)-1].WallTime)
	}
	t.Logf("stochastic_slow_timestamp honest_work=%s slow_work=%s honest_elapsed=%d slow_elapsed=%d",
		honestWork, slowWork,
		honest[len(honest)-1].WallTime-config.AnchorTimestamp,
		slow[len(slow)-1].WallTime-config.AnchorTimestamp)
}

func TestStochasticTargetRulesAlternatingHashRateCorpus(t *testing.T) {
	t.Parallel()

	config := testConfig()
	phases := []Phase{
		{Blocks: 100, HashRate: Ratio{Numerator: 1, Denominator: 1}},
		{Blocks: 700, HashRate: Ratio{Numerator: 4, Denominator: 1}},
	}
	for range 12 {
		phases = append(phases,
			Phase{Blocks: 32, HashRate: Ratio{Numerator: 1, Denominator: 1}},
			Phase{Blocks: 32, HashRate: Ratio{Numerator: 4, Denominator: 1}},
		)
	}
	const seed = 0x1f83d9abfb41bd6b
	v0, err := RunStochastic(config, phases, seed)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := RunStochasticLagged(config, phases, seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(v0) != 1_568 || len(v1) != 1_568 {
		t.Fatalf("oscillation lengths: v0=%d v1=%d", len(v0), len(v1))
	}
	v0Work := new(big.Int).SetBytes(v0[len(v0)-1].CumulativeWork)
	v1Work := new(big.Int).SetBytes(v1[len(v1)-1].CumulativeWork)
	v0Digest := DigestObservations(v0)
	v1Digest := DigestObservations(v1)
	const wantV0Digest = "23e85e47e4d494ef80b5281f6f2b3a6360c665e5e91ab0c08578442c71642d48"
	const wantV1Digest = "af0c193a2c9859f88490fac3289668cd7f0e8ec7f9538a6cfd7b6e33aefa2ba0"
	if v0[len(v0)-1].WallTime-config.AnchorTimestamp != 88_750 || v0Work.Cmp(big.NewInt(2_561)) != 0 ||
		hex.EncodeToString(v0Digest[:]) != wantV0Digest ||
		v1[len(v1)-1].WallTime-config.AnchorTimestamp != 88_791 || v1Work.Cmp(big.NewInt(2_574)) != 0 ||
		hex.EncodeToString(v1Digest[:]) != wantV1Digest {
		t.Fatalf("oscillation corpus changed: v0_time=%d v0_work=%s v0_digest=%s v1_time=%d v1_work=%s v1_digest=%s",
			v0[len(v0)-1].WallTime-config.AnchorTimestamp, v0Work, hex.EncodeToString(v0Digest[:]),
			v1[len(v1)-1].WallTime-config.AnchorTimestamp, v1Work, hex.EncodeToString(v1Digest[:]))
	}
	t.Logf("stochastic_oscillation v0_elapsed=%d v0_work=%s v0_sha256=%s v1_elapsed=%d v1_work=%s v1_sha256=%s",
		v0[len(v0)-1].WallTime-config.AnchorTimestamp, v0Work, hex.EncodeToString(v0Digest[:]),
		v1[len(v1)-1].WallTime-config.AnchorTimestamp, v1Work, hex.EncodeToString(v1Digest[:]))
}

func TestStochasticLaggedCurrentTimestampCannotChangeCurrentSolve(t *testing.T) {
	t.Parallel()

	config := testConfig()
	const seed = 0xbb67ae8584caa73b
	honest, err := RunStochasticLagged(config, []Phase{{
		Blocks: 1, HashRate: Ratio{Numerator: 4, Denominator: 1},
	}}, seed)
	if err != nil {
		t.Fatal(err)
	}
	future, err := RunStochasticLagged(config, []Phase{{
		Blocks: 1, HashRate: Ratio{Numerator: 4, Denominator: 1},
		TimestampBias: int64(block.MaxFutureDrift),
	}}, seed)
	if err != nil {
		t.Fatal(err)
	}
	if honest[0].Target != future[0].Target || honest[0].SolveSeconds != future[0].SolveSeconds {
		t.Fatalf("current timestamp changed fixed stochastic target/solve: honest=%+v future=%+v",
			honest[0], future[0])
	}
	if honest[0].Timestamp == future[0].Timestamp {
		t.Fatal("future-bias fixture did not change the candidate timestamp")
	}
}

func TestStochasticModelRejectsZeroSeedAndBoundedNoSolution(t *testing.T) {
	t.Parallel()

	phase := []Phase{{Blocks: 1, HashRate: Ratio{Numerator: 1, Denominator: 1}}}
	if _, err := RunStochastic(testConfig(), phase, 0); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("zero seed error = %v, want ErrConfiguration", err)
	}
	excessiveSolve := testConfig()
	excessiveSolve.MaxSolveSeconds = MaxStochasticSolveSeconds + 1
	if _, err := RunStochastic(excessiveSolve, phase, 1); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("excessive solve bound error = %v, want ErrConfiguration", err)
	}
	excessiveBlocks := []Phase{{
		Blocks: MaxStochasticBlocks + 1, HashRate: Ratio{Numerator: 1, Denominator: 1},
	}}
	if _, err := RunStochastic(testConfig(), excessiveBlocks, 1); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("excessive block corpus error = %v, want ErrConfiguration", err)
	}
	config := testConfig()
	config.MaxSolveSeconds = 1
	phase[0].HashRate.Denominator = ^uint64(0)
	if _, err := RunStochasticLagged(config, phase, 1); !errors.Is(err, ErrNoSolution) {
		t.Fatalf("bounded solve error = %v, want ErrNoSolution", err)
	}
}

func stochasticDistribution(observations []Observation) (uint64, uint64, uint64, uint64, uint64, uint64) {
	durations := make([]uint64, len(observations))
	for index, observation := range observations {
		durations[index] = observation.SolveSeconds
	}
	sort.Slice(durations, func(left, right int) bool { return durations[left] < durations[right] })
	return durations[0], averageSolveTime(observations), durations[len(durations)/2],
		durations[len(durations)*95/100], durations[len(durations)*99/100], durations[len(durations)-1]
}
