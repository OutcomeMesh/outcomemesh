package powmodel

import (
	"math/big"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/difficulty"
)

func TestLaggedASERTBaselineAndParentCommitment(t *testing.T) {
	t.Parallel()

	config := testConfig()
	observations, err := RunLagged(config, []Phase{{
		Blocks: 200, HashRate: Ratio{Numerator: 1, Denominator: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	parentTimestamp := config.AnchorTimestamp
	for _, observation := range observations {
		expected, err := difficulty.ASERT(
			config.AnchorTarget, config.AnchorTimestamp, observation.Height,
			parentTimestamp+config.TargetSpacing, config.TargetSpacing, config.HalfLife,
		)
		if err != nil {
			t.Fatal(err)
		}
		if observation.Target != expected || observation.SolveSeconds != config.TargetSpacing {
			t.Fatalf("height %d target/solve mismatch: solve=%d", observation.Height, observation.SolveSeconds)
		}
		parentTimestamp = observation.Timestamp
	}
}

func TestLaggedASERTCurrentTimestampCannotEaseCurrentProof(t *testing.T) {
	t.Parallel()

	config := testConfig()
	honest, err := RunLagged(config, []Phase{{
		Blocks: 1, HashRate: Ratio{Numerator: 4, Denominator: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	future, err := RunLagged(config, []Phase{{
		Blocks: 1, HashRate: Ratio{Numerator: 4, Denominator: 1}, TimestampBias: int64(block.MaxFutureDrift),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if honest[0].Target != future[0].Target || honest[0].SolveSeconds != future[0].SolveSeconds {
		t.Fatal("current timestamp bias changed its already precommitted proof target")
	}
	if honest[0].Timestamp == future[0].Timestamp {
		t.Fatal("timestamp-bias fixture did not change the header timestamp")
	}
}

func TestLaggedASERTConvergesAfterHashRateStep(t *testing.T) {
	t.Parallel()

	config := testConfig()
	observations, err := RunLagged(config, []Phase{
		{Blocks: 100, HashRate: Ratio{Numerator: 1, Denominator: 1}},
		{Blocks: 700, HashRate: Ratio{Numerator: 4, Denominator: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observations[100].SolveSeconds >= config.TargetSpacing/2 {
		t.Fatalf("lagged 4x step did not initially shorten blocks: %d", observations[100].SolveSeconds)
	}
	average := averageSolveTime(observations[len(observations)-100:])
	if average < 55 || average > 65 {
		t.Fatalf("lagged ASERT did not reconverge near 60 seconds: %d", average)
	}
	if new(big.Int).SetBytes(observations[len(observations)-1].Work).Cmp(big.NewInt(3)) < 0 {
		t.Fatal("lagged ASERT did not convert 4x hash rate into harder chain work")
	}
	t.Logf("lagged_4x first=%ds final_100_average=%ds", observations[100].SolveSeconds, average)
}

func TestLaggedSlowTimestampCannotCreateCheapHeight(t *testing.T) {
	t.Parallel()

	config := testConfig()
	honest, err := RunLagged(config, []Phase{{
		Blocks: 300, HashRate: Ratio{Numerator: 4, Denominator: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	slow, err := RunLagged(config, []Phase{{
		Blocks: 300, HashRate: Ratio{Numerator: 4, Denominator: 1}, TimestampBias: -3_600,
	}})
	if err != nil {
		t.Fatal(err)
	}
	honestWork := new(big.Int).SetBytes(honest[len(honest)-1].CumulativeWork)
	slowWork := new(big.Int).SetBytes(slow[len(slow)-1].CumulativeWork)
	if slowWork.Cmp(honestWork) <= 0 || slow[len(slow)-1].WallTime <= honest[len(honest)-1].WallTime {
		t.Fatalf("slow lagged timestamps produced cheap height: honest_work=%s slow_work=%s", honestWork, slowWork)
	}
}
