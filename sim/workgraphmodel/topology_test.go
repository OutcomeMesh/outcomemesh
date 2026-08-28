package workgraphmodel

import (
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func TestFullMeshOneEventPropagationCommitsEveryPublishedShare(t *testing.T) {
	t.Parallel()

	miners := fullMeshTopology(8)
	result, err := RunTopology(TopologyConfig{
		Rounds: 2_000, Seed: 0x510e527fade682d1, ShareRatio: 128, LinkDelayEvents: 1, Miners: miners,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PublishedShares != result.IncludedShares || result.UnseenAtWinner != 0 ||
		result.KnownButUncommitted != 0 || result.RoundsOverFourWinnerTips != 0 {
		t.Fatalf("full-mesh propagation lost shares: %+v", result)
	}
	t.Logf("full_mesh shares=%d max_tips=%d", result.IncludedShares, result.MaxWinnerTips)
}

func TestDelayedLineQuantifiesWinnerVisibilityAndTipPressure(t *testing.T) {
	t.Parallel()

	miners := lineTopology(8)
	result, err := RunTopology(TopologyConfig{
		Rounds: 2_000, Seed: 0x1f83d9abfb41bd6b, ShareRatio: 128, LinkDelayEvents: 3, Miners: miners,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.UnseenAtWinner == 0 || result.IncludedShares >= result.PublishedShares {
		t.Fatalf("delayed line did not expose propagation loss: %+v", result)
	}
	if result.IncludedShares*100 < result.PublishedShares*80 {
		t.Fatalf("delayed line lost more than 20%% of published shares: %+v", result)
	}
	t.Logf("delayed_line published=%d included=%d unseen=%d uncommitted=%d over_four_rounds=%d max_tips=%d",
		result.PublishedShares, result.IncludedShares, result.UnseenAtWinner,
		result.KnownButUncommitted, result.RoundsOverFourWinnerTips, result.MaxWinnerTips)
}

func TestStrategicWithholdingAndTipOmissionAreVisible(t *testing.T) {
	t.Parallel()

	miners := fullMeshTopology(4)
	miners[0].HashUnits = 4
	miners[0].WithholdPPM = 500_000
	miners[0].OmitForeignTipsPPM = PartsPerMillion
	result, err := RunTopology(TopologyConfig{
		Rounds: 3_000, Seed: 0x5be0cd19137e2179, ShareRatio: 64, LinkDelayEvents: 2, Miners: miners,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Miners[0].AnchorWins == 0 || result.StrategicTipOmissions == 0 ||
		result.PublishedShares >= result.DiscoveredShares {
		t.Fatalf("strategic fixture was not exercised: %+v", result)
	}
	if result.Miners[0].IncludedShares >= result.Miners[0].DiscoveredShares {
		t.Fatalf("withholding had no lost-credit cost: %+v", result.Miners[0])
	}
	t.Logf("strategic discovered=%d published=%d included=%d omitted_tips=%d attacker=%+v",
		result.DiscoveredShares, result.PublishedShares, result.IncludedShares,
		result.StrategicTipOmissions, result.Miners[0])
}

func TestTopologyRejectsDisconnectedOrInvalidGraphs(t *testing.T) {
	t.Parallel()

	_, err := RunTopology(TopologyConfig{
		Rounds: 1, Seed: 1, ShareRatio: 2, LinkDelayEvents: 1,
		Miners: []TopologyMiner{{HashUnits: 1}, {HashUnits: 1}},
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("disconnected graph error = %v", err)
	}
	_, err = RunTopology(TopologyConfig{
		Rounds: 1, Seed: 1, ShareRatio: 2, LinkDelayEvents: 1,
		Miners: []TopologyMiner{
			{HashUnits: 1, RelayBatchShares: workgraph.MaxShares + 1, Links: []int{1}},
			{HashUnits: 1, Links: []int{0}},
		},
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("oversized relay batch error = %v", err)
	}
}

func TestTimedPartialRelayProtectsSmallMinerReward(t *testing.T) {
	miners := fullMeshTopology(2)
	miners[0].HashUnits = 1
	miners[1].HashUnits = 9
	config := TopologyConfig{
		Rounds: 1_000, Seed: 0x6a09e667f3bcc909, ShareRatio: workgraph.ShareDifficultyRatio,
		LinkDelayEvents: 1, BlockSubsidy: 5_000_000_000, Miners: miners,
	}
	immediate, err := RunTopology(config)
	if err != nil {
		t.Fatal(err)
	}
	for index := range config.Miners {
		config.Miners[index].RelayBatchShares = 128
	}
	batchOnly, err := RunTopology(config)
	if err != nil {
		t.Fatal(err)
	}
	for index := range config.Miners {
		config.Miners[index].RelayIntervalEvents = 69
	}
	timed, err := RunTopology(config)
	if err != nil {
		t.Fatal(err)
	}
	immediateSmallPPM, err := RewardSharePPM(immediate.Miners[0].Reward, immediate.Miners[1].Reward)
	if err != nil {
		t.Fatal(err)
	}
	batchSmallPPM, err := RewardSharePPM(batchOnly.Miners[0].Reward, batchOnly.Miners[1].Reward)
	if err != nil {
		t.Fatal(err)
	}
	timedSmallPPM, err := RewardSharePPM(timed.Miners[0].Reward, timed.Miners[1].Reward)
	if err != nil {
		t.Fatal(err)
	}
	if batchSmallPPM+20_000 >= immediateSmallPPM {
		t.Fatalf("full-batch-only relay did not expose small-miner bias: immediate=%d batch=%d", immediateSmallPPM, batchSmallPPM)
	}
	if timedSmallPPM <= batchSmallPPM+20_000 || absoluteDifference(timedSmallPPM, immediateSmallPPM) > 10_000 {
		t.Fatalf("timed relay did not restore small-miner reward: immediate=%d batch=%d timed=%d",
			immediateSmallPPM, batchSmallPPM, timedSmallPPM)
	}
	if timed.IncludedShares*100 < immediate.IncludedShares*90 ||
		timed.UnreleasedAtWinner >= batchOnly.UnreleasedAtWinner || timed.IssuedSubsidy <= batchOnly.IssuedSubsidy {
		t.Fatalf("timed relay failed delivery/issuance bounds: immediate=%+v batch=%+v timed=%+v",
			immediate, batchOnly, timed)
	}
	if immediateSmallPPM != 104_349 || batchSmallPPM != 73_611 || timedSmallPPM != 102_033 ||
		immediate.IncludedShares != 496_602 || batchOnly.IncludedShares != 455_372 ||
		timed.IncludedShares != 490_321 || batchOnly.UnreleasedAtWinner != 99_674 ||
		timed.UnreleasedAtWinner != 32_784 {
		t.Fatalf("relay calibration corpus changed: immediate=%+v batch=%+v timed=%+v ppm=%d/%d/%d",
			immediate, batchOnly, timed, immediateSmallPPM, batchSmallPPM, timedSmallPPM)
	}
	t.Logf("small_miner_reward_ppm immediate=%d batch_only=%d timed=%d", immediateSmallPPM, batchSmallPPM, timedSmallPPM)
	t.Logf("relay_delivery immediate_included=%d batch_included=%d timed_included=%d batch_unreleased=%d timed_unreleased=%d",
		immediate.IncludedShares, batchOnly.IncludedShares, timed.IncludedShares,
		batchOnly.UnreleasedAtWinner, timed.UnreleasedAtWinner)
}

func absoluteDifference(left, right uint64) uint64 {
	if left >= right {
		return left - right
	}
	return right - left
}

func fullMeshTopology(count int) []TopologyMiner {
	miners := make([]TopologyMiner, count)
	for source := range miners {
		miners[source].HashUnits = 1
		for destination := range miners {
			if source != destination {
				miners[source].Links = append(miners[source].Links, destination)
			}
		}
	}
	return miners
}

func lineTopology(count int) []TopologyMiner {
	miners := make([]TopologyMiner, count)
	for index := range miners {
		miners[index].HashUnits = 1
		if index > 0 {
			miners[index].Links = append(miners[index].Links, index-1)
		}
		if index+1 < count {
			miners[index].Links = append(miners[index].Links, index+1)
		}
	}
	return miners
}
