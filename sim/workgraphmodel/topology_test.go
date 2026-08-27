package workgraphmodel

import (
	"errors"
	"testing"
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
