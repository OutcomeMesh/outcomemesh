package workgraphmodel

import (
	"errors"
	"testing"
)

func TestGlobalTieBreakGrindingMakesPublishedAdoptionCertain(t *testing.T) {
	result, err := RunGlobalTieBreakGrinding(GlobalTieBreakGrindingConfig{
		Trials: 10_000,
		Seed:   0xd1310ba698dfb5ac,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.PotentialRaces != 10_000 || result.PublishedRaces != 4_959 ||
		result.SuppressedRaces != 5_041 || result.PublishedAdoptions != 4_959 ||
		result.FavorableIDPPM != 495_900 || result.PublishedAdoptionPPM != uint64(PartsPerMillion) {
		t.Fatalf("global tie-break grinding result=%+v", result)
	}
	t.Logf("global_tie_break_grinding=%+v", result)
}

func TestGlobalTieBreakGrindingRejectsUnboundedInput(t *testing.T) {
	for _, config := range []GlobalTieBreakGrindingConfig{
		{},
		{Trials: 1, Seed: 0},
		{Trials: MaximumGlobalTieBreakTrials + 1, Seed: 1},
	} {
		if _, err := RunGlobalTieBreakGrinding(config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("config=%+v error=%v", config, err)
		}
	}
}
