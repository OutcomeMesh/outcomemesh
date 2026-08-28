package workgraphmodel

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestHoeffdingUpper99PPMGolden(t *testing.T) {
	tests := []struct {
		successes uint64
		trials    uint64
		empirical uint32
		margin    uint32
		upper     uint32
	}{
		{successes: 0, trials: 1, empirical: 0, margin: 1_000_000, upper: 1_000_000},
		{successes: 0, trials: 100, empirical: 0, margin: 151_743, upper: 151_743},
		{successes: 2_000, trials: 10_000, empirical: 200_000, margin: 15_175, upper: 215_175},
		{successes: 2_400, trials: 10_000, empirical: 240_000, margin: 15_175, upper: 255_175},
		{successes: 1, trials: 3, empirical: 333_334, margin: 876_088, upper: 1_000_000},
	}
	for _, test := range tests {
		bound, err := HoeffdingUpper99PPM(test.successes, test.trials)
		if err != nil {
			t.Fatalf("HoeffdingUpper99PPM(%d, %d): %v", test.successes, test.trials, err)
		}
		if bound.EmpiricalPPM != test.empirical || bound.MarginPPM != test.margin || bound.UpperPPM != test.upper {
			t.Fatalf("HoeffdingUpper99PPM(%d, %d) = %+v, want empirical=%d margin=%d upper=%d",
				test.successes, test.trials, bound, test.empirical, test.margin, test.upper)
		}
	}
}

func TestHoeffdingUpper99PPMRejectsInvalidEvidence(t *testing.T) {
	for _, test := range [][2]uint64{{0, 0}, {2, 1}} {
		if _, err := HoeffdingUpper99PPM(test[0], test[1]); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("HoeffdingUpper99PPM(%d, %d) error = %v, want ErrConfiguration", test[0], test[1], err)
		}
	}
	if _, err := HoeffdingFamilyUpper99PPM(0, 1, 0); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("zero comparisons error = %v, want ErrConfiguration", err)
	}
}

func TestHoeffdingFamilyUpper99PPMCorrectsSelection(t *testing.T) {
	single, err := HoeffdingFamilyUpper99PPM(11_000, 50_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	family, err := HoeffdingFamilyUpper99PPM(11_000, 50_000, 64)
	if err != nil {
		t.Fatal(err)
	}
	if single.MarginPPM != 6_787 || family.MarginPPM != 9_362 || family.UpperPPM != 229_362 {
		t.Fatalf("selection correction single=%+v family=%+v", single, family)
	}
	rounded, err := HoeffdingFamilyUpper99PPM(11_000, 50_000, 33)
	if err != nil {
		t.Fatal(err)
	}
	if rounded.MarginPPM != family.MarginPPM {
		t.Fatalf("power-of-two correction 33=%d, 64=%d", rounded.MarginPPM, family.MarginPPM)
	}
}

func TestPublicTestnetCalibrationGateAndDigest(t *testing.T) {
	config := PublicTestnetCalibrationConfig{
		ObservationWindowSeconds: PublicTestnetMinimumWindowSeconds,
		ControlledTieAdoptions:   2_000,
		ControlledTieTrials:      10_000,
		LargestCoordinatedWork:   11_000,
		ObservedWork:             50_000,
		CoordinatedClusters:      64,
		MaximumUpperPPM:          PublicTestnetMaximumUpperPPM,
	}
	document, err := EvaluatePublicTestnetCalibration(config)
	if err != nil {
		t.Fatal(err)
	}
	if !document.Result.Pass || !document.Result.WindowPass || !document.Result.TieAdoptionPass || !document.Result.CoordinatedWorkPass {
		t.Fatalf("passing calibration = %+v", document.Result)
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "3126281dfc8b5bc1e49cf960521ec33576c096cbc8228e7a9e66ffa4bb9ec3d4"
	if got := hex.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("calibration digest = %s, want %s; result=%+v", got, wantDigest, document.Result)
	}

	short := config
	short.ObservationWindowSeconds--
	shortDocument, err := EvaluatePublicTestnetCalibration(short)
	if err != nil {
		t.Fatal(err)
	}
	if shortDocument.Result.Pass || shortDocument.Result.WindowPass {
		t.Fatalf("short observation window passed: %+v", shortDocument.Result)
	}

	highTie := config
	highTie.ControlledTieAdoptions = 2_400
	highDocument, err := EvaluatePublicTestnetCalibration(highTie)
	if err != nil {
		t.Fatal(err)
	}
	if highDocument.Result.Pass || highDocument.Result.TieAdoptionPass {
		t.Fatalf("high tie adoption passed: %+v", highDocument.Result)
	}
}

func TestPublicTestnetCalibrationRejectsInvalidConfiguration(t *testing.T) {
	config := PublicTestnetCalibrationConfig{
		ObservationWindowSeconds: PublicTestnetMinimumWindowSeconds,
		ControlledTieTrials:      1,
		ObservedWork:             1,
		CoordinatedClusters:      1,
		MaximumUpperPPM:          PublicTestnetMaximumUpperPPM,
	}
	for _, limit := range []uint32{0, PartsPerMillion + 1} {
		config.MaximumUpperPPM = limit
		if _, err := EvaluatePublicTestnetCalibration(config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("limit %d error = %v, want ErrConfiguration", limit, err)
		}
	}

	document := PublicTestnetCalibrationDocument{}
	if _, err := document.CanonicalJSON(); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("invalid document error = %v, want ErrConfiguration", err)
	}
}
