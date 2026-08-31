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
		TieCompletedTrials:       10_000,
		LargestCoordinatedWork:   11_000,
		ObservedWork:             50_000,
		CoordinatedClusters:      64,
		EvidenceRecords:          720,
		EvidenceTailID:           "8498100edacc5868a99f555f523280e4039aa8bf2be9f1c972e6bf7f687b616c",
		EvidenceVerified:         true,
		TiePlanID:                "5066c5b78d96483c7aa99b1c35166d52fda67344005103e885ee1881a9d65676",
		TiePlanVersion:           1,
		TieEvidenceReceipts:      10_000,
		TieObserverCount:         1,
		TieValidatedReceipts:     10_000,
		TieEvidenceTailID:        "fd13185e9b02fb5d6bf2998eaa0ca8239db644538f01e10ad0a325b21069f3a7",
		TieEvidenceVerified:      true,
		MaximumUpperPPM:          PublicTestnetMaximumUpperPPM,
	}
	document, err := EvaluatePublicTestnetCalibration(config)
	if err != nil {
		t.Fatal(err)
	}
	if !document.Result.Pass || !document.Result.WindowPass || !document.Result.TieAdoptionPass ||
		!document.Result.CoordinatedWorkPass || !document.Result.EvidencePass {
		t.Fatalf("passing calibration = %+v", document.Result)
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "19f52e9a351965eebe5f18d39d1ed04f164225593d40e59f1a0759471b79094e"
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

	missingEvidence := config
	missingEvidence.EvidenceTailID = ""
	missingDocument, err := EvaluatePublicTestnetCalibration(missingEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if missingDocument.Result.Pass || missingDocument.Result.EvidencePass {
		t.Fatalf("missing evidence passed: %+v", missingDocument.Result)
	}
	unverified := config
	unverified.EvidenceVerified = false
	unverifiedDocument, err := EvaluatePublicTestnetCalibration(unverified)
	if err != nil {
		t.Fatal(err)
	}
	if unverifiedDocument.Result.Pass || unverifiedDocument.Result.EvidencePass {
		t.Fatalf("unverified evidence passed: %+v", unverifiedDocument.Result)
	}
	unverifiedTie := config
	unverifiedTie.TieEvidenceVerified = false
	unverifiedTieDocument, err := EvaluatePublicTestnetCalibration(unverifiedTie)
	if err != nil {
		t.Fatal(err)
	}
	if unverifiedTieDocument.Result.Pass || unverifiedTieDocument.Result.EvidencePass {
		t.Fatalf("unverified tie evidence passed: %+v", unverifiedTieDocument.Result)
	}
	missingReceipt := config
	missingReceipt.TieEvidenceReceipts--
	missingReceiptDocument, err := EvaluatePublicTestnetCalibration(missingReceipt)
	if err != nil {
		t.Fatal(err)
	}
	missingObserverReceipt := config
	missingObserverReceipt.TiePlanVersion = 2
	missingObserverReceipt.TieObserverCount = 2
	if document, err := EvaluatePublicTestnetCalibration(missingObserverReceipt); err != nil || document.Result.EvidencePass {
		t.Fatalf("missing multi-observer receipt passed: result=%+v err=%v", document.Result, err)
	}
	versionTwoWithOneObserver := config
	versionTwoWithOneObserver.TiePlanVersion = 2
	if document, err := EvaluatePublicTestnetCalibration(versionTwoWithOneObserver); err != nil || document.Result.EvidencePass {
		t.Fatalf("single-observer version-2 evidence passed: result=%+v err=%v", document.Result, err)
	}
	versionOneWithTwoObservers := config
	versionOneWithTwoObservers.TieObserverCount = 2
	versionOneWithTwoObservers.TieValidatedReceipts = 20_000
	if document, err := EvaluatePublicTestnetCalibration(versionOneWithTwoObservers); err != nil || document.Result.EvidencePass {
		t.Fatalf("multi-observer version-1 evidence passed: result=%+v err=%v", document.Result, err)
	}
	disagreementOutsideNoPair := config
	disagreementOutsideNoPair.TieDisagreementSlots = 1
	if document, err := EvaluatePublicTestnetCalibration(disagreementOutsideNoPair); err != nil || document.Result.EvidencePass {
		t.Fatalf("unaccounted observer disagreement passed: result=%+v err=%v", document.Result, err)
	}
	overflowedObserverReceipts := config
	overflowedObserverReceipts.ControlledTieTrials = 1 << 63
	overflowedObserverReceipts.TieCompletedTrials = 1 << 63
	overflowedObserverReceipts.TieEvidenceReceipts = 1 << 63
	overflowedObserverReceipts.TiePlanVersion = 2
	overflowedObserverReceipts.TieObserverCount = 2
	overflowedObserverReceipts.TieValidatedReceipts = 0
	if document, err := EvaluatePublicTestnetCalibration(overflowedObserverReceipts); err != nil || document.Result.EvidencePass {
		t.Fatalf("overflowed observer receipt count passed: result=%+v err=%v", document.Result, err)
	}
	if missingReceiptDocument.Result.Pass || missingReceiptDocument.Result.EvidencePass {
		t.Fatalf("missing tie receipt passed: %+v", missingReceiptDocument.Result)
	}
	missingPlan := config
	missingPlan.TiePlanID = ""
	missingPlanDocument, err := EvaluatePublicTestnetCalibration(missingPlan)
	if err != nil {
		t.Fatal(err)
	}
	if missingPlanDocument.Result.Pass || missingPlanDocument.Result.EvidencePass {
		t.Fatalf("missing tie plan checkpoint passed: %+v", missingPlanDocument.Result)
	}
	selectiveFailure := config
	selectiveFailure.TieCompletedTrials--
	selectiveFailure.TieNoPairSlots++
	selectiveFailure.ControlledTieAdoptions = 0
	selectiveFailureDocument, err := EvaluatePublicTestnetCalibration(selectiveFailure)
	if err != nil {
		t.Fatal(err)
	}
	if selectiveFailureDocument.Result.EvidencePass {
		t.Fatalf("unaccounted no-pair penalty passed: %+v", selectiveFailureDocument.Result)
	}
	shortEvidence := config
	shortEvidence.EvidenceRecords--
	shortEvidenceDocument, err := EvaluatePublicTestnetCalibration(shortEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if shortEvidenceDocument.Result.Pass || shortEvidenceDocument.Result.EvidencePass {
		t.Fatalf("insufficient evidence records passed: %+v", shortEvidenceDocument.Result)
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
