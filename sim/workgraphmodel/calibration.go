package workgraphmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/bits"
)

const (
	// PublicTestnetCalibrationSchema versions the evidence snapshot separately
	// from the deterministic economic review corpus.
	PublicTestnetCalibrationSchema = "outcomemesh/public-testnet-calibration/v4"
	PublicTestnetCalibrationMethod = "hoeffding-bonferroni-one-sided-99%-integer-ppm/v1"

	PublicTestnetMinimumWindowSeconds uint64 = 30 * 24 * 60 * 60
	PublicTestnetMaximumRecordSeconds uint64 = 60 * 60
	PublicTestnetMaximumUpperPPM      uint32 = 250_000

	// ln(100) is strictly less than 4.605171. Using the upper rational here
	// makes the integer Hoeffding margin conservative without floating point.
	logOneHundredUpperNumerator   uint64 = 4_605_171
	logTwoUpperNumerator          uint64 = 693_148
	logOneHundredUpperDenominator uint64 = 1_000_000
)

// OneSidedUpperBound is a deterministic 99% Hoeffding upper bound for an
// independently sampled Bernoulli proportion. Comparisons records the
// Bonferroni family size. All ratios are parts per million and are rounded
// upward.
type OneSidedUpperBound struct {
	Successes    uint64
	Trials       uint64
	Comparisons  uint64
	EmpiricalPPM uint32
	MarginPPM    uint32
	UpperPPM     uint32
}

// PublicTestnetCalibrationConfig contains the aggregate counters required by
// ER-5. In verified mode ControlledTieAdoptions is the raw tested-branch
// selections plus every NoPair slot, while ControlledTieTrials is the full
// precommitted slot count. LargestCoordinatedWork counts work attributed to one
// coordination cluster whose definition was frozen before the window.
type PublicTestnetCalibrationConfig struct {
	ObservationWindowSeconds uint64
	ControlledTieAdoptions   uint64
	ControlledTieTrials      uint64
	TieCompletedTrials       uint64
	TieNoPairSlots           uint64
	LargestCoordinatedWork   uint64
	ObservedWork             uint64
	CoordinatedClusters      uint64
	EvidenceRecords          uint64
	EvidenceTailID           string
	EvidenceVerified         bool
	TiePlanID                string
	TiePlanVersion           uint16
	TieEvidenceReceipts      uint64
	TieObserverCount         uint64
	TieValidatedReceipts     uint64
	TieDisagreementSlots     uint64
	TieEvidenceTailID        string
	TieEvidenceVerified      bool
	MaximumUpperPPM          uint32
}

type PublicTestnetCalibrationResult struct {
	TieAdoption         OneSidedUpperBound
	CoordinatedWork     OneSidedUpperBound
	WindowPass          bool
	TieAdoptionPass     bool
	CoordinatedWorkPass bool
	EvidencePass        bool
	Pass                bool
}

// PublicTestnetCalibrationDocument is timestamp-free so a signed telemetry
// manifest can bind its canonical digest without platform-dependent output.
// The manifest remains responsible for proving continuity and provenance.
type PublicTestnetCalibrationDocument struct {
	Schema string
	Method string
	Config PublicTestnetCalibrationConfig
	Result PublicTestnetCalibrationResult
}

// HoeffdingUpper99PPM returns ceil(pObserved)+ceil(epsilon), capped at one,
// where epsilon=sqrt(ln(100)/(2*trials)). The implementation uses only integer
// arithmetic and a conservative rational upper approximation of ln(100).
func HoeffdingUpper99PPM(successes, trials uint64) (OneSidedUpperBound, error) {
	return HoeffdingFamilyUpper99PPM(successes, trials, 1)
}

// HoeffdingFamilyUpper99PPM applies a Bonferroni correction so that selecting
// the largest observed proportion from comparisons predeclared series still
// has a family-wise one-sided confidence of at least 99%. The comparison count
// is rounded up to a power of two and ln(2) is rounded upward.
func HoeffdingFamilyUpper99PPM(successes, trials, comparisons uint64) (OneSidedUpperBound, error) {
	if trials == 0 || successes > trials || comparisons == 0 {
		return OneSidedUpperBound{}, ErrConfiguration
	}
	empirical := ceilRatioPPM(successes, trials)
	margin := hoeffding99MarginPPM(trials, comparisons)
	upper := uint64(empirical) + uint64(margin)
	if upper > uint64(PartsPerMillion) {
		upper = uint64(PartsPerMillion)
	}
	return OneSidedUpperBound{
		Successes: successes, Trials: trials, Comparisons: comparisons, EmpiricalPPM: empirical,
		MarginPPM: margin, UpperPPM: uint32(upper),
	}, nil
}

func EvaluatePublicTestnetCalibration(config PublicTestnetCalibrationConfig) (PublicTestnetCalibrationDocument, error) {
	if config.MaximumUpperPPM == 0 || config.MaximumUpperPPM > PartsPerMillion {
		return PublicTestnetCalibrationDocument{}, ErrConfiguration
	}
	tie, err := HoeffdingUpper99PPM(config.ControlledTieAdoptions, config.ControlledTieTrials)
	if err != nil {
		return PublicTestnetCalibrationDocument{}, err
	}
	work, err := HoeffdingFamilyUpper99PPM(
		config.LargestCoordinatedWork,
		config.ObservedWork,
		config.CoordinatedClusters,
	)
	if err != nil {
		return PublicTestnetCalibrationDocument{}, err
	}
	result := PublicTestnetCalibrationResult{
		TieAdoption:         tie,
		CoordinatedWork:     work,
		WindowPass:          config.ObservationWindowSeconds >= PublicTestnetMinimumWindowSeconds,
		TieAdoptionPass:     tie.UpperPPM <= config.MaximumUpperPPM,
		CoordinatedWorkPass: work.UpperPPM <= config.MaximumUpperPPM,
		EvidencePass:        validEvidence(config),
	}
	result.Pass = result.WindowPass && result.TieAdoptionPass && result.CoordinatedWorkPass && result.EvidencePass
	return PublicTestnetCalibrationDocument{
		Schema: PublicTestnetCalibrationSchema,
		Method: PublicTestnetCalibrationMethod,
		Config: config,
		Result: result,
	}, nil
}

func validEvidence(config PublicTestnetCalibrationConfig) bool {
	if !config.EvidenceVerified || !config.TieEvidenceVerified {
		return false
	}
	if !validCanonicalHash(config.EvidenceTailID) || !validCanonicalHash(config.TiePlanID) ||
		!validCanonicalHash(config.TieEvidenceTailID) {
		return false
	}
	if config.ObservationWindowSeconds == 0 {
		return false
	}
	minimumRecords := uint64(1) + (config.ObservationWindowSeconds-1)/PublicTestnetMaximumRecordSeconds
	if config.EvidenceRecords < minimumRecords || config.TieEvidenceReceipts != config.ControlledTieTrials ||
		(config.TiePlanVersion == 1 && config.TieObserverCount != 1) ||
		(config.TiePlanVersion == 2 && (config.TieObserverCount < 2 || config.TieObserverCount > 64)) ||
		(config.TiePlanVersion != 1 && config.TiePlanVersion != 2) ||
		config.TieValidatedReceipts%config.TieObserverCount != 0 ||
		config.TieValidatedReceipts/config.TieObserverCount != config.ControlledTieTrials ||
		config.TieDisagreementSlots > config.TieNoPairSlots ||
		config.TieNoPairSlots > config.ControlledTieTrials ||
		config.TieCompletedTrials != config.ControlledTieTrials-config.TieNoPairSlots ||
		config.ControlledTieAdoptions < config.TieNoPairSlots ||
		config.ControlledTieAdoptions-config.TieNoPairSlots > config.TieCompletedTrials {
		return false
	}
	return true
}

func validCanonicalHash(input string) bool {
	decoded, err := hex.DecodeString(input)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == input
}

func (document PublicTestnetCalibrationDocument) CanonicalJSON() ([]byte, error) {
	if document.Schema != PublicTestnetCalibrationSchema || document.Method != PublicTestnetCalibrationMethod {
		return nil, ErrConfiguration
	}
	return json.Marshal(document)
}

func (document PublicTestnetCalibrationDocument) Digest() ([sha256.Size]byte, error) {
	encoded, err := document.CanonicalJSON()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func ceilRatioPPM(numerator, denominator uint64) uint32 {
	value := new(big.Int).SetUint64(numerator)
	value.Mul(value, new(big.Int).SetUint64(uint64(PartsPerMillion)))
	divisor := new(big.Int).SetUint64(denominator)
	value.Add(value, new(big.Int).Sub(divisor, big.NewInt(1)))
	value.Div(value, divisor)
	return uint32(value.Uint64())
}

func hoeffding99MarginPPM(trials, comparisons uint64) uint32 {
	// Find the smallest integer m satisfying:
	// m^2 / PPM^2 >= ln(100*2^ceil(log2(comparisons))) / (2*trials).
	comparisonPower := bits.Len64(comparisons - 1)
	logUpperNumerator := logOneHundredUpperNumerator + uint64(comparisonPower)*logTwoUpperNumerator
	right := new(big.Int).SetUint64(logUpperNumerator)
	ppmSquared := new(big.Int).SetUint64(uint64(PartsPerMillion))
	ppmSquared.Mul(ppmSquared, ppmSquared)
	right.Mul(right, ppmSquared)

	leftFactor := new(big.Int).SetUint64(trials)
	leftFactor.Mul(leftFactor, new(big.Int).SetUint64(2*logOneHundredUpperDenominator))
	satisfies := func(margin uint32) bool {
		left := new(big.Int).SetUint64(uint64(margin))
		left.Mul(left, left)
		left.Mul(left, leftFactor)
		return left.Cmp(right) >= 0
	}
	if !satisfies(PartsPerMillion) {
		return PartsPerMillion
	}
	low, high := uint32(0), PartsPerMillion
	for low < high {
		middle := low + (high-low)/2
		if satisfies(middle) {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return low
}
