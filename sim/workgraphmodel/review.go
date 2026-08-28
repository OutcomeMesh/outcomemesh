package workgraphmodel

const (
	MaxFeeSweepHashShares = 32
	MaxFeeSweepFees       = 32
	MaxFeeSweepPoints     = 512
)

// FeeFragmentationSweepConfig defines a deterministic two-template market
// sweep. One miner may choose a private-fee template while the rest of the
// tested hash power remains on the common template. HashSharesPPM and
// PrivateFees must be strictly increasing so the result has one canonical
// order.
type FeeFragmentationSweepConfig struct {
	BlockSubsidy  uint64
	HashSharesPPM []uint32
	PrivateFees   []uint64
	MaxPasses     int
}

// FeeFragmentationPoint compares immediate fees with the same fees deposited
// into the smoothed, hash-proportional future pool. Fragmented is true when the
// tested miner's stable best response selects its private template.
type FeeFragmentationPoint struct {
	MinerHashPPM uint32
	PrivateFee   uint64

	DirectFragmented           bool
	DirectIncludedSharePPM     uint64
	DirectSubsidySchedulePPM   uint64
	DirectMinerRewardPPM       uint64
	SmoothedFragmented         bool
	SmoothedIncludedSharePPM   uint64
	SmoothedSubsidySchedulePPM uint64
	SmoothedMinerRewardPPM     uint64
}

// FeeFragmentationThreshold records the first tested private fee that makes
// fragmentation a stable best response. Found is false when the threshold is
// above the tested fee grid.
type FeeFragmentationThreshold struct {
	MinerHashPPM uint32

	DirectFirstFee   uint64
	DirectFound      bool
	SmoothedFirstFee uint64
	SmoothedFound    bool
}

type FeeFragmentationSweepResult struct {
	Points     []FeeFragmentationPoint
	Thresholds []FeeFragmentationThreshold
}

// RunFeeFragmentationSweep exposes the private-template pressure created by
// fees without using floating point or changing the production market model.
// Every grid point starts from the common template, then runs both immediate
// and smoothed-fee best responses to a stable assignment.
func RunFeeFragmentationSweep(config FeeFragmentationSweepConfig) (FeeFragmentationSweepResult, error) {
	if err := validateFeeFragmentationSweep(config); err != nil {
		return FeeFragmentationSweepResult{}, err
	}
	result := FeeFragmentationSweepResult{
		Points:     make([]FeeFragmentationPoint, 0, len(config.HashSharesPPM)*len(config.PrivateFees)),
		Thresholds: make([]FeeFragmentationThreshold, 0, len(config.HashSharesPPM)),
	}
	for _, hashShare := range config.HashSharesPPM {
		threshold := FeeFragmentationThreshold{MinerHashPPM: hashShare}
		for _, privateFee := range config.PrivateFees {
			point, err := runFeeFragmentationPoint(config, hashShare, privateFee)
			if err != nil {
				return FeeFragmentationSweepResult{}, err
			}
			result.Points = append(result.Points, point)
			if point.DirectFragmented && !threshold.DirectFound {
				threshold.DirectFirstFee = privateFee
				threshold.DirectFound = true
			}
			if point.SmoothedFragmented && !threshold.SmoothedFound {
				threshold.SmoothedFirstFee = privateFee
				threshold.SmoothedFound = true
			}
		}
		result.Thresholds = append(result.Thresholds, threshold)
	}
	return result, nil
}

func runFeeFragmentationPoint(
	config FeeFragmentationSweepConfig,
	hashShare uint32,
	privateFee uint64,
) (FeeFragmentationPoint, error) {
	market := MarketConfig{
		BlockSubsidy: config.BlockSubsidy,
		Templates:    []MarketTemplate{{}, {Fees: privateFee}},
		Miners: []MarketMiner{
			{
				HashUnits: uint64(hashShare), InitialTemplate: 0,
				AllowedTemplates: []int{0, 1},
			},
			{
				HashUnits: uint64(PartsPerMillion - hashShare), InitialTemplate: 0,
				AllowedTemplates: []int{0},
			},
		},
		MaxPasses: config.MaxPasses,
	}
	direct, err := RunTemplateMarket(market)
	if err != nil || !direct.Stable {
		return FeeFragmentationPoint{}, ErrConfiguration
	}
	market.SmoothFees = true
	smoothed, err := RunTemplateMarket(market)
	if err != nil || !smoothed.Stable {
		return FeeFragmentationPoint{}, ErrConfiguration
	}
	return FeeFragmentationPoint{
		MinerHashPPM:               hashShare,
		PrivateFee:                 privateFee,
		DirectFragmented:           direct.Assignments[0] == 1,
		DirectIncludedSharePPM:     direct.ExpectedIncludedSharePPM,
		DirectSubsidySchedulePPM:   direct.ExpectedSubsidyPPMOfSchedule,
		DirectMinerRewardPPM:       direct.MinerRewardPPM[0],
		SmoothedFragmented:         smoothed.Assignments[0] == 1,
		SmoothedIncludedSharePPM:   smoothed.ExpectedIncludedSharePPM,
		SmoothedSubsidySchedulePPM: smoothed.ExpectedSubsidyPPMOfSchedule,
		SmoothedMinerRewardPPM:     smoothed.MinerRewardPPM[0],
	}, nil
}

func validateFeeFragmentationSweep(config FeeFragmentationSweepConfig) error {
	if config.BlockSubsidy == 0 || config.MaxPasses <= 0 || config.MaxPasses > MaxMarketIterations ||
		len(config.HashSharesPPM) == 0 || len(config.HashSharesPPM) > MaxFeeSweepHashShares ||
		len(config.PrivateFees) == 0 || len(config.PrivateFees) > MaxFeeSweepFees ||
		len(config.HashSharesPPM)*len(config.PrivateFees) > MaxFeeSweepPoints {
		return ErrConfiguration
	}
	for index, hashShare := range config.HashSharesPPM {
		if hashShare == 0 || hashShare >= PartsPerMillion ||
			(index > 0 && hashShare <= config.HashSharesPPM[index-1]) {
			return ErrConfiguration
		}
	}
	for index, fee := range config.PrivateFees {
		if fee == 0 || (index > 0 && fee <= config.PrivateFees[index-1]) {
			return ErrConfiguration
		}
	}
	return nil
}
