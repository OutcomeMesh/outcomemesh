package workgraphmodel

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

const ActivationReviewSchema = "outcomemesh/economic-activation-review/v3"

// ActivationReviewConfig freezes the deterministic economic corpus separately
// from its results. A reviewer can therefore change one assumption, rerun the
// same code, and compare both the input document and its digest.
type ActivationReviewConfig struct {
	SelfishMining    SelfishSweepConfig
	FeeFragmentation FeeFragmentationSweepConfig
}

type ActivationReviewResult struct {
	SelfishMining    SelfishSweepResult
	TrailDepths      []ActivationTrailDepthResult
	FeeFragmentation FeeFragmentationSweepResult
}

type ActivationTrailDepthResult struct {
	Depth uint8
	Sweep SelfishSweepResult
}

// ActivationReviewDocument is intentionally free of timestamps, platform
// metadata, maps, and floating point so its JSON and digest are reproducible.
// The digest covers the compact JSON returned by CanonicalJSON.
type ActivationReviewDocument struct {
	Schema string
	Config ActivationReviewConfig
	Result ActivationReviewResult
}

// CanonicalActivationReviewConfig returns the checked-in public-activation
// corpus. It samples selfish-mining hash share every percentage point from 15%
// through 45%, and compares direct and smoothed private fees across six miner
// sizes. The corpus remains bounded by the simulation admission limits.
func CanonicalActivationReviewConfig() ActivationReviewConfig {
	hashShares := make([]uint32, 0, 31)
	for hashShare := uint32(150_000); hashShare <= 450_000; hashShare += 10_000 {
		hashShares = append(hashShares, hashShare)
	}
	return ActivationReviewConfig{
		SelfishMining: SelfishSweepConfig{
			HardDiscoveries: 1_000,
			Seeds: []uint64{
				0x243f6a8885a308d3,
				0x9e3779b97f4a7c15,
				0xcbbb9d5dc1059ed8,
			},
			HashSharesPPM: hashShares,
			TieAdoptionsPPM: []uint32{
				0,
				250_000,
				500_000,
				750_000,
				1_000_000,
			},
			ShareRatio:      workgraph.ShareDifficultyRatio,
			BlockSubsidy:    5_000_000_000,
			FeesPerBlock:    100_000,
			ProfitMarginPPM: 5_000,
		},
		FeeFragmentation: FeeFragmentationSweepConfig{
			BlockSubsidy:  5_000_000_000,
			HashSharesPPM: []uint32{10_000, 50_000, 100_000, 200_000, 300_000, 400_000},
			PrivateFees: []uint64{
				1_000_000_000,
				2_000_000_000,
				2_500_000_000,
				3_000_000_000,
				4_000_000_000,
				6_000_000_000,
				10_000_000_000,
				20_000_000_000,
				25_000_000_000,
				50_000_000_000,
				100_000_000_000,
				250_000_000_000,
			},
			MaxPasses: 100,
		},
	}
}

func RunActivationReview(config ActivationReviewConfig) (ActivationReviewDocument, error) {
	selfish, err := RunSelfishSweep(config.SelfishMining)
	if err != nil {
		return ActivationReviewDocument{}, err
	}
	trails := make([]ActivationTrailDepthResult, 0, MaxTrailDepth)
	for depth := uint8(1); depth <= MaxTrailDepth; depth++ {
		trail, err := RunTrailDepthSweep(config.SelfishMining, depth)
		if err != nil {
			return ActivationReviewDocument{}, err
		}
		trails = append(trails, ActivationTrailDepthResult{Depth: depth, Sweep: trail})
	}
	fees, err := RunFeeFragmentationSweep(config.FeeFragmentation)
	if err != nil {
		return ActivationReviewDocument{}, err
	}
	return ActivationReviewDocument{
		Schema: ActivationReviewSchema,
		Config: config,
		Result: ActivationReviewResult{
			SelfishMining:    selfish,
			TrailDepths:      trails,
			FeeFragmentation: fees,
		},
	}, nil
}

func (document ActivationReviewDocument) CanonicalJSON() ([]byte, error) {
	if document.Schema != ActivationReviewSchema {
		return nil, ErrConfiguration
	}
	return json.Marshal(document)
}

func (document ActivationReviewDocument) Digest() ([sha256.Size]byte, error) {
	encoded, err := document.CanonicalJSON()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
