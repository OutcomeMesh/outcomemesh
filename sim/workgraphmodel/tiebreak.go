package workgraphmodel

import (
	"encoding/binary"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

const MaximumGlobalTieBreakTrials uint64 = 1_000_000

// GlobalTieBreakGrindingConfig models a withheld publisher that reveals an
// equal-work anchor only when the shared smaller-ID rule favors it. The IDs are
// deterministic SHA-256 samples; two proofs at the same target have the same
// symmetric ordering property.
type GlobalTieBreakGrindingConfig struct {
	Trials uint64
	Seed   uint64
}

type GlobalTieBreakGrindingResult struct {
	PotentialRaces       uint64
	PublishedRaces       uint64
	SuppressedRaces      uint64
	PublishedAdoptions   uint64
	FavorableIDPPM       uint64
	PublishedAdoptionPPM uint64
}

// RunGlobalTieBreakGrinding exposes why a universal block-ID tie-break is not
// a neutral network parameter. The attacker suppresses every unfavorable ID;
// every race it does publish is then adopted by all nodes applying that global
// rule. Version 1 keeps the incumbent on exact ties instead.
func RunGlobalTieBreakGrinding(config GlobalTieBreakGrindingConfig) (GlobalTieBreakGrindingResult, error) {
	if config.Trials == 0 || config.Trials > MaximumGlobalTieBreakTrials || config.Seed == 0 {
		return GlobalTieBreakGrindingResult{}, ErrConfiguration
	}
	result := GlobalTieBreakGrindingResult{PotentialRaces: config.Trials}
	var sample [16]byte
	binary.BigEndian.PutUint64(sample[:8], config.Seed)
	for trial := uint64(0); trial < config.Trials; trial++ {
		binary.BigEndian.PutUint64(sample[8:], trial)
		attackerID := types.DomainHash("OMESH/sim/global-id-tie/attacker/v0", sample[:])
		honestID := types.DomainHash("OMESH/sim/global-id-tie/honest/v0", sample[:])
		if attackerID == honestID {
			return GlobalTieBreakGrindingResult{}, ErrConfiguration
		}
		attacker := storage.Tip{ID: attackerID, CumulativeWork: []byte{1}}
		honest := storage.Tip{ID: honestID, CumulativeWork: []byte{1}}
		if storage.BetterTip(attacker, honest) {
			result.PublishedRaces++
			result.PublishedAdoptions++
		}
	}
	result.SuppressedRaces = result.PotentialRaces - result.PublishedRaces
	var ok bool
	result.FavorableIDPPM, ok = multiplyDivide(
		result.PublishedRaces, uint64(PartsPerMillion), result.PotentialRaces,
	)
	if !ok || result.PublishedRaces == 0 {
		return GlobalTieBreakGrindingResult{}, ErrConfiguration
	}
	result.PublishedAdoptionPPM, ok = multiplyDivide(
		result.PublishedAdoptions, uint64(PartsPerMillion), result.PublishedRaces,
	)
	if !ok {
		return GlobalTieBreakGrindingResult{}, ErrConfiguration
	}
	return result, nil
}
