package main

import (
	"context"
	"errors"
	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	pebblestore "github.com/outcomemesh/outcomemesh/storage/pebble"
	"path/filepath"
)

func loadMigratedPruneBase(ctx context.Context, data string, binding workarchive.Binding, height uint64, roots []string) (workchain.Base, workblock.Parameters, uint64, error) {
	dataPath, err := canonicalPruneLineageDirectory(data)
	if err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	for _, root := range roots {
		resolved, err := filepath.Abs(root)
		if err != nil || root == "" || workarchive.CustodyEvidencePathsOverlap(dataPath, resolved) {
			return workchain.Base{}, workblock.Parameters{}, 0, store.ErrRootOverlap
		}
	}
	documentRaw, err := readRegularArtifact(filepath.Join(dataPath, genesisFilename), 64+genesis.MaxAllocations*resource.CanonicalSize)
	if err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	document, err := genesis.Decode(documentRaw)
	if err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	profileRaw, err := readRegularArtifact(filepath.Join(dataPath, workActivationFilename), workActivationSize)
	if err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	profile, err := decodeWorkActivation(profileRaw)
	if err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	if err := validateWorkActivation(profile, document); err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	genesisID, err := document.ID()
	if err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	if binding.NetworkID != document.NetworkID || binding.GenesisID != genesisID || binding.ActivationHeight != profile.ActivationHeight {
		return workchain.Base{}, workblock.Parameters{}, 0, store.ErrMigratedPrune
	}
	ledger, err := pebblestore.OpenExistingReadOnly(filepath.Join(dataPath, ledgerDirectory), document, pebblestore.DefaultPolicy())
	if err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	base, baseErr := archiveBaseFromLedger(ledger, binding.BaseID, profile.ActivationHeight)
	closeErr := ledger.Close()
	if err := errors.Join(baseErr, closeErr, ctx.Err()); err != nil {
		return workchain.Base{}, workblock.Parameters{}, 0, err
	}
	legacy := legacyblock.ParametersFromGenesis(document)
	parameters := workblock.Parameters{NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy, RewardMaturity: legacy.RewardMaturity, ActivationHeight: profile.ActivationHeight, RadixActivationHeight: height, DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target, TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: profile.FeeDelay}
	return base, parameters, profile.MaxHistoryBytes, nil
}
