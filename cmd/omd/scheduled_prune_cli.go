package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	pebblestore "github.com/outcomemesh/outcomemesh/storage/pebble"
)

const scheduledPruneCommand = "work-archive-prune-scheduled"

type scheduledPruneCLISource struct {
	AssignmentID string `json:"assignment_id"`
	Authority    string `json:"authority"`
	Pins         string `json:"authority_pins"`
	Journal      string `json:"journal"`
	Directory    string `json:"directory"`
}

func runScheduledPruneCLI(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runScheduledPrune(ctx, args, os.Stdout)
}
func runScheduledPrune(ctx context.Context, args []string, out io.Writer) (returnErr error) {
	if ctx == nil || out == nil {
		return store.ErrScheduledPrune
	}
	f := flag.NewFlagSet(scheduledPruneCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review, execute, or read-only effect recovery")
	inventory := f.String("inventory", "", "existing canonical scheduled inventory")
	inventoryID := f.String("inventory-id", "", "independently retained inventory ID")
	expected := f.String("expected-review-id", "", "exact preceding owned review ID for execute/recover")
	data := f.String("data", "", "existing disjoint activation base source")
	roots := f.String("sources", "", "bounded operator-reviewed source paths JSON")
	executor := f.String("executor", "", "existing original executor")
	executorPins := f.String("executor-pins", "", "existing original executor pins")
	chain := f.String("chain", "", "existing migrated protected chain")
	chainPins := f.String("chain-pins", "", "existing independent storage position pins")
	migrationID := f.String("storage-migration-id", "", "independently retained storage migration review ID")
	fenceNetwork := f.String("fence-network", "", "execute fenced request: original witness endpoints JSON")
	fenceOwner := f.String("fence-owner-key", "", "execute fenced request: private owner seed")
	fenceTransport := f.String("fence-transport-key", "", "execute fenced request: separate private transport seed")
	fenceTimeout := f.Duration("fence-timeout", 5*time.Second, "bounded time per independent witness")
	custody := addArchiveCustodyPolicyFlags(f)
	journal := addArchiveCustodyJournalLimitFlags(f)
	defaults := workchain.DefaultPolicy()
	maxHistory := f.Uint64("max-history-bytes", 0, "storage history budget; default from activation source")
	forkRetention := f.Uint64("fork-retention", defaults.ForkRetention, "storage fork retention")
	checkpointEvery := f.Uint64("checkpoint-every", defaults.CheckpointEvery, "storage replay checkpoint interval")
	checkpointKeep := f.Uint("checkpoint-keep", uint(defaults.CheckpointKeep), "retained replay checkpoints")
	canonicalRetention := f.Uint64("canonical-retention", defaults.CanonicalRetention, "minimum selected-tip distance")
	limits := workarchive.DefaultLimits()
	maxBlocks := f.Uint64("max-archive-blocks", limits.MaximumBlocks, "bounded archive replay")
	maxChunks := f.Uint("max-archive-chunks", uint(limits.MaximumChunks), "bounded archive chunks")
	maxBytes := f.Uint64("max-archive-bytes", limits.MaximumBytes, "bounded archive bytes")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	if *mode != "review" && *mode != "execute" && *mode != "recover" {
		return store.ErrScheduledPrune
	}
	if (*mode == "review") != (*expected == "") || *checkpointKeep > uint(^uint32(0)) || *maxChunks > uint(^uint32(0)) || *canonicalRetention == 0 {
		return store.ErrScheduledPrune
	}
	if err := custody.validate(); err != nil {
		return err
	}
	if err := journal.limits().Validate(); err != nil {
		return err
	}
	config := store.ScheduledPruneRuntimeConfig{InventoryPath: *inventory, ExecutorPath: *executor, ExecutorPinsPath: *executorPins, ChainPath: *chain, ChainPinsPath: *chainPins, Limits: workarchive.Limits{MaximumBlocks: *maxBlocks, MaximumChunks: uint32(*maxChunks), MaximumBytes: *maxBytes}}
	var err error
	config.InventoryID, err = pruneExternalID("inventory-id", *inventoryID)
	if err != nil {
		return err
	}
	config.StorageMigrationID, err = pruneExternalID("storage-migration-id", *migrationID)
	if err != nil {
		return err
	}
	var reviewID types.Hash
	if *expected != "" {
		reviewID, err = pruneExternalID("expected-review-id", *expected)
		if err != nil {
			return err
		}
	}
	v, err := store.LoadScheduledPruneInventory(*inventory, config.InventoryID)
	if err != nil {
		return err
	}
	fenceFlags := false
	f.Visit(func(flag *flag.Flag) {
		if flag.Name == "fence-network" || flag.Name == "fence-owner-key" || flag.Name == "fence-transport-key" || flag.Name == "fence-timeout" {
			fenceFlags = true
		}
	})
	if fenceFlags && (*mode != "execute" || v.FencePolicy == nil) {
		return store.ErrScheduledPrune
	}
	if *mode == "execute" && v.FencePolicy != nil {
		collect, closeClient, err := openPruneFenceCollector(ctx, v, *fenceNetwork, *fenceOwner, *fenceTransport, *fenceTimeout)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, closeClient()) }()
		config.CollectPruneClaim = collect
	}
	raw, err := readRegularArtifact(*roots, maximumPruneEffectRootsBytes)
	if err != nil {
		return err
	}
	var sources []scheduledPruneCLISource
	if err := cutoverJSON(raw, &sources); err != nil {
		return err
	}
	if len(sources) != len(v.Replicas) {
		return store.ErrScheduledPrune
	}
	for _, source := range sources {
		id, err := pruneExternalID("assignment_id", source.AssignmentID)
		if err != nil {
			return err
		}
		var auditors [][32]byte
		for _, s := range v.Replicas {
			aid, _ := s.Assignment.ID()
			if aid == id {
				auditors = s.Assignment.Auditors
			}
		}
		if len(auditors) == 0 {
			return store.ErrScheduledPrune
		}
		config.Authorities = append(config.Authorities, store.PruneArchiveAuthorityRoots{AssignmentID: id, AuthorityPath: source.Authority, AuthorityPinsPath: source.Pins})
		config.Sources = append(config.Sources, store.ScheduledPruneSource{AssignmentID: id, Directory: source.Directory, JournalPath: source.Journal, CustodyPolicy: workarchive.CustodyPolicy{TrustedAuditors: auditors, MaximumChallengeLifetime: *custody.challengeLifetime, MaximumProofAge: *custody.proofAge, MaximumRenewalTerm: *custody.renewalTerm}, JournalLimits: journal.limits()})
	}
	dataPath, err := canonicalPruneLineageDirectory(*data)
	if err != nil {
		return err
	}
	owned := []string{config.ExecutorPath, config.ExecutorPinsPath, config.ChainPath, config.ChainPinsPath, *inventory, *roots}
	for _, s := range sources {
		owned = append(owned, s.Authority, s.Pins, s.Journal, s.Directory)
	}
	for _, root := range owned {
		resolved, err := filepath.Abs(root)
		if err != nil || workarchive.CustodyEvidencePathsOverlap(dataPath, resolved) {
			return store.ErrScheduledPrune
		}
	}
	documentRaw, err := readRegularArtifact(filepath.Join(dataPath, genesisFilename), 64+genesis.MaxAllocations*resource.CanonicalSize)
	if err != nil {
		return err
	}
	document, err := genesis.Decode(documentRaw)
	if err != nil {
		return err
	}
	profileRaw, err := readRegularArtifact(filepath.Join(dataPath, workActivationFilename), workActivationSize)
	if err != nil {
		return err
	}
	profile, err := decodeWorkActivation(profileRaw)
	if err != nil {
		return err
	}
	if err := validateWorkActivation(profile, document); err != nil {
		return err
	}
	genesisID, err := document.ID()
	if err != nil {
		return err
	}
	binding := v.OriginalPolicy.Binding
	if binding.NetworkID != document.NetworkID || binding.GenesisID != genesisID || binding.ActivationHeight != profile.ActivationHeight {
		return store.ErrScheduledPrune
	}
	ledger, err := pebblestore.OpenExistingReadOnly(filepath.Join(dataPath, ledgerDirectory), document, pebblestore.DefaultPolicy())
	if err != nil {
		return err
	}
	base, baseErr := archiveBaseFromLedger(ledger, binding.BaseID, profile.ActivationHeight)
	closeErr := ledger.Close()
	if err := errors.Join(baseErr, closeErr, ctx.Err()); err != nil {
		return err
	}
	config.Base = base
	legacy := legacyblock.ParametersFromGenesis(document)
	config.Parameters = workblock.Parameters{NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy, RewardMaturity: legacy.RewardMaturity, ActivationHeight: profile.ActivationHeight, RadixActivationHeight: v.Request.Boundary.RadixActivationHeight, DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target, TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: profile.FeeDelay}
	if *maxHistory == 0 {
		*maxHistory = profile.MaxHistoryBytes
	}
	config.StoragePolicy = workchain.Policy{MaxHistoryBytes: *maxHistory, ForkRetention: *forkRetention, CheckpointEvery: *checkpointEvery, CheckpointKeep: uint32(*checkpointKeep), CanonicalRetention: *canonicalRetention}
	result, err := store.RunScheduledPrune(ctx, config, *mode, reviewID)
	if err != nil {
		return err
	}
	report, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return writeCustodyScheduleReport(ctx, out, report)
}
