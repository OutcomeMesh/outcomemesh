package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	pebblestore "github.com/outcomemesh/outcomemesh/storage/pebble"
)

const maximumPruneEffectRootsBytes = 256 << 10

type pruneArchiveEffectOptions struct {
	mode       string
	config     authoritystore.PruneArchiveEffectServiceConfig
	sourceData string
	rootsPath  string
}

// Parsing loads retained content and an existing read-only activation source.
// It never opens current authority/executor/WorkChain owners or creates data.
func loadPruneArchiveEffectOptions(ctx context.Context, arguments []string) (pruneArchiveEffectOptions, error) {
	if ctx == nil || len(arguments) == 0 || arguments[0] != pruneArchiveEffectCommand {
		return pruneArchiveEffectOptions{}, errors.New("archive effect needs a context and explicit command")
	}
	if err := ctx.Err(); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	flags := flag.NewFlagSet(pruneArchiveEffectCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review (default) or explicitly supervised control")
	inventoryPath := flags.String("inventory", "", "existing canonical prepared inventory file (required)")
	inventoryText := flags.String("inventory-id", "", "independently retained inventory ID (required)")
	policyText := flags.String("policy-id", "", "independently retained inventory policy ID (required)")
	data := flags.String("data", "", "existing disjoint node containing the verified activation base (required)")
	rootsPath := flags.String("roots", "", "existing bounded assignment-labelled owner/replica JSON (required)")
	executor := flags.String("executor", "", "existing original executor root (required)")
	executorPins := flags.String("executor-pins", "", "existing original executor pin root (required)")
	chain := flags.String("chain", "", "existing position-pinned WorkChain root (required)")
	chainPins := flags.String("chain-pins", "", "existing independent WorkChain position root (required)")
	availability := flags.String("availability-out", "", "explicit availability filename in an existing dedicated parent (required)")
	lineage := flags.String("lineage-evidence", "", "existing historical lineage evidence file (lineage mode only)")
	lineageText := flags.String("lineage-evidence-id", "", "independently retained historical evidence ID (lineage mode only)")
	storage := workchain.DefaultPolicy()
	maximumHistory := flags.Uint64("max-history-bytes", 0, "logical WorkChain history budget; defaults to source activation policy")
	forkRetention := flags.Uint64("fork-retention", storage.ForkRetention, "local retained side-fork distance; zero disables side-fork pruning")
	checkpointEvery := flags.Uint64("checkpoint-every", storage.CheckpointEvery, "local replay-checkpoint spacing; zero disables checkpoints")
	checkpointKeep := flags.Uint64("checkpoint-keep", uint64(storage.CheckpointKeep), "local replay-checkpoint count; zero disables checkpoints")
	canonicalRetention := flags.Uint64("canonical-retention", storage.CanonicalRetention, "explicit nonzero selected-tip distance required for archive pruning")
	limits := workarchive.DefaultLimits()
	maximumBlocks := flags.Uint64("max-archive-blocks", limits.MaximumBlocks, "local archive replay block limit")
	maximumChunks := flags.Uint64("max-archive-chunks", uint64(limits.MaximumChunks), "local archive replay chunk limit")
	maximumBytes := flags.Uint64("max-archive-bytes", limits.MaximumBytes, "local archive replay byte limit")
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	present := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { present[f.Name] = true })
	if *mode != "review" && *mode != "control" {
		return pruneArchiveEffectOptions{}, errors.New("archive effect mode must be review or control")
	}
	if *inventoryPath == "" || *data == "" || *rootsPath == "" || *executor == "" || *executorPins == "" ||
		*chain == "" || *chainPins == "" || *availability == "" {
		return pruneArchiveEffectOptions{}, errors.New("inventory, data, roots, all executor/chain roots and availability-out are required")
	}
	if *checkpointKeep > uint64(^uint32(0)) || *maximumChunks > uint64(^uint32(0)) || *canonicalRetention == 0 ||
		(present["max-history-bytes"] && *maximumHistory < minimumHistoryBytes) {
		return pruneArchiveEffectOptions{}, errors.New("checkpoint/chunk counts must fit u32, canonical-retention must be nonzero and an explicit history budget must meet the minimum")
	}
	limits = workarchive.Limits{MaximumBlocks: *maximumBlocks, MaximumChunks: uint32(*maximumChunks), MaximumBytes: *maximumBytes}
	if err := limits.Validate(); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	config := authoritystore.PruneArchiveEffectServiceConfig{ExecutorPath: *executor, ExecutorPinsPath: *executorPins,
		ChainPath: *chain, ChainPinsPath: *chainPins, Limits: limits}
	var err error
	if config.InventoryID, err = pruneExternalID("inventory-id", *inventoryText); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	if config.PolicyID, err = pruneExternalID("policy-id", *policyText); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	config.InventoryPath, _, err = canonicalPruneLineageFile(*inventoryPath)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	inventory, err := authoritystore.LoadArchivePruneInventoryFile(config.InventoryPath, config.InventoryID, config.PolicyID)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	if inventory.Mode == authoritystore.ArchivePruneInitial {
		if present["lineage-evidence"] || present["lineage-evidence-id"] {
			return pruneArchiveEffectOptions{}, errors.New("initial mode forbids lineage evidence flags, including empty values")
		}
	} else {
		if *lineage == "" {
			return pruneArchiveEffectOptions{}, errors.New("lineage mode requires retained evidence and its independent ID")
		}
		if config.LineageID, err = pruneExternalID("lineage-evidence-id", *lineageText); err != nil {
			return pruneArchiveEffectOptions{}, err
		}
		config.LineagePath, _, err = canonicalPruneLineageFile(*lineage)
		if err != nil {
			return pruneArchiveEffectOptions{}, err
		}
	}
	metadata, _, err := canonicalPruneLineageFile(*rootsPath)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	encoded, err := readRegularArtifact(metadata, maximumPruneEffectRootsBytes)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	config.Authorities, config.Replicas, err = decodePruneEffectRoots(encoded)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	if err := bindPruneEffectRoots(&config, inventory, filepath.Dir(metadata)); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	config.AvailabilityPath, err = canonicalPruneLineageOutput(*availability)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	sourceData, err := canonicalPruneLineageDirectory(*data)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	if err := validatePruneEffectSourcePlacement(sourceData, metadata, &config); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	if err := ctx.Err(); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	// Source data is separate from every live effect owner. Open only an existing
	// read-only ledger: the normal openStore helper may initialize missing data.
	documentBytes, err := readRegularArtifact(filepath.Join(sourceData, genesisFilename), 64+genesis.MaxAllocations*resource.CanonicalSize)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	document, err := genesis.Decode(documentBytes)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	profileBytes, err := readRegularArtifact(filepath.Join(sourceData, workActivationFilename), workActivationSize)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	profile, err := decodeWorkActivation(profileBytes)
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	if err := validateWorkActivation(profile, document); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	genesisID, err := document.ID()
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	binding := inventory.Policy.CheckpointPolicy.Binding
	if binding.NetworkID != document.NetworkID || binding.GenesisID != genesisID || binding.ActivationHeight != profile.ActivationHeight {
		return pruneArchiveEffectOptions{}, errors.New("inventory binding does not match the activation source")
	}
	ledger, err := pebblestore.OpenExistingReadOnly(filepath.Join(sourceData, ledgerDirectory), document, pebblestore.DefaultPolicy())
	if err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	base, baseErr := archiveBaseFromLedger(ledger, binding.BaseID, profile.ActivationHeight)
	closeErr := ledger.Close()
	if err := errors.Join(baseErr, closeErr, ctx.Err()); err != nil {
		return pruneArchiveEffectOptions{}, err
	}
	legacy := legacyblock.ParametersFromGenesis(document)
	config.Base = base
	config.Parameters = workblock.Parameters{NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy,
		RewardMaturity: legacy.RewardMaturity, ActivationHeight: profile.ActivationHeight,
		DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
		TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: profile.FeeDelay}
	if !present["max-history-bytes"] {
		*maximumHistory = profile.MaxHistoryBytes
	}
	config.StoragePolicy = workchain.Policy{MaxHistoryBytes: *maximumHistory, ForkRetention: *forkRetention,
		CheckpointEvery: *checkpointEvery, CheckpointKeep: uint32(*checkpointKeep), CanonicalRetention: *canonicalRetention}
	return pruneArchiveEffectOptions{mode: *mode, config: config, sourceData: sourceData, rootsPath: metadata}, nil
}

func bindPruneEffectRoots(config *authoritystore.PruneArchiveEffectServiceConfig, inventory authoritystore.ArchivePruneInventory, parent string) error {
	if len(config.Authorities) != len(inventory.Policy.Assignments) || len(config.Replicas) != len(inventory.Policy.Assignments) {
		return authoritystore.ErrPruneInventory
	}
	selected := make(map[types.Hash]bool, len(inventory.Policy.Assignments))
	for _, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID()
		selected[id] = true
	}
	for _, roots := range config.Authorities {
		if !selected[roots.AssignmentID] {
			return authoritystore.ErrPruneInventory
		}
	}
	for _, roots := range config.Replicas {
		if !selected[roots.AssignmentID] {
			return authoritystore.ErrPruneInventory
		}
	}
	resolve := func(path string) (string, error) {
		if !filepath.IsAbs(path) {
			path = filepath.Join(parent, path)
		}
		return canonicalPruneLineageDirectory(path)
	}
	for i := range config.Authorities {
		var err error
		if config.Authorities[i].AuthorityPath, err = resolve(config.Authorities[i].AuthorityPath); err != nil {
			return err
		}
		if config.Authorities[i].AuthorityPinsPath, err = resolve(config.Authorities[i].AuthorityPinsPath); err != nil {
			return err
		}
	}
	for i := range config.Replicas {
		var err error
		if config.Replicas[i].Directory, err = resolve(config.Replicas[i].Directory); err != nil {
			return err
		}
	}
	return nil
}

// A source root must not alias, contain or sit inside an effect-owned tree or
// artifact directory. This check runs before even the read-only source DB opens.
func validatePruneEffectSourcePlacement(sourceData, metadata string, config *authoritystore.PruneArchiveEffectServiceConfig) error {
	paths := []*string{&config.ExecutorPath, &config.ExecutorPinsPath, &config.ChainPath, &config.ChainPinsPath}
	for i := range config.Authorities {
		paths = append(paths, &config.Authorities[i].AuthorityPath, &config.Authorities[i].AuthorityPinsPath)
	}
	for i := range config.Replicas {
		paths = append(paths, &config.Replicas[i].Directory)
	}
	for _, path := range paths {
		canonical, err := canonicalPruneLineageDirectory(*path)
		if err != nil {
			return err
		}
		*path = canonical
	}
	directories := make([]string, 0, len(paths)+4)
	for _, path := range paths {
		directories = append(directories, *path)
	}
	directories = append(directories, filepath.Dir(config.InventoryPath), filepath.Dir(config.AvailabilityPath), filepath.Dir(metadata))
	if config.LineagePath != "" {
		directories = append(directories, filepath.Dir(config.LineagePath))
	}
	for _, path := range directories {
		if pruneEffectPathsOverlap(sourceData, path) {
			return errors.New("activation source must be disjoint from every effect owner, replica and artifact directory")
		}
	}
	// Metadata is input, not an owner. It may share an immutable input-artifact
	// parent but cannot live inside trees this operation owns or publishes into.
	for _, path := range append(directories[:len(paths):len(paths)], filepath.Dir(config.AvailabilityPath)) {
		if pruneEffectPathsOverlap(filepath.Dir(metadata), path) {
			return errors.New("roots metadata parent must be outside effect-owned and output trees")
		}
	}
	return nil
}

func pruneEffectPathsOverlap(a, b string) bool {
	within := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
	}
	return within(a, b) || within(b, a)
}

// The roots descriptor is local path metadata, not a grant or journal. Token
// parsing preserves duplicate keys and exact spelling; encoding/json structs
// would silently accept duplicate and case-insensitive field names.
func decodePruneEffectRoots(encoded []byte) ([]authoritystore.PruneArchiveAuthorityRoots, []authoritystore.PruneArchiveReplicaPath, error) {
	invalid := func() ([]authoritystore.PruneArchiveAuthorityRoots, []authoritystore.PruneArchiveReplicaPath, error) {
		return nil, nil, errors.New("roots must be a bounded exact authorities/replicas object with unique assignments and string paths")
	}
	if len(encoded) == 0 || len(encoded) > maximumPruneEffectRootsBytes || !utf8.Valid(encoded) {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return invalid()
	}
	var authorities []authoritystore.PruneArchiveAuthorityRoots
	var replicas []authoritystore.PruneArchiveReplicaPath
	seen := make(map[string]bool, 2)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || (name != "authorities" && name != "replicas") {
			return invalid()
		}
		seen[name] = true
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return invalid()
		}
		ids := make(map[types.Hash]bool)
		for decoder.More() {
			if len(ids) >= workarchive.MaximumReplicas {
				return invalid()
			}
			if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
				return invalid()
			}
			fields := make(map[string]string, 3)
			for decoder.More() {
				token, err := decoder.Token()
				field, ok := token.(string)
				if _, duplicate := fields[field]; err != nil || !ok || duplicate ||
					(field != "assignment_id" && !(name == "authorities" && (field == "authority" || field == "authority_pins")) && !(name == "replicas" && field == "directory")) {
					return invalid()
				}
				token, err = decoder.Token()
				value, ok := token.(string)
				if err != nil || !ok || value == "" || strings.IndexByte(value, 0) >= 0 {
					return invalid()
				}
				fields[field] = value
			}
			if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
				return invalid()
			}
			id, err := pruneExternalID("assignment_id", fields["assignment_id"])
			if err != nil || id.String() != fields["assignment_id"] || ids[id] {
				return invalid()
			}
			ids[id] = true
			if name == "authorities" {
				if len(fields) != 3 {
					return invalid()
				}
				authorities = append(authorities, authoritystore.PruneArchiveAuthorityRoots{AssignmentID: id, AuthorityPath: fields["authority"], AuthorityPinsPath: fields["authority_pins"]})
			} else {
				if len(fields) != 2 {
					return invalid()
				}
				replicas = append(replicas, authoritystore.PruneArchiveReplicaPath{AssignmentID: id, Directory: fields["directory"]})
			}
		}
		if len(ids) == 0 {
			return invalid()
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return invalid()
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 2 {
		return invalid()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid()
	}
	if len(authorities) != len(replicas) {
		return invalid()
	}
	return authorities, replicas, nil
}
