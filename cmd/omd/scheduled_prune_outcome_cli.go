package main

import (
	"context"
	"flag"
	"io"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const scheduledOutcomeCommand = "work-prune-scheduled-outcome"

func runScheduledPruneOutcomeCLI(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet(scheduledOutcomeCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review, publish, cancel-before-start, cancel-with-closure, resume-executor, recover-effect, review-settlement, prepare-settlement or settle-effect")
	c := store.ScheduledPruneCommandConfig{}
	f.StringVar(&c.PlanPath, "plan", "", "canonical scheduled plan")
	planID := f.String("plan-id", "", "independently retained plan ID")
	f.StringVar(&c.InventoryPath, "inventory", "", "original accepted scheduled inventory")
	inventoryID := f.String("inventory-id", "", "independently retained inventory ID")
	f.StringVar(&c.ClosurePath, "closure", "", "certified cancellation: original witness closure")
	closureID := f.String("closure-id", "", "independently retained closure ID")
	f.StringVar(&c.SettlementPath, "settlement-certificate", "", "settle-effect: co-signed witness decision")
	settlementID := f.String("certificate-id", "", "independently retained settlement certificate ID")
	assignmentID := f.String("assignment-id", "", "selected original assignment; cancel, resume and recovery require the primary")
	f.StringVar(&c.AuthorityPath, "authority", "", "original selected authority")
	f.StringVar(&c.AuthorityPinsPath, "authority-pins", "", "original authority pins")
	f.StringVar(&c.ExecutorPath, "executor", "", "original executor")
	f.StringVar(&c.ExecutorPinsPath, "executor-pins", "", "original executor pins")
	expected := f.String("expected-review-id", "", "exact preceding review ID")
	dest := f.String("out", "", "publish/prepare-settlement: immutable outcome or proposal")
	data := f.String("data", "", "recovery/settlement: original activation base")
	chain := f.String("chain", "", "recovery/settlement: migrated protected chain")
	chainPins := f.String("chain-pins", "", "original storage position pins")
	migration := f.String("storage-migration-id", "", "independently retained storage migration ID")
	defaults := workchain.DefaultPolicy()
	history := f.Uint64("max-history-bytes", 0, "storage history budget; default from activation profile")
	fork := f.Uint64("fork-retention", defaults.ForkRetention, "storage fork retention")
	every := f.Uint64("checkpoint-every", defaults.CheckpointEvery, "storage checkpoint spacing")
	keep := f.Uint("checkpoint-keep", uint(defaults.CheckpointKeep), "storage checkpoint count")
	retention := f.Uint64("canonical-retention", defaults.CanonicalRetention, "storage canonical retention")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	present := custodyCommandPresence(f)
	switch *mode {
	case "review", "review-settlement":
		if err := custodyCommandForbid(present, "expected-review-id", "out"); err != nil {
			return err
		}
	case "publish", "cancel-before-start", "cancel-with-closure", "resume-executor", "recover-effect", "prepare-settlement", "settle-effect":
	default:
		return store.ErrScheduledPrune
	}
	if *mode != "publish" && *mode != "prepare-settlement" && present["out"] {
		return store.ErrScheduledPrune
	}
	c.PrepareSettlement = *mode == "review-settlement" || *mode == "prepare-settlement"
	hasSettlement := present["settlement-certificate"] || present["certificate-id"]
	if hasSettlement {
		if (*mode != "review" && *mode != "settle-effect") || c.SettlementPath == "" {
			return store.ErrScheduledPrune
		}
		id, err := pruneExternalID("certificate-id", *settlementID)
		if err != nil {
			return err
		}
		c.SettlementID = id
	}
	if *mode == "settle-effect" && !hasSettlement {
		return store.ErrScheduledPrune
	}
	hasClosure := present["closure"] || present["closure-id"]
	if hasClosure {
		if (*mode != "review" && *mode != "cancel-with-closure") || c.ClosurePath == "" {
			return store.ErrScheduledPrune
		}
		id, err := pruneExternalID("closure-id", *closureID)
		if err != nil {
			return err
		}
		c.ClosureID = id
	}
	if *mode == "cancel-with-closure" && !hasClosure {
		return store.ErrScheduledPrune
	}
	for _, v := range []struct {
		target     *types.Hash
		text, name string
	}{
		{&c.PlanID, *planID, "plan-id"}, {&c.InventoryID, *inventoryID, "inventory-id"}, {&c.AssignmentID, *assignmentID, "assignment-id"},
	} {
		id, err := pruneExternalID(v.name, v.text)
		if err != nil {
			return err
		}
		*v.target = id
	}
	var reviewID types.Hash
	if *mode != "review" && *mode != "review-settlement" {
		id, err := pruneExternalID("expected-review-id", *expected)
		if err != nil {
			return err
		}
		reviewID = id
	}
	plan, err := store.LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
	if err != nil {
		return err
	}
	inventory, err := store.LoadScheduledPruneInventory(c.InventoryPath, c.InventoryID)
	if err != nil {
		return err
	}
	if err := plan.BindInventory(inventory); err != nil {
		return err
	}
	roots := []string{c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath}
	inputs := []string{c.PlanPath, c.InventoryPath}
	if c.ClosurePath != "" {
		inputs = append(inputs, c.ClosurePath)
	}
	if c.SettlementPath != "" {
		inputs = append(inputs, c.SettlementPath)
	}
	storageFlags := []string{"data", "chain", "chain-pins", "storage-migration-id", "max-history-bytes", "fork-retention", "checkpoint-every", "checkpoint-keep", "canonical-retention"}
	hasStorage := false
	for _, name := range storageFlags {
		hasStorage = hasStorage || present[name]
	}
	if hasStorage {
		if hasClosure || (*mode != "review" && *mode != "recover-effect" && *mode != "review-settlement" && *mode != "prepare-settlement" && *mode != "settle-effect") || uint64(*keep) > uint64(^uint32(0)) {
			return store.ErrScheduledPrune
		}
		mid, err := pruneExternalID("storage-migration-id", *migration)
		if err != nil {
			return err
		}
		roots = append(roots, *chain, *chainPins)
		base, parameters, budget, err := loadMigratedPruneBase(ctx, *data, plan.OriginalPolicy.Binding, inventory.Checkpoint.Statement.RadixActivationHeight, append(append([]string(nil), roots...), inputs...))
		if err != nil {
			return err
		}
		if !present["max-history-bytes"] {
			*history = budget
		}
		c.Storage = &store.PruneRecoveryStorage{ChainPath: *chain, ChainPinsPath: *chainPins, MigrationID: mid, Base: base, Parameters: parameters, Policy: workchain.Policy{MaxHistoryBytes: *history, ForkRetention: *fork, CheckpointEvery: *every, CheckpointKeep: uint32(*keep), CanonicalRetention: *retention}}
	}
	if (*mode == "recover-effect" || c.PrepareSettlement || hasSettlement) && !hasStorage {
		return store.ErrScheduledPrune
	}
	actualMode, actualReview := *mode, reviewID
	if *mode == "publish" || *mode == "review-settlement" {
		actualMode, actualReview = "review", types.Hash{}
	}
	result, err := store.RunScheduledPruneCommand(ctx, c, actualMode, actualReview)
	if err != nil {
		return err
	}
	outcome, terminalErr := store.RetainedScheduledPruneOutcome(inventory, result.Executor)
	var kind, outcomeID string
	if terminalErr == nil {
		kind = "effect"
		if outcome.Cancellation != nil {
			kind = "cancellation"
		}
		if outcome.Settlement != nil {
			kind = "settlement"
		}
		id, err := outcome.EvidenceID(inventory)
		if err != nil {
			return err
		}
		outcomeID = id.String()
	}
	if *mode == "publish" {
		if terminalErr != nil {
			return terminalErr
		}
		if reviewID != result.Review.ReviewID {
			return store.ErrPruneArchiveEffectReview
		}
		if err := scheduledOperatorOutput(*dest, inputs, roots); err != nil {
			return err
		}
		raw, err := outcome.Artifact()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publishImmutableArtifact(*dest, raw); err != nil {
			return err
		}
	}
	var proposalID string
	if result.Proposal != nil {
		id, _ := result.Proposal.ID()
		proposalID = id.String()
	}
	if *mode == "prepare-settlement" {
		if result.Proposal == nil {
			return store.ErrPruneOutcome
		}
		if err := scheduledOperatorOutput(*dest, inputs, roots); err != nil {
			return err
		}
		raw, err := result.Proposal.CanonicalBytes()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publishImmutableArtifact(*dest, raw); err != nil {
			return err
		}
	}
	return scheduledOperatorReport(ctx, out, struct {
		store.ScheduledPruneCommandResult
		ProposalID  string `json:"proposal_id,omitempty"`
		ReviewID    string `json:"review_id"`
		OutcomeKind string `json:"outcome_kind,omitempty"`
		OutcomeID   string `json:"outcome_id,omitempty"`
	}{result, proposalID, result.Review.ReviewID.String(), kind, outcomeID})
}
