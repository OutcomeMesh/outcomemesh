package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const (
	migratedPruneOutcomeCommand = "work-prune-migrated-outcome"
	migratedPruneSignCommand    = "work-prune-migrated-command-sign"
	migratedPruneCosignCommand  = "work-prune-migrated-command-cosign"
	migratedPruneApplyCommand   = "work-prune-migrated-command"
)

func runMigratedPruneCLI(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runMigratedPruneCLIContext(ctx, args, os.Stdout)
}
func runMigratedPruneCLIContext(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || out == nil || len(args) == 0 {
		return store.ErrMigratedPrune
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	signing := args[0] == migratedPruneSignCommand || args[0] == migratedPruneCosignCommand
	cosign := args[0] == migratedPruneCosignCommand
	capture := args[0] == migratedPruneOutcomeCommand
	if !signing && !capture && args[0] != migratedPruneApplyCommand {
		return store.ErrMigratedPrune
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review by default; explicit modes depend on the command")
	c := store.MigratedPruneConfig{}
	f.StringVar(&c.InventoryPath, "inventory", "", "original archive inventory")
	f.StringVar(&c.ProofPath, "schedule-proof", "", "original assignment's verified schedule proof")
	inventoryID := f.String("inventory-id", "", "independent original inventory ID")
	policyID := f.String("policy-id", "", "independent original policy ID")
	scopeID := f.String("schedule-id", "", "independent schedule proof ID")
	expected := f.String("expected-review-id", "", "exact preceding review ID")
	dest := f.String("out", "", "immutable signed command, entry or retained outcome")
	f.StringVar(&c.OutcomePath, "outcome", "", "exact existing effect or pre-start cancellation")
	f.StringVar(&c.OutcomeKind, "outcome-kind", "", "effect or cancellation")
	outcomeID := f.String("outcome-id", "", "independently retained original outcome ID")
	keyName := "consumer-key"
	if cosign {
		keyName = "authority-key"
	}
	key := f.String(keyName, "", "original role-specific seed file")
	seq := f.String("expected-sequence", "", "explicit reviewed sequence")
	head := f.String("expected-head", "", "explicit reviewed head")
	command := f.String("command", "", "consumer-signed completion (cosign only)")
	f.StringVar(&c.AuthorityPath, "authority", "", "original selected authority")
	f.StringVar(&c.AuthorityPinsPath, "authority-pins", "", "original authority pins")
	f.StringVar(&c.ExecutorPath, "executor", "", "original executor")
	f.StringVar(&c.ExecutorPinsPath, "executor-pins", "", "original executor pins")
	f.StringVar(&c.EntryPath, "entry", "", "exact co-signed completion")
	entryID := f.String("entry-id", "", "independently retained completion entry ID")
	data := f.String("data", "", "existing separate activation base, recovery only")
	chain := f.String("chain", "", "existing migrated protected chain")
	chainPins := f.String("chain-pins", "", "original storage position pins")
	migration := f.String("storage-migration-id", "", "original storage migration review ID")
	defaults := workchain.DefaultPolicy()
	history := f.Uint64("max-history-bytes", 0, "recovery storage policy; default from activation profile")
	fork := f.Uint64("fork-retention", defaults.ForkRetention, "storage fork retention")
	every := f.Uint64("checkpoint-every", defaults.CheckpointEvery, "storage checkpoint spacing")
	keep := f.Uint("checkpoint-keep", uint(defaults.CheckpointKeep), "storage checkpoint count")
	retention := f.Uint64("canonical-retention", defaults.CanonicalRetention, "storage canonical retention")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	accepted := map[string]bool{"mode": true, "inventory": true, "inventory-id": true, "policy-id": true, "schedule-proof": true, "schedule-id": true}
	allow := func(names ...string) {
		for _, name := range names {
			accepted[name] = true
		}
	}
	if signing {
		if *mode != "review" && *mode != "sign" {
			return store.ErrMigratedPrune
		}
		allow("outcome", "outcome-kind", "outcome-id", "expected-sequence", "expected-head")
		if cosign {
			allow("command")
		}
		if *mode == "sign" {
			allow(keyName, "out", "expected-review-id")
		}
	} else {
		allow("authority", "authority-pins", "executor", "executor-pins")
		if capture {
			if *mode != "review" && *mode != "publish" && *mode != "resume-executor" && *mode != "recover-effect" && *mode != "cancel-before-start" {
				return store.ErrMigratedPrune
			}
			if *mode == "publish" {
				allow("out")
			}
			if *mode == "review" || *mode == "recover-effect" {
				allow("data", "chain", "chain-pins", "storage-migration-id", "max-history-bytes", "fork-retention", "checkpoint-every", "checkpoint-keep", "canonical-retention")
			}
		} else {
			if *mode != "review" && *mode != "apply" && *mode != "resume" {
				return store.ErrMigratedPrune
			}
			allow("entry", "entry-id", "outcome", "outcome-kind", "outcome-id")
		}
		if *mode != "review" {
			allow("expected-review-id")
		}
	}
	var flagErr error
	f.Visit(func(v *flag.Flag) {
		if !accepted[v.Name] && flagErr == nil {
			flagErr = fmt.Errorf("flag %s is not used by %s mode %s", v.Name, args[0], *mode)
		}
	})
	if flagErr != nil {
		return flagErr
	}
	for _, p := range []struct {
		to         *types.Hash
		text, name string
	}{{&c.InventoryID, *inventoryID, "inventory-id"}, {&c.PolicyID, *policyID, "policy-id"}, {&c.ScheduleID, *scopeID, "schedule-id"}} {
		id, err := pruneExternalID(p.name, p.text)
		if err != nil {
			return err
		}
		*p.to = id
	}
	var reviewID types.Hash
	var err error
	if *mode != "review" {
		reviewID, err = pruneExternalID("expected-review-id", *expected)
		if err != nil {
			return err
		}
	}
	v, err := store.LoadMigratedPruneContext(c)
	if err != nil {
		return err
	}
	if signing || !capture {
		c.OutcomeID, err = pruneExternalID("outcome-id", *outcomeID)
		if err != nil {
			return err
		}
		if c.OutcomePath == "" {
			return store.ErrMigratedPrune
		}
	}
	inputs := []string{c.InventoryPath, c.ProofPath, c.OutcomePath, c.EntryPath, *command, *key}
	if signing {
		evidence, err := store.LoadMigratedPruneOutcome(c.OutcomePath, c.OutcomeKind, c.OutcomeID)
		if err != nil {
			return err
		}
		n, err := scheduledOperatorNumber(*seq)
		if err != nil {
			return err
		}
		h, err := pruneExternalID("expected-head", *head)
		if err != nil {
			return err
		}
		draft, err := store.BuildMigratedPruneCompletion(v, evidence, custodyauthority.Position{Sequence: n, HeadID: h})
		if err != nil {
			return err
		}
		a, err := v.SelectedAssignment()
		if err != nil {
			return err
		}
		signatureReview, err := custodyauthority.ScheduledPruneCommandReviewID(a, draft)
		if err != nil {
			return err
		}
		signed := draft
		if cosign {
			raw, err := readRegularArtifact(*command, custodyauthority.MaximumCommandBytes)
			if err != nil {
				return err
			}
			signed, err = custodyauthority.DecodeCommand(raw)
			if err != nil {
				return err
			}
			unsigned := signed
			unsigned.Signature = [64]byte{}
			if unsigned != draft {
				return store.ErrMigratedPrune
			}
			signatureReview, err = custodyauthority.ScheduledPruneEntryReviewID(a, signed)
			if err != nil {
				return err
			}
		}
		var eid string
		if *mode == "sign" {
			if reviewID != signatureReview {
				return custodyauthority.ErrPruneReview
			}
			if err := scheduledOperatorOutput(*dest, inputs, nil); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			private, err := loadPruneOfflineKey(*key)
			if err != nil {
				return err
			}
			defer clear(private)
			var raw []byte
			if cosign {
				entry, err := custodyauthority.CosignReviewedScheduledPruneCommand(a, signed, signatureReview, private)
				if err != nil {
					return err
				}
				id, _ := entry.ID()
				eid = id.String()
				raw, err = entry.CanonicalBytes()
				if err != nil {
					return err
				}
			} else {
				signed, err = custodyauthority.SignReviewedScheduledPruneCommand(a, draft, signatureReview, private)
				if err != nil {
					return err
				}
				raw, err = signed.CanonicalBytes()
				if err != nil {
					return err
				}
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := publishImmutableArtifact(*dest, raw); err != nil {
				return err
			}
		}
		return scheduledOperatorReport(ctx, out, struct {
			ReviewID  string                   `json:"review_id"`
			EntryID   string                   `json:"entry_id,omitempty"`
			Draft     custodyauthority.Command `json:"draft"`
			Published bool                     `json:"published"`
		}{signatureReview.String(), eid, draft, *mode == "sign"})
	}
	if !capture {
		c.EntryID, err = pruneExternalID("entry-id", *entryID)
		if err != nil {
			return err
		}
		if c.EntryPath == "" {
			return store.ErrMigratedPrune
		}
	}
	if capture && (*data != "" || *chain != "" || *chainPins != "" || *migration != "") {
		if uint64(*keep) > uint64(^uint32(0)) {
			return store.ErrMigratedPrune
		}
		mid, err := pruneExternalID("storage-migration-id", *migration)
		if err != nil {
			return err
		}
		roots := []string{c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath, *chain, *chainPins}
		for _, input := range inputs {
			if input != "" {
				roots = append(roots, input)
			}
		}
		base, parameters, profileHistory, err := loadMigratedPruneBase(ctx, *data, v.Inventory.Policy.CheckpointPolicy.Binding, v.Proof.TargetCheckpoint.Statement.RadixActivationHeight, roots)
		if err != nil {
			return err
		}
		if !custodyCommandPresence(f)["max-history-bytes"] {
			*history = profileHistory
		}
		c.Storage = &store.MigratedPruneStorage{ChainPath: *chain, ChainPinsPath: *chainPins, MigrationID: mid, Base: base, Parameters: parameters, Policy: workchain.Policy{MaxHistoryBytes: *history, ForkRetention: *fork, CheckpointEvery: *every, CheckpointKeep: uint32(*keep), CanonicalRetention: *retention}}
	} else if capture {
		if err := custodyCommandForbid(custodyCommandPresence(f), "max-history-bytes", "fork-retention", "checkpoint-every", "checkpoint-keep", "canonical-retention", "data", "chain", "chain-pins", "storage-migration-id"); err != nil {
			return err
		}
	}
	actualMode := *mode
	actualReview := reviewID
	if *mode == "publish" {
		actualMode = "review"
		actualReview = types.Hash{}
	}
	result, err := store.RunMigratedPrune(ctx, c, actualMode, actualReview)
	if err != nil {
		return err
	}
	var evidenceID, kind string
	if id, e := result.Review.Outcome.EvidenceID(v); e == nil {
		evidenceID = id.String()
		kind = "effect"
		if result.Review.Outcome.Cancellation != nil {
			kind = "cancellation"
		}
	}
	if *mode == "publish" {
		if reviewID != result.Review.ReviewID {
			return store.ErrPruneRecoveryReview
		}
		if evidenceID == "" || result.Review.Authority.Pending != nil {
			return store.ErrPruneOutcome
		}
		if err := scheduledOperatorOutput(*dest, inputs, []string{c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath}); err != nil {
			return err
		}
		raw, err := result.Review.Outcome.Artifact()
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
		Result    store.MigratedPruneResult `json:"result"`
		ReviewID  string                    `json:"review_id"`
		Head      string                    `json:"confirmed_head"`
		Sequence  uint64                    `json:"confirmed_sequence"`
		OutcomeID string                    `json:"outcome_id,omitempty"`
		Kind      string                    `json:"outcome_kind,omitempty"`
		Published bool                      `json:"published"`
	}{result, result.Review.ReviewID.String(), result.Review.Authority.Confirmed.HeadID.String(), result.Review.Authority.Confirmed.Sequence, evidenceID, kind, *mode == "publish"})
}
