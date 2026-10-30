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
	"strconv"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	scheduledPlanCommand      = "work-prune-scheduled-plan"
	scheduledSignCommand      = "work-prune-scheduled-command-sign"
	scheduledCosignCommand    = "work-prune-scheduled-command-cosign"
	scheduledApplyCommand     = "work-prune-scheduled-command"
	scheduledInventoryCommand = "work-prune-scheduled-inventory"
	scheduledEffectCommand    = "work-prune-scheduled-effect"
)

func runScheduledPruneOperatorCLI(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runScheduledPruneOperator(ctx, args, os.Stdout)
}
func runScheduledPruneOperator(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || out == nil || len(args) == 0 {
		return store.ErrScheduledPrune
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch args[0] {
	case pruneFencePolicyCommand, pruneFenceScopeCommand:
		return runPruneFenceArtifactCLI(ctx, args, out)
	case scheduledPlanCommand:
		return runScheduledPrunePlanCLI(ctx, args[1:], out)
	case scheduledSignCommand, scheduledCosignCommand:
		return runScheduledPruneSigningCLI(ctx, args, out)
	case scheduledApplyCommand, scheduledEffectCommand:
		return runScheduledPruneCommandCLI(ctx, args, out)
	case scheduledOutcomeCommand:
		return runScheduledPruneOutcomeCLI(ctx, args[1:], out)
	case scheduledInventoryCommand:
		return runScheduledPruneInventoryCLI(ctx, args[1:], out)
	}
	return store.ErrScheduledPrune
}
func scheduledOperatorReport(ctx context.Context, out io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeCustodyScheduleReport(ctx, out, append(raw, '\n'))
}
func scheduledOperatorNumber(text string) (uint64, error) {
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != text {
		return 0, store.ErrScheduledPrune
	}
	return n, nil
}
func scheduledOperatorOutput(path string, inputs, roots []string) error {
	if path == "" {
		return store.ErrScheduledPrune
	}
	for _, root := range roots {
		if workarchive.CustodyEvidencePathsOverlap(filepath.Dir(path), root) {
			return store.ErrRootOverlap
		}
	}
	for _, input := range inputs {
		if input != "" && workarchive.CustodyEvidencePathsOverlap(path, input) {
			return store.ErrRootOverlap
		}
	}
	return nil
}

func runScheduledPrunePlanCLI(ctx context.Context, args []string, out io.Writer) error {
	var mode, primary, storage, pair, consumer, at, expected, destination, requestOut *string
	var fencePath, fenceID *string
	var flags *flag.FlagSet
	input, err := loadCustodyScheduleQuorumInputs(ctx, args, func(f *flag.FlagSet) {
		flags = f
		mode = f.String("mode", "review", "review or publish immutable plan/request")
		primary = f.String("primary-assignment-id", "", "original primary assignment")
		storage = f.String("storage-id", "", "independently retained protected storage ID")
		pair = f.String("storage-pair-id", "", "independently retained database/pins pair ID")
		consumer = f.String("consumer-public-key", "", "authorized Prune consumer")
		at = f.String("verified-at", "", "fixed positive Unix request time; never the live execution clock")
		expected = f.String("expected-plan-id", "", "publish: previously reviewed plan ID")
		destination = f.String("out", "", "publish: immutable canonical plan")
		requestOut = f.String("request-out", "", "publish: immutable canonical request for executor preparation")
		fencePath = f.String("fence-policy", "", "optional independently selected policy, before admission")
		fenceID = f.String("fence-policy-id", "", "independently reviewed policy ID")
	})
	if err != nil {
		return err
	}
	presence := custodyCommandPresence(flags)
	if *mode != "review" && *mode != "publish" {
		return store.ErrScheduledPrune
	}
	if *mode == "review" {
		if err := custodyCommandForbid(presence, "expected-plan-id", "out", "request-out"); err != nil {
			return err
		}
	}
	ids := make([]types.Hash, 4)
	for i, value := range []string{*primary, *storage, *pair, *consumer} {
		ids[i], err = pruneExternalID("plan identity", value)
		if err != nil {
			return err
		}
	}
	verifiedAt, err := scheduledOperatorNumber(*at)
	if err != nil || verifiedAt == 0 {
		return store.ErrScheduledPrune
	}
	p, err := store.PrepareScheduledPrunePlan(ctx, input.Sources, input.Checkpoint, input.OriginalPolicy, input.ReplicaPolicy, ids[0], ids[1], ids[2], [32]byte(ids[3]), verifiedAt, func() uint64 { return uint64(time.Now().Unix()) })
	if err != nil {
		return err
	}
	if (*fencePath == "") != (*fenceID == "") {
		return prunefence.ErrFence
	}
	if *fencePath != "" {
		raw, err := readRegularArtifact(*fencePath, prunefence.MaximumPolicyBytes)
		if err != nil {
			return err
		}
		policy, err := prunefence.DecodePolicy(raw)
		if err != nil {
			return err
		}
		id, _ := policy.ID()
		want, err := pruneExternalID("fence-policy-id", *fenceID)
		if err != nil || want != id {
			return prunefence.ErrFence
		}
		p, err = p.WithFence(policy)
		if err != nil {
			return err
		}
	}
	id, err := p.ID()
	if err != nil {
		return err
	}
	rid, _ := p.Request.ID()
	if *mode == "publish" {
		reviewed, err := pruneExternalID("expected-plan-id", *expected)
		if err != nil || reviewed != id {
			return errors.Join(store.ErrPruneArchiveEffectReview, err)
		}
		inputs := []string{input.SourcePath, input.CheckpointPath, *fencePath}
		var roots []string
		for _, s := range input.Input {
			inputs = append(inputs, s.Assignment, s.Proof, s.Receipt)
			roots = append(roots, s.Authority, s.Pins, s.Journal)
		}
		if err := scheduledOperatorOutput(*destination, inputs, roots); err != nil {
			return err
		}
		if err := scheduledOperatorOutput(*requestOut, append(inputs, *destination), roots); err != nil {
			return err
		}
		if err := store.SaveScheduledPrunePlan(ctx, *destination, p, id); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, _ := p.Request.CanonicalBytes()
		if err := publishImmutableArtifact(*requestOut, raw); err != nil {
			return err
		}
	}
	return scheduledOperatorReport(ctx, out, struct {
		PlanID, RequestID types.Hash
		Plan              store.ScheduledPrunePlan
		Published         bool
		PlanIDText        string `json:"plan_id"`
		RequestIDText     string `json:"request_id"`
	}{id, rid, p, *mode == "publish", id.String(), rid.String()})
}

func runScheduledPruneCommandCLI(ctx context.Context, args []string, out io.Writer) error {
	effect := args[0] == scheduledEffectCommand
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review, apply, resume, resume-executor; effect capture: review or publish")
	plan := f.String("plan", "", "canonical scheduled plan")
	planID := f.String("plan-id", "", "independently retained plan ID")
	assignment := f.String("assignment-id", "", "selected original assignment")
	authority := f.String("authority", "", "original authority")
	pins := f.String("authority-pins", "", "original independent authority pins")
	executor := f.String("executor", "", "existing operation executor")
	executorPins := f.String("executor-pins", "", "original executor pins")
	entry := f.String("entry", "", "exact co-signed entry; omit to inspect owner position")
	entryID := f.String("entry-id", "", "independently retained entry ID")
	inventory := f.String("inventory", "", "completion/recovery: canonical inventory")
	inventoryID := f.String("inventory-id", "", "independently retained inventory ID")
	journal := f.String("journal", "", "new admission: original source journal")
	expected := f.String("expected-review-id", "", "exact preceding owned review")
	destination := f.String("out", "", "effect publish only: immutable canonical effect")
	custody := addArchiveCustodyPolicyFlags(f)
	limits := addArchiveCustodyJournalLimitFlags(f)
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	presence := custodyCommandPresence(f)
	if !effect && *mode != "review" && *mode != "apply" && *mode != "resume" && *mode != "resume-executor" {
		return store.ErrScheduledPrune
	}
	if !effect && presence["out"] {
		return store.ErrScheduledPrune
	}
	if effect {
		if err := custodyCommandForbid(presence, "entry", "entry-id", "journal"); err != nil {
			return err
		}
		if *mode != "review" && *mode != "publish" {
			return store.ErrScheduledPrune
		}
	}
	if *mode == "review" {
		if err := custodyCommandForbid(presence, "expected-review-id", "out"); err != nil {
			return err
		}
	}
	c := store.ScheduledPruneCommandConfig{PlanPath: *plan, AuthorityPath: *authority, AuthorityPinsPath: *pins, ExecutorPath: *executor, ExecutorPinsPath: *executorPins, EntryPath: *entry, InventoryPath: *inventory, JournalPath: *journal, JournalLimits: limits.limits()}
	for _, id := range []struct {
		to         *types.Hash
		text, name string
	}{{&c.PlanID, *planID, "plan-id"}, {&c.AssignmentID, *assignment, "assignment-id"}} {
		v, err := pruneExternalID(id.name, id.text)
		if err != nil {
			return err
		}
		*id.to = v
	}
	var reviewID types.Hash
	var err error
	if *expected != "" {
		reviewID, err = pruneExternalID("expected-review-id", *expected)
		if err != nil {
			return err
		}
	}
	if *entry != "" || *entryID != "" {
		c.EntryID, err = pruneExternalID("entry-id", *entryID)
		if err != nil {
			return err
		}
	}
	if *inventory != "" || *inventoryID != "" {
		c.InventoryID, err = pruneExternalID("inventory-id", *inventoryID)
		if err != nil {
			return err
		}
	}
	p, err := store.LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
	if err != nil {
		return err
	}
	s, err := p.Replica(c.AssignmentID)
	if err != nil {
		return err
	}
	if *journal != "" {
		if err := custody.validate(); err != nil {
			return err
		}
		c.CustodyPolicy = workarchive.CustodyPolicy{TrustedAuditors: s.Assignment.Auditors, MaximumChallengeLifetime: *custody.challengeLifetime, MaximumProofAge: *custody.proofAge, MaximumRenewalTerm: *custody.renewalTerm}
	}
	actualMode := *mode
	if effect {
		actualMode = "review"
	}
	actualReview := reviewID
	if effect {
		actualReview = types.Hash{}
	}
	result, err := store.RunScheduledPruneCommand(ctx, c, actualMode, actualReview)
	if err != nil {
		return err
	}
	if effect {
		e := result.Executor
		if e.Stage != store.PruneSucceeded || e.Effect == nil || e.Protection.Pending != nil || c.InventoryID.IsZero() || e.ArchiveInventoryID != c.InventoryID {
			return store.ErrPruneOutcome
		}
		if *mode == "publish" {
			if reviewID.IsZero() || reviewID != result.Review.ReviewID {
				return store.ErrPruneArchiveEffectReview
			}
			if err := scheduledOperatorOutput(*destination, []string{c.PlanPath, c.InventoryPath}, []string{c.AuthorityPath, c.AuthorityPinsPath, c.ExecutorPath, c.ExecutorPinsPath}); err != nil {
				return err
			}
			raw, err := e.Effect.CanonicalBytes()
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := publishImmutableArtifact(*destination, raw); err != nil {
				return err
			}
		}
	}
	var effectID string
	if result.Executor.Effect != nil {
		id, err := result.Executor.Effect.ID()
		if err != nil {
			return err
		}
		effectID = id.String()
	}
	return scheduledOperatorReport(ctx, out, struct {
		store.ScheduledPruneCommandResult
		ReviewID string `json:"review_id"`
		Sequence uint64 `json:"confirmed_sequence"`
		Head     string `json:"confirmed_head"`
		EffectID string `json:"effect_id,omitempty"`
	}{result, result.Review.ReviewID.String(), result.Review.Authority.Confirmed.Sequence, result.Review.Authority.Confirmed.HeadID.String(), effectID})
}

type scheduledPruneAdmissionJSON struct {
	AssignmentID string `json:"assignment_id"`
	Authority    string `json:"authority"`
	Pins         string `json:"authority_pins"`
	Entry        string `json:"entry"`
	EntryID      string `json:"entry_id"`
}

func runScheduledPruneInventoryCLI(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet(scheduledInventoryCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review or publish")
	plan := f.String("plan", "", "canonical plan")
	planID := f.String("plan-id", "", "independently retained plan ID")
	executor := f.String("executor", "", "existing executor")
	pins := f.String("executor-pins", "", "original executor pins")
	sources := f.String("sources", "", "strict original owner/admission source list")
	expected := f.String("expected-inventory-id", "", "publish: exact reviewed inventory ID")
	destination := f.String("out", "", "publish: immutable inventory")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	if *mode != "review" && *mode != "publish" {
		return store.ErrScheduledPrune
	}
	if *mode == "review" {
		if err := custodyCommandForbid(custodyCommandPresence(f), "out", "expected-inventory-id"); err != nil {
			return err
		}
	}
	c := store.ScheduledPrunePackageConfig{PlanPath: *plan, ExecutorPath: *executor, ExecutorPinsPath: *pins}
	var err error
	c.PlanID, err = pruneExternalID("plan-id", *planID)
	if err != nil {
		return err
	}
	raw, err := readRegularArtifact(*sources, 1<<20)
	if err != nil {
		return err
	}
	var input []scheduledPruneAdmissionJSON
	if err := cutoverJSON(raw, &input); err != nil {
		return err
	}
	if len(input) < 2 || len(input) > workarchive.MaximumReplicas {
		return store.ErrScheduledPrune
	}
	for _, s := range input {
		aid, err := pruneExternalID("assignment-id", s.AssignmentID)
		if err != nil {
			return err
		}
		eid, err := pruneExternalID("entry-id", s.EntryID)
		if err != nil {
			return err
		}
		c.Sources = append(c.Sources, store.ScheduledPruneAdmissionSource{AssignmentID: aid, AuthorityPath: s.Authority, AuthorityPinsPath: s.Pins, EntryPath: s.Entry, EntryID: eid})
	}
	var expectedID types.Hash
	if *mode == "publish" {
		expectedID, err = pruneExternalID("expected-inventory-id", *expected)
		if err != nil {
			return err
		}
		if *destination == "" || workarchive.CustodyEvidencePathsOverlap(*destination, *sources) {
			return store.ErrRootOverlap
		}
	}
	v, err := store.PackageScheduledPruneInventory(ctx, c, *destination, expectedID)
	if err != nil {
		return err
	}
	id, _ := v.ID()
	return scheduledOperatorReport(ctx, out, struct {
		InventoryID     types.Hash
		Inventory       store.ScheduledPruneInventory
		Published       bool
		InventoryIDText string `json:"inventory_id"`
	}{id, v, *mode == "publish", id.String()})
}
