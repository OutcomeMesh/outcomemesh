package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func scheduledCLIRun(t testing.TB, args []string, result any) {
	t.Helper()
	var out bytes.Buffer
	if err := runScheduledPruneOperator(t.Context(), args, &out); err != nil {
		t.Fatalf("%s: %v", args[0], err)
	}
	if result != nil {
		if err := json.Unmarshal(out.Bytes(), result); err != nil {
			t.Fatal(err)
		}
	}
}
func scheduledCLISign(t testing.TB, args []string) (string, types.Hash) {
	t.Helper()
	root := t.TempDir()
	consumerKey, authorityKey := filepath.Join(root, "consumer.seed"), filepath.Join(root, "authority.seed")
	writePruneCLIFile(t, consumerKey, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, authorityKey, pruneCLIKey(1).Seed())
	var report struct{ ReviewID, EntryID types.Hash }
	command := filepath.Join(root, "command")
	entry := filepath.Join(root, "entry")
	sign := append([]string{scheduledSignCommand}, args...)
	scheduledCLIRun(t, sign, &report)
	scheduledCLIRun(t, append(sign, "--mode", "sign", "--expected-review-id", report.ReviewID.String(), "--consumer-key", consumerKey, "--out", command), &report)
	cosign := append(append([]string{scheduledCosignCommand}, args...), "--command", command)
	scheduledCLIRun(t, cosign, &report)
	scheduledCLIRun(t, append(cosign, "--mode", "sign", "--expected-review-id", report.ReviewID.String(), "--authority-key", authorityKey, "--out", entry), &report)
	return entry, report.EntryID
}

func TestScheduledPruneOperatorCLIEntireLifecyclePreservesAccounting(t *testing.T) {
	scheduledPruneCLILifecycle(t, false)
}
func TestPruneScheduledOutcomeCLICancellationLifecycle(t *testing.T) {
	scheduledPruneCLILifecycle(t, true)
}
func scheduledPruneCLILifecycle(t *testing.T, cancelBeforeStart bool) {
	f, cp, cpPath, sources := prepareCustodyScheduleQuorumCLI(t)
	policy := f.inventory.Policy
	chain, err := workchain.OpenPositionPinnedWithPolicy(f.config.ChainPath, f.config.ChainPinsPath, f.config.Base, f.config.Parameters, f.config.StoragePolicy, f.inventory.Request.StorageID)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := chain.ReviewRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.MigrateRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight, migration.ID()); err != nil {
		t.Fatal(err)
	}
	protection, err := chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Close(); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(t.TempDir(), "quorum.json")
	raw, _ := json.Marshal(sources)
	writePruneCLIFile(t, sourcePath, raw)
	keys := func(keys [][32]byte) string {
		var a []string
		for _, k := range keys {
			a = append(a, hex.EncodeToString(k[:]))
		}
		return strings.Join(a, ",")
	}
	cpID, _ := cp.Statement.ID()
	planArgs := []string{scheduledPlanCommand, "--sources", sourcePath, "--checkpoint", cpPath, "--checkpoint-id", cpID.String(), "--attestors", keys(policy.CheckpointPolicy.TrustedAttestors), "--replicas", keys(policy.ReplicaPolicy.TrustedReplicas), "--max-receipt-age-seconds", "1000", "--min-remaining-term-seconds", "100", "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000", "--primary-assignment-id", sources[0].AssignmentID, "--storage-id", protection.StorageID.String(), "--storage-pair-id", protection.PairID.String(), "--consumer-public-key", hex.EncodeToString(f.inventory.Request.ConsumerPublicKey[:]), "--verified-at", strconv.FormatUint(f.inventory.Request.Boundary.VerifiedAt, 10)}
	var prepared struct {
		PlanID, RequestID types.Hash
		Plan              store.ScheduledPrunePlan
		Published         bool
	}
	scheduledCLIRun(t, planArgs, &prepared)
	operatorRoot := t.TempDir()
	planPath, requestPath := filepath.Join(operatorRoot, "plan"), filepath.Join(operatorRoot, "request")
	publishPlan := append(append([]string(nil), planArgs...), "--mode", "publish", "--expected-plan-id", prepared.PlanID.String(), "--out", planPath, "--request-out", requestPath)
	partial := append([]string(nil), publishPlan...)
	partial[len(partial)-1] = filepath.Join(t.TempDir(), "occupied-request")
	writePruneCLIFile(t, partial[len(partial)-1], []byte("retained different request"))
	if err := runScheduledPruneOperator(t.Context(), partial, io.Discard); err == nil {
		t.Fatal("request publication replaced retained bytes")
	}
	if _, err := store.LoadScheduledPrunePlan(planPath, prepared.PlanID); err != nil {
		t.Fatal("partial publication lost retained plan", err)
	}
	if err := runScheduledPruneOperator(t.Context(), publishPlan, pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("plan lost output", err)
	}
	scheduledCLIRun(t, publishPlan, &prepared)
	executor, pins := filepath.Join(t.TempDir(), "executor"), filepath.Join(t.TempDir(), "pins")
	if err := runPruneBootstrap(t.Context(), []string{pruneExecutorPrepareCommand, "--mode", "create", "--assignment", sources[0].Assignment, "--assignment-id", sources[0].AssignmentID, "--request", requestPath, "--request-id", prepared.RequestID.String(), "--executor", executor, "--executor-pins", pins}, io.Discard); err != nil {
		t.Fatal(err)
	}
	common := func(s custodyScheduleQuorumSource) []string {
		return []string{"--plan", planPath, "--plan-id", prepared.PlanID.String(), "--assignment-id", s.AssignmentID, "--authority", s.Authority, "--authority-pins", s.Pins, "--executor", executor, "--executor-pins", pins}
	}
	inspect := func(args []string) store.ScheduledPruneCommandResult {
		t.Helper()
		var r store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append([]string{scheduledApplyCommand}, args...), &r)
		return r
	}
	var admissions []scheduledPruneAdmissionJSON
	var executionSources []scheduledPruneCLISource
	originalOwners := make(map[string]store.Coordination)
	for i, s := range sources {
		before := inspect(common(s))
		originalOwners[s.AssignmentID] = before.Review.Authority
		if before.Review.Authority.Authority.Pending != 1 {
			t.Fatal("fixture lost old pending work")
		}
		signArgs := []string{"--plan", planPath, "--plan-id", prepared.PlanID.String(), "--assignment-id", s.AssignmentID, "--kind", "admit", "--expected-sequence", strconv.FormatUint(before.Review.Authority.Confirmed.Sequence, 10), "--expected-head", before.Review.Authority.Confirmed.HeadID.String()}
		entry, eid := scheduledCLISign(t, signArgs)
		args := append(common(s), "--entry", entry, "--entry-id", eid.String(), "--journal", s.Journal, "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000")
		review := inspect(args)
		var applied store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append(append([]string{scheduledApplyCommand}, args...), "--mode", "apply", "--expected-review-id", review.Review.ReviewID.String()), &applied)
		if applied.Commit == nil || !applied.Commit.Appended || applied.Commit.Snapshot.Pending != 2 {
			t.Fatal("admission reset original pending work")
		}
		retry := inspect(args)
		scheduledCLIRun(t, append(append([]string{scheduledApplyCommand}, args...), "--mode", "apply", "--expected-review-id", retry.Review.ReviewID.String()), &applied)
		if applied.Commit.Appended || applied.Commit.Snapshot.Pending != 2 {
			t.Fatal("retry spent capacity twice")
		}
		admissions = append(admissions, scheduledPruneAdmissionJSON{AssignmentID: s.AssignmentID, Authority: s.Authority, Pins: s.Pins, Entry: entry, EntryID: eid.String()})
		directory := filepath.Join(t.TempDir(), "target")
		if _, _, err := workarchive.MigrateRadixArchiveDirectory(f.config.Replicas[i].Directory, directory, policy.Checkpoint, cp, policy.CheckpointPolicy, f.config.Base, f.config.Parameters, workarchive.DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		executionSources = append(executionSources, scheduledPruneCLISource{AssignmentID: s.AssignmentID, Authority: s.Authority, Pins: s.Pins, Journal: s.Journal, Directory: directory})
	}
	admissionPath := filepath.Join(t.TempDir(), "admissions.json")
	raw, _ = json.Marshal(admissions)
	writePruneCLIFile(t, admissionPath, raw)
	inventoryArgs := []string{scheduledInventoryCommand, "--plan", planPath, "--plan-id", prepared.PlanID.String(), "--executor", executor, "--executor-pins", pins, "--sources", admissionPath}
	var packaged struct {
		InventoryID types.Hash
		Inventory   store.ScheduledPruneInventory
	}
	scheduledCLIRun(t, inventoryArgs, &packaged)
	inventoryPath := filepath.Join(operatorRoot, "inventory")
	scheduledCLIRun(t, append(inventoryArgs, "--mode", "publish", "--expected-inventory-id", packaged.InventoryID.String(), "--out", inventoryPath), &packaged)
	paths := filepath.Join(t.TempDir(), "execution.json")
	raw, _ = json.Marshal(executionSources)
	writePruneCLIFile(t, paths, raw)
	executeArgs := []string{"--inventory", inventoryPath, "--inventory-id", packaged.InventoryID.String(), "--data", f.data, "--sources", paths, "--executor", executor, "--executor-pins", pins, "--chain", f.config.ChainPath, "--chain-pins", f.config.ChainPinsPath, "--storage-migration-id", migration.ID().String(), "--canonical-retention", strconv.FormatUint(f.config.StoragePolicy.CanonicalRetention, 10), "--max-history-bytes", strconv.FormatUint(f.config.StoragePolicy.MaxHistoryBytes, 10), "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000"}
	outcomeArgs := append(append([]string{scheduledOutcomeCommand}, common(sources[0])...), "--inventory", inventoryPath, "--inventory-id", packaged.InventoryID.String())
	var outcomeReview store.ScheduledPruneCommandResult
	if cancelBeforeStart {
		scheduledCLIRun(t, outcomeArgs, &outcomeReview)
		// A lost response must retain exactly one cancellation and all tickets.
		fail := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
		if err := runScheduledPruneOperator(t.Context(), append(outcomeArgs, "--mode", "cancel-before-start", "--expected-review-id", outcomeReview.Review.ReviewID.String()), fail); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("cancel lost output", err)
		}
		scheduledCLIRun(t, outcomeArgs, &outcomeReview)
		if outcomeReview.Executor.Stage != store.PruneCancelled || outcomeReview.Review.Authority.Authority.Pending != 2 {
			t.Fatal("cancellation cleared tickets")
		}
		var cancelledReview bytes.Buffer
		if err := runScheduledPrune(t.Context(), executeArgs, &cancelledReview); err != nil {
			t.Fatal(err)
		}
		var reviewed store.ScheduledPruneRuntimeResult
		if err := json.Unmarshal(cancelledReview.Bytes(), &reviewed); err != nil {
			t.Fatal(err)
		}
		if err := runScheduledPrune(t.Context(), append(executeArgs, "--mode", "execute", "--expected-review-id", reviewed.Review.ReviewID.String()), io.Discard); err == nil {
			t.Fatal("cancelled task could be executed")
		}
	} else {
		var out bytes.Buffer
		if err := runScheduledPrune(t.Context(), executeArgs, &out); err != nil {
			t.Fatal(err)
		}
		var executeReview store.ScheduledPruneRuntimeResult
		if err := json.Unmarshal(out.Bytes(), &executeReview); err != nil {
			t.Fatal(err)
		}
		if err := runScheduledPrune(t.Context(), append(executeArgs, "--mode", "execute", "--expected-review-id", executeReview.Review.ReviewID.String()), io.Discard); err != nil {
			t.Fatal(err)
		}
		// Preserve the existing effect-only command and its output bytes.
		legacy := append([]string{scheduledEffectCommand}, outcomeArgs[1:]...)
		scheduledCLIRun(t, legacy, &outcomeReview)
	}
	for _, source := range executionSources {
		for _, path := range []string{source.Directory, source.Journal} {
			if err := os.Rename(path, path+".offline"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !cancelBeforeStart {
		recovery := append(append([]string(nil), outcomeArgs...), "--data", f.data, "--chain", f.config.ChainPath, "--chain-pins", f.config.ChainPinsPath, "--storage-migration-id", migration.ID().String(), "--canonical-retention", strconv.FormatUint(f.config.StoragePolicy.CanonicalRetention, 10), "--max-history-bytes", strconv.FormatUint(f.config.StoragePolicy.MaxHistoryBytes, 10))
		scheduledCLIRun(t, recovery, &outcomeReview)
		var recovered store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append(recovery, "--mode", "recover-effect", "--expected-review-id", outcomeReview.Review.ReviewID.String()), &recovered)
		if recovered.Recovered == nil || recovered.Recovered.Applied {
			t.Fatal("recovery repeated deletion")
		}
	}
	scheduledCLIRun(t, outcomeArgs, &outcomeReview)
	outcome, err := store.RetainedScheduledPruneOutcome(packaged.Inventory, outcomeReview.Executor)
	if err != nil {
		t.Fatal(err)
	}
	effectID, _ := outcome.EvidenceID(packaged.Inventory)
	effectPath := filepath.Join(operatorRoot, "outcome")
	publishEffect := append(append([]string(nil), outcomeArgs...), "--mode", "publish", "--expected-review-id", outcomeReview.Review.ReviewID.String(), "--out", effectPath)
	failedOutput := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runScheduledPruneOperator(t.Context(), publishEffect, failedOutput); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("outcome lost output", err)
	}
	scheduledCLIRun(t, publishEffect, nil)
	evidenceFlag, idFlag := "--effect", "--effect-id"
	if cancelBeforeStart {
		evidenceFlag, idFlag = "--cancellation", "--cancellation-id"
	}
	for _, extra := range [][]string{
		{"--mode", "review", "--out", filepath.Join(t.TempDir(), "ignored")},
		{"--mode", "publish", "--expected-review-id", pruneCLIHash(240).String(), "--out", filepath.Join(t.TempDir(), "wrong-review")},
		{"--mode", "publish", "--expected-review-id", outcomeReview.Review.ReviewID.String(), "--out", inventoryPath},
		{"--mode", "publish", "--expected-review-id", outcomeReview.Review.ReviewID.String(), "--out", filepath.Join(executor, "overlap")},
		{"--max-history-bytes", "1"},
		{"--mode", "recover-effect", "--expected-review-id", outcomeReview.Review.ReviewID.String()},
	} {
		if err := runScheduledPruneOperator(t.Context(), append(append([]string(nil), outcomeArgs...), extra...), io.Discard); err == nil {
			t.Fatal("accepted invalid outcome flags", extra)
		}
	}
	wrongCommand := append([]string{scheduledApplyCommand}, outcomeArgs[1:]...)
	if err := runScheduledPruneOperator(t.Context(), append(wrongCommand, "--mode", "cancel-before-start", "--expected-review-id", outcomeReview.Review.ReviewID.String()), io.Discard); err == nil {
		t.Fatal("command acceptance silently selected an outcome action")
	}
	for _, s := range sources {
		args := append(common(s), "--inventory", inventoryPath, "--inventory-id", packaged.InventoryID.String())
		before := inspect(args)
		entry, eid := scheduledCLISign(t, []string{"--plan", planPath, "--plan-id", prepared.PlanID.String(), "--assignment-id", s.AssignmentID, "--kind", "complete", "--expected-sequence", strconv.FormatUint(before.Review.Authority.Confirmed.Sequence, 10), "--expected-head", before.Review.Authority.Confirmed.HeadID.String(), "--inventory", inventoryPath, "--inventory-id", packaged.InventoryID.String(), evidenceFlag, effectPath, idFlag, effectID.String()})
		args = append(args, "--entry", entry, "--entry-id", eid.String())
		review := inspect(args)
		appliedArgs := append(append([]string{scheduledApplyCommand}, args...), "--mode", "apply", "--expected-review-id", review.Review.ReviewID.String())
		if err := runScheduledPruneOperator(t.Context(), appliedArgs, failedOutput); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("completion lost output", err)
		}
		after := inspect(args)
		if after.Review.Authority.Authority.Pending != 1 || len(after.Review.Authority.Authority.Operations) != 2 || !after.Review.AlreadyApplied {
			t.Fatal("completion erased original work")
		}
		for _, old := range originalOwners[s.AssignmentID].Authority.Operations {
			found := false
			for _, retained := range after.Review.Authority.Authority.Operations {
				if reflect.DeepEqual(old, retained) {
					found = true
				}
			}
			if !found {
				t.Fatal("old operation identity or evidence changed")
			}
		}
		var retried store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append(append([]string{scheduledApplyCommand}, args...), "--mode", "apply", "--expected-review-id", after.Review.ReviewID.String()), &retried)
		if retried.Commit.Appended || !reflect.DeepEqual(after.Review.Authority.Authority, retried.Commit.Snapshot) {
			t.Fatal("completion retry changed accounting")
		}
	}
}
