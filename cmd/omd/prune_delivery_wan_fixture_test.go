//go:build integration && (linux || darwin)

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// This explicit subprocess fixture keeps all original owners on this host. It
// pauses before delivery, while production CLI processes own the journals. Exit
// deliberately retains test roots, including on failure, for later inspection.
// No fixture hooks or fault controls are linked into the production binary.
func TestProcessPruneWANFixture(t *testing.T) {
	configPath := os.Getenv("OMESH_REMOTE_GATE_ARGS")
	if configPath == "" {
		t.Skip("explicit two-host fixture")
	}
	var cfg struct{ Root, Scenario string }
	raw, err := readRegularArtifact(configPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	root, err := managedCustodyCanonicalDirectory(cfg.Root)
	if err != nil || (cfg.Scenario != "cancellation" && cfg.Scenario != "settlement") {
		t.Fatal("invalid private fixture placement/scenario", err)
	}
	tmp := filepath.Join(root, "originals")
	if err := os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	// The test harness would otherwise delete originals at process exit. This
	// helper runs alone; every network child is supervised by the external runner.
	defer func() {
		if t.Failed() {
			os.Exit(1)
		}
		os.Exit(0)
	}()
	t.Setenv("TMPDIR", tmp)
	serverKey := filepath.Join(root, "server.seed")
	writePruneCLIFile(t, serverKey, pruneCLIKey(45).Seed())
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 96), 96)
	step, complete := 0, 0
	callback := func(t *testing.T, args []string, review store.ScheduledPruneCommandResult) {
		v := map[string]string{}
		for n := 0; n < len(args); n += 2 {
			v[args[n]] = args[n+1]
		}
		pid, err := pruneExternalID("plan-id", v["--plan-id"])
		if err != nil {
			t.Fatal(err)
		}
		aid, err := pruneExternalID("assignment-id", v["--assignment-id"])
		if err != nil {
			t.Fatal(err)
		}
		plan, err := store.LoadScheduledPrunePlan(v["--plan"], pid)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := plan.Replica(aid)
		if err != nil {
			t.Fatal(err)
		}
		entryBytes, err := readRegularArtifact(v["--entry"], custodyauthority.MaximumEntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.DecodeEntry(entryBytes)
		if err != nil {
			t.Fatal(err)
		}
		assignment := filepath.Join(root, fmt.Sprintf("assignment-%d", step))
		aRaw, _ := selected.Assignment.CanonicalBytes()
		writePruneCLIFile(t, assignment, aRaw)
		rid, _ := plan.Request.ID()
		kind := "admit"
		if entry.Command.Kind == custodyauthority.Complete {
			kind = "complete"
			complete++
			if cfg.Scenario == "settlement" {
				if review.Executor.FenceSettlement == nil {
					t.Fatal("missing full settlement")
				}
				id, _ := review.Executor.FenceSettlement.ID()
				if entry.Command.EvidenceID != id {
					t.Fatal("completion downgraded settlement evidence")
				}
			}
		}
		c := store.ScheduledPruneCommandConfig{PlanPath: v["--plan"], PlanID: pid, AssignmentID: aid, EntryPath: v["--entry"], AuthorityPath: v["--authority"], AuthorityPinsPath: v["--authority-pins"], ExecutorPath: v["--executor"], ExecutorPinsPath: v["--executor-pins"], JournalPath: v["--journal"], InventoryPath: v["--inventory"], JournalLimits: workarchive.DefaultCustodyJournalLimits()}
		c.EntryID, _ = entry.ID()
		if c.InventoryPath != "" {
			c.InventoryID, err = pruneExternalID("inventory-id", v["--inventory-id"])
			if err != nil {
				t.Fatal(err)
			}
		}
		if c.JournalPath != "" {
			parse := func(name string) uint64 {
				n, e := strconv.ParseUint(v[name], 10, 64)
				if e != nil {
					t.Fatal(e)
				}
				return n
			}
			c.CustodyPolicy = workarchive.CustodyPolicy{TrustedAuditors: selected.Assignment.Auditors, MaximumChallengeLifetime: parse("--max-challenge-lifetime-seconds"), MaximumProofAge: parse("--max-proof-age-seconds"), MaximumRenewalTerm: parse("--max-renewal-term-seconds")}
		}
		meta := map[string]any{"step": step, "scenario": cfg.Scenario, "kind": kind, "owner_args": args, "command": c, "assignment": assignment, "assignment_id": aid.String(), "request_id": rid.String(), "executor_binding_id": review.Executor.Protection.BindingID.String(), "receiver_review_id": review.Review.ReviewID.String(), "client_peer_id": pruneCLIPeer(46).String(), "server_peer_id": pruneCLIPeer(45).String(), "server_key": serverKey, "evidence_id": entry.Command.EvidenceID.String(), "ticket_id": entry.Command.TicketID.String(), "before": review}
		line, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("prune_wan_step %s\n", line)
		if !input.Scan() || input.Text() != fmt.Sprintf("continue %d", step) {
			t.Fatal("missing exact fixture continuation", input.Err())
		}
		var after store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append([]string{scheduledApplyCommand}, args...), &after)
		if !after.Review.AlreadyApplied {
			t.Fatal("runner continued before original confirmation")
		}
		step++
	}
	if cfg.Scenario == "cancellation" {
		scheduledPruneCLILifecycleWithDelivery(t, true, callback)
	} else {
		scheduledPruneCLILifecycleWithDelivery(t, false, callback, true, false, true)
	}
	if step != 4 || complete != 2 {
		t.Fatal("fixture did not complete both original tickets", step, complete)
	}
	fmt.Printf("prune_wan_done %s\n", cfg.Scenario)
}
