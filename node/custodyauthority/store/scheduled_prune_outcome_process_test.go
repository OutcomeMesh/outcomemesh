//go:build integration

package store

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestProcessPruneScheduledOutcomes(t *testing.T) {
	for _, tc := range []struct{ mode, stage string }{
		{"settle-effect", "prune-settlement-before-retain"},
		{"settle-effect", "pins-result-intent-after-publish"},
		{"settle-effect", "prune-result-after-publish"},
		{"settle-effect", "pins-result-confirm-before-publish"},
		{"apply-settled", "intent-after-publish"},
		{"apply-settled", "authority-after-publish"},
		{"apply-settled", "confirm-before-publish"},
		{"cancel-before-start", "pins-cancel-intent-after-publish"},
		{"cancel-before-start", "pins-cancel-confirm-before-publish"},
		{"cancel-with-closure", "pins-cancel-intent-after-publish"},
		{"cancel-with-closure", "prune-cancel-after-publish"},
		{"cancel-with-closure", "pins-cancel-confirm-before-publish"},
		{"apply-certified", "intent-after-publish"},
		{"apply-certified", "authority-after-publish"},
		{"apply-certified", "confirm-before-publish"},
		{"recover-effect", "scheduled-prune-before-recovery"},
		{"recover-effect", "pins-result-intent-after-publish"},
		{"recover-effect", "pins-result-confirm-before-publish"},
		{"apply", "intent-after-publish"},
		{"apply", "authority-after-publish"},
		{"apply", "confirm-before-publish"},
	} {
		t.Run(tc.mode+"/"+tc.stage, func(t *testing.T) {
			mode := tc.mode
			if mode == "apply-certified" || mode == "apply-settled" {
				mode = "apply"
			}
			outcome := "admitted"
			if tc.mode == "recover-effect" {
				outcome = "prune-after-effect"
			}
			var configs []ScheduledPruneCommandConfig
			if tc.mode == "settle-effect" || tc.mode == "apply-settled" {
				_, configs = observedOutcomeFixture(t)
			} else if tc.mode == "cancel-with-closure" || tc.mode == "apply-certified" {
				_, configs = certifiedOutcomeFixture(t)
			} else {
				_, configs = scheduledOutcomeFixture(t, outcome)
			}
			c := configs[0]
			if tc.mode != "recover-effect" && tc.mode != "settle-effect" && tc.mode != "apply-settled" {
				c.Storage = nil
			}
			if mode == "apply" {
				r := scheduledOperatorReview(t, c)
				cancelMode := "cancel-before-start"
				if tc.mode == "apply-certified" {
					cancelMode = "cancel-with-closure"
				}
				if tc.mode == "apply-settled" {
					cancelMode = "settle-effect"
				}
				if _, err := RunScheduledPruneCommand(t.Context(), c, cancelMode, r.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
				c = scheduledOutcomeCompletion(t, configs[1])
			}
			before := scheduledOperatorReview(t, c)
			disk := c
			if c.Storage != nil {
				s := *c.Storage
				s.Base = workchain.Base{}
				disk.Storage = &s
			}
			raw, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			path, marker := filepath.Join(t.TempDir(), "config"), filepath.Join(t.TempDir(), "reached")
			writeTestFile(t, path, raw)
			child := exec.Command(os.Args[0], "-test.run=^TestProcessScheduledPruneOperatorHelper$", "-test.count=1")
			child.Env = append(os.Environ(), "OM_PRUNE_OPERATOR_CONFIG="+path, "OM_PRUNE_OPERATOR_MODE="+mode, "OM_PRUNE_OPERATOR_STAGE="+tc.stage, "OM_PRUNE_OPERATOR_MARKER="+marker)
			var output bytes.Buffer
			child.Stdout, child.Stderr = &output, &output
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			t.Cleanup(func() { _ = child.Process.Kill() })
			deadline := time.NewTimer(20 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
		wait:
			for {
				if _, err := os.Stat(marker); err == nil {
					break wait
				}
				select {
				case err := <-done:
					t.Fatal("child stopped early", err, output.String())
				case <-deadline.C:
					t.Fatal("child missed boundary")
				case <-tick.C:
				}
			}
			if _, err := RunScheduledPruneCommand(t.Context(), c, "review", types.Hash{}); err == nil {
				t.Fatal("concurrent process acquired owner")
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("child survived kill")
			}
			coldConfig := c
			if mode == "settle-effect" {
				coldConfig = withoutPruneSettlement(c)
			}
			cold := scheduledOperatorReview(t, coldConfig)
			if !reflect.DeepEqual(cold, scheduledOperatorReview(t, coldConfig)) {
				t.Fatal("review changed pending outcome")
			}
			if mode == "apply" {
				r, err := RunScheduledPruneCommand(t.Context(), c, "resume", cold.Review.ReviewID)
				if err != nil || r.Commit == nil || r.Commit.Snapshot.Pending != before.Review.Authority.Authority.Pending-1 {
					t.Fatal("completion recovery", err)
				}
				if r := scheduledOperatorApply(t, c); r.Commit.Appended {
					t.Fatal("completion applied twice")
				}
				return
			}
			if !reflect.DeepEqual(before.Review.Authority, cold.Review.Authority) || !reflect.DeepEqual(before.Review.Storage, cold.Review.Storage) {
				t.Fatal("outcome recovery changed obligations or storage")
			}
			if cold.Executor.Protection.Pending != nil {
				resume := withoutPruneSettlement(withoutPruneClosure(c))
				resume.Storage = nil
				rr := scheduledOperatorReview(t, resume)
				if _, err := RunScheduledPruneCommand(t.Context(), resume, "resume-executor", rr.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
			}
			stable := scheduledOperatorReview(t, c)
			r, err := RunScheduledPruneCommand(t.Context(), c, mode, stable.Review.ReviewID)
			if err != nil {
				t.Fatal("cold outcome recovery", err)
			}
			if mode == "settle-effect" && (r.Executor.FenceSettlement == nil || r.Executor.FenceResult != nil || r.Executor.Stage != PruneSucceeded) {
				t.Fatal("lost settlement or fabricated signature")
			}
			if tc.mode == "recover-effect" && (r.Recovered == nil || r.Recovered.Applied || r.Executor.Stage != PruneSucceeded) {
				t.Fatal("repeated deletion")
			}
			if (mode == "cancel-before-start" || mode == "cancel-with-closure") && r.Executor.Stage != PruneCancelled {
				t.Fatal("lost cancellation")
			}
		})
	}
}
