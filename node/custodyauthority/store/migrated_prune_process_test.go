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

func TestProcessPruneMigratedRecovery(t *testing.T) {
	cases := []struct{ mode, stage string }{{"cancel-before-start", "pins-cancel-intent-after-publish"}, {"cancel-before-start", "pins-cancel-confirm-before-publish"}, {"apply", "intent-after-publish"}, {"apply", "authority-after-publish"}, {"apply", "confirm-before-publish"}, {"recover-effect", "migrated-prune-before-recovery"}, {"recover-effect", "pins-result-intent-after-publish"}, {"recover-effect", "pins-result-confirm-before-publish"}}
	for _, test := range cases {
		t.Run(test.mode+"/"+test.stage, func(t *testing.T) {
			outcome := "success"
			if test.mode == "recover-effect" {
				outcome = "prune-after-effect"
			}
			if test.mode == "cancel-before-start" {
				outcome = "admitted"
			}
			_, configs := migratedPruneFixture(t, outcome)
			c := configs[0]
			if test.mode == "apply" {
				c = migratedPruneCompletionConfig(t, configs[1])
			}
			if test.mode == "cancel-before-start" {
				c.Storage = nil
			}
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
			child := exec.Command(os.Args[0], "-test.run=^TestProcessPruneMigratedHelper$", "-test.count=1")
			child.Env = append(os.Environ(), "OM_MIGRATED_PRUNE_CONFIG="+path, "OM_MIGRATED_PRUNE_MODE="+test.mode, "OM_MIGRATED_PRUNE_STAGE="+test.stage, "OM_MIGRATED_PRUNE_MARKER="+marker)
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
					t.Fatal("child missed publication boundary")
				case <-tick.C:
				}
			}
			if _, err := RunMigratedPrune(t.Context(), c, "review", types.Hash{}); err == nil {
				t.Fatal("concurrent process acquired original owners")
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("child survived SIGKILL")
			}
			r := migratedPruneReview(t, c)
			if test.mode == "apply" {
				if r.Review.Authority.Pending == nil {
					t.Fatal("missing durable authority intent")
				}
				result, err := RunMigratedPrune(t.Context(), c, "resume", r.Review.ReviewID)
				if err != nil || result.Commit.Snapshot.Pending != 0 || len(result.Commit.Snapshot.Operations) != 1 {
					t.Fatal("cold completion", err)
				}
			} else {
				if r.Review.Authority.Authority.Pending != 1 {
					t.Fatal("recovery erased pending obligation")
				}
				if r.Executor.Protection.Pending != nil {
					bare := c
					bare.Storage = nil
					pending := migratedPruneReview(t, bare)
					if _, err := RunMigratedPrune(t.Context(), bare, "resume-executor", pending.Review.ReviewID); err != nil {
						t.Fatal(err)
					}
					r = migratedPruneReview(t, c)
				}
				if test.mode == "cancel-before-start" {
					if r.Executor.Stage != PruneCancelled || r.Review.Authority.Authority.Pending != 1 {
						t.Fatal("cold cancellation reset accounting")
					}
					return
				}
				result, err := RunMigratedPrune(t.Context(), c, "recover-effect", r.Review.ReviewID)
				if err != nil || result.Recovered.Applied || result.Executor.Stage != PruneSucceeded {
					t.Fatal("cold exact effect recovery", err)
				}
			}
		})
	}
}
func TestProcessPruneMigratedHelper(t *testing.T) {
	path := os.Getenv("OM_MIGRATED_PRUNE_CONFIG")
	if path == "" {
		t.Skip("subprocess only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c MigratedPruneConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Storage != nil {
		c.Storage.Base, _, _ = pruneChainConfig()
	}
	r := migratedPruneReview(t, c)
	hooks := storeHooks{at: func(stage string) error {
		if stage == os.Getenv("OM_MIGRATED_PRUNE_STAGE") {
			if err := os.WriteFile(os.Getenv("OM_MIGRATED_PRUNE_MARKER"), []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}}
	if os.Getenv("OM_MIGRATED_PRUNE_MODE") == "observe" {
		_, err = runMigratedPruneOwned(t.Context(), c, "review", types.Hash{}, hooks, true)
	} else {
		_, err = runMigratedPrune(t.Context(), c, os.Getenv("OM_MIGRATED_PRUNE_MODE"), r.Review.ReviewID, hooks)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("escaped process boundary")
}

func TestProcessPruneMigratedObservation(t *testing.T) {
	for _, outcome := range []string{"prune-before-effect", "prune-after-effect"} {
		for _, boundary := range []string{"prune-observation-before-read", "prune-observation-after-read"} {
			t.Run(outcome+"/"+boundary, func(t *testing.T) {
				_, configs := migratedPruneFixture(t, outcome)
				c := configs[0]
				before := migratedPruneReview(t, c)
				disk := c
				s := *c.Storage
				s.Base = workchain.Base{}
				disk.Storage = &s
				raw, err := json.Marshal(disk)
				if err != nil {
					t.Fatal(err)
				}
				path, marker := filepath.Join(t.TempDir(), "config"), filepath.Join(t.TempDir(), "reached")
				writeTestFile(t, path, raw)
				child := exec.Command(os.Args[0], "-test.run=^TestProcessPruneMigratedHelper$", "-test.count=1")
				child.Env = append(os.Environ(), "OM_MIGRATED_PRUNE_CONFIG="+path, "OM_MIGRATED_PRUNE_MODE=observe", "OM_MIGRATED_PRUNE_STAGE="+boundary, "OM_MIGRATED_PRUNE_MARKER="+marker)
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
						t.Fatal("child missed inspection boundary")
					case <-tick.C:
					}
				}
				if _, err := InspectMigratedPrune(t.Context(), c); err == nil {
					t.Fatal("second process acquired original owners")
				}
				if err := child.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err == nil {
					t.Fatal("child survived SIGKILL")
				}
				if after := migratedPruneReview(t, c); !reflect.DeepEqual(before, after) {
					t.Fatal("inspection kill changed obligations or storage")
				}
				observed, err := InspectMigratedPrune(t.Context(), c)
				if err != nil || observed.Observation == nil || observed.Executor.Stage != PruneStarted || (observed.Observation.Effect != nil) != (outcome == "prune-after-effect") {
					t.Fatal("cold inspection failed", err)
				}
			})
		}
	}
}
