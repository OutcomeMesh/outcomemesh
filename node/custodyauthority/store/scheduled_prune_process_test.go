//go:build integration

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestCustodyScheduledPruneProcessCrashRecovery(t *testing.T) {
	for _, stage := range []string{"scheduled-prune-before-start", "prune-before-effect", "prune-after-effect"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneFixture(t)
			c := f.runtimeConfig(t)
			disk := c
			disk.Base = workchain.Base{}
			raw, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			file, marker := filepath.Join(t.TempDir(), "config.json"), filepath.Join(t.TempDir(), "reached")
			writeTestFile(t, file, raw)
			child := exec.Command(os.Args[0], "-test.run=^TestCustodyScheduledPruneCrashHelper$", "-test.count=1")
			child.Env = append(os.Environ(), "OM_SCHEDULED_PRUNE_FIXTURE="+file, "OM_SCHEDULED_PRUNE_STAGE="+stage, "OM_SCHEDULED_PRUNE_MARKER="+marker)
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
					t.Fatal("child stopped before durable boundary", err, output.String())
				case <-deadline.C:
					t.Fatal("child did not reach durable boundary", output.String())
				case <-tick.C:
				}
			}
			if _, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{}); err == nil {
				t.Fatal("second process acquired active owners")
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("child survived SIGKILL")
			}
			review, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
			if err != nil {
				t.Fatal("cold review", err)
			}
			for _, a := range review.Review.Authorities {
				if a.Authority.Pending != 2 {
					t.Fatal("crash discarded obligations")
				}
			}
			if stage == "scheduled-prune-before-start" {
				if review.Review.Executor.Stage != PruneAdmitted {
					t.Fatal("unstarted operation consumed")
				}
				if _, err := RunScheduledPrune(t.Context(), c, "execute", review.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
				return
			}
			if review.Review.Executor.Stage != PruneStarted {
				t.Fatal("uncertain outcome promoted")
			}
			if _, err := RunScheduledPrune(t.Context(), c, "execute", review.Review.ReviewID); !errors.Is(err, ErrPruneOutcome) {
				t.Fatal("execution repeated", err)
			}
			recovered, err := RunScheduledPrune(t.Context(), c, "recover", review.Review.ReviewID)
			if stage == "prune-before-effect" {
				if !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("absence released pending work", err)
				}
			} else if err != nil || recovered.Commit == nil || recovered.Commit.Applied || recovered.Commit.Effect.Operation.ScheduleID != f.inventory.Request.ScheduleID {
				t.Fatal("exact effect recovery", err)
			}
		})
	}
}

func TestCustodyScheduledPruneCrashHelper(t *testing.T) {
	path := os.Getenv("OM_SCHEDULED_PRUNE_FIXTURE")
	if path == "" {
		t.Skip("subprocess only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c ScheduledPruneRuntimeConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Base, _, _ = pruneChainConfig()
	review, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	hooks := storeHooks{at: func(stage string) error {
		if stage == os.Getenv("OM_SCHEDULED_PRUNE_STAGE") {
			if err := os.WriteFile(os.Getenv("OM_SCHEDULED_PRUNE_MARKER"), []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}}
	if _, err := runScheduledPrune(t.Context(), c, "execute", review.Review.ReviewID, hooks); err != nil {
		t.Fatal(err)
	}
	t.Fatal("child escaped crash boundary")
}
