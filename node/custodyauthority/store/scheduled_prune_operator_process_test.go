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
)

func TestProcessScheduledPruneOperatorRecovery(t *testing.T) {
	for _, kind := range []string{"admit", "complete"} {
		for _, stage := range []string{"intent-after-publish", "authority-after-publish", "confirm-before-publish", "pins-admission-confirm-before-publish"} {
			if kind == "complete" && stage == "pins-admission-confirm-before-publish" {
				continue
			}
			t.Run(kind+"/"+stage, func(t *testing.T) {
				var c ScheduledPruneCommandConfig
				if kind == "admit" {
					f := newScheduledPruneOperatorFixture(t)
					c = f.config[0]
				} else {
					_, _, configs := scheduledCompletedOperatorFixture(t)
					c = configs[1]
				}
				before := scheduledOperatorReview(t, c)
				file, marker := filepath.Join(t.TempDir(), "config"), filepath.Join(t.TempDir(), "reached")
				raw, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, file, raw)
				child := exec.Command(os.Args[0], "-test.run=^TestProcessScheduledPruneOperatorHelper$", "-test.count=1")
				child.Env = append(os.Environ(), "OM_PRUNE_OPERATOR_CONFIG="+file, "OM_PRUNE_OPERATOR_STAGE="+stage, "OM_PRUNE_OPERATOR_MARKER="+marker)
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
					t.Fatal("concurrent process acquired owners")
				}
				if err := child.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err == nil {
					t.Fatal("child survived SIGKILL")
				}
				cold := scheduledOperatorReview(t, c)
				if cold.Review.Authority.Pending == nil && cold.Executor.Protection.Pending == nil {
					t.Fatal("retained attempt missing after kill")
				}
				again := scheduledOperatorReview(t, c)
				if !reflect.DeepEqual(cold, again) {
					t.Fatal("review consumed attempt")
				}
				result, err := RunScheduledPruneCommand(t.Context(), c, "resume", cold.Review.ReviewID)
				if err != nil {
					t.Fatal("cold exact resume", err)
				}
				want := before.Review.Authority.Authority.Pending + 1
				if kind == "complete" {
					want = before.Review.Authority.Authority.Pending - 1
				}
				if result.Commit == nil || result.Commit.Snapshot.Pending != want || len(result.Commit.Snapshot.Operations) != 2 {
					t.Fatal("process recovery reset accounting")
				}
				stable := scheduledOperatorReview(t, c)
				retried := scheduledOperatorApply(t, c)
				if retried.Commit.Appended || !reflect.DeepEqual(stable.Review.Authority.Authority, retried.Commit.Snapshot) {
					t.Fatal("cold retry consumed twice")
				}
			})
		}
	}
}
func TestProcessScheduledPruneOperatorHelper(t *testing.T) {
	path := os.Getenv("OM_PRUNE_OPERATOR_CONFIG")
	if path == "" {
		t.Skip("subprocess only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c ScheduledPruneCommandConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	r := scheduledOperatorReview(t, c)
	hooks := storeHooks{at: func(stage string) error {
		if stage == os.Getenv("OM_PRUNE_OPERATOR_STAGE") {
			if err := os.WriteFile(os.Getenv("OM_PRUNE_OPERATOR_MARKER"), []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}}
	if _, err := runScheduledPruneCommand(t.Context(), c, "apply", r.Review.ReviewID, hooks); err != nil {
		t.Fatal(err)
	}
	t.Fatal("escaped crash boundary")
}
