//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func pruneProcessClaim(_ context.Context, _ custodyfence.Scope, c custodyfence.Command) (custodyfence.Certificate, error) {
	c, err := c.Sign(testKey(4))
	if err != nil {
		return custodyfence.Certificate{}, err
	}
	return f.Certificate(c, 70, 71, 72), nil
}

func TestPruneFenceProcessDeathKeepsObligations(t *testing.T) {
	testPruneFenceProcessDeath(t, false)
}
func TestPruneServiceProcessDeathKeepsObligations(t *testing.T) {
	testPruneFenceProcessDeath(t, true)
}
func testPruneFenceProcessDeath(t *testing.T, service bool) {
	for _, stage := range []string{"prune-fence-candidate-synced", "prune-fence-quorum-before-start", "prune-before-effect", "prune-after-effect", "prune-result-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			var fixture *scheduledPruneFixture
			if service {
				fixture = newServicePruneFixture(t)
			} else {
				fixture = newScheduledPruneFixture(t, pruneFencePolicy())
			}
			config := fixture.runtimeConfig(t)
			disk := config
			disk.Base = workchain.Base{}
			raw, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			path, marker := filepath.Join(t.TempDir(), "config"), filepath.Join(t.TempDir(), "reached")
			writeTestFile(t, path, raw)
			child := exec.Command(os.Args[0], "-test.run=^TestPruneFenceProcessHelper$", "-test.count=1")
			child.Env = append(os.Environ(), "OM_PRUNE_FENCE_CONFIG="+path, "OM_PRUNE_FENCE_STAGE="+stage, "OM_PRUNE_FENCE_MARKER="+marker)
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
					t.Fatal("missed crash boundary")
				case <-tick.C:
				}
			}
			if _, err := RunScheduledPrune(t.Context(), config, "review", types.Hash{}); err == nil {
				t.Fatal("second process acquired owners")
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("child survived kill")
			}
			review, err := RunScheduledPrune(t.Context(), config, "review", types.Hash{})
			if err != nil {
				t.Fatal("cold review", err)
			}
			for _, owner := range review.Review.Authorities {
				if owner.Authority.Pending != 2 {
					t.Fatal("obligations lost")
				}
			}
			config.CollectPruneClaim = pruneProcessClaim
			if service {
				config.ServiceIdentity, err = prunefence.NewServiceIdentity(*fixture.inventory.FencePolicy.Service, testKey(90), new(pruneServiceGuard))
				if err != nil {
					t.Fatal(err)
				}
				defer config.ServiceIdentity.Close()
			}

			if _, err := RunScheduledPrune(t.Context(), config, "execute", review.Review.ReviewID); err == nil {
				t.Fatal("cold process repeated deletion")
			}
			if review.Review.Executor.Stage != PruneSucceeded {
				if _, err := RunScheduledPrune(t.Context(), config, "recover", review.Review.ReviewID); err == nil {
					t.Fatal("missing signature reconstructed")
				}
			}
			if stage == "prune-before-effect" || stage == "prune-after-effect" {
				plan := planFromInventory(fixture.inventory)
				pid, _ := plan.ID()
				planPath := filepath.Join(t.TempDir(), "plan")
				if err := SaveScheduledPrunePlan(t.Context(), planPath, plan, pid); err != nil {
					t.Fatal(err)
				}
				primary := config.Authorities[0]
				for _, owner := range config.Authorities {
					if owner.AssignmentID == plan.Request.AssignmentID {
						primary = owner
					}
				}
				c := ScheduledPruneCommandConfig{PlanPath: planPath, PlanID: pid, InventoryPath: config.InventoryPath, InventoryID: config.InventoryID, AssignmentID: primary.AssignmentID,
					AuthorityPath: primary.AuthorityPath, AuthorityPinsPath: primary.AuthorityPinsPath, ExecutorPath: config.ExecutorPath, ExecutorPinsPath: config.ExecutorPinsPath, PrepareSettlement: true,
					Storage: &PruneRecoveryStorage{ChainPath: config.ChainPath, ChainPinsPath: config.ChainPinsPath, MigrationID: config.StorageMigrationID, Base: config.Base, Parameters: config.Parameters, Policy: config.StoragePolicy}}
				prepared, err := RunScheduledPruneCommand(t.Context(), c, "review", types.Hash{})
				if stage == "prune-before-effect" {
					if err == nil {
						t.Fatal("SIGKILL before effect became settlement")
					}
					return
				}
				if err != nil || prepared.Proposal == nil {
					t.Fatal("lost signature with retained effect", err)
				}
				decision := certifyObservedProposal(t, *prepared.Proposal)
				c.PrepareSettlement = false
				c.SettlementPath = filepath.Join(t.TempDir(), "decision")
				c.SettlementID, _ = decision.ID()
				raw, _ := decision.CanonicalBytes()
				writeTestFile(t, c.SettlementPath, raw)
				owned := scheduledOperatorReview(t, c)
				settled, err := RunScheduledPruneCommand(t.Context(), c, "settle-effect", owned.Review.ReviewID)
				if err != nil || settled.Executor.FenceSettlement == nil || settled.Executor.FenceResult != nil || settled.Review.Authority.Authority.Pending != 2 {
					t.Fatal("SIGKILL settlement", err)
				}
				complete := scheduledOutcomeCompletion(t, withoutPruneSettlement(c))
				completed := scheduledOperatorApply(t, complete)
				if completed.Commit == nil || completed.Commit.Snapshot.Pending != 1 || len(completed.Commit.Snapshot.Operations) != 2 {
					t.Fatal("SIGKILL settlement reset accounting")
				}
				if service {
					for _, owner := range config.Authorities {
						if owner.AssignmentID == primary.AssignmentID {
							continue
						}
						other := withoutPruneSettlement(c)
						other.AssignmentID, other.AuthorityPath, other.AuthorityPinsPath = owner.AssignmentID, owner.AuthorityPath, owner.AuthorityPinsPath
						result := scheduledOperatorApply(t, scheduledOutcomeCompletion(t, other))
						if result.Commit == nil || result.Commit.Snapshot.Pending != 1 || len(result.Commit.Snapshot.Operations) != 2 {
							t.Fatal("secondary completion reset original accounting")
						}
					}
				}
			}
		})
	}
}
func TestPruneFenceProcessHelper(t *testing.T) {
	path := os.Getenv("OM_PRUNE_FENCE_CONFIG")
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
	c.CollectPruneClaim = pruneProcessClaim
	v, err := LoadScheduledPruneInventory(c.InventoryPath, c.InventoryID)
	if err != nil {
		t.Fatal(err)
	}
	if v.FencePolicy.Service != nil {
		c.ServiceIdentity, err = prunefence.NewServiceIdentity(*v.FencePolicy.Service, testKey(90), new(pruneServiceGuard))
		if err != nil {
			t.Fatal(err)
		}
		defer c.ServiceIdentity.Close()
	}
	r, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	hook := storeHooks{at: func(stage string) error {
		if stage == os.Getenv("OM_PRUNE_FENCE_STAGE") {
			if err := os.WriteFile(os.Getenv("OM_PRUNE_FENCE_MARKER"), []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}}
	_, err = runScheduledPrune(t.Context(), c, "execute", r.Review.ReviewID, hook)
	t.Fatal("escaped boundary", err)
}
