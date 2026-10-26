//go:build integration

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// JSON here is disposable subprocess fixture metadata, not a protocol,
// operator configuration, journal format or independently trusted content pin.
func TestPruneArchiveEffectServiceProcessRecovery(t *testing.T) {
	stages := []string{"effect-review-ready", "archive-inventory-synced", "pins-start-intent-after-publish",
		"prune-before-effect", "prune-after-effect", "pins-result-confirm-before-publish", "effect-service-done"}
	for _, mode := range []string{"initial", "lineage"} {
		for _, stage := range stages {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				var p *archivePruneFixture
				if mode == "lineage" {
					p = newArchivePruneFixtureWithRenewals(t, []int{2, 1})
				} else {
					p = newArchivePruneFixture(t)
				}
				before, _, err := p.f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				raw := archiveProcessInputs(p)
				config := archiveEffectServiceFixture(t, p)
				raw.InventoryPath, raw.InventoryID = config.InventoryPath, config.InventoryID
				file, marker := filepath.Join(t.TempDir(), "fixture.json"), filepath.Join(t.TempDir(), "reached")
				// The deterministic chain fixture is rebuilt by the child. Never
				// serialize state.Memory's private representation as trusted state.
				disk := config
				disk.Base = workchain.Base{}
				encoded, err := json.Marshal(disk)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, file, encoded)
				command := exec.Command(os.Args[0], "-test.run=^TestPruneArchiveEffectServiceCrashHelper$", "-test.count=1")
				command.Env = append(os.Environ(), "OUTCOMEMESH_EFFECT_SERVICE_FIXTURE="+file,
					"OUTCOMEMESH_EFFECT_SERVICE_STAGE="+stage, "OUTCOMEMESH_EFFECT_SERVICE_MARKER="+marker)
				var output bytes.Buffer
				command.Stdout, command.Stderr = &output, &output
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				var exitErr error
				go func() { exitErr = command.Wait(); close(done) }()
				t.Cleanup(func() { _ = command.Process.Kill(); <-done })
				deadline := time.NewTimer(15 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
			wait:
				for {
					if _, err := os.Stat(marker); err == nil {
						break wait
					}
					select {
					case <-done:
						t.Fatal("effect child exited before checkpoint", exitErr, output.String())
					case <-deadline.C:
						_ = command.Process.Kill()
						<-done
						t.Fatal("effect checkpoint not reached", output.String())
					case <-tick.C:
					}
				}
				// Even after Execute returns, every original owner stays retained
				// until explicit Close or process death. The competing open must
				// neither repair nor recover any retained uncertain transition.
				assertArchiveEffectOwnersBusy(t, p, config)
				if other, err := OpenPruneArchiveEffectService(config); err == nil {
					_ = other.Close()
					t.Fatal("second effect service acquired active owners")
				}
				if err := command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				<-done
				if exitErr == nil {
					t.Fatal("effect child escaped forced termination")
				}
				wantStage := PruneStarted
				switch stage {
				case "effect-review-ready", "archive-inventory-synced", "pins-start-intent-after-publish":
					wantStage = PruneAdmitted
				case "pins-result-confirm-before-publish", "effect-service-done":
					wantStage = PruneSucceeded
				}
				pending := stage == "pins-start-intent-after-publish" || stage == "pins-result-confirm-before-publish"
				hasEffect := stage == "prune-after-effect" || wantStage == PruneSucceeded
				var previous PruneExecution
				var previousStorage workchain.StorageProtection
				for attempt := range 2 {
					// Opening the new runtime never authorizes replay, confirms a
					// pending start/result, or promotes Started into success.
					service, openErr := OpenPruneArchiveEffectService(config)
					if openErr != nil {
						t.Fatal("runtime could not reopen retained owners", openErr)
					}
					_, reviewErr := service.Review(t.Context())
					if (wantStage == PruneAdmitted && !pending) != (reviewErr == nil) {
						t.Fatal("runtime review promoted retained uncertainty", reviewErr)
					}
					if _, err := service.Execute(t.Context(), types.Hash{}); err == nil {
						t.Fatal("empty review executed work")
					}
					if err := service.Close(); err != nil {
						t.Fatal(err)
					}
					p = openArchiveProcess(t, raw)
					state := pruneSnapshot(t, p.f.executor)
					if state.Stage != wantStage || (state.Protection.Pending != nil) != pending {
						t.Fatal("reopen changed retained stage or pending intent", state.Stage)
					}
					var wantInventory types.Hash
					if wantStage >= PruneStarted {
						wantInventory = config.InventoryID
					}
					if state.ArchiveInventoryID != wantInventory {
						t.Fatal("lost or manufactured start inventory binding")
					}
					storage, err := p.f.chain.StorageProtection()
					if err != nil || storage.Pending != nil || storage.Database != storage.Confirmed {
						t.Fatal("atomic effect storage position is not confirmed", err)
					}
					if attempt == 1 && (!reflect.DeepEqual(previous, state) || !reflect.DeepEqual(previousStorage, storage)) {
						t.Fatal("a second runtime open advanced retained history")
					}
					previous, previousStorage = state, storage
					effect, found, err := p.f.chain.CanonicalPruneEffect(p.operations[0].Binding.TicketID)
					if err != nil || found != hasEffect {
						t.Fatal("wrong atomic effect after process death", found, err)
					}
					if state.Effect != nil && !reflect.DeepEqual(*state.Effect, effect) {
						t.Fatal("retained result differs from atomic effect")
					}
					usage, _, err := p.f.chain.HistoryUsage()
					if err != nil || (!hasEffect && usage != before) {
						t.Fatal("opening or reviewing changed chain history", err)
					}
					for _, operation := range p.operations {
						authority := testCoordination(t, operation.Coordinator)
						if authority.Pending != nil || authority.Authority.Sequence != 1 || authority.Authority.Pending != 1 {
							t.Fatal("runtime reopen completed or replaced an original ticket")
						}
					}
					closeArchiveProcess(p)
				}
				if stage == "effect-review-ready" {
					if _, err := os.Stat(config.AvailabilityPath); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("read-only review published availability", err)
					}
				}
			})
		}
	}
}

func TestPruneArchiveEffectServiceCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_EFFECT_SERVICE_FIXTURE")
	if file == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := readRegular(file, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var config PruneArchiveEffectServiceConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	config.Base, config.Parameters, config.StoragePolicy = pruneChainConfig()
	service := openArchiveEffectService(t, config)
	reach := func(stage string) error {
		if stage == os.Getenv("OUTCOMEMESH_EFFECT_SERVICE_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_EFFECT_SERVICE_MARKER"), nil)
			select {}
		}
		return nil
	}
	service.hooks, service.executor.hooks, service.executor.pins.hooks = storeHooks{at: reach}, storeHooks{at: reach}, storeHooks{at: reach}
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil {
		t.Fatal(err)
	}
	_ = reach("effect-review-ready")
	if result, err := service.Execute(t.Context(), id); err != nil || !result.Applied {
		t.Fatal("reviewed effect failed", err)
	}
	_ = reach("effect-service-done")
	t.Fatal("effect child missed controlled checkpoint")
}
