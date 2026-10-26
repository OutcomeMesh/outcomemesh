//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// Disposable subprocess fixture only. The co-signed completion is retained
// exactly before a child starts; recovery never chooses another authority head.
type archiveSecondaryCompletionProcessConfig struct {
	Archive    archiveProcessConfig
	Completion custodyauthority.Entry
}

func TestArchiveSecondaryCompletionProcessRecovery(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, retry := range []bool{false, true} {
			stages := []string{"authority-before-publish", "authority-after-publish", "confirm-before-publish", "confirm-after-publish", "secondary-completion-done"}
			if !retry {
				stages = append([]string{"archive-secondary-complete-inventory-synced", "intent-before-publish", "intent-after-publish"}, stages...)
			}
			for _, stage := range stages {
				name := outcome + "/initial/" + stage
				if retry {
					name = outcome + "/pending-retry/" + stage
				}
				t.Run(name, func(t *testing.T) {
					p, inventory := newArchiveSecondaryFixture(t, nil)
					if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
						t.Fatal(err)
					}
					if outcome == "cancelled" {
						if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
							t.Fatal(err)
						}
					} else if result, err := p.execute(t.Context()); err != nil || !result.Applied {
						t.Fatal("failed to retain archive result", err)
					}
					terminal := pruneSnapshot(t, p.f.executor)
					var evidence types.Hash
					var err error
					if terminal.Cancellation != nil {
						evidence, err = terminal.Cancellation.ID()
					} else {
						evidence, err = terminal.Effect.ID()
					}
					if err != nil {
						t.Fatal(err)
					}
					secondaryBefore := testCoordination(t, p.operations[1].Coordinator).Authority
					completion := testEntry(t, secondaryBefore, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, evidence)
					model, err := custodyauthority.NewState(p.policy.Assignments[1], p.operations[1].Binding.AssignmentID)
					if err != nil {
						t.Fatal(err)
					}
					if err := model.Apply(inventory.Admissions[1]); err != nil {
						t.Fatal(err)
					}
					if err := model.Apply(completion); err != nil {
						t.Fatal(err)
					}
					secondaryAfter, _ := model.Snapshot()
					primaryBefore := testCoordination(t, p.f.coordinator)
					usage, _, err := p.f.chain.HistoryUsage()
					if err != nil {
						t.Fatal(err)
					}
					effect, foundEffect, err := p.f.chain.CanonicalPruneEffect(p.operations[0].Binding.TicketID)
					if err != nil || foundEffect != (outcome == "succeeded") {
						t.Fatal("unexpected pre-completion effect", err)
					}
					if retry {
						ctx, cancel := context.WithCancel(t.Context())
						setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: func(at string) error {
							if at == "intent-after-apply" {
								cancel()
							}
							return nil
						}})
						_, err := p.f.executor.CompletePreparedArchiveSecondary(ctx, p.operations[1].Coordinator,
							p.inventoryPath, p.inventoryID, p.policyID, completion)
						cancel()
						if !errors.Is(err, ErrPendingAttempt) {
							t.Fatal("failed to retain exact secondary completion", err)
						}
					}
					config := archiveSecondaryCompletionProcessConfig{Archive: archiveProcessInputs(p), Completion: completion}
					closeArchiveProcess(p)
					file, marker := filepath.Join(t.TempDir(), "fixture.json"), filepath.Join(t.TempDir(), "reached")
					encoded, err := json.Marshal(config)
					if err != nil {
						t.Fatal(err)
					}
					writeTestFile(t, file, encoded)
					command := exec.Command(os.Args[0], "-test.run=^TestArchiveSecondaryCompletionCrashHelper$", "-test.count=1")
					command.Env = append(os.Environ(), "OUTCOMEMESH_SECONDARY_COMPLETION_FIXTURE="+file,
						"OUTCOMEMESH_SECONDARY_COMPLETION_STAGE="+stage, "OUTCOMEMESH_SECONDARY_COMPLETION_MARKER="+marker)
					var output bytes.Buffer
					command.Stdout, command.Stderr = &output, &output
					if err := command.Start(); err != nil {
						t.Fatal(err)
					}
					done := make(chan struct{})
					var exitErr error
					go func() { exitErr = command.Wait(); close(done) }()
					t.Cleanup(func() { _ = command.Process.Kill(); <-done })
					deadline, tick := time.NewTimer(15*time.Second), time.NewTicker(10*time.Millisecond)
					defer deadline.Stop()
					defer tick.Stop()
				wait:
					for {
						if _, err := os.Stat(marker); err == nil {
							break wait
						}
						select {
						case <-done:
							t.Fatal("child exited before secondary completion boundary", exitErr, output.String())
						case <-deadline.C:
							_ = command.Process.Kill()
							<-done
							t.Fatal("secondary completion boundary not reached", output.String())
						case <-tick.C:
						}
					}
					archive := config.Archive
					opened, err := OpenPinnedPruneExecutor(archive.Executor, archive.ExecutorPins, archive.Policy.Assignments[0], archive.Policy.RequestID)
					if opened != nil {
						_ = opened.Close()
					}
					if !errors.Is(err, ErrBusy) {
						t.Fatal("child lost executor lifetime ownership", err)
					}
					target := archive.Authorities[1]
					owner, err := OpenCoordinator(target.Path, target.Pins, archive.Policy.Assignments[1], target.Binding.AssignmentID)
					if owner != nil {
						_ = owner.Close()
					}
					if !errors.Is(err, ErrBusy) {
						t.Fatal("child lost secondary lifetime ownership", err)
					}
					if err := command.Process.Kill(); err != nil {
						t.Fatal(err)
					}
					<-done
					if exitErr == nil {
						t.Fatal("child was not killed")
					}
					prepared := retry || stage != "archive-secondary-complete-inventory-synced" && stage != "intent-before-publish"
					decided := stage == "authority-after-publish" || strings.HasPrefix(stage, "confirm-") || stage == "secondary-completion-done"
					confirmed := stage == "confirm-after-publish" || stage == "secondary-completion-done"
					checkUnchanged := func(p *archivePruneFixture) {
						t.Helper()
						if !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) || !reflect.DeepEqual(primaryBefore, testCoordination(t, p.f.coordinator)) {
							t.Fatal("secondary completion changed executor or primary")
						}
						if after, _, err := p.f.chain.HistoryUsage(); err != nil || after != usage {
							t.Fatal("secondary completion touched chain history", err)
						}
						got, found, err := p.f.chain.CanonicalPruneEffect(p.operations[0].Binding.TicketID)
						if err != nil || found != foundEffect || !reflect.DeepEqual(got, effect) {
							t.Fatal("secondary completion changed retained database effect", err)
						}
					}
					for range 2 {
						p = openArchiveProcess(t, archive)
						checkRecoveredCoordination(t, p.operations[1].Coordinator, completion, secondaryBefore, secondaryAfter, prepared, decided, confirmed)
						checkUnchanged(p)
						closeArchiveProcess(p)
					}
					p = openArchiveProcess(t, archive)
					result, err := p.f.executor.CompletePreparedArchiveSecondary(t.Context(), p.operations[1].Coordinator,
						p.inventoryPath, p.inventoryID, p.policyID, completion)
					id, _ := completion.ID()
					if err != nil || result.Appended == decided || result.EntryID != id || result.Snapshot.Pending != 0 ||
						testCoordination(t, p.operations[1].Coordinator).Pending != nil {
						t.Fatal("exact secondary completion recovery failed", err)
					}
					checkUnchanged(p)
					closeArchiveProcess(p)
				})
			}
		}
	}
}

func TestArchiveSecondaryCompletionCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_SECONDARY_COMPLETION_FIXTURE")
	if file == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var config archiveSecondaryCompletionProcessConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	p := openArchiveProcess(t, config.Archive)
	hook := func(at string) error {
		if at == os.Getenv("OUTCOMEMESH_SECONDARY_COMPLETION_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_SECONDARY_COMPLETION_MARKER"), nil)
			select {}
		}
		return nil
	}
	p.f.executor.hooks.at = hook
	setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: hook})
	if _, err := p.f.executor.CompletePreparedArchiveSecondary(t.Context(), p.operations[1].Coordinator,
		p.inventoryPath, p.inventoryID, p.policyID, config.Completion); err != nil {
		t.Fatal(err)
	}
	_ = hook("secondary-completion-done")
	t.Fatal("child missed secondary completion boundary")
}
