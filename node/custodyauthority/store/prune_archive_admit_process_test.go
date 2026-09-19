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
	"strings"
	"testing"
	"time"
)

func TestArchiveSecondaryAdmissionProcessRecovery(t *testing.T) {
	for _, retry := range []bool{false, true} {
		stages := []string{"authority-before-publish", "authority-after-publish", "confirm-before-publish", "confirm-after-publish", "secondary-admission-done"}
		if !retry {
			stages = append([]string{"archive-secondary-inventory-synced", "intent-before-publish", "intent-after-publish"}, stages...)
		}
		for _, stage := range stages {
			name := "initial/" + stage
			if retry {
				name = "pending-retry/" + stage
			}
			t.Run(name, func(t *testing.T) {
				p, inventory := newArchiveSecondaryFixture(t, nil)
				before := pruneSnapshot(t, p.f.executor)
				usage, _, err := p.f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				if retry {
					ctx, cancel := context.WithCancel(t.Context())
					setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: func(at string) error {
						if at == "intent-after-apply" {
							cancel()
						}
						return nil
					}})
					_, err := admitArchiveSecondary(ctx, p, inventory)
					cancel()
					if !errors.Is(err, ErrPendingAttempt) {
						t.Fatal("failed to retain exact secondary attempt", err)
					}
				}
				config := archiveProcessInputs(p)
				closeArchiveProcess(p)
				file, marker := filepath.Join(t.TempDir(), "fixture.json"), filepath.Join(t.TempDir(), "reached")
				encoded, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, file, encoded)
				command := exec.Command(os.Args[0], "-test.run=^TestArchiveSecondaryAdmissionCrashHelper$", "-test.count=1")
				command.Env = append(os.Environ(), "OUTCOMEMESH_SECONDARY_FIXTURE="+file, "OUTCOMEMESH_SECONDARY_STAGE="+stage, "OUTCOMEMESH_SECONDARY_MARKER="+marker)
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
						t.Fatal("child exited before secondary boundary", exitErr, output.String())
					case <-deadline.C:
						_ = command.Process.Kill()
						<-done
						t.Fatal("secondary boundary not reached", output.String())
					case <-tick.C:
					}
				}
				for i, authority := range config.Authorities {
					owner, err := OpenCoordinator(authority.Path, authority.Pins, config.Policy.Assignments[i], authority.Binding.AssignmentID)
					if owner != nil {
						_ = owner.Close()
					}
					if !errors.Is(err, ErrBusy) {
						t.Fatal("child lost original coordinator ownership", err)
					}
				}
				if err := command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				<-done
				if exitErr == nil {
					t.Fatal("child was not killed")
				}
				prepared := retry || stage != "archive-secondary-inventory-synced" && stage != "intent-before-publish"
				decided := stage == "authority-after-publish" || strings.HasPrefix(stage, "confirm-") || stage == "secondary-admission-done"
				confirmed := stage == "confirm-after-publish" || stage == "secondary-admission-done"
				for range 2 {
					p = openArchiveProcess(t, config)
					assertArchiveSecondaryRecovery(t, p, inventory, before, prepared, decided, confirmed)
					closeArchiveProcess(p)
				}
				p = openArchiveProcess(t, config)
				result, err := admitArchiveSecondary(t.Context(), p, inventory)
				if err != nil || result.Appended == decided || testCoordination(t, p.operations[1].Coordinator).Pending != nil {
					t.Fatal("exact secondary recovery failed", err)
				}
				if after, _, err := p.f.chain.HistoryUsage(); err != nil || after != usage {
					t.Fatal("secondary process touched chain history", err)
				}
				if _, found, err := p.f.chain.CanonicalPruneEffect(p.operations[0].Binding.TicketID); err != nil || found {
					t.Fatal("secondary admission executed work", err)
				}
				closeArchiveProcess(p)
			})
		}
	}
}

func TestArchiveSecondaryAdmissionCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_SECONDARY_FIXTURE")
	if file == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var config archiveProcessConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	p := openArchiveProcess(t, config)
	inventory, err := LoadArchivePruneInventoryFile(config.InventoryPath, config.InventoryID, config.PolicyID)
	if err != nil {
		t.Fatal(err)
	}
	hook := func(at string) error {
		if at == os.Getenv("OUTCOMEMESH_SECONDARY_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_SECONDARY_MARKER"), nil)
			select {}
		}
		return nil
	}
	p.f.executor.hooks.at = hook
	setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: hook})
	if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
		t.Fatal(err)
	}
	_ = hook("secondary-admission-done")
	t.Fatal("child missed secondary boundary")
}
