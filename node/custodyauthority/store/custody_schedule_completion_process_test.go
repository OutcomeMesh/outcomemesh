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
)

type scheduledCompletionCrashInput struct {
	Config        ManagedCustodyCommandServiceConfig
	Stage, Marker string
}

func TestProcessCustodyScheduleCompletionRecovery(t *testing.T) {
	for _, stage := range []string{"intent-after-publish", "authority-after-publish", "confirm-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			f, terminal, _ := scheduledCompleteFixture(t)
			owner := f.serve.archive.f.coordinator
			before := testCoordination(t, owner).Authority
			config := managedCommandApplyTestCompleteConfig(t, f, owner, terminal, f.config.JournalPath)
			input := scheduledCompletionCrashInput{Config: config, Stage: stage, Marker: filepath.Join(t.TempDir(), "reached")}
			owner.Close()
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "input.json")
			if err = os.WriteFile(file, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCustodyScheduleCompletionCrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "OUTCOMEMESH_SCHEDULE_COMPLETION_CRASH_INPUT="+file)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			timer := time.NewTimer(20 * time.Second)
			defer timer.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			reached := false
			for !reached {
				select {
				case err := <-done:
					t.Fatalf("child exited before fault: %v %s", err, output.String())
				case <-timer.C:
					cmd.Process.Kill()
					<-done
					t.Fatalf("child missed fault: %s", output.String())
				case <-ticker.C:
					_, err := os.Stat(input.Marker)
					reached = err == nil
				}
			}
			if opened, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Scope.Assignment, config.Scope.AssignmentID); !errors.Is(err, ErrBusy) {
				if opened != nil {
					opened.Close()
				}
				cmd.Process.Kill()
				<-done
				t.Fatal("live owner released early", err)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err == nil {
				t.Fatal("child was not killed")
			}
			service := managedCommandApplyTestOpen(t, config)
			review, id := managedCommandApplyTestReview(t, service)
			if review.Pending {
				_, err = service.Resume(t.Context(), id)
			} else {
				_, err = service.Apply(t.Context(), id)
			}
			if err != nil {
				t.Fatal("cold completion recovery", err)
			}
			final := testCoordination(t, service.life.owner)
			if final.Pending != nil || final.Authority.Pending != before.Pending-1 || final.Authority.Sequence != before.Sequence+1 || final.Authority.ScheduleID != before.ScheduleID || len(final.Authority.Operations) != len(before.Operations) {
				t.Fatal("process recovery reset accounting")
			}
			for i, op := range before.Operations {
				if op.TicketID != final.Authority.Operations[i].TicketID {
					t.Fatal("process recovery reissued tickets")
				}
			}
		})
	}
}
func TestCustodyScheduleCompletionCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_SCHEDULE_COMPLETION_CRASH_INPUT")
	if file == "" {
		t.Skip("subprocess helper")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var in scheduledCompletionCrashInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	service := managedCommandApplyTestOpen(t, in.Config)
	_, id := managedCommandApplyTestReview(t, service)
	setCoordinatorHooks(service.life.owner, storeHooks{at: func(stage string) error {
		if stage == in.Stage {
			if err := os.WriteFile(in.Marker, []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}})
	_, err = service.Apply(t.Context(), id)
	t.Fatal("helper returned", err)
}
