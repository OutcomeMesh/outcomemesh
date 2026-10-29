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

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type scheduleCrashInput struct {
	Authority, Pins, Journal, Stage, Marker string
	Assignment                              custodyauthority.Assignment
	Entry                                   custodyauthority.Entry
	Scope                                   CustodyScheduleContext
	Policy                                  workarchive.CustodyPolicy
	Limits                                  workarchive.CustodyJournalLimits
}

func TestProcessCustodyScheduleRecovery(t *testing.T) {
	for _, stage := range []string{"intent-after-publish", "authority-after-publish", "confirm-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			f, _ := newManagedCustodyPair(t)
			s, e := managedScheduleFixture(t, f)
			owner := f.serve.archive.f.coordinator
			before := testCoordination(t, owner).Authority
			input := scheduleCrashInput{f.serve.archive.f.authorityPath, f.serve.archive.f.pinsPath, f.serve.config.JournalPath, stage, filepath.Join(t.TempDir(), "reached"), f.serve.archive.policy.Assignments[0], e, s, f.config.CustodyPolicy, f.config.JournalLimits}
			owner.Close()
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "input.json")
			if err = os.WriteFile(file, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCustodyScheduleCrashHelper$", "-test.count=1")
			cmd.Env = append(os.Environ(), "OUTCOMEMESH_SCHEDULE_CRASH_INPUT="+file)
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
			if opened, err := OpenCoordinator(input.Authority, input.Pins, input.Assignment, s.Proof.AssignmentID); !errors.Is(err, ErrBusy) {
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
			owner, err = OpenCoordinator(input.Authority, input.Pins, input.Assignment, s.Proof.AssignmentID)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			f.serve.archive.f.coordinator = owner
			current := testCoordination(t, owner)
			if current.Authority.Pending != before.Pending || !reflect.DeepEqual(current.Authority.Operations, before.Operations) {
				t.Fatal("process death reset obligations")
			}
			if current.Pending != nil {
				if *current.Pending != e {
					t.Fatal("different retained migration")
				}
				if _, err = owner.Resume(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			migrateManagedSchedule(t, f, s, e)
			final := testCoordination(t, owner)
			if final.Pending != nil || final.Authority.Sequence != before.Sequence+1 || final.Authority.ScheduleID != s.ExpectedID {
				t.Fatal("cold recovery changed migration")
			}
		})
	}
}
func TestCustodyScheduleCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_SCHEDULE_CRASH_INPUT")
	if file == "" {
		t.Skip("subprocess helper")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var in scheduleCrashInput
	if err = json.Unmarshal(b, &in); err != nil {
		t.Fatal(err)
	}
	owner, err := OpenCoordinator(in.Authority, in.Pins, in.Assignment, in.Scope.Proof.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	setCoordinatorHooks(owner, storeHooks{at: func(stage string) error {
		if stage == in.Stage {
			if err := os.WriteFile(in.Marker, []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}})
	_, err = owner.MigrateCustodySchedule(t.Context(), in.Entry, in.Scope, in.Journal, in.Policy, in.Limits)
	t.Fatal("helper returned", err)
}
