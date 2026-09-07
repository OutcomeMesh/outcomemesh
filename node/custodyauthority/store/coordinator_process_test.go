//go:build integration

package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// Process-kill coverage for two independently located stores. This does not
// certify physical power loss or deploy independent failure/access domains.
func TestAuthorityCoordinatorProcessCrashAtomicity(t *testing.T) {
	history, snapshots := testHistory(t)
	for prefix, entry := range history {
		for _, part := range []string{"intent", "authority", "confirm"} {
			for _, stage := range appendStages {
				t.Run(fmt.Sprintf("entry-%d/%s/%s", prefix+1, part, stage), func(t *testing.T) {
					coordinator, aPath, jPath := newTestCoordinator(t)
					for _, previous := range history[:prefix] {
						appendCoordinated(t, coordinator, previous)
					}
					_ = coordinator.Close()
					killCoordinatorChild(t, aPath, jPath, prefix, part+"-"+stage)
					coordinator = testOpenCoordinator(t, aPath, jPath)
					prepared := part != "intent" || isPublishedStage(stage)
					decided := part == "confirm" || (part == "authority" && isPublishedStage(stage))
					confirmed := part == "confirm" && isPublishedStage(stage)
					checkRecoveredCoordination(t, coordinator, entry, snapshots[prefix], snapshots[prefix+1], prepared, decided, confirmed)
					// Opening twice must not submit the retained intent or confirm an
					// observed authority decision merely because the process restarted.
					_ = coordinator.Close()
					coordinator = testOpenCoordinator(t, aPath, jPath)
					checkRecoveredCoordination(t, coordinator, entry, snapshots[prefix], snapshots[prefix+1], prepared, decided, confirmed)
					var result Commit
					var err error
					if prepared && !confirmed {
						result, err = coordinator.Resume(t.Context())
					} else {
						result, err = coordinator.Append(t.Context(), entry)
					}
					if err != nil || result.Appended == decided || !reflect.DeepEqual(result.Snapshot, snapshots[prefix+1]) {
						t.Fatalf("crash retry changed the decision: %+v %v", result, err)
					}
					for _, next := range history[prefix+1:] {
						appendCoordinated(t, coordinator, next)
					}
					_ = coordinator.Close()
					coordinator = testOpenCoordinator(t, aPath, jPath)
					terminal := testCoordination(t, coordinator)
					if terminal.Pending != nil || terminal.Confirmed != position(snapshots[len(history)]) || !reflect.DeepEqual(terminal.Authority, snapshots[len(history)]) {
						t.Fatal("crash recovery failed to retain the original drain/retirement")
					}
					for _, old := range history {
						result := appendCoordinated(t, coordinator, old)
						if result.Appended || !reflect.DeepEqual(result.Snapshot, snapshots[len(history)]) {
							t.Fatal("old retry reopened retired work")
						}
					}
				})
			}
		}
	}
	for _, stage := range []string{"intent-before-ready", "intent-ready-file-synced", "intent-ready-directory-synced"} {
		t.Run("create/"+stage, func(t *testing.T) {
			authority, aPath := newTestStore(t)
			_ = authority.Close()
			jPath := filepath.Join(t.TempDir(), "intent-journal")
			killCoordinatorChild(t, aPath, jPath, -1, stage)
			if opened, err := CreateCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatalf("crashed journal was rebuilt: %v", err)
			}
			opened, err := OpenCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t))
			if stage == "intent-before-ready" {
				if err == nil {
					_ = opened.Close()
					t.Fatal("partial initialization accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			status := testCoordination(t, opened)
			if status.Pending != nil || status.Confirmed != initialPosition(t) || !reflect.DeepEqual(status.Authority, snapshots[0]) {
				t.Fatal("initialization crash admitted or confirmed work")
			}
		})
	}
}

func killCoordinatorChild(t *testing.T, aPath, jPath string, prefix int, stage string) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "reached")
	command := exec.Command(os.Args[0], "-test.run=^TestAuthorityCoordinatorCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_COORDINATOR_STAGE="+stage, "OUTCOMEMESH_COORDINATOR_PREFIX="+strconv.Itoa(prefix),
		"OUTCOMEMESH_COORDINATOR_AUTHORITY="+aPath, "OUTCOMEMESH_COORDINATOR_JOURNAL="+jPath, "OUTCOMEMESH_COORDINATOR_MARKER="+marker)
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
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for reached := false; !reached; {
		select {
		case <-done:
			t.Fatalf("coordinator helper exited before %s: %v\n%s", stage, exitErr, output.String())
		case <-deadline.C:
			_ = command.Process.Kill()
			<-done
			t.Fatalf("coordinator helper did not reach %s\n%s", stage, output.String())
		case <-ticker.C:
			_, err := os.Stat(marker)
			reached = err == nil
		}
	}
	if opened, err := OpenCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("live process lost intent ownership: %v", err)
	}
	if opened, err := Open(aPath, testAssignment(), testAssignmentID(t), initialPosition(t)); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("live coordinator lost authority ownership: %v", err)
	}
	identities := make(map[string]os.FileInfo)
	for _, path := range []string{filepath.Join(aPath, lockName), filepath.Join(jPath, intentLockName)} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		identities[path] = info
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	if exitErr == nil {
		t.Fatal("coordinator helper exited without being killed")
	}
	if _, err := os.Lstat(marker + ".ack"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("helper returned before the crash boundary")
	}
	for path, before := range identities {
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("process death replaced an ownership inode")
		}
	}
}

func TestAuthorityCoordinatorCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_COORDINATOR_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	prefix, err := strconv.Atoi(os.Getenv("OUTCOMEMESH_COORDINATOR_PREFIX"))
	if err != nil {
		t.Fatal(err)
	}
	aPath, jPath := os.Getenv("OUTCOMEMESH_COORDINATOR_AUTHORITY"), os.Getenv("OUTCOMEMESH_COORDINATOR_JOURNAL")
	marker := os.Getenv("OUTCOMEMESH_COORDINATOR_MARKER")
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, marker, []byte(stage))
			for {
				time.Sleep(time.Hour)
			}
		}
		return nil
	}}
	if prefix == -1 {
		coordinator, err := createCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t), hooks)
		if coordinator != nil {
			_ = coordinator.Close()
		}
		writeTestFile(t, marker+".ack", nil)
		t.Fatalf("coordinator creation returned before kill: %v", err)
	}
	history, _ := testHistory(t)
	if prefix < 0 || prefix >= len(history) {
		t.Fatal("invalid history prefix")
	}
	coordinator, err := openCoordinator(aPath, jPath, testAssignment(), testAssignmentID(t), hooks)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	_, err = coordinator.Append(t.Context(), history[prefix])
	writeTestFile(t, marker+".ack", nil)
	t.Fatalf("coordinator append returned before kill: %v", err)
}
