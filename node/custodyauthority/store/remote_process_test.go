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

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// Real process death at each independent publication layer. No remote worker,
// copied owner, network listener or physical-media guarantee is implied here.
func TestRemoteCoordinatorProcessCrashBarriers(t *testing.T) {
	f := newRemoteStoreFixture(t)
	cuts := []struct {
		stage                        string
		prepared, decided, confirmed bool
	}{
		{"intent-before-publish", false, false, false},
		{"intent-directory-synced", true, false, false},
		{"authority-before-publish", true, false, false},
		{"authority-directory-synced", true, true, false},
		{"confirm-before-publish", true, true, false},
		{"confirm-directory-synced", true, true, true},
	}
	for _, index := range []int{2, 3} {
		for _, cut := range cuts {
			t.Run(fmt.Sprintf("kind-%d/%s", f.history[index].Command.Kind, cut.stage), func(t *testing.T) {
				owner, aPath, jPath := f.coordinator(t, index)
				_ = owner.Close()
				killRemoteCoordinatorChild(t, f, aPath, jPath, index, cut.stage)
				beforeOpen := custodyCommandPathTrees(t, []string{aPath, jPath})
				owner = f.open(t, aPath, jPath)
				checkRecoveredCoordination(t, owner, f.history[index], f.snapshots[index], f.snapshots[index+1], cut.prepared, cut.decided, cut.confirmed)
				if !reflect.DeepEqual(custodyCommandPathTrees(t, []string{aPath, jPath}), beforeOpen) {
					t.Fatal("open published or confirmed an observed remote transition")
				}
				assertRemoteProcessGuard(t, f, owner)
				// A second open is still observation-only, including a durable B
				// drain whose authority record exists but its pin is unconfirmed.
				_ = owner.Close()
				owner = f.open(t, aPath, jPath)
				checkRecoveredCoordination(t, owner, f.history[index], f.snapshots[index], f.snapshots[index+1], cut.prepared, cut.decided, cut.confirmed)
				assertRemoteProcessGuard(t, f, owner)
				var result Commit
				var err error
				if cut.prepared && !cut.confirmed {
					result, err = owner.Resume(t.Context())
				} else {
					result, err = owner.Append(t.Context(), f.history[index])
				}
				if err != nil || result.Appended == cut.decided || !reflect.DeepEqual(result.Snapshot, f.snapshots[index+1]) {
					t.Fatal("explicit exact remote recovery changed/repeated the decision", result, err)
				}
				status := testCoordination(t, owner)
				if status.Pending != nil || status.Confirmed != position(f.snapshots[index+1]) || status.Authority.Pending != 2 {
					t.Fatal("remote transition implicitly completed tickets or returned before confirmation", status)
				}
				assertRemoteProcessGuard(t, f, owner)
				for _, next := range f.history[index+1:] {
					appendCoordinated(t, owner, next)
				}
				_ = owner.Close()
				owner = f.open(t, aPath, jPath)
				if got := testCoordination(t, owner); !reflect.DeepEqual(got.Authority, f.snapshots[8]) || got.Pending != nil {
					t.Fatal("remote history did not survive explicit completions/retirement", got)
				}
				for _, old := range f.history {
					if result := appendCoordinated(t, owner, old); result.Appended || result.Snapshot.Remote != nil || result.Snapshot.Phase != custodyauthority.Retired {
						t.Fatal("historical lookup reopened remote work", result)
					}
				}
			})
		}
	}
}

func assertRemoteProcessGuard(t testing.TB, f remoteStoreFixture, owner *Coordinator) {
	t.Helper()
	status := testCoordination(t, owner)
	if status.Pending == nil && status.Authority.Remote == nil {
		return // no live callback is inferred from a historical observation
	}
	want := custodyauthority.ErrRemoteActive
	if status.Pending != nil {
		want = ErrPendingAttempt
	}
	for _, admission := range f.history[:2] {
		ticket, _ := admission.ID()
		c := admission.Command
		binding := OperationBinding{AssignmentID: f.id, TicketID: ticket, ConsumerPublicKey: c.ActorPublicKey,
			OperationID: c.OperationID, Purpose: c.Purpose}
		if err := owner.WithOperation(t.Context(), binding, func() error { t.Error("remote/pending authority entered live effect"); return nil }); !errors.Is(err, want) {
			t.Fatal("reopened owner bypassed the remote/confirmation fence", err)
		}
	}
	stop := remoteStoreCommand(t, f.assignment, status.Authority, custodyauthority.Stop, 0, types.Hash{}, types.Hash{}, testHash(180), 1)
	if _, err := owner.Append(t.Context(), stop); !errors.Is(err, want) {
		t.Fatal("new Stop crossed a retained remote/pending barrier", err)
	}
}

func killRemoteCoordinatorChild(t *testing.T, f remoteStoreFixture, aPath, jPath string, index int, stage string) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "remote-reached")
	command := exec.Command(os.Args[0], "-test.run=^TestRemoteCoordinatorCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_REMOTE_COORDINATOR_STAGE="+stage,
		"OUTCOMEMESH_REMOTE_COORDINATOR_INDEX="+strconv.Itoa(index), "OUTCOMEMESH_REMOTE_COORDINATOR_AUTHORITY="+aPath,
		"OUTCOMEMESH_REMOTE_COORDINATOR_PINS="+jPath, "OUTCOMEMESH_REMOTE_COORDINATOR_MARKER="+marker)
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
	for reached := false; !reached; {
		select {
		case <-done:
			t.Fatalf("remote helper exited before %s: %v\n%s", stage, exitErr, output.String())
		case <-deadline.C:
			_ = command.Process.Kill()
			<-done
			t.Fatalf("remote helper did not reach %s\n%s", stage, output.String())
		case <-tick.C:
			_, err := os.Lstat(marker)
			reached = err == nil
		}
	}
	if other, err := OpenCoordinator(aPath, jPath, f.assignment, f.id); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("live remote coordinator lost its original owner lock", err)
	}
	if other, err := Open(aPath, f.assignment, f.id, position(f.snapshots[index])); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("raw store bypassed the original remote owner lock", err)
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
		t.Fatal("remote helper exited normally instead of being killed")
	}
	if _, err := os.Lstat(marker + ".ack"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("remote helper acknowledged before the selected crash boundary")
	}
	for path, before := range identities {
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) {
			t.Fatal("process death replaced a remote owner lock inode")
		}
	}
}

func TestRemoteCoordinatorCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_REMOTE_COORDINATOR_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	index, err := strconv.Atoi(os.Getenv("OUTCOMEMESH_REMOTE_COORDINATOR_INDEX"))
	if err != nil || (index != 2 && index != 3) {
		t.Fatal("invalid remote transition index", err)
	}
	f := newRemoteStoreFixture(t)
	aPath, jPath := os.Getenv("OUTCOMEMESH_REMOTE_COORDINATOR_AUTHORITY"), os.Getenv("OUTCOMEMESH_REMOTE_COORDINATOR_PINS")
	marker := os.Getenv("OUTCOMEMESH_REMOTE_COORDINATOR_MARKER")
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, marker, []byte(stage))
			for {
				time.Sleep(time.Second)
			}
		}
		return nil
	}}
	owner, err := openCoordinator(aPath, jPath, f.assignment, f.id, hooks)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	_, err = owner.Append(t.Context(), f.history[index])
	writeTestFile(t, marker+".ack", nil)
	t.Fatalf("remote append returned before selected kill: %v", err)
}
