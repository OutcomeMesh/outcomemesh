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

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// SIGKILL tests process death and lock release, not controller cache loss or a
// filesystem's power-loss behavior. Un-synced publication is visible after this
// kind of death; real power-loss recovery permits either exact pinned outcome.
func TestAuthorityStoreProcessCrashAtomicity(t *testing.T) {
	history, snapshots := testHistory(t)
	for prefix, entry := range history {
		for _, stage := range []string{"before-write", "before-file-sync", "file-synced", "before-publish", "after-publish", "directory-synced", "after-apply"} {
			t.Run(fmt.Sprintf("entry-%d/%s", prefix+1, stage), func(t *testing.T) {
				store, path := newTestStore(t)
				for _, previous := range history[:prefix] {
					appendTest(t, store, previous)
				}
				_ = store.Close()
				crashChild(t, path, prefix, stage)
				recovered, err := Recover(path, testAssignment(), testAssignmentID(t), position(snapshots[prefix]), entry)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = recovered.Close() })
				published := stage == "after-publish" || stage == "directory-synced" || stage == "after-apply"
				want := snapshots[prefix]
				if published {
					want = snapshots[prefix+1]
				}
				if !reflect.DeepEqual(testSnapshot(t, recovered), want) {
					t.Fatal("process death changed admission/drain/retirement ordering")
				}
				result, err := recovered.Append(t.Context(), entry)
				if err != nil || result.Appended == published || !reflect.DeepEqual(result.Snapshot, snapshots[prefix+1]) {
					t.Fatalf("lost-response retry duplicated or lost a decision: %+v %v", result, err)
				}
				for _, next := range history[prefix+1:] {
					appendTest(t, recovered, next)
				}
				if !reflect.DeepEqual(testSnapshot(t, recovered), snapshots[len(history)]) {
					t.Fatal("recovered operations could not drain to the original retirement")
				}
				_ = recovered.Close()
				recovered = testOpen(t, path, position(snapshots[len(history)]))
				for _, old := range history {
					result, err := recovered.Append(t.Context(), old)
					if err != nil || result.Appended || result.Snapshot.Phase != custodyauthority.Retired || result.Snapshot.Pending != 0 {
						t.Fatalf("old response revived retired work: %+v %v", result, err)
					}
				}
			})
		}
	}
	for _, stage := range []string{"before-ready", "ready-file-synced", "ready-directory-synced"} {
		t.Run("create/"+stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authority")
			crashChild(t, path, -1, stage)
			if opened, err := Create(path, testAssignment(), testAssignmentID(t)); !errors.Is(err, os.ErrExist) {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatalf("crashed initialization was automatically replaced: %v", err)
			}
			opened, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t))
			if stage == "before-ready" {
				if err == nil {
					_ = opened.Close()
					t.Fatal("incomplete initialization became active")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if !reflect.DeepEqual(testSnapshot(t, opened), snapshots[0]) {
				t.Fatal("crashed initialization created admissions")
			}
		})
	}
}

func crashChild(t *testing.T, path string, prefix int, stage string) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "reached")
	command := exec.Command(os.Args[0], "-test.run=^TestAuthorityStoreCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_AUTHORITY_STORE_STAGE="+stage,
		"OUTCOMEMESH_AUTHORITY_STORE_PREFIX="+strconv.Itoa(prefix), "OUTCOMEMESH_AUTHORITY_STORE_PATH="+path,
		"OUTCOMEMESH_AUTHORITY_STORE_MARKER="+marker)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() { exitErr = command.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = command.Process.Kill()
		<-done
	})
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	waiting := true
	for waiting {
		select {
		case <-done:
			t.Fatalf("helper exited before %s: %v\n%s", stage, exitErr, output.String())
		case <-deadline.C:
			_ = command.Process.Kill()
			<-done
			t.Fatalf("helper did not reach %s\n%s", stage, output.String())
		case <-ticker.C:
			if _, err := os.Stat(marker); err == nil {
				waiting = false
			}
		}
	}
	lockBefore, err := os.Lstat(filepath.Join(path, lockName))
	if err != nil {
		t.Fatal(err)
	}
	// The second process must not enter even while the first has not applied its
	// published decision or completed initialization. It cannot repair around it.
	if opened, err := Open(path, testAssignment(), testAssignmentID(t), initialPosition(t)); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("live process did not own the store exclusively: %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	if exitErr == nil {
		t.Fatal("helper exited normally instead of being killed")
	}
	if _, err := os.Lstat(marker + ".ack"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("helper returned a result before the selected crash boundary")
	}
	lockAfter, err := os.Lstat(filepath.Join(path, lockName))
	if err != nil || !os.SameFile(lockBefore, lockAfter) {
		t.Fatal("process death removed/replaced the ownership inode")
	}
}

func TestAuthorityStoreCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_AUTHORITY_STORE_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	prefix, err := strconv.Atoi(os.Getenv("OUTCOMEMESH_AUTHORITY_STORE_PREFIX"))
	if err != nil {
		t.Fatal(err)
	}
	path, marker := os.Getenv("OUTCOMEMESH_AUTHORITY_STORE_PATH"), os.Getenv("OUTCOMEMESH_AUTHORITY_STORE_MARKER")
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
		store, err := create(path, testAssignment(), testAssignmentID(t), hooks)
		if store != nil {
			_ = store.Close()
		}
		writeTestFile(t, marker+".ack", nil)
		t.Fatalf("initialization returned before kill: %v", err)
	}
	history, snapshots := testHistory(t)
	if prefix < 0 || prefix >= len(history) {
		t.Fatal("invalid history prefix")
	}
	store := testOpen(t, path, position(snapshots[prefix]))
	store.hooks = hooks
	_, err = store.Append(t.Context(), history[prefix])
	writeTestFile(t, marker+".ack", nil)
	t.Fatalf("append returned before kill: %v", err)
}
