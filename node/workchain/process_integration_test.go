//go:build integration

package workchain

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	crashModeEnvironment   = "OUTCOMEMESH_WORKCHAIN_CRASH_MODE"
	crashPathEnvironment   = "OUTCOMEMESH_WORKCHAIN_CRASH_PATH"
	crashMarkerEnvironment = "OUTCOMEMESH_WORKCHAIN_CRASH_MARKER"
)

func TestPebbleProcessCrashAtomicity(t *testing.T) {
	for _, fixture := range []struct {
		name      string
		wantBlock bool
	}{
		{name: "before-commit", wantBlock: false},
		{name: "after-commit", wantBlock: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			parameters := testParameters()
			base := testBase(t, parameters)
			path := filepath.Join(t.TempDir(), "chain")
			marker := filepath.Join(t.TempDir(), "reached")
			reference, err := New(base, parameters)
			if err != nil {
				t.Fatal(err)
			}
			candidate, _ := mineChild(
				t, reference, base.Tip.ID, base.Tip.Timestamp+parameters.TargetSpacing, "process-crash",
			)
			candidateID, _ := candidate.Header.ID()

			command := exec.Command(os.Args[0], "-test.run=^TestWorkChainCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				crashModeEnvironment+"="+fixture.name,
				crashPathEnvironment+"="+path,
				crashMarkerEnvironment+"="+marker,
			)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()

			reopened, err := Open(path, base, parameters)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			tip, err := reopened.Tip()
			if err != nil {
				t.Fatal(err)
			}
			_, blockErr := reopened.BlockByID(candidateID)
			if fixture.wantBlock {
				if tip.ID != candidateID || blockErr != nil {
					t.Fatalf("durable commit tip=%s blockErr=%v", tip.ID, blockErr)
				}
			} else if tip.ID != base.Tip.ID || !errors.Is(blockErr, ErrParent) {
				t.Fatalf("pre-commit crash tip=%s blockErr=%v", tip.ID, blockErr)
			}
			usage, limit, err := reopened.HistoryUsage()
			if err != nil || usage == 0 || usage > limit {
				t.Fatalf("recovered history=%d/%d err=%v", usage, limit, err)
			}
		})
	}
}

func TestWorkChainCrashHelper(t *testing.T) {
	mode := os.Getenv(crashModeEnvironment)
	if mode == "" {
		t.Skip("subprocess helper")
	}
	path := os.Getenv(crashPathEnvironment)
	marker := os.Getenv(crashMarkerEnvironment)
	parameters := testParameters()
	base := testBase(t, parameters)
	store, err := Open(path, base, parameters)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := mineChild(
		t, store, base.Tip.ID, base.Tip.Timestamp+parameters.TargetSpacing, "process-crash",
	)
	stop := func() { blockAtCrashMarker(marker) }
	switch mode {
	case "before-commit":
		store.persistence.commitHook = func() error {
			stop()
			return storage.ErrCorrupt
		}
	case "after-commit":
		store.persistence.afterCommitHook = stop
	default:
		t.Fatalf("unknown crash mode %q", mode)
	}
	_, _, _ = store.Commit(candidate, candidate.Header.Seal.Timestamp)
	t.Fatal("crash hook returned")
}

func blockAtCrashMarker(path string) {
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		panic(err)
	}
	select {}
}

func waitForCrashMarker(t testing.TB, path string, command *exec.Cmd) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if command.ProcessState != nil && command.ProcessState.Exited() {
			t.Fatal("crash helper exited before reaching durability boundary")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	t.Fatal("crash helper did not reach durability boundary")
}
