//go:build integration

package remoteworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestWorkerSealingSurvivesKilledOriginalProcess(t *testing.T) {
	j, path, c := newWorker(t)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	metadata := t.TempDir()
	configPath := filepath.Join(metadata, "config.json")
	marker := filepath.Join(metadata, "sealing-durable")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestWorkerSealingCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OMESH_REMOTE_WORKER_CRASH_CONFIG="+configPath, "OMESH_REMOTE_WORKER_CRASH_ROOT="+path, "OMESH_REMOTE_WORKER_CRASH_MARKER="+marker)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	var exitErr error
	go func() { exitErr = command.Wait(); close(exited) }()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = command.Process.Kill()
			<-exited
		}
	})
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
waiting:
	for {
		if b, err := os.ReadFile(marker); err == nil && string(b) == "sealing-record-durable" {
			break waiting
		}
		select {
		case <-exited:
			t.Fatal("worker exited before durable sealing checkpoint", exitErr, output.String())
		case <-deadline.C:
			t.Fatal("worker did not reach sealing checkpoint", output.String())
		case <-tick.C:
		}
	}
	if another, err := Open(t.Context(), path, c); !errors.Is(err, ErrBusy) {
		if another != nil {
			_ = another.Close()
		}
		t.Fatal("helper lost original worker lock", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-exited
	if exitErr == nil {
		t.Fatal("worker did not crash")
	}
	sealBefore, err := os.ReadFile(filepath.Join(path, sealingName))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(t.Context(), path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	state, err := opened.Snapshot(t.Context())
	if err != nil || state.Stage != Sealing || state.Pending != Sealing || state.Started {
		t.Fatal("crash lost or promoted sealing", state, err)
	}
	if _, err := opened.Start(t.Context(), c.BeginID); !errors.Is(err, ErrTransition) {
		t.Fatal("delayed Start survived sealing crash", err)
	}
	if _, err := os.Lstat(filepath.Join(path, confirmName(Sealing))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Open auto-confirmed interrupted sealing", err)
	}
	sealAfter, _ := os.ReadFile(filepath.Join(path, sealingName))
	if !bytes.Equal(sealBefore, sealAfter) {
		t.Fatal("reopen rewrote the frozen sealing record")
	}
	if _, err := opened.BeginSeal(t.Context()); err != nil {
		t.Fatal("explicit exact sealing retry", err)
	}
	if _, err := opened.CommitSeal(t.Context(), Unseen, types.Hash{}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerSealingCrashHelper(t *testing.T) {
	path := os.Getenv("OMESH_REMOTE_WORKER_CRASH_CONFIG")
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	j, err := Open(t.Context(), os.Getenv("OMESH_REMOTE_WORKER_CRASH_ROOT"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.hooks.at = func(stage string) error {
		if stage == sealingName+"-record-durable" {
			marker, err := os.OpenFile(os.Getenv("OMESH_REMOTE_WORKER_CRASH_MARKER"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			if _, err := marker.WriteString("sealing-record-durable"); err != nil {
				_ = marker.Close()
				return err
			}
			if err := marker.Sync(); err != nil {
				_ = marker.Close()
				return err
			}
			if err := marker.Close(); err != nil {
				return err
			}
			<-time.After(time.Hour)
		}
		return nil
	}
	if _, err := j.BeginSeal(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash helper unexpectedly returned from sealing checkpoint")
}
