//go:build integration

package store

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestPruneExecutorProcessCrashAtomicity(t *testing.T) {
	stages := []string{"prune-before-ready", "prune-ready-file-synced", "prune-ready-directory-synced", "prune-before-effect", "prune-after-effect"}
	for _, part := range []string{"prune-admission", "prune-start", "prune-result"} {
		for _, stage := range appendStages {
			stages = append(stages, part+"-"+stage)
		}
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := newPruneFixture(t)
			initializing := strings.Contains(stage, "ready")
			if initializing {
				_ = f.executor.Close()
				f.executorPath = filepath.Join(t.TempDir(), "new-executor")
			} else {
				f.admit(t, !strings.HasPrefix(stage, "prune-admission-"))
			}
			_ = f.executor.Close()
			_ = f.coordinator.Close()
			_ = f.chain.Close()
			killPruneExecutorChild(t, f, stage, initializing)
			if initializing {
				opened, err := OpenPruneExecutor(f.executorPath, testAssignment(), f.id)
				if stage == "prune-before-ready" {
					if err == nil {
						_ = opened.Close()
						t.Fatal("partial initialization opened")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer opened.Close()
				if pruneSnapshot(t, opened).Stage != PrunePrepared {
					t.Fatal("initialization executed work")
				}
				return
			}
			f.reopen(t)
			s := pruneSnapshot(t, f.executor)
			want := PruneStarted
			switch {
			case strings.HasPrefix(stage, "prune-admission-"):
				want = PrunePrepared
				if isPublishedStage(strings.TrimPrefix(stage, "prune-admission-")) {
					want = PruneAdmitted
				}
			case strings.HasPrefix(stage, "prune-start-"):
				want = PruneAdmitted
				if isPublishedStage(strings.TrimPrefix(stage, "prune-start-")) {
					want = PruneStarted
				}
			case strings.HasPrefix(stage, "prune-result-"):
				if isPublishedStage(strings.TrimPrefix(stage, "prune-result-")) {
					want = PruneSucceeded
				}
			}
			if s.Stage != want {
				t.Fatalf("recovered phase=%d want=%d", s.Stage, want)
			}
			ticket, _ := f.admission.ID()
			effect, found, err := f.chain.CanonicalPruneEffect(ticket)
			hadEffect := strings.HasPrefix(stage, "prune-result-") || stage == "prune-after-effect"
			if err != nil || found != hadEffect {
				t.Fatal("wrong effect after crash", found, err)
			}
			// A second open cannot start work or turn a pending ticket into completion.
			f.reopen(t)
			if pruneSnapshot(t, f.executor).Stage != want || testCoordination(t, f.coordinator).Authority.Pending != 1 {
				t.Fatal("open advanced execution")
			}
			if want == PruneStarted && !hadEffect {
				if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("uncertain start reran"); return 200, nil }); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal(err)
				}
				if _, err := f.executor.Recover(t.Context(), f.chain); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("absent effect completed", err)
				}
				stop := f.stop(t)
				s := testCoordination(t, f.coordinator).Authority
				if _, err := f.coordinator.Append(t.Context(), testEntry(t, s, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop)); !errors.Is(err, custodyauthority.ErrOutstanding) {
					t.Fatal("unknown operation retired", err)
				}
				return
			}
			var result workchain.CanonicalPruneCommit
			if hadEffect {
				result, err = f.executor.Recover(t.Context(), f.chain)
				if err != nil || result.Applied || !samePruneEffect(result.Effect, effect) {
					t.Fatal("recovery changed committed effect", err)
				}
			} else {
				if want == PrunePrepared {
					if err := f.executor.BindAdmission(t.Context(), f.coordinator, f.admission); err != nil {
						t.Fatal(err)
					}
				}
				result, err = f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { return 200, nil })
				if err != nil || !result.Applied {
					t.Fatal("unstarted operation did not execute explicitly", err)
				}
			}
			f.complete(t, result.Effect)
			f.reopen(t)
			retained, err := f.executor.Recover(t.Context(), nil)
			if err != nil || retained.Applied || !samePruneEffect(result.Effect, retained.Effect) {
				t.Fatal("retirement/reopen lost result", err)
			}
		})
	}
}

func killPruneExecutorChild(t *testing.T, f *pruneFixture, stage string, initializing bool) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "reached")
	request, _ := f.request.CanonicalBytes()
	admission, _ := f.admission.CanonicalBytes()
	command := exec.Command(os.Args[0], "-test.run=^TestPruneExecutorCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_PRUNE_STAGE="+stage, "OUTCOMEMESH_PRUNE_EXECUTOR="+f.executorPath,
		"OUTCOMEMESH_PRUNE_AUTHORITY="+f.authorityPath, "OUTCOMEMESH_PRUNE_PINS="+f.pinsPath, "OUTCOMEMESH_PRUNE_CHAIN="+f.chainPath,
		"OUTCOMEMESH_PRUNE_REQUEST="+hex.EncodeToString(request), "OUTCOMEMESH_PRUNE_ADMISSION="+hex.EncodeToString(admission), "OUTCOMEMESH_PRUNE_MARKER="+marker)
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
			t.Fatalf("helper exited before %s: %v\n%s", stage, exitErr, output.String())
		case <-deadline.C:
			_ = command.Process.Kill()
			<-done
			t.Fatalf("helper did not reach %s\n%s", stage, output.String())
		case <-ticker.C:
			_, err := os.Stat(marker)
			reached = err == nil
		}
	}
	if opened, err := OpenPruneExecutor(f.executorPath, testAssignment(), f.id); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("live process lost executor ownership", err)
	}
	if !initializing {
		if opened, err := OpenCoordinator(f.authorityPath, f.pinsPath, testAssignment(), testAssignmentID(t)); !errors.Is(err, ErrBusy) {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatal("live authority owner lost", err)
		}
	}
	before, err := os.Lstat(filepath.Join(f.executorPath, pruneLockName))
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	if exitErr == nil {
		t.Fatal("helper was not killed")
	}
	after, err := os.Lstat(filepath.Join(f.executorPath, pruneLockName))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("kill replaced permanent lock")
	}
	if _, err := os.Lstat(marker + ".ack"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("helper returned before kill")
	}
}

func TestPruneExecutorCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_PRUNE_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_PRUNE_REQUEST"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodePruneRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	id, err := request.ID()
	if err != nil {
		t.Fatal(err)
	}
	path, marker := os.Getenv("OUTCOMEMESH_PRUNE_EXECUTOR"), os.Getenv("OUTCOMEMESH_PRUNE_MARKER")
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, marker, []byte(stage))
			select {}
		}
		return nil
	}}
	if strings.Contains(stage, "ready") {
		created, err := createPruneExecutor(path, testAssignment(), request, id, hooks)
		if created != nil {
			_ = created.Close()
		}
		writeTestFile(t, marker+".ack", nil)
		t.Fatal("initialization returned before kill", err)
	}
	executor, err := OpenPruneExecutor(path, testAssignment(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close()
	executor.hooks = hooks
	coordinator, err := OpenCoordinator(os.Getenv("OUTCOMEMESH_PRUNE_AUTHORITY"), os.Getenv("OUTCOMEMESH_PRUNE_PINS"), testAssignment(), testAssignmentID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	base, parameters, policy := pruneChainConfig()
	chain, err := workchain.OpenWithPolicy(os.Getenv("OUTCOMEMESH_PRUNE_CHAIN"), base, parameters, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	if strings.HasPrefix(stage, "prune-admission-") {
		encoded, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_PRUNE_ADMISSION"))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.DecodeEntry(encoded)
		if err != nil {
			t.Fatal(err)
		}
		err = executor.BindAdmission(t.Context(), coordinator, entry)
	} else {
		_, err = executor.Execute(t.Context(), coordinator, chain, func() (uint64, error) { return 200, nil })
	}
	writeTestFile(t, marker+".ack", nil)
	t.Fatal("execution returned before kill", err)
}
