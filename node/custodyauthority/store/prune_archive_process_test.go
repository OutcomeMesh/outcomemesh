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

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// JSON is disposable subprocess TEST configuration, never an operator, journal,
// protocol or consensus encoding. All fixture roots/keys are local test data.
type archiveProcessConfig struct {
	Policy                                                   ArchivePrunePolicy
	PolicyID                                                 types.Hash
	Executor, ExecutorPins, Database, DatabasePins, Evidence string
	Replicas                                                 []workarchive.Replica
	Authorities                                              []archiveProcessAuthority
}
type archiveProcessAuthority struct {
	Path, Pins string
	Binding    OperationBinding
}

func archiveProcessInputs(p *archivePruneFixture) archiveProcessConfig {
	c := archiveProcessConfig{Policy: p.policy, PolicyID: p.policyID, Executor: p.f.executorPath, ExecutorPins: p.f.executorPinsPath,
		Database: p.f.chainPath, DatabasePins: p.f.chainPositionPinsPath, Evidence: p.path, Replicas: p.replicas}
	for _, operation := range p.operations {
		c.Authorities = append(c.Authorities, archiveProcessAuthority{operation.Coordinator.authority.path, operation.Coordinator.journal.path, operation.Binding})
	}
	return c
}

func closeArchiveProcess(p *archivePruneFixture) {
	_ = p.f.executor.Close()
	_ = p.f.chain.Close()
	for _, operation := range p.operations {
		_ = operation.Coordinator.Close()
	}
}

func openArchiveProcess(t testing.TB, config archiveProcessConfig) *archivePruneFixture {
	t.Helper()
	f := &pruneFixture{executorPath: config.Executor, executorPinsPath: config.ExecutorPins, chainPath: config.Database, chainPositionPinsPath: config.DatabasePins, id: config.Policy.RequestID}
	f.base, f.parameters, f.policy = pruneChainConfig()
	var err error
	f.executor, err = OpenPinnedPruneExecutor(config.Executor, config.ExecutorPins, config.Policy.Assignments[0], f.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.executor.Close() })
	execution := pruneSnapshot(t, f.executor)
	f.request = execution.Request
	if execution.Admission != nil {
		f.admission = *execution.Admission
	}
	f.chain, err = workchain.OpenPositionPinnedWithPolicy(config.Database, config.DatabasePins, f.base, f.parameters, f.policy, f.request.StorageID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.chain.Close() })
	p := &archivePruneFixture{f: f, policy: config.Policy, policyID: config.PolicyID, replicas: config.Replicas, path: config.Evidence}
	for i, authority := range config.Authorities {
		c, err := OpenCoordinator(authority.Path, authority.Pins, config.Policy.Assignments[i], authority.Binding.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		p.operations = append(p.operations, RequiredOperation{c, authority.Binding})
		if i == 0 {
			f.coordinator, f.authorityPath, f.pinsPath = c, authority.Path, authority.Pins
		}
	}
	return p
}

func TestPruneArchiveProcessRecovery(t *testing.T) {
	for _, stage := range []string{"archive-before-verification", "archive-before-start", "prune-before-effect", "prune-after-effect", "pins-result-confirm-before-publish", "archive-done"} {
		t.Run(stage, func(t *testing.T) {
			p := newArchivePruneFixture(t)
			config := archiveProcessInputs(p)
			before, _, err := p.f.chain.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			closeArchiveProcess(p)
			file, marker := filepath.Join(t.TempDir(), "fixture.json"), filepath.Join(t.TempDir(), "reached")
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, file, encoded)
			command := exec.Command(os.Args[0], "-test.run=^TestPruneArchiveCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "OUTCOMEMESH_ARCHIVE_PRUNE_FIXTURE="+file, "OUTCOMEMESH_ARCHIVE_PRUNE_STAGE="+stage, "OUTCOMEMESH_ARCHIVE_PRUNE_MARKER="+marker)
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
		wait:
			for {
				if _, err := os.Stat(marker); err == nil {
					break wait
				}
				select {
				case <-done:
					t.Fatal("child exited early", exitErr, output.String())
				case <-deadline.C:
					_ = command.Process.Kill()
					<-done
					t.Fatal("checkpoint not reached", output.String())
				case <-tick.C:
				}
			}
			for i, authority := range config.Authorities {
				other, err := OpenCoordinator(authority.Path, authority.Pins, config.Policy.Assignments[i], authority.Binding.AssignmentID)
				if other != nil {
					_ = other.Close()
				}
				if !errors.Is(err, ErrBusy) {
					t.Fatal("child lost authority ownership", err)
				}
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-done
			if exitErr == nil {
				t.Fatal("child missed forced termination")
			}
			wantStage := PruneStarted
			if stage == "archive-before-verification" || stage == "archive-before-start" {
				wantStage = PruneAdmitted
			}
			if stage == "pins-result-confirm-before-publish" || stage == "archive-done" {
				wantStage = PruneSucceeded
			}
			hasEffect := stage == "prune-after-effect" || wantStage == PruneSucceeded
			var previous PruneExecution
			for attempt := range 2 {
				p = openArchiveProcess(t, config)
				state := pruneSnapshot(t, p.f.executor)
				if state.Stage != wantStage || (state.Protection.Pending != nil) != (stage == "pins-result-confirm-before-publish") {
					t.Fatal("crash changed retained stage", state.Stage)
				}
				if attempt == 1 && !reflect.DeepEqual(state, previous) {
					t.Fatal("open promoted executor")
				}
				previous = state
				_, found, err := p.f.chain.CanonicalPruneEffect(p.operations[0].Binding.TicketID)
				if err != nil || found != hasEffect {
					t.Fatal("wrong atomic effect", found, err)
				}
				for _, operation := range p.operations {
					if s := testCoordination(t, operation.Coordinator); s.Pending != nil || s.Authority.Sequence != 1 || s.Authority.Pending != 1 {
						t.Fatal("open completed authority")
					}
				}
				if !hasEffect {
					if after, _, err := p.f.chain.HistoryUsage(); err != nil || after != before {
						t.Fatal("no-effect crash changed chain", err)
					}
				}
				if attempt == 1 && wantStage == PruneStarted {
					if _, err := p.execute(t.Context()); !errors.Is(err, ErrPruneOutcome) {
						t.Fatal("started work reexecuted", err)
					}
					historical, err := p.f.executor.Recover(t.Context(), p.f.chain)
					if hasEffect {
						if err != nil || historical.Applied {
							t.Fatal("positive recovery reexecuted", err)
						}
					} else if !errors.Is(err, ErrPruneOutcome) {
						t.Fatal("absence settled unknown work", err)
					}
				}
				closeArchiveProcess(p)
			}
		})
	}
}

func TestPruneArchiveCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_ARCHIVE_PRUNE_FIXTURE")
	if file == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := readRegular(file, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var config archiveProcessConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	p := openArchiveProcess(t, config)
	reach := func(at string) error {
		if at == os.Getenv("OUTCOMEMESH_ARCHIVE_PRUNE_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_ARCHIVE_PRUNE_MARKER"), nil)
			select {}
		}
		return nil
	}
	p.f.executor.hooks, p.f.executor.pins.hooks = storeHooks{at: reach}, storeHooks{at: reach}
	if _, err := p.execute(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = reach("archive-done")
	t.Fatal("child missed controlled checkpoint")
}
