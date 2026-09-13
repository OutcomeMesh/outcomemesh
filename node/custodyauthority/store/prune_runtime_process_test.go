//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestPruneCommandRuntimeProcessRecovery(t *testing.T) {
	for _, phase := range []string{"prepared", "admitted", "cancelled", "succeeded", "retired"} {
		stages := []string{"opened", "started"}
		if phase == "prepared" || phase == "admitted" || phase == "retired" {
			stages = append(stages, "admission-confirmed")
		}
		if phase == "cancelled" || phase == "succeeded" || phase == "retired" {
			stages = append(stages, "completion-confirmed")
		}
		for _, stage := range stages {
			t.Run(phase+"/"+stage, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				var complete custodyauthority.Entry
				switch phase {
				case "prepared":
					prepareAdmissionOutboxPhase(t, f, "initial")
				case "admitted":
					prepareAdmissionOutboxPhase(t, f, "admitted")
				case "succeeded", "cancelled", "retired":
					outcome := phase
					if phase == "retired" {
						outcome = "cancelled"
					}
					finishPruneForCompletion(t, f, outcome)
					complete = pruneCompletionEntry(t, f)
					if phase == "retired" {
						if _, err := f.executor.Complete(t.Context(), f.coordinator, complete); err != nil {
							t.Fatal(err)
						}
						stop := f.stop(t)
						appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
					}
				}
				useCompletion := (phase == "succeeded" || phase == "cancelled" || phase == "retired") && stage != "admission-confirmed"
				var delivery PruneDeliveryConfig
				if useCompletion {
					intent := CompletionIntent{ClientPeerID: runtimePeer(46), ServerPeerID: runtimePeer(45), Entry: complete}
					outbox, path, id := newTestOutbox(t, intent)
					_ = outbox.Close()
					delivery = runtimeDeliveryConfig(path, id, "")
				} else {
					delivery = retainedRuntimeAdmit(t, f, "")
				}
				before, executor := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
				usage, _, err := f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				_ = f.executor.Close()
				_ = f.coordinator.Close()
				_ = f.chain.Close()
				address, marker, stop := startPruneRuntimeChild(t, f, stage)
				delivery.Address = address
				sent := stage == "admission-confirmed" || stage == "completion-confirmed"
				result := make(chan error, 1)
				if sent {
					go func() {
						if useCompletion {
							ack, err := DeliverPruneCompletion(t.Context(), testKey(46), delivery)
							if ack != (completionwire.Acknowledgement{}) {
								t.Error("pre-reply server death acknowledged completion")
							}
							result <- err
						} else {
							ack, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery)
							if ack != (admissionwire.Acknowledgement{}) {
								t.Error("pre-reply server death acknowledged admission")
							}
							result <- err
						}
					}()
				}
				waitCompletionMarker(t, marker+".reached")
				assertRuntimeOwnersBusy(t, f)
				stop()
				if sent {
					err := <-result
					if useCompletion && !errors.Is(err, completionwire.ErrUnconfirmed) || !useCompletion && !errors.Is(err, admissionwire.ErrUnconfirmed) {
						t.Fatal("missing reply settled client", err)
					}
				}
				wantSequence, wantPending := before.Authority.Sequence, before.Authority.Pending
				if stage == "admission-confirmed" && phase == "prepared" {
					wantSequence, wantPending = 1, 1
				}
				if stage == "completion-confirmed" && phase != "retired" {
					wantSequence, wantPending = 2, 0
				}
				for range 2 {
					f.reopen(t)
					c := testCoordination(t, f.coordinator)
					if c.Pending != nil || c.Authority.Sequence != wantSequence || c.Confirmed.Sequence != wantSequence || c.Authority.Pending != wantPending {
						t.Fatal("reopen changed confirmation", c)
					}
					if after, _, err := f.chain.HistoryUsage(); err != nil || after != usage {
						t.Fatal("command process changed chain", err)
					}
				}
				// Restart owns the same roots; it does not promote the client's
				// unresolved state or change either signed compare-and-append.
				s := openTestPruneService(t, f)
				delivery.Address = startTestPruneService(t, s)
				if useCompletion {
					ack, err := DeliverPruneCompletion(t.Context(), testKey(46), delivery)
					id, _ := complete.ID()
					if err != nil || ack.EntryID != id {
						t.Fatal("exact completion recovery failed", err)
					}
				} else {
					ack, err := DeliverPruneAdmission(t.Context(), testKey(46), delivery)
					id, _ := f.admission.ID()
					if err != nil || ack.EntryID != id {
						t.Fatal("exact admission recovery failed", err)
					}
				}
				c := testCoordination(t, s.coordinator)
				if phase == "prepared" {
					wantSequence, wantPending = 1, 1
				}
				if phase == "cancelled" || phase == "succeeded" {
					wantSequence, wantPending = 2, 0
				}
				if c.Pending != nil || c.Authority.Sequence != wantSequence || c.Authority.Pending != wantPending {
					t.Fatal("retry repeated decision", c)
				}
				if phase != "prepared" && !reflect.DeepEqual(executor, pruneSnapshot(t, s.executor)) {
					t.Fatal("retry changed executor")
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				f.reopen(t)
				if after, _, err := f.chain.HistoryUsage(); err != nil || after != usage {
					t.Fatal("runtime repeated effect", err)
				}
			})
		}
	}
}

func startPruneRuntimeChild(t *testing.T, f *pruneFixture, stage string) (string, string, func()) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "runtime")
	command := exec.Command(os.Args[0], "-test.run=^TestPruneCommandRuntimeCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_COMMAND_RUNTIME_STAGE="+stage, "OUTCOMEMESH_COMMAND_RUNTIME_MARKER="+marker,
		"OUTCOMEMESH_COMMAND_RUNTIME_EXECUTOR="+f.executorPath, "OUTCOMEMESH_COMMAND_RUNTIME_EXECUTOR_PINS="+f.executorPinsPath,
		"OUTCOMEMESH_COMMAND_RUNTIME_AUTHORITY="+f.authorityPath, "OUTCOMEMESH_COMMAND_RUNTIME_AUTHORITY_PINS="+f.pinsPath,
		"OUTCOMEMESH_COMMAND_RUNTIME_REQUEST_ID="+f.id.String())
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			killErr := command.Process.Kill()
			<-done // drain both output and exit before reading diagnostics
			if killErr != nil || waitErr == nil {
				t.Errorf("child missed controlled crash: kill=%v wait=%v output=%s", killErr, waitErr, output.String())
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if address, err := os.ReadFile(marker + ".ready"); err == nil {
			return string(address), marker, stop
		}
		select {
		case <-done:
			t.Fatalf("runtime child exited: %s", output.String())
		case <-deadline.C:
			stop()
			t.Fatalf("runtime child not ready: %s", output.String())
		case <-tick.C:
		}
	}
}

func TestPruneCommandRuntimeCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_COMMAND_RUNTIME_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_COMMAND_RUNTIME_REQUEST_ID"))
	if err != nil || len(encoded) != types.HashSize {
		t.Fatal("invalid external request ID", err)
	}
	var id types.Hash
	copy(id[:], encoded)
	config := PruneCommandServiceConfig{Assignment: testAssignment(), AssignmentID: testAssignmentID(t), RequestID: id,
		ServerPeerID: runtimePeer(45), ClientPeerID: runtimePeer(46), Timeout: 10 * time.Second,
		AuthorityPath: os.Getenv("OUTCOMEMESH_COMMAND_RUNTIME_AUTHORITY"), AuthorityPinsPath: os.Getenv("OUTCOMEMESH_COMMAND_RUNTIME_AUTHORITY_PINS"),
		ExecutorPath: os.Getenv("OUTCOMEMESH_COMMAND_RUNTIME_EXECUTOR"), ExecutorPinsPath: os.Getenv("OUTCOMEMESH_COMMAND_RUNTIME_EXECUTOR_PINS")}
	s, err := OpenPruneCommandService(config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	marker := os.Getenv("OUTCOMEMESH_COMMAND_RUNTIME_MARKER")
	reach := func(at string) error {
		if at == stage {
			writeTestFile(t, marker+".reached", nil)
			select {}
		}
		return nil
	}
	s.hooks.at = reach
	publish := func(address string) {
		if err := writeExclusive(marker+".staged", []byte(address)); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(marker+".staged", marker+".ready"); err != nil {
			t.Fatal(err)
		}
	}
	if stage == "opened" {
		publish("")
		_ = reach("opened")
	}
	if err := s.Start(context.Background(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	publish(s.Addresses()[0])
	_ = reach("started")
	if strings.HasPrefix(stage, "recovery-") {
		hooks := storeHooks{at: func(at string) error { return reach("recovery-" + at) }}
		s.executor.hooks, s.executor.pins.hooks = hooks, hooks
		setCoordinatorHooks(s.coordinator, hooks)
		owner, err := s.EnterMaintenance(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		review, id := recoveryReview(t, owner)
		if _, err := owner.Recover(context.Background(), id, review.Action); err != nil {
			t.Fatal(err)
		}
		t.Fatal("recovery helper missed controlled checkpoint")
	}
	if stage == "runtime-maintenance-drained" || strings.HasPrefix(stage, "maintenance-") {
		s.executor.hooks.at = func(at string) error { return reach("maintenance-" + at) }
		s.executor.pins.hooks.at = func(at string) error { return reach("maintenance-" + at) }
		owner, err := s.EnterMaintenance(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		review, err := owner.Review(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		id, err := review.ID()
		if err != nil {
			t.Fatal(err)
		}
		_ = reach("maintenance-reviewed")
		if _, err := owner.CancelBeforeStart(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		_ = reach("maintenance-cancelled")
		t.Fatal("maintenance helper missed controlled checkpoint")
	}
	select {
	case <-s.Done():
		t.Fatal("runtime stopped before controlled crash", s.Close())
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}
