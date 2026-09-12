//go:build integration

package store

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestAdmissionOutboxProcessCrashAtomicity(t *testing.T) {
	for _, phase := range []string{"initial", "admitted", "stopping", "retired"} {
		stages := append([]string{"admission-outbox-before-send", "admission-outbox-reply-verified"}, admissionOutboxWriteStages()...)
		if phase == "initial" {
			stages = append(stages, "server-authority-confirming", "server-executor-confirming")
		}
		for _, stage := range stages {
			t.Run(phase+"/"+stage, func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				prepareAdmissionOutboxPhase(t, f, phase)
				server, client := completionHosts(t)
				intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: f.admission}
				outbox, path, id := newTestAdmissionOutbox(t, intent)
				_ = outbox.Close()
				reached, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				serverStage := stage == "server-authority-confirming" || stage == "server-executor-confirming"
				hook := func(at string) error {
					if stage == "server-authority-confirming" && at == "confirm-before-publish" ||
						stage == "server-executor-confirming" && at == "pins-admission-confirm-before-publish" {
						close(reached)
						<-release
					}
					return nil
				}
				setCoordinatorHooks(f.coordinator, storeHooks{at: hook})
				f.executor.pins.hooks.at = hook
				results := installAdmissionServer(t, f, server, client, nil)
				marker, stop := startAdmissionOutboxChild(t, path, id, stage, server.Addresses()[0], false)
				if serverStage {
					select {
					case <-reached:
					case <-time.After(15 * time.Second):
						t.Fatal("server did not reach confirmation")
					}
				} else {
					waitCompletionMarker(t, marker)
				}
				if other, err := OpenAdmissionOutbox(path, testAssignment(), id); !errors.Is(err, ErrBusy) {
					if other != nil {
						_ = other.Close()
					}
					t.Fatal("child lost journal ownership", err)
				}
				stop()
				unblock()
				if stage != "admission-outbox-before-send" {
					_ = awaitCompletionServe(t, results)
				}
				setCoordinatorHooks(f.coordinator, storeHooks{})
				f.executor.pins.hooks = storeHooks{}
				decided := phase != "initial" || stage != "admission-outbox-before-send"
				current, executor := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
				if decided {
					assertAdmissionOutboxPhase(t, f, phase)
				} else if current.Pending != nil || current.Authority.Sequence != 0 || executor.Stage != PrunePrepared || executor.Protection.Pending != nil {
					t.Fatal("client sent before durable intent boundary")
				}
				for range 2 {
					outbox = openTestAdmissionOutbox(t, path, id)
					s := testAdmissionOutboxSnapshot(t, outbox)
					if s.Intent != intent || (s.Acknowledgement != nil) != admissionOutboxHasReceipt(stage) {
						t.Fatal("client recovery changed outcome", s)
					}
					_ = outbox.Close()
				}
				if !reflect.DeepEqual(current, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(executor, pruneSnapshot(t, f.executor)) {
					t.Fatal("open changed server")
				}
				select {
				case <-results:
					t.Fatal("reopen sent admission")
				default:
				}
				outbox = openTestAdmissionOutbox(t, path, id)
				ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 5*time.Second)
				entryID, _ := intent.Entry.ID()
				if err != nil || ack.EntryID != entryID {
					t.Fatal("explicit client recovery", err)
				}
				if !admissionOutboxHasReceipt(stage) {
					if result := awaitCompletionServe(t, results); result.err != nil || result.commit.Appended == decided {
						t.Fatal("retry repeated server decision", result.err)
					}
				} else {
					select {
					case <-results:
						t.Fatal("durable local ACK sent again")
					default:
					}
				}
				if s := testAdmissionOutboxSnapshot(t, outbox); s.Acknowledgement == nil || *s.Acknowledgement != ack {
					t.Fatal("client success was not durable")
				}
				assertAdmissionOutboxPhase(t, f, phase)
				if decided && (!reflect.DeepEqual(current, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(executor, pruneSnapshot(t, f.executor))) {
					t.Fatal("historical retry changed server")
				}
			})
		}
	}
	for _, stage := range []string{"admission-outbox-before-ready", "admission-outbox-ready-file-synced", "admission-outbox-ready-directory-synced"} {
		t.Run("initialization/"+stage, func(t *testing.T) {
			intent := testAdmissionIntent(t)
			id, _ := intent.ID()
			path := t.TempDir() + "/outbox"
			marker, stop := startAdmissionOutboxChild(t, path, id, stage, "", true)
			waitCompletionMarker(t, marker)
			stop()
			if _, err := CreateAdmissionOutbox(path, testAssignment(), intent, id); !errors.Is(err, os.ErrExist) {
				t.Fatal("partial init recreated", err)
			}
			outbox, err := OpenAdmissionOutbox(path, testAssignment(), id)
			if outbox != nil {
				defer outbox.Close()
			}
			if stage == "admission-outbox-before-ready" {
				if err == nil || errors.Is(err, ErrBusy) {
					t.Fatal("incomplete init opened or lock retained", err)
				}
			} else if err != nil || testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
				t.Fatal("init recovery sent or failed", err)
			}
		})
	}
}

func startAdmissionOutboxChild(t *testing.T, path string, id types.Hash, stage, address string, initialize bool) (string, func()) {
	t.Helper()
	marker := t.TempDir() + "/reached"
	command := exec.Command(os.Args[0], "-test.run=^TestAdmissionOutboxCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_ADMISSION_OUTBOX_STAGE="+stage, "OUTCOMEMESH_ADMISSION_OUTBOX_PATH="+path,
		"OUTCOMEMESH_ADMISSION_OUTBOX_ID="+id.String(), "OUTCOMEMESH_ADMISSION_OUTBOX_MARKER="+marker, "OUTCOMEMESH_ADMISSION_OUTBOX_ADDRESS="+address)
	if initialize {
		command.Env = append(command.Env, "OUTCOMEMESH_ADMISSION_OUTBOX_INIT=1")
	}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			killErr := command.Process.Kill()
			err := <-done
			// Wait drains the output buffer before diagnostics read it. An
			// early helper failure is not evidence of a controlled crash.
			if killErr != nil || err == nil {
				t.Errorf("child missed controlled crash: kill=%v wait=%v output=%s", killErr, err, output.String())
			}
		})
	}
	t.Cleanup(stop)
	return marker, stop
}

func TestAdmissionOutboxCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_ADMISSION_OUTBOX_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	encodedID, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_ADMISSION_OUTBOX_ID"))
	if err != nil || len(encodedID) != types.HashSize {
		t.Fatal(err)
	}
	var id types.Hash
	copy(id[:], encodedID)
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_ADMISSION_OUTBOX_MARKER"), nil)
			select {}
		}
		return nil
	}}
	path := os.Getenv("OUTCOMEMESH_ADMISSION_OUTBOX_PATH")
	if os.Getenv("OUTCOMEMESH_ADMISSION_OUTBOX_INIT") == "1" {
		_, err := createAdmissionOutbox(path, testAssignment(), testAdmissionIntent(t), id, hooks)
		t.Fatal("initialization missed crash stage", err)
	}
	outbox, err := OpenAdmissionOutbox(path, testAssignment(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	outbox.hooks = hooks
	client, err := libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = outbox.Deliver(t.Context(), client, os.Getenv("OUTCOMEMESH_ADMISSION_OUTBOX_ADDRESS"), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("delivery missed crash stage")
}
