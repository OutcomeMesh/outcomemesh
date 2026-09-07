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

func TestCompletionOutboxProcessCrashAtomicity(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, mode := range []string{"initial", "retry"} {
			stages := append([]string{"outbox-before-send", "outbox-reply-verified"}, completionOutboxWriteStages()...)
			if mode == "initial" {
				stages = append(stages, "server-confirming")
			}
			for _, stage := range stages {
				t.Run(outcome+"/"+mode+"/"+stage, func(t *testing.T) {
					f := newPruneFixtureWithStorageID(t, testHash(91))
					finishPruneForCompletion(t, f, outcome)
					server, client := completionHosts(t)
					intent := CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: pruneCompletionEntry(t, f)}
					outbox, path, id := newTestOutbox(t, intent)
					terminal := pruneSnapshot(t, f.executor)
					if mode == "retry" {
						// Model a previous successful server decision with no local
						// receipt. The child must retry the retained command unchanged.
						if _, err := f.executor.Complete(t.Context(), f.coordinator, intent.Entry); err != nil {
							t.Fatal(err)
						}
					}
					_ = outbox.Close()
					reached, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					t.Cleanup(unblock)
					if stage == "server-confirming" {
						setCoordinatorHooks(f.coordinator, storeHooks{at: func(at string) error {
							if at == "confirm-before-publish" {
								close(reached)
								<-release
							}
							return nil
						}})
					}
					results := installCompletionServer(t, f, server, client, nil)
					marker, stop := startCompletionOutboxChild(t, path, id, stage, server.Addresses()[0], false)
					if stage == "server-confirming" {
						select {
						case <-reached:
						case <-time.After(15 * time.Second):
							t.Fatal("server did not reach confirmation")
						}
					} else {
						waitCompletionMarker(t, marker)
					}
					if other, err := OpenCompletionOutbox(path, testAssignment(), id); !errors.Is(err, ErrBusy) {
						if other != nil {
							_ = other.Close()
						}
						t.Fatal("child lost journal ownership", err)
					}
					stop()
					unblock()
					if stage != "outbox-before-send" {
						_ = awaitCompletionServe(t, results)
					}
					setCoordinatorHooks(f.coordinator, storeHooks{})
					decided := mode == "retry" || stage != "outbox-before-send"
					current := testCoordination(t, f.coordinator)
					if current.Pending != nil || (current.Authority.Pending == 0) != decided {
						t.Fatal("client death discarded server decision")
					}
					for range 2 {
						outbox = openTestOutbox(t, path, id)
						s := testOutboxSnapshot(t, outbox)
						if s.Intent != intent || (s.Acknowledgement != nil) != completionOutboxHasReceipt(stage) {
							t.Fatal("client recovery changed outcome", s)
						}
						_ = outbox.Close()
					}
					select {
					case <-results:
						t.Fatal("reopen sent completion")
					default:
					}
					outbox = openTestOutbox(t, path, id)
					ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 5*time.Second)
					entryID, _ := intent.Entry.ID()
					if err != nil || ack.EntryID != entryID {
						t.Fatal("explicit client recovery", err)
					}
					if !completionOutboxHasReceipt(stage) {
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
					if s := testOutboxSnapshot(t, outbox); s.Acknowledgement == nil || *s.Acknowledgement != ack {
						t.Fatal("client success was not durable")
					}
					if c := testCoordination(t, f.coordinator); c.Authority.Sequence != 2 || c.Authority.Pending != 0 || c.Pending != nil {
						t.Fatal("client recovery changed authority")
					}
					if !reflect.DeepEqual(terminal, pruneSnapshot(t, f.executor)) {
						t.Fatal("client crash replayed effect")
					}
				})
			}
		}
	}
	for _, stage := range []string{"outbox-before-ready", "outbox-ready-file-synced", "outbox-ready-directory-synced"} {
		t.Run("initialization/"+stage, func(t *testing.T) {
			intent := testCompletionIntent(t)
			id, _ := intent.ID()
			path := t.TempDir() + "/outbox"
			marker, stop := startCompletionOutboxChild(t, path, id, stage, "", true)
			waitCompletionMarker(t, marker)
			stop()
			if _, err := CreateCompletionOutbox(path, testAssignment(), intent, id); !errors.Is(err, os.ErrExist) {
				t.Fatal("partial init recreated", err)
			}
			outbox, err := OpenCompletionOutbox(path, testAssignment(), id)
			if outbox != nil {
				defer outbox.Close()
			}
			if stage == "outbox-before-ready" {
				if err == nil || errors.Is(err, ErrBusy) {
					t.Fatal("incomplete init opened or lock retained", err)
				}
			} else if err != nil || testOutboxSnapshot(t, outbox).Acknowledgement != nil {
				t.Fatal("init recovery sent or failed", err)
			}
		})
	}
}

func startCompletionOutboxChild(t *testing.T, path string, id types.Hash, stage, address string, initialize bool) (string, func()) {
	t.Helper()
	marker := t.TempDir() + "/reached"
	command := exec.Command(os.Args[0], "-test.run=^TestCompletionOutboxCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_OUTBOX_STAGE="+stage, "OUTCOMEMESH_OUTBOX_PATH="+path,
		"OUTCOMEMESH_OUTBOX_ID="+id.String(), "OUTCOMEMESH_OUTBOX_MARKER="+marker, "OUTCOMEMESH_OUTBOX_ADDRESS="+address)
	if initialize {
		command.Env = append(command.Env, "OUTCOMEMESH_OUTBOX_INIT=1")
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
			_ = command.Process.Kill()
			err := <-done
			if err == nil {
				t.Errorf("child exited without crash: %s", output.String())
			}
		})
	}
	t.Cleanup(stop)
	return marker, stop
}

func TestCompletionOutboxCrashHelper(t *testing.T) {
	stage := os.Getenv("OUTCOMEMESH_OUTBOX_STAGE")
	if stage == "" {
		t.Skip("subprocess helper")
	}
	encodedID, err := hex.DecodeString(os.Getenv("OUTCOMEMESH_OUTBOX_ID"))
	if err != nil || len(encodedID) != types.HashSize {
		t.Fatal(err)
	}
	var id types.Hash
	copy(id[:], encodedID)
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_OUTBOX_MARKER"), nil)
			select {}
		}
		return nil
	}}
	path := os.Getenv("OUTCOMEMESH_OUTBOX_PATH")
	if os.Getenv("OUTCOMEMESH_OUTBOX_INIT") == "1" {
		_, err := createCompletionOutbox(path, testAssignment(), testCompletionIntent(t), id, hooks)
		t.Fatal("initialization missed crash stage", err)
	}
	outbox, err := OpenCompletionOutbox(path, testAssignment(), id)
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
	_, err = outbox.Deliver(t.Context(), client, os.Getenv("OUTCOMEMESH_OUTBOX_ADDRESS"), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("delivery missed crash stage")
}
