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
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type scheduledDeliveryProcessConfig struct {
	Command         ScheduledPruneCommandConfig
	Assignment      custodyauthority.Assignment
	Intent          scheduledwire.Intent
	Outbox, Address string
}

func startScheduledDeliveryChild(t testing.TB, c scheduledDeliveryProcessConfig, stage, mode string) (string, func()) {
	t.Helper()
	root := t.TempDir()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "config"), raw)
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessPruneScheduledDeliveryHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "OUTCOMEMESH_SCHEDULED_CHILD="+root, "OUTCOMEMESH_SCHEDULED_STAGE="+stage, "OUTCOMEMESH_SCHEDULED_MODE="+mode)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			k := cmd.Process.Kill()
			err := cmd.Wait()
			if k != nil || err == nil {
				t.Errorf("child missed controlled crash: kill=%v wait=%v output=%s", k, err, output.String())
			}
		})
	}
	t.Cleanup(stop)
	return root, stop
}

func TestProcessPruneScheduledDeliveryRecovery(t *testing.T) {
	for _, stage := range []string{"scheduled-outbox-before-send", "scheduled-outbox-reply-verified", "scheduled-outbox-file-synced", "scheduled-outbox-after-publish", "scheduled-outbox-directory-synced", "scheduled-outbox-after-apply"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneOperatorFixture(t)
			c := f.config[0]
			server, client := completionHosts(t)
			intent := scheduledDeliveryIntent(t, c, server, client)
			id, _ := intent.ID()
			a, _ := f.plan.Replica(c.AssignmentID)
			path := filepath.Join(t.TempDir(), "outbox")
			outbox, err := CreateScheduledPruneOutbox(path, a.Assignment, intent, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := outbox.Close(); err != nil {
				t.Fatal(err)
			}
			results := installScheduledDelivery(t, c, intent, server, storeHooks{}, false)
			root, stop := startScheduledDeliveryChild(t, scheduledDeliveryProcessConfig{Command: c, Assignment: a.Assignment, Intent: intent, Outbox: path, Address: server.Addresses()[0]}, stage, "client")
			waitCompletionMarker(t, filepath.Join(root, "reached"))
			if other, err := OpenScheduledPruneOutbox(path, a.Assignment, id); !errors.Is(err, ErrBusy) {
				if other != nil {
					_ = other.Close()
				}
				t.Fatal("child did not own original outbox", err)
			}
			stop()
			if stage != "scheduled-outbox-before-send" {
				if err := awaitScheduledDelivery(t, results); err != nil {
					t.Fatal(err)
				}
			}
			before := scheduledOperatorReview(t, c)
			published := stage == "scheduled-outbox-after-publish" || stage == "scheduled-outbox-directory-synced" || stage == "scheduled-outbox-after-apply"
			for range 2 {
				outbox, err = OpenScheduledPruneOutbox(path, a.Assignment, id)
				if err != nil {
					t.Fatal(err)
				}
				s, err := outbox.Snapshot()
				if err != nil || s.Intent != intent || (s.Acknowledgement != nil) != published {
					t.Fatal("reopen changed retained receipt", err)
				}
				if err := outbox.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("open mutated original owners")
			}
			outbox, err = OpenScheduledPruneOutbox(path, a.Assignment, id)
			if err != nil {
				t.Fatal(err)
			}
			defer outbox.Close()
			if ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 3*time.Second); err != nil || ack.IntentID != id {
				t.Fatal(err)
			}
			if !published {
				if err := awaitScheduledDelivery(t, results); err != nil {
					t.Fatal(err)
				}
			}
			after := scheduledOperatorReview(t, c)
			if !after.Review.AlreadyApplied || after.Executor.Stage != PruneAdmitted {
				t.Fatal("explicit retry did not confirm admission")
			}
			if stage != "scheduled-outbox-before-send" && !reflect.DeepEqual(before, after) {
				t.Fatal("retry repeated original command")
			}
		})
	}
	for _, stage := range []string{"pins-admission-confirm-before-publish", "scheduled-delivery-confirmed"} {
		t.Run("server/"+stage, func(t *testing.T) {
			f := newScheduledPruneOperatorFixture(t)
			c := f.config[0]
			server, client := completionHosts(t)
			intent := scheduledDeliveryIntent(t, c, server, client)
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			root, stop := startScheduledDeliveryChild(t, scheduledDeliveryProcessConfig{Command: c, Intent: intent}, stage, "server")
			waitCompletionMarker(t, filepath.Join(root, "address"))
			address, err := os.ReadFile(filepath.Join(root, "address"))
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := client.DeliverScheduledPrune(t.Context(), string(address), intent.ServerPeerID, intent, 3*time.Second)
				done <- err
			}()
			waitCompletionMarker(t, filepath.Join(root, "reached"))
			stop()
			if err := <-done; err == nil {
				t.Fatal("killed server acknowledged")
			}
			// The killed QUIC connection is unresolved, not a route to the new
			// listener. An explicit retry creates a fresh transport, as the public
			// DeliverScheduledPrune wrapper does; no automatic retry is inferred.
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			client, err = libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			before := scheduledOperatorReview(t, c)
			cold, err := libp2ptransport.New(t.Context(), testKey(45), libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Close()
			results := installScheduledDelivery(t, c, intent, cold, storeHooks{}, false)
			_, err = client.DeliverScheduledPrune(t.Context(), cold.Addresses()[0], cold.ID(), intent, 3*time.Second)
			serverErr := awaitScheduledDelivery(t, results)
			if stage == "pins-admission-confirm-before-publish" {
				if err == nil || !errors.Is(serverErr, ErrPendingAttempt) {
					t.Fatal("cold server resumed unknown write", err, serverErr)
				}
				if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
					t.Fatal("cold request mutated held attempt")
				}
				if _, err := RunScheduledPruneCommand(t.Context(), c, "resume", before.Review.ReviewID); err != nil {
					t.Fatal(err)
				}
				if _, err := client.DeliverScheduledPrune(t.Context(), cold.Addresses()[0], cold.ID(), intent, 3*time.Second); err != nil {
					t.Fatal(err)
				}
				if err := awaitScheduledDelivery(t, results); err != nil {
					t.Fatal(err)
				}
			} else if err != nil || serverErr != nil || !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("confirmed cold retry failed", err, serverErr)
			}
		})
	}
}

func TestProcessPruneScheduledDeliveryHelper(t *testing.T) {
	root := os.Getenv("OUTCOMEMESH_SCHEDULED_CHILD")
	if root == "" {
		t.Skip("subprocess helper")
	}
	raw, err := os.ReadFile(filepath.Join(root, "config"))
	if err != nil {
		t.Fatal(err)
	}
	var c scheduledDeliveryProcessConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	id, _ := c.Intent.ID()
	stage := os.Getenv("OUTCOMEMESH_SCHEDULED_STAGE")
	hooks := storeHooks{at: func(at string) error {
		if at == stage {
			writeTestFile(t, filepath.Join(root, "reached"), nil)
			select {}
		}
		return nil
	}}
	if os.Getenv("OUTCOMEMESH_SCHEDULED_MODE") == "server" {
		host, err := libp2ptransport.New(t.Context(), testKey(45), libp2ptransport.DefaultConfig(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer host.Close()
		results := installScheduledDelivery(t, c.Command, c.Intent, host, hooks, false)
		writeTestFile(t, filepath.Join(root, "address"), []byte(host.Addresses()[0]))
		t.Fatal("server missed crash stage", <-results)
	}
	outbox, err := OpenScheduledPruneOutbox(c.Outbox, c.Assignment, id)
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
	_, err = outbox.Deliver(t.Context(), client, c.Address, 3*time.Second)
	t.Fatal("client missed crash stage", err)
}
