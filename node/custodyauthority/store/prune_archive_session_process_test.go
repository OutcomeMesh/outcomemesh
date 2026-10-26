//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// These are disposable child-process fixture bytes, not a new operator format.
// The command and client outbox are fixed before any child network exchange.
type archiveSecondaryNetworkProcessConfig struct {
	Archive archiveProcessConfig
	Admit   bool
	Entry   custodyauthority.Entry
}

func TestArchiveSecondaryQUICProcessRecovery(t *testing.T) {
	for _, outcome := range []string{"admit", "succeeded", "cancelled"} {
		prefix := "completion"
		if outcome == "admit" {
			prefix = "admission"
		}
		for _, stage := range []string{prefix + "-request", "intent-after-apply", "authority-after-apply", "confirm-before-publish", prefix + "-confirmed", prefix + "-replied"} {
			t.Run(outcome+"/"+stage, func(t *testing.T) {
				p, inventory := newArchiveSecondaryFixture(t, nil)
				entry := inventory.Admissions[1]
				admit := outcome == "admit"
				if !admit {
					if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
						t.Fatal(err)
					}
					if outcome == "cancelled" {
						if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
							t.Fatal(err)
						}
					} else if commit, err := p.execute(t.Context()); err != nil || !commit.Applied {
						t.Fatal("failed to retain primary result", err)
					}
					execution := pruneSnapshot(t, p.f.executor)
					var evidence types.Hash
					if execution.Cancellation != nil {
						evidence, _ = execution.Cancellation.ID()
					} else {
						evidence, _ = execution.Effect.ID()
					}
					entry = testEntry(t, testCoordination(t, p.operations[1].Coordinator).Authority,
						custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, evidence)
				}
				secondaryBefore := testCoordination(t, p.operations[1].Coordinator).Authority
				model, err := custodyauthority.NewState(p.policy.Assignments[1], p.operations[1].Binding.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				if !admit {
					if err := model.Apply(inventory.Admissions[1]); err != nil {
						t.Fatal(err)
					}
				}
				if err := model.Apply(entry); err != nil {
					t.Fatal(err)
				}
				secondaryAfter, _ := model.Snapshot()
				executionBefore, primaryBefore := pruneSnapshot(t, p.f.executor), testCoordination(t, p.f.coordinator)
				usage, _, err := p.f.chain.HistoryUsage()
				if err != nil {
					t.Fatal(err)
				}
				effect, foundEffect, err := p.f.chain.CanonicalPruneEffect(p.operations[0].Binding.TicketID)
				if err != nil {
					t.Fatal(err)
				}
				config := archiveSecondaryNetworkProcessConfig{Archive: archiveProcessInputs(p), Admit: admit, Entry: entry}
				transportConfig := archiveSecondarySessionConfig(p)
				outboxPath := filepath.Join(t.TempDir(), "client-outbox")
				var admission *AdmissionOutbox
				var completion *CompletionOutbox
				var intentID types.Hash
				if admit {
					intent := AdmissionIntent{ClientPeerID: transportConfig.ClientPeerID, ServerPeerID: transportConfig.ServerPeerID, Entry: entry}
					intentID, _ = intent.ID()
					admission, err = CreateAdmissionOutbox(outboxPath, p.policy.Assignments[1], intent, intentID)
				} else {
					intent := CompletionIntent{ClientPeerID: transportConfig.ClientPeerID, ServerPeerID: transportConfig.ServerPeerID, Entry: entry}
					intentID, _ = intent.ID()
					completion, err = CreateCompletionOutbox(outboxPath, p.policy.Assignments[1], intent, intentID)
				}
				if err != nil {
					t.Fatal(err)
				}
				deliver := func(client *libp2ptransport.Host, address string) error {
					if admit {
						_, err := admission.Deliver(t.Context(), client, address, 10*time.Second)
						return err
					}
					_, err := completion.Deliver(t.Context(), client, address, 10*time.Second)
					return err
				}
				t.Cleanup(func() {
					if admission != nil {
						_ = admission.Close()
					}
					if completion != nil {
						_ = completion.Close()
					}
				})
				closeArchiveProcess(p)
				client, err := libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				address, marker, stop := startArchiveSecondaryQUICChild(t, config, stage)
				reply := make(chan error, 1)
				go func() { reply <- deliver(client, address) }()
				waitCompletionMarker(t, marker+".reached")
				opened, err := OpenPinnedPruneExecutor(config.Archive.Executor, config.Archive.ExecutorPins,
					config.Archive.Policy.Assignments[0], config.Archive.Policy.RequestID)
				if opened != nil {
					_ = opened.Close()
				}
				if !errors.Is(err, ErrBusy) {
					t.Fatal("child lost executor ownership", err)
				}
				for i, authority := range config.Archive.Authorities {
					opened, err := OpenCoordinator(authority.Path, authority.Pins, config.Archive.Policy.Assignments[i], authority.Binding.AssignmentID)
					if opened != nil {
						_ = opened.Close()
					}
					if !errors.Is(err, ErrBusy) {
						t.Fatal("child lost original authority ownership", err)
					}
				}
				stop()
				_ = client.Close() // explicitly retire the dead QUIC connection
				deliveryErr := <-reply
				if stage != prefix+"-replied" {
					unconfirmed := admissionwire.ErrUnconfirmed
					if !admit {
						unconfirmed = completionwire.ErrUnconfirmed
					}
					if !errors.Is(deliveryErr, unconfirmed) {
						t.Fatal("lost reply claimed a confirmed delivery", deliveryErr)
					}
				} else if deliveryErr != nil && !errors.Is(deliveryErr, admissionwire.ErrUnconfirmed) && !errors.Is(deliveryErr, completionwire.ErrUnconfirmed) {
					t.Fatal("unexpected final-ACK race result", deliveryErr)
				}
				if admit {
					_ = admission.Close()
				} else {
					_ = completion.Close()
				}
				prepared := stage != prefix+"-request"
				decided := prepared && stage != "intent-after-apply"
				confirmed := stage == prefix+"-confirmed" || stage == prefix+"-replied"
				checkUnchanged := func(p *archivePruneFixture) {
					t.Helper()
					if !reflect.DeepEqual(executionBefore, pruneSnapshot(t, p.f.executor)) || !reflect.DeepEqual(primaryBefore, testCoordination(t, p.f.coordinator)) {
						t.Fatal("secondary network command changed primary/executor")
					}
					if after, _, err := p.f.chain.HistoryUsage(); err != nil || after != usage {
						t.Fatal("secondary network command changed history", err)
					}
					got, found, err := p.f.chain.CanonicalPruneEffect(p.operations[0].Binding.TicketID)
					if err != nil || found != foundEffect || !reflect.DeepEqual(got, effect) {
						t.Fatal("secondary network command changed database effect", err)
					}
				}
				for range 2 {
					p = openArchiveProcess(t, config.Archive)
					checkRecoveredCoordination(t, p.operations[1].Coordinator, entry, secondaryBefore, secondaryAfter, prepared, decided, confirmed)
					checkUnchanged(p)
					closeArchiveProcess(p)
					if admit {
						admission, err = OpenAdmissionOutbox(outboxPath, config.Archive.Policy.Assignments[1], intentID)
						if err == nil {
							state, err := admission.Snapshot()
							if err != nil || state.Intent.Entry != entry || deliveryErr != nil && state.Acknowledgement != nil {
								t.Fatal("reopen invented or changed admission receipt", err)
							}
							_ = admission.Close()
						}
					} else {
						completion, err = OpenCompletionOutbox(outboxPath, config.Archive.Policy.Assignments[1], intentID)
						if err == nil {
							state, err := completion.Snapshot()
							if err != nil || state.Intent.Entry != entry || deliveryErr != nil && state.Acknowledgement != nil {
								t.Fatal("reopen invented or changed completion receipt", err)
							}
							_ = completion.Close()
						}
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				address, _, stop = startArchiveSecondaryQUICChild(t, config, "retry")
				client, err = libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if admit {
					admission, err = OpenAdmissionOutbox(outboxPath, config.Archive.Policy.Assignments[1], intentID)
				} else {
					completion, err = OpenCompletionOutbox(outboxPath, config.Archive.Policy.Assignments[1], intentID)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := deliver(client, address); err != nil {
					t.Fatal("exact retained outbox retry failed", err)
				}
				stop()
				_ = client.Close()
				entryID, _ := entry.ID()
				if admit {
					before, err := admission.Snapshot()
					if err != nil || before.Intent.Entry != entry || before.Acknowledgement == nil ||
						before.Acknowledgement.EntryID != entryID || before.Acknowledgement.Nonce.IsZero() {
						t.Fatal("exact retry did not retain the checked admission receipt", err)
					}
					if err := deliver(client, "offline-route-after-server-close"); err != nil {
						t.Fatal("historical admission receipt required another live exchange", err)
					}
					after, err := admission.Snapshot()
					if err != nil || !reflect.DeepEqual(before, after) {
						t.Fatal("cached admission observation changed retained intent/receipt", err)
					}
				} else {
					before, err := completion.Snapshot()
					if err != nil || before.Intent.Entry != entry || before.Acknowledgement == nil ||
						before.Acknowledgement.EntryID != entryID || before.Acknowledgement.Nonce.IsZero() {
						t.Fatal("exact retry did not retain the checked completion receipt", err)
					}
					if err := deliver(client, "offline-route-after-server-close"); err != nil {
						t.Fatal("historical completion receipt required another live exchange", err)
					}
					after, err := completion.Snapshot()
					if err != nil || !reflect.DeepEqual(before, after) {
						t.Fatal("cached completion observation changed retained intent/receipt", err)
					}
				}
				p = openArchiveProcess(t, config.Archive)
				checkRecoveredCoordination(t, p.operations[1].Coordinator, entry, secondaryBefore, secondaryAfter, true, true, true)
				checkUnchanged(p)
				closeArchiveProcess(p)
			})
		}
	}
}

func startArchiveSecondaryQUICChild(t *testing.T, config archiveSecondaryNetworkProcessConfig, stage string) (string, string, func()) {
	t.Helper()
	file, marker := filepath.Join(t.TempDir(), "fixture.json"), filepath.Join(t.TempDir(), "secondary-network")
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, file, encoded)
	command := exec.Command(os.Args[0], "-test.run=^TestArchiveSecondaryQUICCrashHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OUTCOMEMESH_SECONDARY_NETWORK_FIXTURE="+file,
		"OUTCOMEMESH_SECONDARY_NETWORK_STAGE="+stage, "OUTCOMEMESH_SECONDARY_NETWORK_MARKER="+marker)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	var once sync.Once
	stop := func() { once.Do(func() { _ = command.Process.Kill(); <-done }) }
	t.Cleanup(stop)
	deadline, tick := time.NewTimer(15*time.Second), time.NewTicker(10*time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()
	for {
		if address, err := os.ReadFile(marker + ".ready"); err == nil {
			return string(address), marker, stop
		}
		select {
		case <-done:
			t.Fatal("secondary network child exited before readiness", output.String())
		case <-deadline.C:
			stop()
			t.Fatal("secondary network child not ready", output.String())
		case <-tick.C:
		}
	}
}

func TestArchiveSecondaryQUICCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_SECONDARY_NETWORK_FIXTURE")
	if file == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var config archiveSecondaryNetworkProcessConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal(err)
	}
	p := openArchiveProcess(t, config.Archive)
	scope := archiveSecondarySessionConfig(p)
	scope.Timeout = 10 * time.Second
	hook := func(at string) error {
		if at == os.Getenv("OUTCOMEMESH_SECONDARY_NETWORK_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_SECONDARY_NETWORK_MARKER")+".reached", nil)
			select {}
		}
		return nil
	}
	setCoordinatorHooks(p.operations[1].Coordinator, storeHooks{at: hook})
	p.f.executor.hooks.at = hook
	host, err := libp2ptransport.New(t.Context(), testKey(45), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if host.ID() != scope.ServerPeerID {
		t.Fatal("test server identity does not match its independent pin")
	}
	if config.Admit {
		server, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, scope)
		if err != nil {
			t.Fatal(err)
		}
		server.hooks.at = hook
		err = host.SetPruneAdmissionHandler(scope.ClientPeerID, func(ctx context.Context, peer types.Hash, stream network.Stream) {
			if _, err := server.Serve(ctx, peer, stream); err != nil {
				t.Log(err)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		server, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, scope)
		if err != nil {
			t.Fatal(err)
		}
		server.hooks.at = hook
		err = host.SetPruneCompletionHandler(scope.ClientPeerID, func(ctx context.Context, peer types.Hash, stream network.Stream) {
			if _, err := server.Serve(ctx, peer, stream); err != nil {
				t.Log(err)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	marker := os.Getenv("OUTCOMEMESH_SECONDARY_NETWORK_MARKER")
	if err := writeExclusive(marker+".staged", []byte(host.Addresses()[0])); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(marker+".staged", marker+".ready"); err != nil {
		t.Fatal(err)
	}
	select {}
}
