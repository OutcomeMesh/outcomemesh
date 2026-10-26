package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func archiveSecondarySessionConfig(p *archivePruneFixture) PreparedArchiveSecondaryCommandConfig {
	return PreparedArchiveSecondaryCommandConfig{InventoryPath: p.inventoryPath, InventoryID: p.inventoryID, PolicyID: p.policyID,
		AssignmentID: p.operations[1].Binding.AssignmentID, ServerPeerID: runtimePeer(45), ClientPeerID: runtimePeer(46), Timeout: 2 * time.Second}
}

func installArchiveSecondaryAdmission(t testing.TB, session *PruneAdmissionServer, server, client *libp2ptransport.Host,
	wrap func(network.Stream) admissionwire.Stream,
) <-chan completionServeResult {
	t.Helper()
	results := make(chan completionServeResult, 16)
	if err := server.SetPruneAdmissionHandler(client.ID(), func(ctx context.Context, peer types.Hash, stream network.Stream) {
		var rw admissionwire.Stream = stream
		if wrap != nil {
			rw = wrap(stream)
		}
		commit, err := session.Serve(ctx, peer, rw)
		results <- completionServeResult{commit, err}
	}); err != nil {
		t.Fatal(err)
	}
	return results
}

func installArchiveSecondaryCompletion(t testing.TB, session *PruneCompletionServer, server, client *libp2ptransport.Host,
	wrap func(network.Stream) completionwire.Stream,
) <-chan completionServeResult {
	t.Helper()
	results := make(chan completionServeResult, 16)
	if err := server.SetPruneCompletionHandler(client.ID(), func(ctx context.Context, peer types.Hash, stream network.Stream) {
		var rw completionwire.Stream = stream
		if wrap != nil {
			rw = wrap(stream)
		}
		commit, err := session.Serve(ctx, peer, rw)
		results <- completionServeResult{commit, err}
	}); err != nil {
		t.Fatal(err)
	}
	return results
}

func TestArchiveSecondaryQUICOutboxesBothOutcomesAndModes(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, lineage := range []bool{false, true} {
			t.Run(outcome+map[bool]string{false: "/initial", true: "/lineage"}[lineage], func(t *testing.T) {
				var renewals []int
				if lineage {
					renewals = []int{2, 1}
				}
				p, inventory := newArchiveSecondaryFixture(t, renewals)
				config := archiveSecondarySessionConfig(p)
				admission, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config)
				if err != nil {
					t.Fatal(err)
				}
				// Install Complete before any admission/result exists. It must
				// consult the live executor anew when a later request arrives.
				completion, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config)
				if err != nil {
					t.Fatal(err)
				}
				server, client := completionHosts(t)
				if server.ID() != config.ServerPeerID || client.ID() != config.ClientPeerID {
					t.Fatal("caller installed sessions on a different host identity")
				}
				admitted := installArchiveSecondaryAdmission(t, admission, server, client, nil)
				completed := installArchiveSecondaryCompletion(t, completion, server, client, nil)
				// The config is copied; a caller edit cannot redirect the session.
				config.InventoryPath, config.InventoryID, config.ClientPeerID = "missing", testHash(99), runtimePeer(47)
				before := pruneSnapshot(t, p.f.executor)
				intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: inventory.Admissions[1]}
				id, _ := intent.ID()
				outbox, err := CreateAdmissionOutbox(filepath.Join(t.TempDir(), "admit"), p.policy.Assignments[1], intent, id)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = outbox.Close() })
				ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
				if err != nil || ack.EntryID != p.operations[1].Binding.TicketID {
					t.Fatal("secondary delivery did not retain the selected ticket", err)
				}
				if result := awaitCompletionServe(t, admitted); result.err != nil || !result.commit.Appended || result.commit.Snapshot.Operations[0].OperationID != p.f.id {
					t.Fatal("secondary wire admission lost the original primary request", result.err)
				}
				if !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
					t.Fatal("wire admission changed executor history")
				}
				premature := testEntry(t, testCoordination(t, p.operations[1].Coordinator).Authority, custodyauthority.Complete,
					types.Hash{}, ack.EntryID, testHash(98))
				if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), premature, 2*time.Second); !errors.Is(err, completionwire.ErrUnconfirmed) {
					t.Fatal("preterminal Complete was acknowledged", err)
				}
				if result := awaitCompletionServe(t, completed); !errors.Is(result.err, ErrPruneStage) {
					t.Fatal("preterminal Complete reached a terminal branch", result.err)
				}
				if outcome == "cancelled" {
					if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
						t.Fatal(err)
					}
				} else if commit, err := p.execute(t.Context()); err != nil || !commit.Applied {
					t.Fatal("explicit guarded pruning failed", err)
				}
				terminal := pruneSnapshot(t, p.f.executor)
				if _, err := p.f.executor.Complete(t.Context(), p.f.coordinator, pruneCompletionEntry(t, p.f)); err != nil {
					t.Fatal(err)
				}
				if err := p.f.coordinator.Close(); err != nil {
					t.Fatal(err)
				}
				entry := archiveSecondaryCompletionEntry(t, p)
				completeIntent := CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: entry}
				completeID, _ := completeIntent.ID()
				completeBox, err := CreateCompletionOutbox(filepath.Join(t.TempDir(), "complete"), p.policy.Assignments[1], completeIntent, completeID)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = completeBox.Close() })
				completeAck, err := completeBox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
				entryID, _ := entry.ID()
				if err != nil || completeAck.EntryID != entryID {
					t.Fatal("secondary completion outbox did not observe confirmation", err)
				}
				if result := awaitCompletionServe(t, completed); result.err != nil || !result.commit.Appended || result.commit.Snapshot.Pending != 0 {
					t.Fatal("completion did not drain secondary", result.err)
				}
				cached, err := completeBox.Deliver(t.Context(), client, "offline", 2*time.Second)
				if err != nil || cached != completeAck {
					t.Fatal("confirmed outbox required a fresh exchange", err)
				}
				secondary := p.operations[1].Coordinator
				stop := appendCoordinated(t, secondary, testEntry(t, testCoordination(t, secondary).Authority,
					custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80)))
				appendCoordinated(t, secondary, testEntry(t, testCoordination(t, secondary).Authority,
					custodyauthority.Retire, types.Hash{}, types.Hash{}, stop.EntryID))
				// A newly constructed completion handler needs no live primary.
				completion, err = NewPreparedArchiveSecondaryCompletionServer(p.f.executor, secondary, archiveSecondarySessionConfig(p))
				if err != nil {
					t.Fatal(err)
				}
				completed = installArchiveSecondaryCompletion(t, completion, server, client, nil)
				retry, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second)
				if err != nil || retry.EntryID != completeAck.EntryID || retry.Nonce == completeAck.Nonce {
					t.Fatal("historical retry lost its exact entry/fresh exchange nonce", err)
				}
				if result := awaitCompletionServe(t, completed); result.err != nil || result.commit.Appended || result.commit.Snapshot.Phase != custodyauthority.Retired {
					t.Fatal("historical completion changed retired authority", result.err)
				}
				if !reflect.DeepEqual(terminal, pruneSnapshot(t, p.f.executor)) {
					t.Fatal("secondary wire completion changed executor outcome")
				}
			})
		}
	}
}

func TestArchiveSecondarySessionConstructorPinsAndPeerRoles(t *testing.T) {
	p, _ := newArchiveSecondaryFixture(t, nil)
	good := archiveSecondarySessionConfig(p)
	before := pruneSnapshot(t, p.f.executor)
	for _, mode := range []string{"inventory-pin", "policy-pin", "zero-target", "primary-target", "unknown-target", "zero-client", "same-peers", "zero-server", "short-timeout", "long-timeout", "missing-package"} {
		config := good
		switch mode {
		case "inventory-pin":
			config.InventoryID = testHash(99)
		case "policy-pin":
			config.PolicyID = testHash(99)
		case "zero-target":
			config.AssignmentID = types.Hash{}
		case "primary-target":
			config.AssignmentID = p.f.request.AssignmentID
		case "unknown-target":
			config.AssignmentID = testHash(99)
		case "zero-client":
			config.ClientPeerID = types.Hash{}
		case "same-peers":
			config.ClientPeerID = config.ServerPeerID
		case "zero-server":
			config.ServerPeerID = types.Hash{}
		case "short-timeout":
			config.Timeout = admissionwire.MinimumTimeout - 1
		case "long-timeout":
			config.Timeout = completionwire.MaximumTimeout + 1
		case "missing-package":
			config.InventoryPath = filepath.Join(t.TempDir(), "missing")
		}
		if _, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config); err == nil {
			t.Fatal("invalid admission configuration accepted", mode)
		}
		if _, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config); err == nil {
			t.Fatal("invalid completion configuration accepted", mode)
		}
	}
	// Test EVERY inventory assignment, including the other primary replica
	// which the target-only outbox role validator cannot see.
	for _, assignment := range p.policy.Assignments {
		keys := [][32]byte{assignment.AuthorityPublicKey, assignment.ReplicaPublicKey}
		keys = append(keys, assignment.Auditors...)
		for _, consumer := range assignment.Consumers {
			keys = append(keys, consumer.PublicKey)
		}
		for _, key := range keys {
			for _, serverRole := range []bool{false, true} {
				config := good
				peer := types.DomainHash("OMESH/p2p/ed25519/v0", key[:])
				if serverRole {
					config.ServerPeerID = peer
				} else {
					config.ClientPeerID = peer
				}
				if _, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config); !errors.Is(err, ErrPruneRuntime) {
					t.Fatal("inventory-wide admission peer role accepted", err)
				}
				if _, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config); !errors.Is(err, ErrPruneRuntime) {
					t.Fatal("inventory-wide completion peer role accepted", err)
				}
			}
		}
	}
	for _, key := range p.policy.CheckpointPolicy.TrustedAttestors {
		for _, serverRole := range []bool{false, true} {
			config := good
			peer := types.DomainHash("OMESH/p2p/ed25519/v0", key[:])
			if serverRole {
				config.ServerPeerID = peer
			} else {
				config.ClientPeerID = peer
			}
			if _, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config); !errors.Is(err, ErrPruneRuntime) {
				t.Fatal("checkpoint attestor reused as admission transport", err)
			}
			if _, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config); !errors.Is(err, ErrPruneRuntime) {
				t.Fatal("checkpoint attestor reused as completion transport", err)
			}
		}
	}
	if _, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.operations[1].Coordinator, p.operations[1].Coordinator, good); err == nil {
		t.Fatal("secondary replaced original primary owner")
	}
	if _, err := NewPreparedArchiveSecondaryAdmissionServer(nil, p.f.coordinator, p.operations[1].Coordinator, good); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, nil, good); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) || testCoordination(t, p.operations[1].Coordinator).Authority.Sequence != 0 {
		t.Fatal("constructing sessions changed owner history")
	}
}

func TestArchiveSecondarySessionRejectsUnselectedTrustedReplicaPeer(t *testing.T) {
	p, inventory := newArchiveSecondaryFixture(t, nil)
	inventory.Policy.ReplicaPolicy.TrustedReplicas = append(inventory.Policy.ReplicaPolicy.TrustedReplicas, testPublic(70))
	sort.Slice(inventory.Policy.ReplicaPolicy.TrustedReplicas, func(i, j int) bool {
		return bytes.Compare(inventory.Policy.ReplicaPolicy.TrustedReplicas[i][:], inventory.Policy.ReplicaPolicy.TrustedReplicas[j][:]) < 0
	})
	p.inventoryID, _ = inventory.ID()
	p.policyID, _ = inventory.PolicyID()
	p.inventoryPath = filepath.Join(t.TempDir(), "expanded-trust.ompi")
	if err := SaveArchivePruneInventoryFile(p.inventoryPath, inventory, p.inventoryID, p.policyID); err != nil {
		t.Fatal(err)
	}
	for _, serverRole := range []bool{false, true} {
		config := archiveSecondarySessionConfig(p)
		if serverRole {
			config.ServerPeerID = runtimePeer(70)
		} else {
			config.ClientPeerID = runtimePeer(70)
		}
		if _, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config); !errors.Is(err, ErrPruneRuntime) {
			t.Fatal("unselected trusted replica reused as admission peer", err)
		}
		if _, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config); !errors.Is(err, ErrPruneRuntime) {
			t.Fatal("unselected trusted replica reused as completion peer", err)
		}
	}
}

type archiveSecondaryPeerStream struct {
	reads  int
	closed bool
}

func (s *archiveSecondaryPeerStream) Read([]byte) (int, error)    { s.reads++; return 0, io.EOF }
func (s *archiveSecondaryPeerStream) Write([]byte) (int, error)   { return 0, io.ErrClosedPipe }
func (s *archiveSecondaryPeerStream) Close() error                { s.closed = true; return nil }
func (s *archiveSecondaryPeerStream) CloseWrite() error           { return nil }
func (s *archiveSecondaryPeerStream) SetDeadline(time.Time) error { return nil }

func TestArchiveSecondarySessionRejectsWrongAuthenticatedPeerBeforeRead(t *testing.T) {
	p, _ := newArchiveSecondaryFixture(t, nil)
	config := archiveSecondarySessionConfig(p)
	admit, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []types.Hash{{}, runtimePeer(47)} {
		stream := &archiveSecondaryPeerStream{}
		if _, err := admit.Serve(t.Context(), peer, stream); !errors.Is(err, admissionwire.ErrProtocol) || stream.reads != 0 || !stream.closed {
			t.Fatal("admission read an unauthenticated request", err)
		}
		stream = &archiveSecondaryPeerStream{}
		if _, err := complete.Serve(t.Context(), peer, stream); !errors.Is(err, completionwire.ErrProtocol) || stream.reads != 0 || !stream.closed {
			t.Fatal("completion read an unauthenticated request", err)
		}
	}
	if testCoordination(t, p.operations[1].Coordinator).Authority.Sequence != 0 {
		t.Fatal("wrong transport peer caused admission")
	}
}

func TestArchiveSecondaryQUICRequiresEOFAndFixedTarget(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, mode := range []string{"no-eof", "extra-byte", "second-request", "wrong-target"} {
			t.Run(map[bool]string{false: "admit/", true: "complete/"}[complete]+mode, func(t *testing.T) {
				p, inventory := newArchiveSecondaryFixture(t, nil)
				entry := inventory.Admissions[1]
				if complete {
					if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
						t.Fatal(err)
					}
					if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
						t.Fatal(err)
					}
					entry = archiveSecondaryCompletionEntry(t, p)
				}
				if mode == "wrong-target" {
					entry = inventory.Admissions[0]
					if complete {
						entry = pruneCompletionEntry(t, p.f)
					}
				}
				before, executor := testCoordination(t, p.operations[1].Coordinator), pruneSnapshot(t, p.f.executor)
				config := archiveSecondarySessionConfig(p)
				config.Timeout = 500 * time.Millisecond
				server, client := completionHosts(t)
				var results <-chan completionServeResult
				if complete {
					session, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config)
					if err != nil {
						t.Fatal(err)
					}
					results = installArchiveSecondaryCompletion(t, session, server, client, nil)
					stream, _, err := client.OpenPruneCompletionStream(t.Context(), server.Addresses()[0], server.ID())
					if err != nil {
						t.Fatal(err)
					}
					defer stream.Close()
					_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
					r := completionwire.Request{Nonce: testHash(93), Entry: entry}
					if err := completionwire.WriteRequest(stream, r); err != nil {
						t.Fatal(err)
					}
					if mode == "extra-byte" {
						_, _ = stream.Write([]byte{1})
					}
					if mode == "second-request" {
						_ = completionwire.WriteRequest(stream, r)
					}
					if mode != "no-eof" {
						_ = stream.CloseWrite()
					}
					if _, err := completionwire.ReadAcknowledgement(stream); err == nil {
						t.Fatal("invalid Complete got an ACK")
					}
				} else {
					session, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config)
					if err != nil {
						t.Fatal(err)
					}
					results = installArchiveSecondaryAdmission(t, session, server, client, nil)
					stream, _, err := client.OpenPruneAdmissionStream(t.Context(), server.Addresses()[0], server.ID())
					if err != nil {
						t.Fatal(err)
					}
					defer stream.Close()
					_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
					r := admissionwire.Request{Nonce: testHash(93), Entry: entry}
					if err := admissionwire.WriteRequest(stream, r); err != nil {
						t.Fatal(err)
					}
					if mode == "extra-byte" {
						_, _ = stream.Write([]byte{1})
					}
					if mode == "second-request" {
						_ = admissionwire.WriteRequest(stream, r)
					}
					if mode != "no-eof" {
						_ = stream.CloseWrite()
					}
					if _, err := admissionwire.ReadAcknowledgement(stream); err == nil {
						t.Fatal("invalid Admit got an ACK")
					}
				}
				if result := awaitCompletionServe(t, results); result.err == nil {
					t.Fatal("invalid request reached guarded success")
				}
				if !reflect.DeepEqual(before, testCoordination(t, p.operations[1].Coordinator)) || !reflect.DeepEqual(executor, pruneSnapshot(t, p.f.executor)) {
					t.Fatal("invalid or unclosed request changed history")
				}
			})
		}
	}
}

func TestArchiveSecondaryQUICReloadsInventoryOnEveryServe(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, mode := range []string{"missing", "changed"} {
			p, inventory := newArchiveSecondaryFixture(t, nil)
			entry := inventory.Admissions[1]
			if complete {
				if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
					t.Fatal(err)
				}
				if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
					t.Fatal(err)
				}
				entry = archiveSecondaryCompletionEntry(t, p)
			}
			config := archiveSecondarySessionConfig(p)
			admit, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config)
			if err != nil {
				t.Fatal(err)
			}
			completion, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config)
			if err != nil {
				t.Fatal(err)
			}
			server, client := completionHosts(t)
			var results <-chan completionServeResult
			if complete {
				results = installArchiveSecondaryCompletion(t, completion, server, client, nil)
			} else {
				results = installArchiveSecondaryAdmission(t, admit, server, client, nil)
			}
			before := testCoordination(t, p.operations[1].Coordinator)
			encoded, _ := inventory.CanonicalBytes()
			if mode == "missing" {
				if err := os.Rename(p.inventoryPath, p.inventoryPath+".retained"); err != nil {
					t.Fatal(err)
				}
			} else {
				writeTestFile(t, p.inventoryPath, []byte("changed after construction"))
			}
			if complete {
				if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); !errors.Is(err, completionwire.ErrUnconfirmed) {
					t.Fatal(err)
				}
			} else if _, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); !errors.Is(err, admissionwire.ErrUnconfirmed) {
				t.Fatal(err)
			}
			if result := awaitCompletionServe(t, results); result.err == nil || !reflect.DeepEqual(before, testCoordination(t, p.operations[1].Coordinator)) {
				t.Fatal("constructor observation replaced per-request validation", result.err)
			}
			if mode == "missing" {
				if err := os.Rename(p.inventoryPath+".retained", p.inventoryPath); err != nil {
					t.Fatal(err)
				}
			} else {
				writeTestFile(t, p.inventoryPath, encoded)
			}
			if complete {
				if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); err != nil {
					t.Fatal(err)
				}
			} else if _, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			if result := awaitCompletionServe(t, results); result.err != nil || !result.commit.Appended {
				t.Fatal("exact retry after restoring retained inventory failed", result.err)
			}
		}
	}
}

func TestArchiveSecondaryQUICLostReplyRetainsExactDecision(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			p, inventory := newArchiveSecondaryFixture(t, nil)
			entry := inventory.Admissions[1]
			if complete {
				if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
					t.Fatal(err)
				}
				if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
					t.Fatal(err)
				}
				entry = archiveSecondaryCompletionEntry(t, p)
			}
			config := archiveSecondarySessionConfig(p)
			server, client := completionHosts(t)
			var results <-chan completionServeResult
			if complete {
				session, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config)
				if err != nil {
					t.Fatal(err)
				}
				results = installArchiveSecondaryCompletion(t, session, server, client, func(s network.Stream) completionwire.Stream { return lostCompletionReply{s, partial} })
				if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); !errors.Is(err, completionwire.ErrUnconfirmed) {
					t.Fatal(err)
				}
			} else {
				session, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config)
				if err != nil {
					t.Fatal(err)
				}
				results = installArchiveSecondaryAdmission(t, session, server, client, func(s network.Stream) admissionwire.Stream { return lostCompletionReply{s, partial} })
				if _, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); !errors.Is(err, admissionwire.ErrUnconfirmed) {
					t.Fatal(err)
				}
			}
			if result := awaitCompletionServe(t, results); result.err == nil || !reflect.DeepEqual(result.commit, Commit{}) {
				t.Fatal("lost reply claimed a confirmed exchange", result.err)
			}
			state := testCoordination(t, p.operations[1].Coordinator)
			want := uint64(1)
			if complete {
				want = 2
			}
			if state.Pending != nil || state.Confirmed.Sequence != want || state.Authority.Sequence != want {
				t.Fatal("lost reply discarded independently confirmed decision")
			}
			reopenArchiveSecondary(t, p)
			if complete {
				session, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, config)
				if err != nil {
					t.Fatal(err)
				}
				results = installArchiveSecondaryCompletion(t, session, server, client, nil)
				if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); err != nil {
					t.Fatal(err)
				}
			} else {
				session, err := NewPreparedArchiveSecondaryAdmissionServer(p.f.executor, p.f.coordinator, p.operations[1].Coordinator, config)
				if err != nil {
					t.Fatal(err)
				}
				results = installArchiveSecondaryAdmission(t, session, server, client, nil)
				if _, err := client.AdmitPrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			if result := awaitCompletionServe(t, results); result.err != nil || result.commit.Appended {
				t.Fatal("lost reply retry duplicated decision", result.err)
			}
		}
	}
}

func TestArchiveSecondaryQUICDoesNotCompleteUnknownOrPendingExecutor(t *testing.T) {
	for _, point := range []string{"prune-before-effect", "pins-cancel-confirm-before-publish"} {
		p, inventory := newArchiveSecondaryFixture(t, nil)
		if _, err := admitArchiveSecondary(t.Context(), p, inventory); err != nil {
			t.Fatal(err)
		}
		fault := errors.New("retain incomplete executor transition")
		hook := func(stage string) error {
			if stage == point {
				return fault
			}
			return nil
		}
		p.f.executor.hooks.at, p.f.executor.pins.hooks.at = hook, hook
		var err error
		if point == "prune-before-effect" {
			_, err = p.execute(t.Context())
		} else {
			_, err = p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator)
		}
		if !errors.Is(err, fault) {
			t.Fatal("executor boundary missed", err)
		}
		reopenArchiveSecondary(t, p)
		session, err := NewPreparedArchiveSecondaryCompletionServer(p.f.executor, p.operations[1].Coordinator, archiveSecondarySessionConfig(p))
		if err != nil {
			t.Fatal("constructor resolved or rejected mutable executor state", err)
		}
		state := pruneSnapshot(t, p.f.executor)
		evidence := testHash(99)
		if state.Cancellation != nil {
			evidence, _ = state.Cancellation.ID()
		}
		entry := testEntry(t, testCoordination(t, p.operations[1].Coordinator).Authority, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, evidence)
		server, client := completionHosts(t)
		results := installArchiveSecondaryCompletion(t, session, server, client, nil)
		before := testCoordination(t, p.operations[1].Coordinator)
		if _, err := client.CompletePrune(t.Context(), server.Addresses()[0], server.ID(), entry, 2*time.Second); !errors.Is(err, completionwire.ErrUnconfirmed) {
			t.Fatal(err)
		}
		want := ErrPruneOutcome
		if point == "pins-cancel-confirm-before-publish" {
			want = ErrPrunePinPending
		}
		if result := awaitCompletionServe(t, results); !errors.Is(result.err, want) {
			t.Fatal("unresolved executor completed secondary", result.err)
		}
		if !reflect.DeepEqual(before, testCoordination(t, p.operations[1].Coordinator)) || !reflect.DeepEqual(state, pruneSnapshot(t, p.f.executor)) {
			t.Fatal("wire request resolved executor or changed secondary")
		}
	}
}
