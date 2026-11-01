package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func scheduledDeliveryIntent(t testing.TB, c ScheduledPruneCommandConfig, server, client *libp2ptransport.Host) scheduledwire.Intent {
	t.Helper()
	r := scheduledOperatorReview(t, c)
	raw, err := os.ReadFile(c.EntryPath)
	if err != nil {
		t.Fatal(err)
	}
	e, err := custodyauthority.DecodeEntry(raw)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := LoadScheduledPrunePlan(c.PlanPath, c.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := plan.Request.ID()
	return scheduledwire.Intent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), PlanID: c.PlanID,
		RequestID: rid, ExecutorBindingID: r.Executor.Protection.BindingID, InventoryID: c.InventoryID, ReviewID: r.Review.ReviewID, Entry: e}
}

func installScheduledDelivery(t testing.TB, c ScheduledPruneCommandConfig, intent scheduledwire.Intent, host *libp2ptransport.Host, hooks storeHooks, lost bool) <-chan error {
	t.Helper()
	id, _ := intent.ID()
	s, err := NewScheduledPruneCommandServer(c, intent, id, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s.hooks = hooks
	results := make(chan error, 16)
	if err := host.SetScheduledPruneHandler(intent.ClientPeerID, func(ctx context.Context, peer types.Hash, stream network.Stream) {
		var rw scheduledwire.Stream = stream
		if lost {
			rw = lostCompletionReply{stream, false}
		}
		results <- s.Serve(ctx, peer, rw)
	}); err != nil {
		t.Fatal(err)
	}
	return results
}

func awaitScheduledDelivery(t testing.TB, results <-chan error) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled delivery did not finish")
		return nil
	}
}

func TestPruneScheduledDeliveryLostReplyColdRetryPreservesAccounting(t *testing.T) {
	for _, replica := range []int{0, 1} {
		t.Run(string(rune('0'+replica)), func(t *testing.T) {
			f := newScheduledPruneOperatorFixture(t)
			c := f.config[replica]
			server, client := completionHosts(t)
			intent := scheduledDeliveryIntent(t, c, server, client)
			id, _ := intent.ID()
			a, _ := f.plan.Replica(c.AssignmentID)
			path := filepath.Join(t.TempDir(), "outbox")
			outbox, err := CreateScheduledPruneOutbox(path, a.Assignment, intent, id)
			if err != nil {
				t.Fatal(err)
			}
			results := installScheduledDelivery(t, c, intent, server, storeHooks{}, true)
			if ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 3*time.Second); err == nil || ack != (scheduledwire.Acknowledgement{}) {
				t.Fatal("lost reply accepted", err)
			}
			if err := awaitScheduledDelivery(t, results); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("reply cut not reached", err)
			}
			state, err := outbox.Snapshot()
			if err != nil || state.Acknowledgement != nil {
				t.Fatal("lost reply marked delivered", err)
			}
			if err := outbox.Close(); err != nil {
				t.Fatal(err)
			}
			before := scheduledOperatorReview(t, c)
			if !before.Review.AlreadyApplied || before.Review.Authority.Authority.Pending != f.before[replica].Authority.Pending+1 {
				t.Fatal("admission missing")
			}
			outbox, err = OpenScheduledPruneOutbox(path, a.Assignment, id)
			if err != nil {
				t.Fatal(err)
			}
			defer outbox.Close()
			registered, err := NewScheduledPruneCommandServer(c, intent, id, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err := registered.Register(server); err != nil {
				t.Fatal(err)
			}
			ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 3*time.Second)
			if err != nil || ack.IntentID != id {
				t.Fatal(err)
			}
			after := scheduledOperatorReview(t, c)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("exact retry changed original accounting or executor")
			}
			if err := outbox.Close(); err != nil {
				t.Fatal(err)
			}
			cold, err := OpenScheduledPruneOutbox(path, a.Assignment, id)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Close()
			if again, err := cold.Deliver(t.Context(), client, "offline", 3*time.Second); err != nil || again != ack {
				t.Fatal("durable reply required network", err)
			}
			if err := cold.Close(); err != nil {
				t.Fatal(err)
			}
			delivery := PruneDeliveryConfig{Path: path, Assignment: a.Assignment, IntentID: id, Address: "offline", Timeout: 3 * time.Second}
			if again, err := DeliverScheduledPrune(t.Context(), testKey(46), delivery); err != nil || again != ack {
				t.Fatal("offline wrapper lost original receipt", err)
			}
			if _, err := DeliverScheduledPrune(t.Context(), testKey(47), delivery); err == nil {
				t.Fatal("wrong client key read successful delivery")
			}
		})
	}
}

func TestPruneScheduledDeliveryRejectsPinsBeforeMutation(t *testing.T) {
	f := newScheduledPruneOperatorFixture(t)
	c := f.config[0]
	server, client := completionHosts(t)
	intent := scheduledDeliveryIntent(t, c, server, client)
	before := scheduledOperatorReview(t, c)
	for _, field := range []string{"plan", "request", "executor", "review", "entry", "inventory", "peer"} {
		t.Run(field, func(t *testing.T) {
			bad := intent
			switch field {
			case "plan":
				bad.PlanID = testHash(240)
			case "request":
				bad.RequestID = testHash(240)
			case "executor":
				bad.ExecutorBindingID = testHash(240)
			case "review":
				bad.ReviewID = testHash(240)
			case "entry":
				bad.Entry = f.entries[1]
			case "inventory":
				bad.InventoryID = testHash(240)
			case "peer":
				bad.ClientPeerID = testHash(240)
			}
			results := installScheduledDelivery(t, c, intent, server, storeHooks{}, false)
			if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), bad, 3*time.Second); err == nil {
				t.Fatal("substitution delivered")
			}
			if _, err := bad.ID(); err == nil && bad.ClientPeerID == client.ID() {
				if err := awaitScheduledDelivery(t, results); err == nil {
					t.Fatal("substitution accepted")
				}
			}
			if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("substitution mutated owners")
			}
		})
	}
	// Even an operator-configured envelope with a wrong binding or stale review
	// cannot pass the checks performed while holding the original owners.
	for _, field := range []string{"executor", "review"} {
		bad := intent
		if field == "executor" {
			bad.ExecutorBindingID = testHash(240)
		} else {
			bad.ReviewID = testHash(240)
		}
		results := installScheduledDelivery(t, c, bad, server, storeHooks{}, false)
		if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), bad, 3*time.Second); err == nil {
			t.Fatal("bad local pin accepted")
		}
		if err := awaitScheduledDelivery(t, results); err == nil {
			t.Fatal("bad local pin not checked")
		}
	}
	if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
		t.Fatal("bad local pins mutated owners")
	}
}

func TestPruneScheduledDeliveryPendingNeedsExplicitLocalResume(t *testing.T) {
	for _, stage := range []string{"intent-after-publish", "authority-after-publish", "confirm-after-publish", "pins-admission-intent-after-publish", "pins-admission-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneOperatorFixture(t)
			c := f.config[0]
			server, client := completionHosts(t)
			intent := scheduledDeliveryIntent(t, c, server, client)
			fault := errors.New("delivery interrupted")
			results := installScheduledDelivery(t, c, intent, server, storeHooks{at: func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}}, false)
			if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), intent, 3*time.Second); err == nil {
				t.Fatal("interrupted write acknowledged")
			}
			if err := awaitScheduledDelivery(t, results); !errors.Is(err, fault) {
				t.Fatal("fault not reached", err)
			}
			before := scheduledOperatorReview(t, c)
			results = installScheduledDelivery(t, c, intent, server, storeHooks{}, false)
			if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), intent, 3*time.Second); err == nil {
				t.Fatal("network resumed incomplete command")
			}
			if err := awaitScheduledDelivery(t, results); err == nil {
				t.Fatal("incomplete original owners not checked")
			}
			if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
				t.Fatal("network retry advanced pending state")
			}
			mode := "apply"
			if before.Review.Authority.Pending != nil || before.Executor.Protection.Pending != nil {
				mode = "resume"
			}
			if _, err := RunScheduledPruneCommand(t.Context(), c, mode, before.Review.ReviewID); err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), intent, 3*time.Second); err != nil {
				t.Fatal("original intent could not confirm explicit recovery", err)
			}
			if err := awaitScheduledDelivery(t, results); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneScheduledDeliverySettlementCompletionDoesNotDowngrade(t *testing.T) {
	f, configs := observedOutcomeFixture(t)
	c := configs[0]
	review := scheduledOperatorReview(t, c)
	if _, err := RunScheduledPruneCommand(t.Context(), c, "settle-effect", review.Review.ReviewID); err != nil {
		t.Fatal(err)
	}
	server, client := completionHosts(t)
	for _, c := range configs {
		c = withoutPruneSettlement(c)
		c.Storage = nil
		c = scheduledOutcomeCompletion(t, c)
		intent := scheduledDeliveryIntent(t, c, server, client)
		before := scheduledOperatorReview(t, c)
		settlementID, _ := before.Executor.FenceSettlement.ID()
		if intent.Entry.Command.EvidenceID != settlementID {
			t.Fatal("completion omitted full settlement")
		}
		bad := intent
		cmd := bad.Entry.Command
		cmd.EvidenceID, _ = before.Executor.Effect.ID()
		bad.Entry = managedCommandApplyTestSign(t, cmd)
		badConfig := c
		badConfig.EntryPath = filepath.Join(t.TempDir(), "bare-effect")
		badConfig.EntryID, _ = bad.Entry.ID()
		raw, _ := bad.Entry.CanonicalBytes()
		writeTestFile(t, badConfig.EntryPath, raw)
		results := installScheduledDelivery(t, badConfig, bad, server, storeHooks{}, false)
		if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), bad, 3*time.Second); err == nil {
			t.Fatal("bare effect released settlement")
		}
		if err := awaitScheduledDelivery(t, results); err == nil {
			t.Fatal("bare effect accepted")
		}
		if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
			t.Fatal("bad completion mutated owners")
		}
		started := time.Now()
		results = installScheduledDelivery(t, c, intent, server, storeHooks{at: func(stage string) error { t.Log(stage, time.Since(started)); return nil }}, true)
		if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), intent, 3*time.Second); err == nil {
			t.Fatal("lost completion reply accepted")
		}
		if err := awaitScheduledDelivery(t, results); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("reply cut not reached", err)
		}
		after := scheduledOperatorReview(t, c)
		if after.Review.Authority.Authority.Pending+1 != before.Review.Authority.Authority.Pending || !reflect.DeepEqual(before.Executor, after.Executor) {
			t.Fatal("completion changed wrong obligations")
		}
		results = installScheduledDelivery(t, c, intent, server, storeHooks{}, false)
		if _, err := client.DeliverScheduledPrune(t.Context(), server.Addresses()[0], server.ID(), intent, 3*time.Second); err != nil {
			t.Fatal(err)
		}
		if err := awaitScheduledDelivery(t, results); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, scheduledOperatorReview(t, c)) {
			t.Fatal("completion retry changed accounting")
		}
		outcome, err := RetainedScheduledPruneOutcome(f.inventory, after.Executor)
		if err != nil || outcome.Settlement == nil {
			t.Fatal("settlement lost", err)
		}
	}
}

func TestPruneScheduledReceiptRejectsCorruptionAndCrossIntent(t *testing.T) {
	v := fixedScheduledPrunePlan(t)
	entry, err := custodyauthority.DecodeEntry(v.Completion)
	if err != nil {
		t.Fatal(err)
	}
	i := scheduledwire.Intent{ClientPeerID: testHash(1), ServerPeerID: testHash(2), PlanID: v.PlanID, RequestID: testHash(3), ExecutorBindingID: testHash(4), InventoryID: testHash(5), ReviewID: testHash(6), Entry: entry}
	id, _ := i.ID()
	ack := scheduledwire.Acknowledgement{Nonce: testHash(7), IntentID: id}
	raw, err := scheduledPruneReceipt(id, ack)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeScheduledPruneReceipt(raw, i); err != nil || got != ack {
		t.Fatal(err)
	}
	for n := range raw {
		bad := bytes.Clone(raw)
		bad[n] ^= 1
		if _, err := decodeScheduledPruneReceipt(bad, i); err == nil {
			t.Fatal("corruption accepted", n)
		}
	}
	i.ReviewID = testHash(8)
	if _, err := decodeScheduledPruneReceipt(raw, i); err == nil {
		t.Fatal("cross-intent receipt")
	}
}

type scheduledRequestStream struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (s *scheduledRequestStream) Read(p []byte) (int, error)  { return s.input.Read(p) }
func (s *scheduledRequestStream) Write(p []byte) (int, error) { return s.output.Write(p) }
func (s *scheduledRequestStream) Close() error                { return nil }
func (s *scheduledRequestStream) CloseWrite() error           { return nil }
func (s *scheduledRequestStream) SetDeadline(time.Time) error { return nil }

func TestPruneScheduledServerRejectsIncompleteFramesBeforeOwners(t *testing.T) {
	f := newScheduledPruneOperatorFixture(t)
	c := f.config[0]
	host, client := completionHosts(t)
	intent := scheduledDeliveryIntent(t, c, host, client)
	id, _ := intent.ID()
	server, err := NewScheduledPruneCommandServer(c, intent, id, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Register(client); err == nil {
		t.Fatal("registered on wrong transport")
	}
	before := scheduledOperatorReview(t, c)
	raw, _ := (scheduledwire.Request{Nonce: testHash(9), Intent: intent}).CanonicalBytes()
	future := bytes.Clone(raw)
	future[9] = 1
	for _, body := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 1), future} {
		s := &scheduledRequestStream{input: bytes.NewReader(body)}
		if err := server.Serve(t.Context(), client.ID(), s); err == nil || s.output.Len() != 0 {
			t.Fatal("incomplete or future request acknowledged", err)
		}
		if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
			t.Fatal("invalid frame changed owners")
		}
	}
	s := &scheduledRequestStream{input: bytes.NewReader(raw)}
	if err := server.Serve(t.Context(), testHash(240), s); err == nil || s.output.Len() != 0 || s.input.Len() != len(raw) {
		t.Fatal("unauthenticated peer read or mutated request")
	}
	if err := server.Register(host); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, scheduledOperatorReview(t, c)) {
		t.Fatal("registration changed original owners")
	}
}
