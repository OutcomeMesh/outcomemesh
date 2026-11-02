package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/transport"
)

type scheduledDeliveryCLIHarness struct {
	run    func([]string, io.Writer) error
	start  func([]string) (string, func(bool))
	broken func([]string, error)
}

func scheduledDeliveryReport(t testing.TB, raw []byte) map[string]any {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal("delivery JSON", err, string(raw))
	}
	for _, key := range []string{"execution_authorized", "automatic_retry", "current_head_verified", "terminal_state_verified"} {
		if report[key] != false {
			t.Fatal("delivery report overclaims authority", key, report)
		}
	}
	if report["historical_only"] != true {
		t.Fatal("missing receipt limitation", report)
	}
	return report
}

func scheduledDeliveryReady(t testing.TB, raw []byte) string {
	t.Helper()
	r := scheduledDeliveryReport(t, raw)
	addresses, ok := r["listen"].([]any)
	if !ok || len(addresses) == 0 || r["ready"] != true || r["automatic_resume"] != false {
		t.Fatal("invalid readiness", r)
	}
	address, ok := addresses[0].(string)
	if !ok || address == "" {
		t.Fatal("empty route")
	}
	return address
}

func scheduledDeliveryLocalHarness(t *testing.T) scheduledDeliveryCLIHarness {
	return scheduledDeliveryCLIHarness{
		run: func(args []string, out io.Writer) error { return runScheduledDelivery(t.Context(), args, out) },
		broken: func(args []string, expected error) {
			err := runScheduledDelivery(t.Context(), args, pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe }))
			if !errors.Is(err, io.ErrClosedPipe) || (expected != nil && !errors.Is(err, expected)) {
				t.Fatal("lost output discarded ambiguity", err)
			}
		},
		start: func(args []string) (string, func(bool)) {
			ctx, cancel := context.WithCancel(t.Context())
			ready, done := make(chan []byte, 1), make(chan struct{})
			var runErr error
			go func() {
				runErr = runScheduledDelivery(ctx, args, pruneEffectTestWriter(func(b []byte) (int, error) { ready <- bytes.Clone(b); return len(b), nil }))
				close(done)
			}()
			var once sync.Once
			stop := func(bool) {
				once.Do(func() {
					cancel()
					select {
					case <-done:
						if runErr != nil {
							t.Error(runErr)
						}
					case <-time.After(15 * time.Second):
						t.Error("service did not drain")
					}
				})
			}
			t.Cleanup(func() { stop(false) })
			select {
			case raw := <-ready:
				return scheduledDeliveryReady(t, raw), stop
			case <-done:
				t.Fatal("service failed before readiness", runErr)
			case <-time.After(15 * time.Second):
				t.Fatal("service readiness timeout")
			}
			return "", stop
		},
	}
}

func scheduledDeliveryCLILifecycle(t *testing.T, h scheduledDeliveryCLIHarness, cancelled bool, fenced ...bool) {
	admitted, completed := 0, 0
	scheduledPruneCLILifecycleWithDelivery(t, cancelled, func(t *testing.T, ownerArgs []string, review store.ScheduledPruneCommandResult) {
		values := map[string]string{}
		for n := 0; n < len(ownerArgs); n += 2 {
			values[ownerArgs[n]] = ownerArgs[n+1]
		}
		if values["--inventory"] == "" {
			admitted++
		} else {
			completed++
			if len(fenced) > 2 && fenced[2] && review.Executor.FenceSettlement == nil {
				t.Fatal("settlement completion lost its full retained evidence")
			}
		}
		pid, err := pruneExternalID("plan-id", values["--plan-id"])
		if err != nil {
			t.Fatal(err)
		}
		plan, err := store.LoadScheduledPrunePlan(values["--plan"], pid)
		if err != nil {
			t.Fatal(err)
		}
		aid, err := pruneExternalID("assignment-id", values["--assignment-id"])
		if err != nil {
			t.Fatal(err)
		}
		selected, err := plan.Replica(aid)
		if err != nil {
			t.Fatal(err)
		}
		rid, _ := plan.Request.ID()
		root := t.TempDir()
		assignment, intentPath, outbox := filepath.Join(root, "assignment"), filepath.Join(root, "intent"), filepath.Join(root, "outbox")
		raw, _ := selected.Assignment.CanonicalBytes()
		writePruneCLIFile(t, assignment, raw)
		serverKey, clientKey := filepath.Join(root, "server.seed"), filepath.Join(root, "client.seed")
		writePruneCLIFile(t, serverKey, pruneCLIKey(45).Seed())
		writePruneCLIFile(t, clientKey, pruneCLIKey(46).Seed())
		server, _ := transport.PeerIDFromPublicKey(pruneCLIKey(45).Public().(ed25519.PublicKey))
		client, _ := transport.PeerIDFromPublicKey(pruneCLIKey(46).Public().(ed25519.PublicKey))
		peers := []string{"--client-peer-id", client.String(), "--server-peer-id", server.String()}
		prepare := []string{scheduledDeliveryPrepareCommand}
		for _, flag := range []string{"--plan", "--plan-id", "--assignment-id", "--entry", "--entry-id", "--inventory", "--inventory-id"} {
			if v, ok := values[flag]; ok {
				prepare = append(prepare, flag, v)
			}
		}
		prepare = append(prepare, "--request-id", rid.String(), "--executor-binding-id", review.Executor.Protection.BindingID.String(), "--receiver-review-id", review.Review.ReviewID.String())
		prepare = append(prepare, peers...)
		run := func(args []string) map[string]any {
			t.Helper()
			var out bytes.Buffer
			if err := h.run(args, &out); err != nil {
				t.Fatalf("%s: %v %s", args[0], err, out.String())
			}
			return scheduledDeliveryReport(t, out.Bytes())
		}
		report := run(prepare)
		intentID, ok := report["intent_id"].(string)
		if !ok || intentID == "" || report["sent"] != false || report["published"] != false {
			t.Fatal("invalid review", report)
		}
		for _, bad := range [][]string{
			pruneCLISet(prepare, "plan-id", pruneCLIHash(240).String()),
			pruneCLISet(prepare, "request-id", pruneCLIHash(240).String()),
			pruneCLISet(prepare, "entry-id", pruneCLIHash(240).String()),
			pruneCLISet(prepare, "client-peer-id", server.String()),
			append(append([]string(nil), prepare...), "--out", ""),
			append(append([]string(nil), prepare...), "--plan", values["--plan"]),
			append(append([]string(nil), prepare...), "unexpected"),
		} {
			if err := h.run(bad, io.Discard); err == nil {
				t.Fatal("accepted invalid preparation", bad)
			}
		}
		for _, field := range []string{"plan-id", "assignment-id", "entry-id", "request-id", "executor-binding-id", "receiver-review-id", "client-peer-id", "server-peer-id"} {
			if err := h.run(pruneCLISet(prepare, field, ""), io.Discard); err == nil {
				t.Fatal("accepted missing independent pin", field)
			}
		}
		publish := append(append([]string(nil), prepare...), "--mode", "publish", "--intent-id", intentID, "--out", intentPath)
		if err := h.run(pruneCLISet(publish, "out", values["--entry"]), io.Discard); err == nil {
			t.Fatal("overwrote signed input")
		}
		h.broken(publish, nil)
		run(publish) // exact publication survives lost output
		boxArgs := []string{scheduledDeliveryOutboxCommand, "--assignment", assignment, "--assignment-id", aid.String(), "--intent-id", intentID, "--outbox", outbox}
		create := append(append([]string(nil), boxArgs...), "--mode", "create", "--intent", intentPath)
		h.broken(create, nil)
		if got := run(boxArgs); got["receipt_present"] != false {
			t.Fatal("creation sent command", got)
		}
		if err := h.run(create, io.Discard); err == nil {
			t.Fatal("outbox create replaced original")
		}
		serve := append([]string{scheduledDeliveryServeCommand}, ownerArgs...)
		serve = append(serve, "--intent", intentPath, "--intent-id", intentID, "--key", serverKey)
		serve = append(serve, peers...)
		irrelevant := "inventory"
		if values["--inventory"] != "" {
			irrelevant = "journal"
		}
		for _, bad := range [][]string{
			pruneCLISet(serve, "client-peer-id", pruneCLIHash(240).String()),
			pruneCLISet(serve, "intent-id", pruneCLIHash(240).String()),
			pruneCLISet(serve, "key", clientKey),
			append(append([]string(nil), serve...), "--mode", "resume"),
			append(append([]string(nil), serve...), "--timeout", "0s"),
			append(append([]string(nil), serve...), "--"+irrelevant, ""),
		} {
			if err := h.run(bad, io.Discard); err == nil {
				t.Fatal("accepted invalid service", bad)
			}
		}
		h.broken(serve, nil)
		_, stop := h.start(serve)
		stop(true)
		var after store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append([]string{scheduledApplyCommand}, ownerArgs...), &after)
		if !reflect.DeepEqual(review, after) {
			t.Fatal("start/stop changed original owners")
		}
		address, stop := h.start(serve)
		deliver := []string{scheduledDeliveryCommand, "--assignment", assignment, "--assignment-id", aid.String(), "--intent-id", intentID, "--outbox", outbox, "--key", clientKey, "--peer", address}
		route := strings.SplitN(address, "/p2p/", 2)
		if len(route) != 2 {
			t.Fatal("readiness omitted the transport identity")
		}
		unreachable := append(pruneCLISet(deliver, "peer", "/ip4/127.0.0.1/udp/1/quic-v1/p2p/"+route[1]), "--timeout", "100ms")
		if err := h.run(unreachable, io.Discard); err == nil {
			t.Fatal("unavailable route asserted delivery")
		}
		if err := h.run(pruneCLISet(deliver, "intent-id", pruneCLIHash(240).String()), io.Discard); err == nil {
			t.Fatal("client accepted different pin")
		}
		if err := os.Chmod(clientKey, 0644); err != nil {
			t.Fatal(err)
		}
		if err := h.run(deliver, io.Discard); err == nil {
			t.Fatal("client accepted public seed permissions")
		}
		if err := os.Chmod(clientKey, 0600); err != nil {
			t.Fatal(err)
		}
		if got := run(boxArgs); got["receipt_present"] != false {
			t.Fatal("invalid sender delivered", got)
		}
		h.broken(deliver, scheduledwire.ErrUnconfirmed)
		stop(false)
		retained := run(boxArgs)
		if retained["receipt_present"] != true {
			t.Fatal("lost stdout lost durable receipt", retained)
		}
		delivered := run(pruneCLISet(deliver, "peer", "offline"))
		if delivered["delivery_confirmed"] != true || delivered["receipt_nonce"] != retained["receipt_nonce"] {
			t.Fatal("offline retry changed receipt", delivered)
		}
		if err := h.run(pruneCLISet(deliver, "key", serverKey), io.Discard); err == nil {
			t.Fatal("wrong client key read success")
		}
		// A cold receiver accepts this historical intent only after complete
		// original-owner confirmation, despite its pre-application review ID.
		_, stop = h.start(serve)
		stop(false)
	}, fenced...)
	if admitted != 2 || completed != 2 {
		t.Fatalf("incomplete delivery lifecycle: admissions=%d completions=%d", admitted, completed)
	}
}

func TestPruneScheduledDeliveryCLICancellationLifecycle(t *testing.T) {
	scheduledDeliveryCLILifecycle(t, scheduledDeliveryLocalHarness(t), true)
}

func TestPruneScheduledDeliveryCLIFullSettlementLifecycle(t *testing.T) {
	scheduledDeliveryCLILifecycle(t, scheduledDeliveryLocalHarness(t), false, true, false, true)
}
