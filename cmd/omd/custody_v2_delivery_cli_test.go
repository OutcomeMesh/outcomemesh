package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func deliveryInProcess(t testing.TB, args []string) string {
	t.Helper()
	if args[0] != custodyV2DeliveryCommand && args[0] != custodyV2EnrolledDeliveryCommand {
		return requiredInProcess(t, args)
	}
	var out bytes.Buffer
	if e := runCustodyV2Delivery(t.Context(), args, nil, &out); e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}

func deliveryReviewed(t testing.TB, driver v2CLIDriver, args []string) []string {
	t.Helper()
	review := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
	if review["keys_loaded"] != "false" || review["stores_opened"] != "false" || review["execution_granted"] != "false" || review["proof_only"] != "true" || review["review_id"] == "" {
		t.Fatal(review)
	}
	return append(append([]string{}, args...), "--mode", "run", "--expected-review-id", review["review_id"])
}

func deliveryArgs(z requiredCLIFixture, action string, extra ...string) []string {
	cid, _ := z.c.ID()
	bid, _ := z.binding.ID()
	command := custodyV2DeliveryCommand
	if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled {
		command = custodyV2EnrolledDeliveryCommand
		id, _ := z.enrollment.ID()
		extra = append(append([]string{}, extra...), "--registry-enrollment-id", id.String())
		if action == "delivery" {
			extra = append(extra, "--registry-enrollment", z.enrollmentPath)
		}
	}
	return append([]string{command, "--action", action, "--context", z.contextPath, "--context-id", cid.String(), "--scope-id", z.sid.String(), "--binding-id", bid.String()}, extra...)
}

func deliveryInProcessStart(t testing.TB, args []string, prefix string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	in, input := io.Pipe()
	out, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- runCustodyV2Delivery(ctx, args, in, writer); _ = writer.Close() }()
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(out)
		if scan.Scan() {
			ready <- scan.Text()
		} else {
			ready <- ""
		}
	}()
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = out.Close() })
	select {
	case line := <-ready:
		fields := pruneCLIFields(line)
		if !strings.HasPrefix(line, prefix+" ") || fields["address"] == "" || fields["execution_granted"] != "false" {
			select {
			case e := <-done:
				t.Fatal(line, e)
			default:
				t.Fatal(line)
			}
		}
		return fields["address"], func() {
			_, _ = io.WriteString(input, "close\n")
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("delivery service did not drain")
			}
			cancel()
			_ = out.Close()
		}
	case <-time.After(10 * time.Second):
		t.Fatal("delivery service readiness timeout")
	}
	return "", func() {}
}

// Both roles obtain the same admission through the reviewed network path, then
// close intake and explicitly create real owners. Proof delivery itself never
// creates those owners or obtains an execution session.
func runAdmissionDeliveryCLICampaign(t *testing.T, driver v2CLIDriver, start v2CLIStart) {
	t.Helper()
	z := newRequiredCLIFixture(t, driver)
	driver(t, requiredReviewed(t, driver, z.bindingArgs(t)))
	runAdmissionDeliveryCLIFixtureCampaign(t, z, driver, start)
}
func runAdmissionDeliveryCLIFixtureCampaign(t *testing.T, z requiredCLIFixture, driver v2CLIDriver, start v2CLIStart, workStarts ...v2CLIStart) {
	t.Helper()
	run := func(args []string) { driver(t, deliveryReviewed(t, driver, args)) }
	key47 := filepath.Join(z.dir, "authority-transport.seed")
	writePruneCLIFile(t, key47, f.Key(47).Seed())
	for _, role := range []string{"target", "authority"} {
		roleDir := filepath.Join(z.dir, "delivery-"+role)
		if e := os.Mkdir(roleDir, 0700); e != nil {
			t.Fatal(e)
		}
		inbox, outbox := filepath.Join(roleDir, "inbox"), filepath.Join(roleDir, "outbox")
		enrollmentPath, deliveryPath := filepath.Join(roleDir, "enrollment"), filepath.Join(roleDir, "delivery")
		journal, objects, signKey, transportKey, public := z.x.sources.Journal, z.x.sources.Objects, z.keys[14], z.keys[15], f.Public(15)
		if role == "authority" {
			journal, objects, signKey, transportKey, public = z.x.legacy.base.config.Audit.JournalPath, "", z.keys[1], key47, f.Public(47)
		}
		peer, e := transportPeer(public)
		if e != nil {
			t.Fatal(e)
		}
		paths := []string{"--root", inbox, "--journal", journal}
		if objects != "" {
			paths = append(paths, "--objects", objects)
		}
		selection := append(append([]string{}, paths...), "--role", role, "--recipient-peer-id", peer.String())
		run(deliveryArgs(z, "inbox-create", append(append([]string{}, selection...), "--out", enrollmentPath)...))
		raw, e := os.ReadFile(enrollmentPath)
		if e != nil {
			t.Fatal(e)
		}
		enrollment, e := v2.DecodeAdmissionDeliveryEnrollment(raw)
		if e != nil {
			t.Fatal(e)
		}
		eid, _ := enrollment.ID()
		// The diagnostic export preserves the original candidate descriptor; it
		// does not replace its independently retained semantic ID.
		recoveredEnrollment := filepath.Join(roleDir, "enrollment-recovered")
		run(deliveryArgs(z, "inbox-enrollment", append(append([]string{}, selection...), "--out", recoveredEnrollment)...))
		recovered, _ := os.ReadFile(recoveredEnrollment)
		if !bytes.Equal(raw, recovered) {
			t.Fatal("enrollment output recovery changed original descriptor")
		}
		enrolled := []string{"--enrollment", enrollmentPath, "--enrollment-id", eid.String()}
		run(deliveryArgs(z, "delivery", append(append([]string{}, enrolled...), "--binding", z.bindingPath, "--out", deliveryPath)...))
		raw, e = os.ReadFile(deliveryPath)
		if e != nil {
			t.Fatal(e)
		}
		d, e := v2.DecodeAdmissionDelivery(raw)
		if e != nil {
			t.Fatal(e)
		}
		did, _ := d.ID()
		inboxArgs := append(append(append([]string{}, paths...), enrolled...), "--sign-key", signKey)
		serve := deliveryArgs(z, "inbox-serve", append(append([]string{}, inboxArgs...), "--transport-key", transportKey)...)
		prefix := "custody_v2_delivery_serving"
		if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled {
			prefix = "custody_v2_enrolled_delivery_serving"
		}
		address, closeInbox := start(t, deliveryReviewed(t, driver, serve), prefix)
		outboxArgs := []string{"--root", outbox, "--delivery", deliveryPath, "--delivery-id", did.String(), "--address", address}
		run(deliveryArgs(z, "outbox-create", outboxArgs...))
		first := filepath.Join(roleDir, "sent-receipt")
		send := deliveryArgs(z, "outbox-send", append(append([]string{}, outboxArgs...), "--transport-key", z.keys[46], "--out", first)...)
		run(send)
		before, e := os.ReadFile(first)
		if e != nil {
			t.Fatal(e)
		}
		r, e := v2.DecodeAdmissionDeliveryReceipt(before)
		if e != nil || r.Verify(d) != nil {
			t.Fatal("delivery receipt", e)
		}
		closeInbox()
		// The outbox has been cold-opened by every CLI action. A completed send
		// succeeds while its server is down and preserves exactly the old ACK.
		cached := filepath.Join(roleDir, "cached-receipt")
		if e := os.WriteFile(z.keys[46], []byte("unavailable sender seed"), 0600); e != nil {
			t.Fatal(e)
		}
		run(deliveryArgs(z, "outbox-send", append(append([]string{}, outboxArgs...), "--transport-key", z.keys[46], "--listen", "invalid-unused-listener", "--out", cached)...))
		if e := os.WriteFile(z.keys[46], f.Key(46).Seed(), 0600); e != nil {
			t.Fatal(e)
		}
		after, _ := os.ReadFile(cached)
		if !bytes.Equal(before, after) {
			t.Fatal("cached send changed acknowledgement")
		}
		serverReceipt := filepath.Join(roleDir, "server-receipt")
		run(deliveryArgs(z, "inbox-receipt", append(append([]string{}, inboxArgs...), "--out", serverReceipt)...))
		after, _ = os.ReadFile(serverReceipt)
		if !bytes.Equal(before, after) {
			t.Fatal("cold recipient returned a different acknowledgement")
		}
		binding := filepath.Join(roleDir, "delivered-binding")
		run(deliveryArgs(z, "inbox-binding", append(append([]string{}, inboxArgs...), "--out", binding)...))
		after, _ = os.ReadFile(binding)
		original, _ := os.ReadFile(z.bindingPath)
		if !bytes.Equal(original, after) {
			t.Fatal("delivered proof changed")
		}
		if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled {
			proof := filepath.Join(roleDir, "delivered-registry-enrollment")
			run(deliveryArgs(z, "inbox-registry-enrollment", append(append([]string{}, inboxArgs...), "--out", proof)...))
			a, _ := os.ReadFile(proof)
			b, _ := os.ReadFile(z.enrollmentPath)
			if !bytes.Equal(a, b) {
				t.Fatal("delivered registry proof changed")
			}
			if role == "target" {
				z.targetBindingPath, z.targetEnrollmentPath = binding, proof
			} else {
				z.acceptorBindingPath, z.acceptorEnrollmentPath = binding, proof
			}
		}
		for _, owner := range []string{z.target, z.acceptor} {
			if _, e := os.Lstat(owner); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("delivery implicitly created execution owner", owner, e)
			}
		}
	}
	if z.c.Assignment.Policy.Version == v2.PolicyVersionEnrolled {
		workStart := v2CLIStart(requiredInProcessStart)
		if len(workStarts) > 0 {
			workStart = workStarts[0]
		}
		runRequiredCLIFixtureCampaign(t, z, driver, workStart)
		return
	}
	// Explicit runtime enrollment still verifies the predecessor and complete
	// binding; the later real effect and acceptance remain exactly once.
	for _, args := range [][]string{
		z.args("create-target", "--root", z.target, "--journal", z.x.sources.Journal, "--objects", z.x.sources.Objects),
		z.args("create-acceptor", "--root", z.acceptor, "--journal", z.x.legacy.base.config.Audit.JournalPath),
	} {
		driver(t, requiredReviewed(t, driver, args))
	}
	bundle := z.execute(t)
	raw, _ := bundle.CanonicalBytes()
	bundlePath := filepath.Join(z.dir, "delivered-job-bundle")
	writePruneCLIFile(t, bundlePath, raw)
	args := z.args("accept", append(z.aArgs(), "--in", bundlePath, "--in-id", z.pin(t, bundlePath), "--out", filepath.Join(z.dir, "delivered-job-receipt"))...)
	driver(t, requiredReviewed(t, driver, args))
}

func TestCustodyV2DeliveryCLICompleteRetainedRoundTrip(t *testing.T) {
	runAdmissionDeliveryCLICampaign(t, deliveryInProcess, deliveryInProcessStart)
}

func TestCustodyV2DeliveryCLIReviewPinsAndHasNoEffects(t *testing.T) {
	z := newRequiredCLIFixture(t)
	peer, _ := transportPeer(f.Public(15))
	root, output := filepath.Join(z.dir, "inbox"), filepath.Join(z.dir, "enrollment")
	args := deliveryArgs(z, "inbox-create", "--root", root, "--role", "target", "--journal", z.x.sources.Journal, "--objects", z.x.sources.Objects, "--recipient-peer-id", peer.String(), "--out", output)
	run := deliveryReviewed(t, deliveryInProcess, args)
	for _, p := range []string{root, output} {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("review wrote state", p, e)
		}
	}
	for _, extra := range [][]string{{"--transport-key", z.keys[15]}, {"--action", "inbox-create"}, {"--now", "1"}, {"--address", "/ip4/127.0.0.1/udp/1/quic-v1"}} {
		if e := runCustodyV2Delivery(t.Context(), append(append([]string{}, args...), extra...), nil, io.Discard); e == nil {
			t.Fatal("irrelevant/duplicate selector accepted", extra)
		}
	}
	changed := append([]string{}, run...)
	for i := range changed {
		if changed[i] == "--out" {
			changed[i+1] += "-changed"
		}
	}
	if e := runCustodyV2Delivery(t.Context(), changed, nil, io.Discard); e == nil || !strings.Contains(e.Error(), "exact public action review") {
		t.Fatal("changed output reused reviewed action", e)
	}
	// A same-path source directory replacement cannot reuse a review made for
	// the original physical object directory, even with the same public job.
	oldObjects := z.x.sources.Objects + "-original"
	if e := os.Rename(z.x.sources.Objects, oldObjects); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(z.x.sources.Objects, 0700); e != nil {
		t.Fatal(e)
	}
	if e := runCustodyV2Delivery(t.Context(), run, nil, io.Discard); e == nil || !strings.Contains(e.Error(), "exact public action review") {
		t.Fatal("replacement source reused reviewed enrollment", e)
	}
	if e := os.Remove(z.x.sources.Objects); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(oldObjects, z.x.sources.Objects); e != nil {
		t.Fatal(e)
	}
	if e := runCustodyV2Delivery(t.Context(), run, nil, serveBrokenWriter{}); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("lost enrollment stdout did not propagate", e)
	}
	before, e := os.ReadFile(output)
	if e != nil {
		t.Fatal("enrollment not published before stdout", e)
	}
	enrollment, e := v2.DecodeAdmissionDeliveryEnrollment(before)
	if e != nil {
		t.Fatal(e)
	}
	eid, _ := enrollment.ID()
	// An unusable private seed cannot affect the keyless public review.
	if e := os.WriteFile(z.keys[14], []byte("invalid secret"), 0600); e != nil {
		t.Fatal(e)
	}
	read := deliveryArgs(z, "inbox-receipt", "--root", root, "--journal", z.x.sources.Journal, "--objects", z.x.sources.Objects, "--enrollment", output, "--enrollment-id", eid.String(), "--sign-key", z.keys[14], "--out", filepath.Join(z.dir, "receipt"))
	deliveryReviewed(t, deliveryInProcess, read)
	if e := runCustodyV2Delivery(t.Context(), deliveryReviewed(t, deliveryInProcess, read), nil, io.Discard); e == nil {
		t.Fatal("run accepted invalid role seed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e := runCustodyV2Delivery(ctx, args, nil, io.Discard); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
