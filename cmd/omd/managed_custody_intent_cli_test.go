package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func managedCustodyIntentFixtureArgs(t testing.TB, f *managedCustodyAuditCLIFixture) ([]string, string, string) {
	t.Helper()
	nonce := filepath.Join(t.TempDir(), "nonce.bytes")
	writePruneCLIFile(t, nonce, f.intent.Nonce[:])
	out := filepath.Join(t.TempDir(), "intent.omcai")
	i := f.intent
	return []string{managedCustodyIntentCommand, "--assignment", f.serve.assignmentPath, "--assignment-id", i.AssignmentID.String(), "--intent", out,
		"--consumer-public-key", types.Hash(i.ConsumerPublicKey).String(), "--auditor-public-key", types.Hash(i.AuditorPublicKey).String(), "--replica-peer-id", i.ReplicaPeerID.String(),
		"--prior-sequence", strconv.FormatUint(i.PriorSequence, 10), "--prior-head-id", i.PriorHeadID.String(), "--prior-receipt-id", i.PriorReceiptID.String(),
		"--issued-at", strconv.FormatUint(i.IssuedAt, 10), "--expires-at", strconv.FormatUint(i.ExpiresAt, 10), "--renew-until", strconv.FormatUint(i.RenewUntil, 10), "--samples", strconv.FormatUint(uint64(i.RequestedSamples), 10), "--nonce-file", nonce}, out, nonce
}

func TestManagedCustodyIntentCLICancelBlockedNativePublicationOutput(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("interruptible native pipe adoption is macOS/Linux")
	}
	f := newManagedCustodyAuditCLIFixture(t)
	args, path, _ := managedCustodyIntentFixtureArgs(t, f)
	id, _ := f.intent.ID()
	args = append(args, "--mode", "publish", "--intent-id", id.String())
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := writer.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 1<<20)); !os.IsTimeout(err) {
		t.Fatal("pipe did not fill", err)
	}
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runManagedCustodyIntent(ctx, args, writer) }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatal("publication ended before output blockage", err)
		case <-deadline.C:
			t.Fatal("intent not published")
		case <-tick.C:
		}
	}
	select {
	case err := <-done:
		t.Fatal("full pipe did not block publication output", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("lost output reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release native output")
	}
	if retained, err := workarchive.LoadCustodyAuditIntent(path, id); err != nil || retained != f.intent {
		t.Fatal("lost output discarded/changed retained intent", err)
	}
}

func TestManagedCustodyIntentCLIReviewPublishVerifyExactAndPrivate(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	args, path, _ := managedCustodyIntentFixtureArgs(t, f)
	before := f.snapshot(t)
	var output bytes.Buffer
	if err := runManagedCustodyIntent(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	id, _ := f.intent.ID()
	if !strings.Contains(output.String(), "intent_id="+id.String()) || !strings.Contains(output.String(), "published=false") || strings.Contains(output.String(), f.intent.Nonce.String()) {
		t.Fatal("review omitted pin or exposed nonce", output.String())
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("review published intent", err)
	}
	publish := append(append([]string(nil), args...), "--mode", "publish", "--intent-id", id.String())
	for range 2 {
		output.Reset()
		if err := runManagedCustodyIntent(t.Context(), publish, &output); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := workarchive.LoadCustodyAuditIntent(path, id)
	if err != nil || loaded != f.intent {
		t.Fatal("publication changed reviewed intent", err)
	}
	verify := []string{managedCustodyIntentCommand, "--mode", "verify", "--assignment", f.serve.assignmentPath, "--assignment-id", f.intent.AssignmentID.String(), "--intent", path, "--intent-id", id.String()}
	output.Reset()
	if err := runManagedCustodyIntent(t.Context(), verify, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), f.intent.Nonce.String()) || !strings.Contains(output.String(), "signed=false admitted=false") {
		t.Fatal("verification exposed nonce or claimed authority", output.String())
	}
	if f.snapshot(t).Authority.HeadID != before.Authority.HeadID {
		t.Fatal("intent command admitted an operation")
	}
}

func TestManagedCustodyIntentCLIChangedNonceRejectedBeforePublication(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	args, path, nonce := managedCustodyIntentFixtureArgs(t, f)
	id, _ := f.intent.ID()
	args = append(args, "--mode", "publish", "--intent-id", id.String())
	b := append([]byte(nil), f.intent.Nonce[:]...)
	b[0] ^= 1
	writePruneCLIFile(t, nonce, b)
	if err := runManagedCustodyIntent(t.Context(), args, &bytes.Buffer{}); err == nil {
		t.Fatal("changed nonce accepted under reviewed ID")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed nonce published", err)
	}
}

func TestManagedCustodyIntentCLIRejectsIncompleteConflictingAndMalformedInput(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	args, path, nonce := managedCustodyIntentFixtureArgs(t, f)
	id, _ := f.intent.ID()
	for name, bad := range map[string][]string{
		"mode": replacePruneEffectConfigArg(args, "--mode", "create"), "publish-without-pin": append(append([]string(nil), args...), "--mode", "publish"),
		"wrong-initial-receipt": replacePruneEffectConfigArg(args, "--prior-receipt-id", pruneCLIHash(122).String()), "wrong-role": replacePruneEffectConfigArg(args, "--auditor-public-key", types.Hash(f.config.Assignment.AuthorityPublicKey).String()),
		"zero-head-nonzero-sequence": replacePruneEffectConfigArg(args, "--prior-sequence", "1"), "uppercase-head": replacePruneEffectConfigArg(args, "--prior-head-id", strings.Repeat("AB", 32)),
		"overflow": replacePruneEffectConfigArg(args, "--samples", "65536"), "expired-shape": replacePruneEffectConfigArg(args, "--expires-at", strconv.FormatUint(f.intent.IssuedAt, 10)),
		"same-nonce-parent": replacePruneEffectConfigArg(args, "--intent", filepath.Join(filepath.Dir(nonce), "intent.omcai")), "missing-parent": replacePruneEffectConfigArg(args, "--intent", filepath.Join(t.TempDir(), "missing", "intent.omcai")),
		"empty-optional-pin": append(append([]string(nil), args...), "--intent-id", ""), "duplicate": append(append([]string(nil), args...), "--samples", "1"),
		"verify-construction-fields": append(append([]string(nil), args...), "--mode", "verify", "--intent-id", id.String()),
	} {
		t.Run(name, func(t *testing.T) {
			if err := runManagedCustodyIntent(t.Context(), bad, &bytes.Buffer{}); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
	// Explicit zero predecessor is still required; omission is not a default.
	without := append([]string(nil), args[:1]...)
	for n := 1; n < len(args); n += 2 {
		if args[n] != "--prior-sequence" {
			without = append(without, args[n:n+2]...)
		}
	}
	if err := runManagedCustodyIntent(t.Context(), without, &bytes.Buffer{}); err == nil {
		t.Fatal("omitted predecessor sequence inferred")
	}
	writePruneCLIFile(t, path, []byte("conflict"))
	if err := runManagedCustodyIntent(t.Context(), append(append([]string(nil), args...), "--mode", "publish", "--intent-id", id.String()), &bytes.Buffer{}); err == nil {
		t.Fatal("conflicting intent replaced")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "conflict" {
		t.Fatal("conflicting bytes changed", err)
	}
}
