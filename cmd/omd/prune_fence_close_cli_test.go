package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

func testPruneFenceClosureCLI(t *testing.T, plan string, planID types.Hash, networkArgs []string) {
	t.Helper()
	args := []string{pruneFenceCloseCommand, "--plan", plan, "--plan-id", planID.String()}
	var review pruneFenceCloseReport
	scheduledCLIRun(t, args, &review)
	if review.ClosureVerified || review.AccountingChanged || review.ExecutionAuthorized || review.IntentID.IsZero() || review.ScopeID.IsZero() {
		t.Fatal("review authorized action")
	}
	controller := filepath.Join(t.TempDir(), "controller.seed")
	writePruneCLIFile(t, controller, pruneCLIKey(1).Seed())
	extra := append([]string(nil), networkArgs...)
	for i := range extra {
		if extra[i] == "--fence-owner-key" {
			extra[i] = "--controller-key"
			extra[i+1] = controller
		}
	}
	dest := filepath.Join(t.TempDir(), "closure")
	collect := append(append(append([]string(nil), args...), extra...), "--mode", "collect", "--expected-intent-id", review.IntentID.String(), "--out", dest)
	// Mismatched review, mixed modes, output aliases and a wrong signing role
	// must all fail before taking witness votes or creating a closure artifact.
	badReview := append([]string(nil), collect...)
	badReview[len(badReview)-3] = f.Hash("wrong").String()
	for _, bad := range [][]string{badReview, append(append([]string(nil), args...), "--controller-key", controller), append(append([]string(nil), args...), "--mode", "verify", "--closure", dest), append(append([]string(nil), args...), "--mode", "collect", "--expected-intent-id", review.IntentID.String(), "--out", plan)} {
		if err := runScheduledPruneOperator(t.Context(), bad, io.Discard); err == nil {
			t.Fatal("invalid closure invocation")
		}
	}
	wrongRole := append([]string(nil), collect...)
	for i := range wrongRole {
		if wrongRole[i] == "--controller-key" {
			wrongRole[i+1] = networkArgs[3]
		}
	}
	if err := runScheduledPruneOperator(t.Context(), wrongRole, io.Discard); err == nil {
		t.Fatal("owner acted as controller")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runScheduledPruneOperator(ctx, collect, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("invalid invocation wrote output", err)
	}
	fail := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runScheduledPruneOperator(t.Context(), collect, fail); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost report", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := prunefence.DecodeClosure(raw)
	if err != nil {
		t.Fatal(err)
	}
	cid, _ := closure.ID()
	if _, err := store.DecodePruneCancellation(raw); err == nil {
		t.Fatal("closure became local cancellation")
	}
	// Published evidence remains usable without secrets or reachable endpoints.
	for i := range collect {
		if collect[i] == "--controller-key" || collect[i] == "--fence-network" || collect[i] == "--fence-transport-key" {
			collect[i+1] = filepath.Join(t.TempDir(), "unavailable")
		}
	}
	var recovered pruneFenceCloseReport
	scheduledCLIRun(t, collect, &recovered)
	again, _ := os.ReadFile(dest)
	if !bytes.Equal(raw, again) || !recovered.ClosureVerified || recovered.ClosureID != cid || recovered.AccountingChanged || recovered.ExecutionAuthorized {
		t.Fatal("retry changed evidence or granted an effect")
	}
	verify := append(append([]string(nil), args...), "--mode", "verify", "--closure", dest, "--closure-id", cid.String())
	scheduledCLIRun(t, verify, &recovered)
	verify[len(verify)-1] = f.Hash("wrong certificate").String()
	if err := runScheduledPruneOperator(t.Context(), verify, io.Discard); err == nil {
		t.Fatal("wrong certificate pin")
	}
	foreign := closure
	foreign.Intent.RequestID = f.Hash("another original request")
	_, draft, err := foreign.Intent.Draft()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := draft.Sign(pruneCLIKey(1))
	if err != nil {
		t.Fatal(err)
	}
	foreign.Certificate = f.Certificate(signed, 70, 71, 72)
	foreignRaw, err := foreign.CanonicalBytes()
	if err != nil {
		t.Fatal("foreign fixture is not independently valid", err)
	}
	foreignID, _ := foreign.ID()
	foreignPath := filepath.Join(t.TempDir(), "foreign")
	writePruneCLIFile(t, foreignPath, foreignRaw)
	substituted := append(append([]string(nil), args...), "--mode", "verify", "--closure", foreignPath, "--closure-id", foreignID.String())
	if err := runScheduledPruneOperator(t.Context(), substituted, io.Discard); err == nil {
		t.Fatal("valid foreign certificate bypassed plan pin")
	}
	// Corrupt occupied outputs cannot be replaced by a freshly collected quorum.
	occupied := filepath.Join(t.TempDir(), "occupied")
	writePruneCLIFile(t, occupied, []byte("retained invalid artifact"))
	collect[len(collect)-1] = occupied
	if err := runScheduledPruneOperator(t.Context(), collect, io.Discard); err == nil {
		t.Fatal("overwrote existing output")
	}
	got, _ := os.ReadFile(occupied)
	if string(got) != "retained invalid artifact" {
		t.Fatal("output changed")
	}
}
