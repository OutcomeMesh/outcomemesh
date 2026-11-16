//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func transferPruneFixtureOwner(t *testing.T, f *pruneServiceOwnerCLIFixture, position wire.Position) {
	t.Helper()
	did, _ := f.descriptor.ID()
	target := filepath.Join(filepath.Dir(f.root), "moved")
	cursor := filepath.Join(f.public, "retained-position.json")
	pruneServiceCLIJSON(t, cursor, position)
	review := []string{pruneServiceCommand, "--action", "transfer-review", "--root", f.root, "--destination", target,
		"--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", cursor, "--out", filepath.Join(f.public, "review.json")}
	id := pruneServiceCLIRun(t, review)
	move := replaceRemoteCLIFlag(review, "--action", "transfer")
	move = replaceRemoteCLIFlag(move, "--out", filepath.Join(f.public, "moved.json"))
	pruneServiceCLIRun(t, append(move, "--transfer-id", id))
	f.root = target
}

func TestPruneTransferRejectsLossOfRetainedOwnerHistory(t *testing.T) {
	t.Run("held-intent", func(t *testing.T) {
		f := preparePruneServiceOwnerCLI(t)
		o, pos := pruneFailureExecute(t, f, "guard-loss")
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		transferPruneFixtureOwner(t, f, pos)
		o = f.open(t, pos, &f.request)
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		// Preserve the enrolled events directory; only its pre-transfer
		// intent is missing. Even a separately retained older cursor must fail.
		if err := os.Remove(filepath.Join(f.root, "events", "intent")); err != nil {
			t.Fatal(err)
		}
		did, _ := f.descriptor.ID()
		if stale, err := service.Open(t.Context(), f.root, did, wire.Position{}, nil); err == nil {
			stale.Close()
			t.Fatal("missing retained intent accepted with a pristine cursor")
		}
		if _, err := service.ReviewContinuation(t.Context(), f.root, did, wire.Position{}, f.request); err == nil {
			t.Fatal("continuation accepted loss of a transfer-time intent")
		}
		f.assertObligations(t)
	})

	t.Run("installed-signer", func(t *testing.T) {
		f, receipt := preparePruneServiceReplacement(t)
		pruneServiceCLIRun(t, pruneSuccessorCLIArgs(t, f, receipt))
		transferPruneFixtureOwner(t, f, wire.Position{})
		if err := os.Remove(filepath.Join(f.root, "signer-succession")); err != nil {
			t.Fatal(err)
		}
		did, _ := f.descriptor.ID()
		if stale, err := service.Open(t.Context(), f.root, did, wire.Position{}, nil); err == nil {
			stale.Close()
			t.Fatal("cold move fell back from the retained signer to the revoked signer")
		}
		f.assertObligations(t)
	})
}

func TestPruneTransferAllowsSubsequentSignerAndEvents(t *testing.T) {
	f, receipt := preparePruneServiceReplacement(t)
	transferPruneFixtureOwner(t, f, wire.Position{})
	pruneServiceCLIRun(t, pruneSuccessorCLIArgs(t, f, receipt))
	o := f.open(t, wire.Position{}, nil)
	response, err := o.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		return approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, f.consumerPath, filepath.Join(f.public, "history.challenge"), filepath.Join(f.public, "history.approval"))
	})
	if err != nil || response.Result == nil || response.Result.Claim.Candidate.ServiceSigner() != receipt.Request.Successor {
		t.Fatal("post-transfer signer could not execute the original admission", err)
	}
	pos, err := response.Position()
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	f.stopNetwork()
	cold := f.open(t, pos, &f.request)
	got, err := cold.Execute(t.Context(), f.request, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, _ := response.CanonicalBytes()
	gotBytes, err := got.CanonicalBytes()
	if err != nil || !bytes.Equal(wantBytes, gotBytes) {
		t.Fatal("changed offline replay of post-transfer events", err)
	}
	if err := cold.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertObligations(t)
}
