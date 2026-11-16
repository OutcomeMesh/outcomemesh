//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func TestPruneServiceOwnerTransferCLI(t *testing.T) {
	f, replacement := preparePruneServiceReplacement(t)
	pruneServiceCLIRun(t, pruneSuccessorCLIArgs(t, f, replacement))
	source := f.root
	destination := filepath.Join(filepath.Dir(source), "relocated")
	did, _ := f.descriptor.ID()
	cursor := filepath.Join(f.public, "transfer.cursor")
	pruneServiceCLIJSON(t, cursor, wire.Position{})
	reviewPath := filepath.Join(f.public, "transfer-review.json")
	receiptPath := filepath.Join(f.public, "transferred.json")
	review := []string{pruneServiceCommand, "--action", "transfer-review", "--root", source, "--destination", destination,
		"--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", cursor, "--out", reviewPath}
	apply := func(args []string, out io.Writer) error {
		hash := pruneServiceCLIReview(t, args)
		run := append(append([]string(nil), args...), "--mode", "run", "--expected-review-id", hash)
		return runPruneServiceCLIContext(t.Context(), run, out)
	}
	before := pruneFailureAuthorities(t, f)
	executor := pruneFailureSnapshot(t, f)
	guard, err := f.guard.Position()
	if err != nil {
		t.Fatal(err)
	}
	hot := f.open(t, wire.Position{}, nil)
	if err := apply(review, io.Discard); err == nil {
		t.Fatal("review opened a running owner")
	}
	if err := hot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(reviewPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unconfirmed review published an artifact", err)
	}
	tid := pruneServiceCLIRun(t, review)
	var r pruneServiceTransferReviewReport
	if err := cutoverJSON(pruneServiceCLIRead(t, reviewPath), &r); err != nil || r.ReviewID != tid || r.ExecutionGranted {
		t.Fatal("transfer review omitted its exact pin", err)
	}
	move := replaceRemoteCLIFlag(review, "--action", "transfer")
	move = append(replaceRemoteCLIFlag(move, "--out", receiptPath), "--transfer-id", tid)
	wrong := types.DomainHash("test/another-transfer").String()
	if err := apply(replaceRemoteCLIFlag(move, "--transfer-id", wrong), io.Discard); err == nil {
		t.Fatal("unrelated transfer review accepted")
	}
	conflict := filepath.Join(f.public, "conflict.report")
	writePruneCLIFile(t, conflict, []byte("another transfer"))
	if err := apply(replaceRemoteCLIFlag(move, "--out", conflict), io.Discard); err == nil {
		t.Fatal("transfer accepted a conflicting receipt")
	}
	privateReport := filepath.Join(f.config.Runtime.ExecutorPinsPath, "transfer-report")
	if err := apply(replaceRemoteCLIFlag(move, "--out", privateReport), io.Discard); err == nil {
		t.Fatal("transfer accepted a receipt inside original pins")
	}
	// The receipt and destination are both absent. They still cannot be
	// alternate names for the same future entry on a case-insensitive volume.
	alias := filepath.Join(filepath.Dir(destination), "Relocated")
	if err := apply(replaceRemoteCLIFlag(move, "--out", alias), io.Discard); err == nil {
		t.Fatal("transfer accepted its destination as a differently cased receipt")
	}
	unicodeTarget := filepath.Join(filepath.Dir(destination), "dépôt")
	unicodeReport := filepath.Join(filepath.Dir(destination), "de\u0301po\u0302t")
	alternate := replaceRemoteCLIFlag(review, "--destination", unicodeTarget)
	alternate = replaceRemoteCLIFlag(alternate, "--out", unicodeReport)
	if err := apply(alternate, io.Discard); err == nil {
		t.Fatal("transfer review accepted a canonically equivalent future receipt name")
	}
	for _, path := range []string{destination, privateReport, receiptPath, alias, unicodeReport} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused transfer created a file", path, err)
		}
	}
	for _, invalid := range [][]string{
		replaceRemoteCLIFlag(move, "--destination", source),
		replaceRemoteCLIFlag(move, "--out", destination),
		append(append([]string(nil), move...), "--storage-root", filepath.Dir(source)),
		append(append([]string(nil), move...), "--storage-destination", destination),
		append(append([]string(nil), move...), "--storage-root", filepath.Dir(source), "--storage-destination", destination),
	} {
		if err := runPruneServiceCLIContext(t.Context(), invalid, io.Discard); err == nil {
			t.Fatal("invalid placement received a public review", invalid)
		}
	}
	lost := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := apply(move, lost); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("transfer did not reach final receipt", err)
	}
	receipt := pruneServiceCLIRead(t, receiptPath)
	pruneServiceCLIRun(t, move)
	if !bytes.Equal(receipt, pruneServiceCLIRead(t, receiptPath)) {
		t.Fatal("exact transfer retry changed the receipt")
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source still present", err)
	}
	if old, err := service.Open(t.Context(), source, did, wire.Position{}, nil); err == nil {
		old.Close()
		t.Fatal("old placement still opened")
	}
	f.root = destination
	if !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) || !reflect.DeepEqual(executor, pruneFailureSnapshot(t, f)) {
		t.Fatal("transfer changed original authority or executor accounting")
	}
	if after, err := f.guard.Position(); err != nil || after != guard {
		t.Fatal("transfer changed guard history", err)
	}
	owner := f.open(t, wire.Position{}, nil)
	response, err := owner.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		return approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, f.consumerPath, filepath.Join(f.public, "moved.challenge"), filepath.Join(f.public, "moved.approval"))
	})
	if err != nil || response.Result == nil || response.Result.Claim.Candidate.ServiceSigner() != replacement.Request.Successor || response.Effect.Report.RemovedNodes == 0 {
		t.Fatal("relocated successor did not execute the original operation", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertObligations(t)
}
