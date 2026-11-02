//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func continuationCLI(t testing.TB, f *pruneServiceOwnerCLIFixture, position wire.Position) service.ContinuationReview {
	t.Helper()
	did, _ := f.descriptor.ID()
	pos := filepath.Join(t.TempDir(), "position")
	pruneServiceCLIJSON(t, pos, position)
	out := filepath.Join(t.TempDir(), "review")
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "continuation-review", "--root", f.root, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", pos, "--request", f.requestPath, "--out", out})
	var v struct {
		ReviewID         types.Hash
		Review           service.ContinuationReview
		ExecutionGranted bool
	}
	if err := json.Unmarshal(pruneServiceCLIRead(t, out), &v); err != nil {
		t.Fatal(err)
	}
	id, err := v.Review.ID()
	if err != nil || id != v.ReviewID || v.ExecutionGranted {
		t.Fatal("invalid continuation review", err)
	}
	return v.Review
}

func TestPruneServiceCLIContinuesIntentPrefixWithoutExecution(t *testing.T) {
	for _, n := range []int{0, 1, wire.RequestBytes / 2, wire.RequestBytes - 1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			f := preparePruneServiceOwnerCLI(t)
			did, _ := f.descriptor.ID()
			raw, _ := f.request.CanonicalBytes()
			path := filepath.Join(f.root, "events", "intent")
			// Unit construction only. Process tests kill the real publisher at this boundary.
			writePruneCLIFile(t, path, raw[:n])
			original, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			before := prunePrepareTree(t, f.config.Runtime.ExecutorPath)
			r := continuationCLI(t, f, wire.Position{})
			id, _ := r.ID()
			if r.Record != "intent" || r.RetainedBytes != uint32(n) || !r.Exists {
				t.Fatal("wrong prefix review")
			}
			position := filepath.Join(t.TempDir(), "position")
			pruneServiceCLIJSON(t, position, wire.Position{})
			out, cursor := filepath.Join(t.TempDir(), "continued"), filepath.Join(t.TempDir(), "cursor")
			args := []string{pruneServiceCommand, "--action", "continue", "--root", f.root, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", position, "--request", f.requestPath, "--continuation-id", id.String(), "--out", out, "--position-out", cursor}
			pruneServiceCLIRun(t, args)
			current, err := os.Stat(path)
			if err != nil || !os.SameFile(original, current) || !bytes.Equal(pruneServiceCLIRead(t, path), raw) {
				t.Fatal("original inode/prefix not preserved", err)
			}
			if !reflect.DeepEqual(before, prunePrepareTree(t, f.config.Runtime.ExecutorPath)) {
				t.Fatal("continuation touched execution")
			}
			owner := f.open(t, wire.Position{}, &f.request)
			_, err = owner.Execute(t.Context(), f.request, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
				t.Error("continuation created a session")
				return custodyfence.Command{}, io.ErrUnexpectedEOF
			})
			if !errors.Is(err, service.ErrHeld) {
				t.Fatal("intent not held", err)
			}
			if err = owner.Close(); err != nil {
				t.Fatal(err)
			}
			pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "status", "--root", f.root, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", position, "--request", f.requestPath, "--out", filepath.Join(t.TempDir(), "status")})
			f.assertObligations(t)
		})
	}
}

func TestPruneServiceContinuationRejectsChangedAndMissingEvidence(t *testing.T) {
	f := preparePruneServiceOwnerCLI(t)
	did, _ := f.descriptor.ID()
	raw, _ := f.request.CanonicalBytes()
	path := filepath.Join(f.root, "events", "intent")
	if _, err := service.ReviewContinuation(t.Context(), f.root, did, wire.Position{}, f.request); err == nil {
		t.Fatal("missing intent manufactured")
	}
	writePruneCLIFile(t, path, raw[:30])
	r := continuationCLI(t, f, wire.Position{})
	id, _ := r.ID()
	w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(raw[30:31]); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Continue(t.Context(), f.root, did, wire.Position{}, f.request, id); err == nil {
		t.Fatal("stale prefix review accepted")
	}
	if got := pruneServiceCLIRead(t, path); !bytes.Equal(got, raw[:31]) {
		t.Fatal("stale review wrote bytes")
	}
	r = continuationCLI(t, f, wire.Position{})
	id, _ = r.ID()
	if err = os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, path, raw[:31])
	if err = os.Remove(path + ".saved"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Continue(t.Context(), f.root, did, wire.Position{}, f.request, id); err == nil {
		t.Fatal("replacement inode accepted")
	}
	bad := append([]byte(nil), raw[:31]...)
	bad[20] ^= 1
	if err = os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReviewContinuation(t.Context(), f.root, did, wire.Position{}, f.request); err == nil {
		t.Fatal("conflicting prefix accepted")
	}
	f.assertObligations(t)
}

func TestPruneServiceContinuationRestoresOnlyConfirmedResult(t *testing.T) {
	f := preparePruneServiceOwnerCLI(t)
	did, _ := f.descriptor.ID()
	owner := f.open(t, wire.Position{}, nil)
	r, err := owner.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		return approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, f.consumerPath, filepath.Join(f.public, "challenge"), filepath.Join(f.public, "approval"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.stopNetwork()
	if err = os.Remove(f.consumerPath); err != nil {
		t.Fatal(err)
	}
	for _, src := range f.config.Runtime.Sources {
		for _, p := range []string{src.Directory, src.JournalPath} {
			if err = os.Rename(p, p+".offline"); err != nil {
				t.Fatal(err)
			}
		}
	}
	executorBefore := prunePrepareTree(t, f.config.Runtime.ExecutorPath)
	pinsBefore := prunePrepareTree(t, f.config.Runtime.ExecutorPinsPath)
	raw, _ := r.CanonicalBytes()
	path := filepath.Join(f.root, "events", "result")
	// Represent a torn outer publication while keeping the original signed result.
	if err = os.WriteFile(path, raw[:len(raw)/2], 0600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	position, _ := f.request.IntentPosition()
	review := continuationCLI(t, f, position)
	id, _ := review.ID()
	if review.Record != "result" || review.TargetBytes != uint32(len(raw)) {
		t.Fatal("wrong result review")
	}
	snapshot, err := service.Continue(t.Context(), f.root, did, position, f.request, id)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Response == nil || snapshot.Position.Sequence != 2 {
		t.Fatal("result not confirmed")
	}
	current, err := os.Stat(path)
	if err != nil || !os.SameFile(original, current) || !bytes.Equal(raw, pruneServiceCLIRead(t, path)) {
		t.Fatal("response changed", err)
	}
	if !reflect.DeepEqual(executorBefore, prunePrepareTree(t, f.config.Runtime.ExecutorPath)) || !reflect.DeepEqual(pinsBefore, prunePrepareTree(t, f.config.Runtime.ExecutorPinsPath)) {
		t.Fatal("continuation rewrote original executor")
	}
	// A complete retained response can be synchronized with all original sources offline.
	if err = os.Rename(f.config.Runtime.ExecutorPath, f.config.Runtime.ExecutorPath+".offline"); err != nil {
		t.Fatal(err)
	}
	review = continuationCLI(t, f, snapshot.Position)
	id, _ = review.ID()
	if _, err = service.Continue(t.Context(), f.root, did, snapshot.Position, f.request, id); err != nil {
		t.Fatal("offline confirmation", err)
	}
	f.assertObligations(t)
}
