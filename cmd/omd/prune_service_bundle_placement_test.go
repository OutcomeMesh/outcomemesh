//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func TestPruneStorageBundleRefusesCopiedArchive(t *testing.T) {
	f, b := newPruneTransferBundle(t)
	source := f.root
	did, _ := f.descriptor.ID()
	before := pruneFailureAuthorities(t, f)
	guard, err := f.guard.Position()
	if err != nil {
		t.Fatal(err)
	}
	move, _ := pruneBundleTransferArgs(t, f, b, wire.Position{})
	relativeOwner, err := filepath.Rel(b.Source, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{b.Source, filepath.Join(b.Source, "nested"), filepath.Dir(b.Source)} {
		overlap := replaceRemoteCLIFlag(move, "--storage-destination", destination)
		overlap = replaceRemoteCLIFlag(overlap, "--destination", filepath.Join(destination, relativeOwner))
		if err := runPruneServiceCLIContext(t.Context(), overlap, io.Discard); err == nil {
			t.Fatal("overlapping containers passed public review", destination)
		}
	}
	pruneServiceCLIRun(t, move)
	if stale, err := service.Open(t.Context(), source, did, wire.Position{}, nil); err == nil {
		stale.Close()
		t.Fatal("old placement reopened after completed transfer")
	}
	useTransferredPruneBundle(t, f, b)
	archive := f.config.Runtime.Sources[0].Directory
	original := filepath.Join(filepath.Dir(b.Destination), "original-archive")
	duplicate := filepath.Join(filepath.Dir(b.Destination), "copied-archive")
	// Keep both copies private and identical in content and permissions.
	// Only their filesystem identities distinguish the enrolled archive.
	if err := os.CopyFS(duplicate, os.DirFS(archive)); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(archive, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(archive, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.Chmod(filepath.Join(duplicate, rel), info.Mode().Perm())
	}); err != nil {
		t.Fatal(err)
	}
	hot := f.open(t, wire.Position{}, nil)
	if err := os.Rename(archive, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(duplicate, archive); err != nil {
		t.Fatal(err)
	}
	checkRefusal := func(owner *service.Owner) {
		t.Helper()
		requested := false
		_, err := owner.Execute(t.Context(), f.request, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
			requested = true
			return custodyfence.Command{}, errors.New("unexpected approval request")
		})
		if err == nil || requested {
			t.Fatal("copied archive reached approval", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	checkRefusal(hot)
	if cold, err := service.Open(t.Context(), f.root, did, wire.Position{}, nil); err == nil {
		checkRefusal(cold)
	}
	events, err := os.ReadDir(filepath.Join(f.root, "events"))
	if err != nil || len(events) != 0 {
		t.Fatal("refused request wrote an intent", err)
	}
	if got, err := f.guard.Position(); err != nil || got != guard {
		t.Fatal("refused request consumed a guard choice", err)
	}
	if !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) {
		t.Fatal("refused request changed replica obligations")
	}
	if err := os.Rename(archive, duplicate); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, archive); err != nil {
		t.Fatal(err)
	}
	owner := f.open(t, wire.Position{}, nil)
	r, err := owner.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		return approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, f.consumerPath, filepath.Join(f.public, "original.challenge"), filepath.Join(f.public, "original.approval"))
	})
	if err != nil || r.Result == nil || r.Effect.Report.RemovedNodes == 0 {
		t.Fatal("original archive did not resume execution", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertObligations(t)
}
