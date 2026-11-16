//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyguard"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func pruneBundlePaths(c *store.ScheduledPruneRuntimeConfig) []*string {
	paths := []*string{&c.InventoryPath, &c.ChainPath, &c.ChainPinsPath, &c.ExecutorPath, &c.ExecutorPinsPath}
	for i := range c.Authorities {
		a := &c.Authorities[i]
		paths = append(paths, &a.AuthorityPath, &a.AuthorityPinsPath)
	}
	for i := range c.Sources {
		s := &c.Sources[i]
		paths = append(paths, &s.Directory, &s.JournalPath)
	}
	return paths
}

// Place the fixture's original private roots before the issuer prepares the
// service descriptor. Public signing material and guard/witnesses stay outside.
func stagePruneBundleForEnrollment(t testing.TB, f *pruneServiceOwnerCLIFixture, root string) {
	t.Helper()
	for i, p := range pruneBundlePaths(&f.config.Runtime) {
		dir := filepath.Join(root, fmt.Sprintf("placement-%d", i))
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, filepath.Base(*p))
		if err := os.Rename(*p, target); err != nil {
			t.Fatal(err)
		}
		*p = target
	}
	raw, err := service.EncodeConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.configPath = filepath.Join(f.public, "bundle-config.json")
	writePruneCLIFile(t, f.configPath, raw)
}

func newPruneTransferBundle(t testing.TB) (*pruneServiceOwnerCLIFixture, service.TransferBundle) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := service.TransferBundle{Source: filepath.Join(parent, "source"), Destination: filepath.Join(parent, "destination")}
	if err = os.Mkdir(b.Source, 0700); err != nil {
		t.Fatal(err)
	}
	return preparePruneServiceOwnerAt(t, custodyguard.Config{Limit: 16}, b.Source), b
}

func pruneBundleTransferArgs(t testing.TB, f *pruneServiceOwnerCLIFixture, b service.TransferBundle, pos wire.Position) ([]string, string) {
	t.Helper()
	cursor := filepath.Join(f.public, "bundle.cursor")
	pruneServiceCLIJSON(t, cursor, pos)
	did, _ := f.descriptor.ID()
	relative, err := filepath.Rel(b.Source, f.root)
	if err != nil {
		t.Fatal(err)
	}
	review := []string{pruneServiceCommand, "--action", "transfer-review", "--root", f.root, "--destination", filepath.Join(b.Destination, relative), "--storage-root", b.Source, "--storage-destination", b.Destination, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", cursor, "--out", filepath.Join(f.public, "bundle-review.json")}
	id := pruneServiceCLIRun(t, review)
	move := replaceRemoteCLIFlag(review, "--action", "transfer")
	move = replaceRemoteCLIFlag(move, "--out", filepath.Join(f.public, "bundle-receipt.json"))
	return append(move, "--transfer-id", id), id
}

func useTransferredPruneBundle(t testing.TB, f *pruneServiceOwnerCLIFixture, b service.TransferBundle) {
	t.Helper()
	for _, p := range append(pruneBundlePaths(&f.config.Runtime), &f.root) {
		rel, err := filepath.Rel(b.Source, *p)
		if err != nil || !filepath.IsLocal(rel) {
			t.Fatal("fixture path outside bundle", *p, err)
		}
		*p = filepath.Join(b.Destination, rel)
	}
}

func TestPruneStorageBundleTransfer(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(map[bool]string{false: "admitted", true: "missing-final-signature"}[held], func(t *testing.T) {
			if held && os.Geteuid() == 0 {
				t.Skip("result-write fixture requires a non-root executor")
			}
			f, b := newPruneTransferBundle(t)
			before := pruneFailureAuthorities(t, f)
			var pos wire.Position
			if held {
				o, cursor := pruneFailureExecute(t, f, "result-write")
				pos = cursor
				if err := o.Close(); err != nil {
					t.Fatal(err)
				}
			}
			executor := pruneFailureSnapshot(t, f)
			effect, found := pruneFailureEffect(t, f)
			if found != held {
				t.Fatal("unexpected initial storage effect")
			}
			guard, err := f.guard.Position()
			if err != nil {
				t.Fatal(err)
			}
			originals := make(map[string]os.FileInfo)
			for _, p := range append(pruneBundlePaths(&f.config.Runtime), &f.root) {
				st, e := os.Stat(*p)
				if e != nil {
					t.Fatal(e)
				}
				rel, e := filepath.Rel(b.Source, *p)
				if e != nil {
					t.Fatal(e)
				}
				originals[rel] = st
			}
			move, _ := pruneBundleTransferArgs(t, f, b, pos)
			pruneServiceCLIRun(t, move)
			pruneServiceCLIRun(t, move)
			if _, err = os.Lstat(b.Source); !os.IsNotExist(err) {
				t.Fatal("old bundle still addressable", err)
			}
			for rel, original := range originals {
				newFile, e := os.Stat(filepath.Join(b.Destination, rel))
				if e != nil || !os.SameFile(original, newFile) {
					t.Fatal("original file or directory lost", rel, e)
				}
			}
			useTransferredPruneBundle(t, f, b)
			if !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) || !reflect.DeepEqual(executor, pruneFailureSnapshot(t, f)) {
				t.Fatal("transfer changed original obligations")
			}
			now, present := pruneFailureEffect(t, f)
			if present != found || !reflect.DeepEqual(now, effect) {
				t.Fatal("transfer changed storage effect")
			}
			if current, e := f.guard.Position(); e != nil || current != guard {
				t.Fatal("transfer spent a guard choice", e)
			}
			var response wire.Response
			if held {
				response = settlePruneServiceFixture(t, f, pos)
				completePruneServiceSettlement(t, f, response, before)
			} else {
				o := f.open(t, pos, nil)
				response, err = o.Execute(t.Context(), f.request, func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
					_, draft, e := ch.Candidate.Draft()
					if e != nil {
						return draft, e
					}
					return draft.Sign(pruneCLIKey(4))
				})
				if err != nil || response.Result == nil || response.Effect.Report.RemovedNodes == 0 {
					t.Fatal("original admission failed at new placement", err)
				}
				if e := o.Close(); e != nil {
					t.Fatal(e)
				}
				f.assertObligations(t)
			}
			f.stopNetwork()
			pos, err = response.Position()
			if err != nil {
				t.Fatal(err)
			}
			o := f.open(t, pos, &f.request)
			replayed, err := o.Execute(t.Context(), f.request, nil)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := response.CanonicalBytes()
			got, _ := replayed.CanonicalBytes()
			if !bytes.Equal(want, got) {
				t.Fatal("cold replay changed the signed response")
			}
		})
	}
}
