//go:build integration && (linux || darwin)

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
)

func TestProcessPruneServiceSettlementRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("result-write fault requires an unprivileged owner")
	}
	binary := prunePublicationBinary(t)
	for _, stage := range []string{"settlement-confirmed", "result-created", "result-partial", "result-file-synced", "response-ready"} {
		t.Run(stage, func(t *testing.T) {
			f := preparePruneServiceOwnerCLI(t)
			before := pruneFailureAuthorities(t, f)
			o, pos := pruneFailureExecute(t, f, "result-write")
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			apply, _, _ := preparePruneServiceSettlementCLI(t, f, pos)
			flag := func(name string) string {
				for i := 0; i+1 < len(apply); i++ {
					if apply[i] == name {
						return apply[i+1]
					}
				}
				t.Fatal("missing flag", name)
				return ""
			}
			in := pruneFailureInput(t, f)
			var err error
			in.DecisionPath, err = filepath.EvalSymlinks(flag("--settlement"))
			if err != nil {
				t.Fatal(err)
			}
			in.DecisionID, err = pruneExternalID("settlement-id", flag("--settlement-id"))
			if err != nil {
				t.Fatal(err)
			}
			reviewID, err := pruneExternalID("settlement-review-id", flag("--settlement-review-id"))
			if err != nil {
				t.Fatal(err)
			}
			did, _ := f.descriptor.ID()
			c := prunePublicationFixture{Root: f.root, Request: f.requestPath, DescriptorID: did, Before: pos, Stage: stage, Settlement: &in, SettlementReviewID: reviewID}
			killPrunePublication(t, binary, c)
			core := pruneFailureSnapshot(t, f)
			if core.FenceSettlement == nil || core.FenceResult != nil || core.Protection.Pending != nil {
				t.Fatal("settlement did not reach original confirmation")
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
			r, err := service.ReviewContinuation(t.Context(), f.root, did, pos, f.request)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := r.ID()
			if stage == "result-partial" {
				c.ContinuationID = id
				killPrunePublication(t, binary, c)
				if _, err = service.Continue(t.Context(), f.root, did, pos, f.request, id); err == nil {
					t.Fatal("stale settlement prefix review accepted")
				}
				r, err = service.ReviewContinuation(t.Context(), f.root, did, pos, f.request)
				if err != nil {
					t.Fatal(err)
				}
				id, _ = r.ID()
			}
			snapshot, err := service.Continue(t.Context(), f.root, did, pos, f.request, id)
			if err != nil || snapshot.Response == nil {
				t.Fatal("settlement continuation", err)
			}
			response := snapshot.Response
			if response.Verify(f.descriptor, f.request) != nil || response.Settlement == nil || response.Result != nil {
				t.Fatal("invalid recovered settlement")
			}
			raw, _ := response.CanonicalBytes()
			o = f.open(t, snapshot.Position, &f.request)
			replayed, err := o.Recover(t.Context(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			if err = o.Close(); err != nil {
				t.Fatal(err)
			}
			replayRaw, _ := replayed.CanonicalBytes()
			if !bytes.Equal(raw, replayRaw) || !bytes.Equal(raw, pruneServiceCLIRead(t, filepath.Join(f.root, "events", "result"))) {
				t.Fatal("recovery changed confirmed settlement bytes")
			}
			if !reflect.DeepEqual(core, pruneFailureSnapshot(t, f)) || !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) {
				t.Fatal("publication recovery changed original accounting")
			}
		})
	}
}
