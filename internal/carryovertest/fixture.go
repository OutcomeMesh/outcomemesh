// Package carryovertest reads the committed public legacy acceptance corpus.
// Its deterministic fixture keys are public; no deployment owners are loaded.
package carryovertest

import (
	"archive/tar"
	"compress/gzip"
	review "github.com/outcomemesh/outcomemesh/node/custodycutover/review"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func Proposal(t testing.TB) review.Proposal {
	t.Helper()
	root, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	var file string
	for {
		file = filepath.Join(root, "docs/evidence/custody-cutover-review-public-20261028.tar.gz")
		if _, err := os.Stat(file); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("committed public corpus not found")
		}
		root = parent
	}
	f, e := os.Open(file)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if e != nil {
			t.Fatal(e)
		}
		if h.Name != "proposal" {
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(tr, review.MaximumProposalBytes+1))
		if e != nil {
			t.Fatal(e)
		}
		p, e := review.DecodeProposal(raw)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
}
