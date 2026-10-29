package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/storage"
)

func migrationFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "source")
	if e := runInit([]string{"--data", dir, "--network", "10731", "--timestamp", "1700000000", "--difficulty-bits", "9"}); e != nil {
		t.Fatal(e)
	}
	doc, e := loadGenesis(dir)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := doc.ID()
	if e = runWorkEnable([]string{"--data", dir, "--activation-height", "2", "--confirm-genesis", id.String()}); e != nil {
		t.Fatal(e)
	}
	if e = runWorkMine([]string{"--data", dir, "--count", "3"}); e != nil {
		t.Fatal(e)
	}
	_, ledger, r, p, e := openWorkNode(dir)
	if e != nil {
		t.Fatal(e)
	}
	tip, _ := r.Tip()
	last, e := r.BlockByID(tip.ID)
	if e != nil {
		t.Fatal(e)
	}
	work, _ := last.WorkBlock()
	parent, e := r.TipByID(work.Header.Seal.AnchorParent)
	if e != nil {
		t.Fatal(e)
	}
	for _, label := range []string{"fork-b", "fork-c"} {
		payload, _, e := r.PrepareWork(parent.ID, tip.Timestamp, nil)
		if e != nil {
			t.Fatal(e)
		}
		inc, _ := workgraph.InclusionRoot(nil)
		tmpl, e := payload.SealTemplate(types.Address(types.DomainHash("test/migration", []byte(label))), inc, nil)
		if e != nil {
			t.Fatal(e)
		}
		seal, _, e := workgraph.MineAnchor(context.Background(), tmpl, 0)
		if e != nil {
			t.Fatal(e)
		}
		b, _, e := payload.Finalize(seal, nil)
		if e != nil {
			t.Fatal(e)
		}
		v, e := activation.Work(b, p.ActivationHeight)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = r.Submit(v); e != nil {
			t.Fatal(e)
		}
	}
	got, _ := r.Tip()
	if !storage.EqualTips(tip, got) {
		t.Fatal("fixture changed equal-work incumbent")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = ledger.Close(); e != nil {
		t.Fatal(e)
	}
	return dir
}
func migrationDigest(t *testing.T, path string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	e := filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(path, p)
		if e != nil {
			return e
		}
		out[rel] = sha256.Sum256(b)
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func migrationReview(t *testing.T, src, dst string, h uint64) ([]string, string) {
	t.Helper()
	args := []string{"--source", src, "--out", dst, "--radix-height", strconv.FormatUint(h, 10)}
	var out bytes.Buffer
	if e := workMigrateRadix(context.Background(), args, &out, nil); e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(out.String(), "review_id=")
	if len(parts) != 2 {
		t.Fatal("review output", out.String())
	}
	if _, e := os.Stat(dst); !os.IsNotExist(e) {
		t.Fatal("review created destination", e)
	}
	return args, strings.TrimSpace(parts[1])
}
func TestWorkRadixMigrationPreservesSourceForksAndActivates(t *testing.T) {
	src := migrationFixture(t)
	dst := filepath.Join(t.TempDir(), "destination")
	before := migrationDigest(t, src)
	args, pin := migrationReview(t, src, dst, 5)
	if !reflect.DeepEqual(before, migrationDigest(t, src)) {
		t.Fatal("review changed original")
	}
	wrong := append(append([]string{}, args...), "--mode", "run", "--expected-review-id", types.DomainHash("wrong").String())
	if e := workMigrateRadix(context.Background(), wrong, &bytes.Buffer{}, nil); e == nil {
		t.Fatal("accepted wrong pin")
	}
	if _, e := os.Stat(dst); !os.IsNotExist(e) {
		t.Fatal("wrong pin created output")
	}
	run := append(args, "--mode", "run", "--expected-review-id", pin)
	if e := workMigrateRadix(context.Background(), run, &bytes.Buffer{}, nil); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, migrationDigest(t, src)) {
		t.Fatal("migration changed original")
	}
	_, ledger, r, p, e := openWorkNode(dst)
	if e != nil {
		t.Fatal(e)
	}
	tip, _ := r.Tip()
	blocks, e := r.MigrationWorkBlocks(maximumMigrationBytes)
	if e != nil || len(blocks) != 4 {
		t.Fatal("retained forks", len(blocks), e)
	}
	if tip.Height != 3 || p.RadixActivationHeight != 5 {
		t.Fatal("migration tip/profile")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = ledger.Close(); e != nil {
		t.Fatal(e)
	}
	if e = runWorkMine([]string{"--data", dst, "--count", "3"}); e != nil {
		t.Fatal(e)
	}
	if e = runWorkVerify([]string{"--data", dst}); e != nil {
		t.Fatal(e)
	}
	_, ledger, r, _, e = openWorkNode(dst)
	if e != nil {
		t.Fatal(e)
	}
	defer ledger.Close()
	defer r.Close()
	snap, e := r.Snapshot()
	if e != nil || snap.CommitmentVersion() != state.CommitmentRadixV1 {
		t.Fatal("radix activation", e)
	}
	tip, e = r.Tip()
	if e != nil || tip.Height != 6 {
		t.Fatal("tip", e)
	}
	v, e := r.BlockByID(tip.ID)
	if e != nil || v.Version() != 3 {
		t.Fatal("v3 tip", e)
	}
	if !reflect.DeepEqual(before, migrationDigest(t, src)) {
		t.Fatal("destination execution changed source")
	}
}
func TestWorkRadixMigrationFailuresLeavePendingAndSourceIntact(t *testing.T) {
	src := migrationFixture(t)
	original := migrationDigest(t, src)
	for _, stage := range []string{"prepared", "block", "before-publish"} {
		t.Run(stage, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "incomplete")
			args, pin := migrationReview(t, src, dst, 6)
			args = append(args, "--mode", "run", "--expected-review-id", pin)
			fault := errors.New("injected interruption")
			e := workMigrateRadix(context.Background(), args, &bytes.Buffer{}, func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			})
			if !errors.Is(e, fault) {
				t.Fatal(e)
			}
			if _, e = os.Stat(filepath.Join(dst, workActivationPending)); e != nil {
				t.Fatal("missing barrier", e)
			}
			if _, e = os.Stat(filepath.Join(dst, workActivationFilename)); !os.IsNotExist(e) {
				t.Fatal("published incomplete destination", e)
			}

			doc, loadErr := loadGenesis(dst)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			gid, _ := doc.ID()
			if err := runWorkEnable([]string{"--data", dst, "--activation-height", "2", "--radix-height", "6", "--confirm-genesis", gid.String()}); err == nil {
				t.Fatal("work-enable published interrupted migration")
			}
			if e = rejectWorkActivation(dst, "mine"); e == nil {
				t.Fatal("legacy start accepted")
			}
			if _, s, r, _, e := openWorkNode(dst); e == nil {
				r.Close()
				s.Close()
				t.Fatal("work start accepted")
			}
			if e = workMigrateRadix(context.Background(), args, &bytes.Buffer{}, nil); e == nil {
				t.Fatal("reused failed path")
			}
			if !reflect.DeepEqual(original, migrationDigest(t, src)) {
				t.Fatal("changed source")
			}
		})
	}
}
func TestWorkRadixMigrationRejectsStaleReviewAndOccupiedSource(t *testing.T) {
	src := migrationFixture(t)
	dst := filepath.Join(t.TempDir(), "destination")
	args, pin := migrationReview(t, src, dst, 7)
	_, s, r, _, e := openWorkNode(src)
	if e != nil {
		t.Fatal(e)
	}
	if e = workMigrateRadix(context.Background(), args, &bytes.Buffer{}, nil); e == nil {
		t.Fatal("accepted running source")
	}
	r.Close()
	s.Close()
	if e = runWorkMine([]string{"--data", src, "--count", "1"}); e != nil {
		t.Fatal(e)
	}
	args = append(args, "--mode", "run", "--expected-review-id", pin)
	if e = workMigrateRadix(context.Background(), args, &bytes.Buffer{}, nil); e == nil {
		t.Fatal("accepted stale review")
	}
	if _, e = os.Stat(dst); !os.IsNotExist(e) {
		t.Fatal("stale review wrote destination")
	}
	if e = workMigrateRadix(context.Background(), []string{"--source", src, "--out", dst, "--radix-height", "4"}, &bytes.Buffer{}, nil); e == nil {
		t.Fatal("retroactive activation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = workMigrateRadix(ctx, args, &bytes.Buffer{}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestRadixWorkProfileAndProtocol2Activation(t *testing.T) {
	for _, version := range []string{"0", "2"} {
		t.Run(version, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "node")
			if e := runInit([]string{"--data", dir, "--protocol-version", version, "--network", "10732", "--timestamp", "1700000000", "--difficulty-bits", "9"}); e != nil {
				t.Fatal(e)
			}
			doc, _ := loadGenesis(dir)
			id, _ := doc.ID()
			if e := runWorkEnable([]string{"--data", dir, "--activation-height", "2", "--radix-height", "2", "--confirm-genesis", id.String()}); e != nil {
				t.Fatal(e)
			}
			p, e := loadWorkActivation(dir, doc)
			if e != nil {
				t.Fatal(e)
			}
			raw := p.canonicalBytes()
			got, e := decodeWorkActivation(raw)
			if e != nil || got != p || len(raw) != 72 {
				t.Fatal("profile codec", e)
			}
			for i := 0; i < len(raw); i++ {
				if _, e = decodeWorkActivation(raw[:i]); e == nil {
					t.Fatal("truncated profile", i)
				}
			}
			if e = runWorkMine([]string{"--data", dir, "--count", "3"}); e != nil {
				t.Fatal(e)
			}
			if e = runWorkVerify([]string{"--data", dir}); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func FuzzWorkActivationProfiles(f *testing.F) {
	p := workActivationProfile{NetworkID: 1, GenesisID: types.DomainHash("profile"), ActivationHeight: 2, RadixActivationHeight: 5, FeeDelay: 3, MaxTrees: 4, MaxHistoryBytes: minimumHistoryBytes}
	f.Add(p.canonicalBytes())
	p.RadixActivationHeight = 0
	f.Add(p.canonicalBytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, e := decodeWorkActivation(b); e == nil && !bytes.Equal(p.canonicalBytes(), b) {
			t.Fatal("noncanonical profile")
		}
	})
}

func TestWorkRadixMigrationRejectsIncompleteMetadataAndAliases(t *testing.T) {
	src := migrationFixture(t)
	for _, name := range []string{"FOREST", "SELECTED"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(src, workForestDirectory, name)
			saved := filepath.Join(t.TempDir(), name)
			if e := os.Rename(path, saved); e != nil {
				t.Fatal(e)
			}
			defer os.Rename(saved, path)
			before := migrationDigest(t, src)
			dst := filepath.Join(t.TempDir(), "never-created")
			if e := workMigrateRadix(context.Background(), []string{"--source", src, "--out", dst, "--radix-height", "5"}, &bytes.Buffer{}, nil); e == nil {
				t.Fatal("repaired missing metadata")
			}
			if !reflect.DeepEqual(before, migrationDigest(t, src)) {
				t.Fatal("modified incomplete source")
			}
			if _, e := os.Stat(dst); !os.IsNotExist(e) {
				t.Fatal("created output")
			}
		})
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(src, alias); e != nil {
		t.Fatal(e)
	}
	if _, _, e := migrationPaths(alias, filepath.Join(t.TempDir(), "out")); e == nil {
		t.Fatal("source symlink")
	}
	if _, _, e := migrationPaths(src, filepath.Join(src, "nested")); e == nil {
		t.Fatal("nested destination")
	}
	existing := t.TempDir()
	if _, _, e := migrationPaths(src, existing); e == nil {
		t.Fatal("existing destination")
	}
}

func TestGoldenRadixActivationProfile(t *testing.T) {
	p := workActivationProfile{NetworkID: 1, GenesisID: types.Hash{1}, ActivationHeight: 2, RadixActivationHeight: 5, FeeDelay: 3, MaxTrees: 4, MaxHistoryBytes: minimumHistoryBytes}
	const want = "4f4d574f524b000200000001010000000000000000000000000000000000000000000000000000000000000000000000000000020003000400000000040000000000000000000005"
	if got := hex.EncodeToString(p.canonicalBytes()); got != want {
		t.Fatal(got)
	}
}
