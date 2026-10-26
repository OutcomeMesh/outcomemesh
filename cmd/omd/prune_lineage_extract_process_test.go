//go:build integration

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func pruneLineageProcessFields(t testing.TB, args []string) map[string]string {
	t.Helper()
	output := runProcessCommand(t, 15*time.Second, args...)
	fields := outputFields(output, "work_prune_lineage_extraction")
	if fields["evidence_id"] == "" || fields["owners_closed"] != "true" || fields["historical_only"] != "true" || fields["execution_authorized"] != "false" {
		t.Fatal("process extraction report changed its historical scope", output)
	}
	return fields
}

func assertPruneLineageProcessSources(t testing.TB, f *pruneLineageCLIFixture, expected map[string][]byte) {
	t.Helper()
	after := pruneLineageTree(t, f.root)
	relative, err := filepath.Rel(f.root, f.outPath)
	if err != nil {
		t.Fatal(err)
	}
	delete(after, relative)
	if !reflect.DeepEqual(expected, after) {
		t.Fatal("process extraction changed a source or retained a temporary artifact")
	}
}

func requirePruneLineageProcessArtifact(t testing.TB, f *pruneLineageCLIFixture, original os.FileInfo) os.FileInfo {
	t.Helper()
	current, err := os.Stat(f.outPath)
	encoded, readErr := os.ReadFile(f.outPath)
	if err != nil || readErr != nil || !current.Mode().IsRegular() || current.Mode().Perm()&0o077 != 0 || !bytes.Equal(encoded, f.evidenceBytes) {
		t.Fatal("process publication changed the frozen evidence bytes", err, readErr)
	}
	if original != nil && !os.SameFile(original, current) {
		t.Fatal("exact process retry replaced the retained evidence inode")
	}
	return current
}

func movePruneLineageProcessSourcesOffline(t testing.TB, f *pruneLineageCLIFixture) {
	t.Helper()
	paths := make(map[string]struct{})
	paths[f.sourcesPath] = struct{}{}
	for _, source := range f.sources {
		for _, path := range []string{source.Journal, source.Checkpoint, source.Manifest, source.InitialReceipt} {
			paths[path] = struct{}{}
		}
	}
	for path := range paths {
		if err := os.Rename(path, path+".offline"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProcessPruneLineageExtractionRoundTrip(t *testing.T) {
	if output := runProcessCommand(t, 15*time.Second, "help"); !strings.Contains(output, pruneLineageExtractCommand) {
		t.Fatal("main help did not expose the reviewed extraction command")
	}
	t.Run("review_publish_retry_offline_verify", func(t *testing.T) {
		f := newPruneLineageCLIFixture(t)
		before := pruneLineageTree(t, f.root)
		review := pruneLineageProcessFields(t, f.args("review"))
		if review["mode"] != "review" || review["review_id"] == "" || review["evidence_id"] != f.evidenceID.String() || review["artifact_published"] != "false" {
			t.Fatal("process review did not identify the pinned extraction", review)
		}
		assertPruneLineageTree(t, f.root, before)
		extract := append(f.args("extract"), "--expected-review-id", review["review_id"])
		for _, changed := range [][]string{
			pruneCLISet(extract, "expected-review-id", pruneCLIHash(99).String()),
			pruneCLISet(extract, "out", filepath.Join(filepath.Dir(f.outPath), "other.omple")),
			pruneCLISet(extract, "inventory-id", pruneCLIHash(99).String()),
		} {
			if output, err := runProcessCommandError(15*time.Second, changed...); err == nil || strings.Contains(output, "artifact_published=true") {
				t.Fatal("process published an unreviewed scope", err, output)
			}
			assertPruneLineageTree(t, f.root, before)
		}
		published := pruneLineageProcessFields(t, extract)
		if published["mode"] != "extract" || published["review_id"] != review["review_id"] || published["artifact_published"] != "true" || published["evidence_id"] != f.evidenceID.String() {
			t.Fatal("process publication disagreed with review", published)
		}
		original := requirePruneLineageProcessArtifact(t, f, nil)
		assertPruneLineageProcessSources(t, f, before)
		for range 2 {
			if retried := pruneLineageProcessFields(t, extract); retried["review_id"] != review["review_id"] || retried["evidence_id"] != f.evidenceID.String() {
				t.Fatal("exact process retry changed the reviewed scope", retried)
			}
			requirePruneLineageProcessArtifact(t, f, original)
			assertPruneLineageProcessSources(t, f, before)
		}
		movePruneLineageProcessSourcesOffline(t, f)
		offline := pruneLineageTree(t, f.root)
		verified := pruneLineageProcessFields(t, f.args("verify"))
		if verified["mode"] != "verify" || verified["evidence_verified"] != "true" || verified["artifact_published"] != "false" || verified["evidence_id"] != f.evidenceID.String() {
			t.Fatal("retained verification required original sources", verified)
		}
		if output, err := runProcessCommandError(15*time.Second, pruneCLISet(f.args("verify"), "evidence-id", pruneCLIHash(99).String())...); err == nil || strings.Contains(output, "evidence_verified=true") {
			t.Fatal("process verification accepted the wrong evidence pin", err, output)
		}
		requirePruneLineageProcessArtifact(t, f, original)
		assertPruneLineageTree(t, f.root, offline)
	})
	t.Run("changed_source_after_review", func(t *testing.T) {
		f := newPruneLineageCLIFixture(t)
		review := pruneLineageProcessFields(t, f.args("review"))
		// An uncommitted body changes the reviewed tree even if its selected
		// receipt and sequence slots are unchanged. The CLI must not refresh pins.
		path := filepath.Join(f.sources[0].Journal, "pending", "changed-after-review")
		if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := pruneLineageTree(t, f.root)
		extract := append(f.args("extract"), "--expected-review-id", review["review_id"])
		if output, err := runProcessCommandError(15*time.Second, extract...); err == nil || strings.Contains(output, "artifact_published=true") {
			t.Fatal("changed source was published under an old review", err, output)
		}
		if _, err := os.Lstat(f.outPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("source mismatch left an output artifact", err)
		}
		assertPruneLineageTree(t, f.root, before)
	})
}

func TestProcessPruneLineageExtractionBrokenPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SIGPIPE regression")
	}
	f := newPruneLineageCLIFixture(t)
	before := pruneLineageTree(t, f.root)
	runPruneBrokenOutput(t, f.args("review"), nil)
	assertPruneLineageTree(t, f.root, before)
	if _, err := os.Lstat(f.outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("broken review output published an artifact", err)
	}
	review := pruneLineageProcessFields(t, f.args("review"))
	extract := append(f.args("extract"), "--expected-review-id", review["review_id"])
	runPruneBrokenOutput(t, extract, nil)
	original := requirePruneLineageProcessArtifact(t, f, nil)
	assertPruneLineageProcessSources(t, f, before)
	if retried := pruneLineageProcessFields(t, extract); retried["review_id"] != review["review_id"] || retried["artifact_published"] != "true" {
		t.Fatal("failed stdout prevented an exact publication retry", retried)
	}
	requirePruneLineageProcessArtifact(t, f, original)
	movePruneLineageProcessSourcesOffline(t, f)
	offline := pruneLineageTree(t, f.root)
	runPruneBrokenOutput(t, f.args("verify"), nil)
	if verified := pruneLineageProcessFields(t, f.args("verify")); verified["evidence_verified"] != "true" || verified["artifact_published"] != "false" {
		t.Fatal("verification after failed stdout changed the retained evidence", verified)
	}
	requirePruneLineageProcessArtifact(t, f, original)
	assertPruneLineageTree(t, f.root, offline)
}
