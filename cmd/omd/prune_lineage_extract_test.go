package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type pruneLineageCLISource struct {
	AssignmentID             string `json:"assignment_id"`
	Journal                  string `json:"journal"`
	Checkpoint               string `json:"checkpoint"`
	CheckpointID             string `json:"checkpoint_id"`
	Manifest                 string `json:"manifest"`
	InitialReceipt           string `json:"initial_receipt"`
	MaximumChallengeLifetime uint64 `json:"maximum_challenge_lifetime"`
	MaximumProofAge          uint64 `json:"maximum_proof_age"`
	MaximumRenewalTerm       uint64 `json:"maximum_renewal_term"`
}

type pruneLineageCLIFixture struct {
	root, inventoryPath, sourcesPath, outPath string
	inventoryID, policyID, evidenceID         types.Hash
	evidenceBytes                             []byte
	sources                                   []pruneLineageCLISource
	journals                                  []*workarchive.CustodyJournal
}

func newPruneLineageCLIFixture(t testing.TB) *pruneLineageCLIFixture {
	t.Helper()
	encoded, err := os.ReadFile("../../node/custodyauthority/store/testdata/prune_lineage_evidence_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Inventory, Evidence               []byte
		InventoryID, PolicyID, EvidenceID string
	}
	if err := json.Unmarshal(encoded, &golden); err != nil {
		t.Fatal(err)
	}
	f := &pruneLineageCLIFixture{root: t.TempDir(), evidenceBytes: golden.Evidence}
	for _, item := range []struct {
		text string
		out  *types.Hash
	}{{golden.InventoryID, &f.inventoryID}, {golden.PolicyID, &f.policyID}, {golden.EvidenceID, &f.evidenceID}} {
		*item.out, err = pruneExternalID("fixture", item.text)
		if err != nil {
			t.Fatal(err)
		}
	}
	inputs, output := filepath.Join(f.root, "inputs"), filepath.Join(f.root, "output")
	for _, path := range []string{inputs, output} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.inventoryPath, f.sourcesPath, f.outPath = filepath.Join(inputs, "inventory.ompi"), filepath.Join(inputs, "sources.json"), filepath.Join(output, "lineages.omple")
	writePruneCLIFile(t, f.inventoryPath, golden.Inventory)
	inventory, err := authoritystore.LoadArchivePruneInventoryFile(f.inventoryPath, f.inventoryID, f.policyID)
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(inputs, "frozen.omple")
	writePruneCLIFile(t, evidencePath, golden.Evidence)
	evidence, err := authoritystore.LoadArchivePruneLineageEvidenceFile(t.Context(), evidencePath, inventory, f.inventoryID, f.policyID, f.evidenceID)
	if err != nil {
		t.Fatal(err)
	}
	lineages, err := evidence.Lineages(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i, lineage := range lineages {
		manifest, err := workarchive.DecodeManifest(lineage.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		journalPath := filepath.Join(f.root, fmt.Sprintf("journal-%d", i))
		journal, _, err := workarchive.OpenOrCreateCustodyJournal(journalPath, manifest, lineage.InitialReceipt, lineage.Policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, original := range lineage.Entries {
			entry, err := workarchive.DecodeCustodyJournalEntry(original)
			if err != nil {
				t.Fatal(err)
			}
			actual, applied, err := journal.Append(entry.Record)
			actualBytes, encodeErr := actual.CanonicalBytes()
			if err != nil || encodeErr != nil || !applied || !bytes.Equal(actualBytes, original) {
				t.Fatal("fixture journal changed the frozen winner", err, encodeErr)
			}
		}
		if _, err := journal.Rotate(); err != nil {
			t.Fatal(err)
		}
		checkpoint, err := workarchive.CaptureCustodyCheckpoint(journalPath, "", manifest, lineage.InitialReceipt, lineage.Policy)
		if err != nil {
			t.Fatal(err)
		}
		checkpointID, err := checkpoint.ID()
		if err != nil {
			t.Fatal(err)
		}
		checkpointPath := filepath.Join(inputs, fmt.Sprintf("checkpoint-%d.omwaccpt", i))
		manifestPath := filepath.Join(inputs, fmt.Sprintf("manifest-%d.omwa", i))
		receiptPath := filepath.Join(inputs, fmt.Sprintf("initial-%d.omwarcp", i))
		checkpointBytes, _ := checkpoint.CanonicalBytes()
		receiptBytes, _ := lineage.InitialReceipt.CanonicalBytes()
		writePruneCLIFile(t, checkpointPath, checkpointBytes)
		writePruneCLIFile(t, manifestPath, lineage.Manifest)
		writePruneCLIFile(t, receiptPath, receiptBytes)
		f.sources = append(f.sources, pruneLineageCLISource{AssignmentID: lineage.AssignmentID.String(), Journal: journalPath,
			Checkpoint: checkpointPath, CheckpointID: checkpointID.String(), Manifest: manifestPath, InitialReceipt: receiptPath,
			MaximumChallengeLifetime: lineage.Policy.MaximumChallengeLifetime, MaximumProofAge: lineage.Policy.MaximumProofAge,
			MaximumRenewalTerm: lineage.Policy.MaximumRenewalTerm})
		f.journals = append(f.journals, journal)
	}
	f.writeSources(t)
	return f
}

func (f *pruneLineageCLIFixture) writeSources(t testing.TB) {
	t.Helper()
	encoded, err := json.Marshal(f.sources)
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, f.sourcesPath, encoded)
}

func (f *pruneLineageCLIFixture) args(mode string) []string {
	args := []string{pruneLineageExtractCommand, "--inventory", f.inventoryPath, "--inventory-id", f.inventoryID.String(),
		"--policy-id", f.policyID.String(), "--out", f.outPath}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	if mode == "verify" {
		return append(args, "--evidence-id", f.evidenceID.String())
	}
	return append(args, "--sources", f.sourcesPath)
}

func (f *pruneLineageCLIFixture) review(t testing.TB) map[string]string {
	t.Helper()
	var output bytes.Buffer
	if err := runPruneOffline(t.Context(), f.args("review"), &output); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(strings.SplitN(output.String(), "\n", 2)[0])
	if fields["review_id"] == "" || fields["evidence_id"] != f.evidenceID.String() || fields["artifact_published"] != "false" ||
		fields["historical_only"] != "true" || fields["execution_authorized"] != "false" || fields["owners_closed"] != "true" {
		t.Fatal("invalid historical extraction review", output.String())
	}
	return fields
}

func pruneLineageTree(t testing.TB, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			result[relative+"/"] = nil
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			result[relative] = []byte("symlink:" + target)
			return err
		}
		result[relative], err = os.ReadFile(path)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertPruneLineageTree(t testing.TB, root string, expected map[string][]byte) {
	t.Helper()
	if !reflect.DeepEqual(expected, pruneLineageTree(t, root)) {
		t.Fatal("historical operation changed source tree")
	}
}

func TestPruneLineageCLIReviewExtractVerifyAndOfflineHistory(t *testing.T) {
	f := newPruneLineageCLIFixture(t)
	before := pruneLineageTree(t, f.root)
	review := f.review(t)
	assertPruneLineageTree(t, f.root, before)
	var defaultOutput bytes.Buffer
	if err := runPruneOffline(t.Context(), f.args(""), &defaultOutput); err != nil || pruneCLIFields(strings.SplitN(defaultOutput.String(), "\n", 2)[0])["review_id"] != review["review_id"] {
		t.Fatal("default mode was not the same historical review", err)
	}
	f.sources[0], f.sources[1] = f.sources[1], f.sources[0]
	f.writeSources(t)
	if reordered := f.review(t); reordered["review_id"] != review["review_id"] {
		t.Fatal("source order changed the pinned inventory review")
	}
	args := append(f.args("extract"), "--expected-review-id", review["review_id"])
	var output bytes.Buffer
	if err := runPruneOffline(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(output.String())
	if fields["review_id"] != review["review_id"] || fields["evidence_id"] != f.evidenceID.String() || fields["artifact_published"] != "true" {
		t.Fatal("publication disagreed with review", output.String())
	}
	info, err := os.Stat(f.outPath)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatal("published evidence is missing or public", err)
	}
	for range 2 {
		if err := runPruneOffline(t.Context(), args, io.Discard); err != nil {
			t.Fatal("exact publication retry failed", err)
		}
		current, err := os.Stat(f.outPath)
		encoded, readErr := os.ReadFile(f.outPath)
		if err != nil || readErr != nil || !os.SameFile(info, current) || !bytes.Equal(encoded, f.evidenceBytes) {
			t.Fatal("publication retry replaced the retained evidence", err, readErr)
		}
	}
	// Verification uses the retained file and content pins, not current sources.
	for i, source := range f.sources {
		if err := os.Rename(source.Journal, filepath.Join(f.root, fmt.Sprintf("offline-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(f.sourcesPath); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runPruneOffline(t.Context(), f.args("verify"), &output); err != nil || pruneCLIFields(output.String())["evidence_verified"] != "true" {
		t.Fatal("verify required online sources", err, output.String())
	}
}

func TestPruneLineageCLIRejectsFlagsAndIndependentPins(t *testing.T) {
	f := newPruneLineageCLIFixture(t)
	for _, args := range [][]string{
		{pruneLineageExtractCommand}, append(f.args("review"), "positional"), append(f.args("review"), "--unknown", "true"),
		append(f.args("review"), "--sources", f.sourcesPath), append(f.args("review"), "--expected-review-id", ""),
		append(f.args("review"), "--evidence-id", ""), f.args("extract"), append(f.args("extract"), "--evidence-id", f.evidenceID.String()),
		append(f.args("verify"), "--sources", ""), append(f.args("verify"), "--expected-review-id", ""),
		pruneCLISet(f.args("review"), "mode", "unknown"), pruneCLISet(f.args("review"), "inventory-id", pruneCLIHash(99).String()),
		pruneCLISet(f.args("review"), "policy-id", pruneCLIHash(99).String()), pruneCLISet(f.args("review"), "out", ""),
	} {
		if err := runPruneOffline(t.Context(), args, io.Discard); err == nil {
			t.Fatal("invalid extraction flags or independent pins accepted", args)
		}
	}
	for _, input := range []struct {
		ctx context.Context
		out io.Writer
	}{{nil, io.Discard}, {t.Context(), nil}} {
		if err := runPruneOffline(input.ctx, f.args("review"), input.out); err == nil {
			t.Fatal("missing invocation context/output accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runPruneOffline(ctx, f.args("review"), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled review ignored its context", err)
	}
	if _, err := os.Stat(f.outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected invocation published evidence", err)
	}
}

type pruneLineageScopeFailWriter struct {
	writes int
	err    error
}

func (writer *pruneLineageScopeFailWriter) Write(encoded []byte) (int, error) {
	writer.writes++
	if writer.writes > 1 {
		return 0, writer.err
	}
	return len(encoded), nil
}

func TestPruneLineageCLIReviewShowsCanonicalScope(t *testing.T) {
	f := newPruneLineageCLIFixture(t)
	path := filepath.Join(filepath.Dir(f.sources[0].Manifest), "manifest with spaces=review.omwa")
	encoded, err := os.ReadFile(f.sources[0].Manifest)
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, path, encoded)
	f.sources[0].Manifest = path
	f.writeSources(t)
	var output bytes.Buffer
	if err := runPruneOffline(t.Context(), f.args("review"), &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(strings.TrimSpace(output.String()), "\n", 2)
	if len(lines) != 2 {
		t.Fatal("review exposed only an opaque digest", output.String())
	}
	var scope any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "scope:\n")), &scope); err != nil {
		t.Fatal("review scope is not complete JSON", err, output.String())
	}
	object, ok := scope.(map[string]any)
	if !ok {
		t.Fatal("review scope is not an object")
	}
	ordered, ok := object["inputs"].([]any)
	if !ok || len(ordered) != len(f.sources) {
		t.Fatal("review scope omitted its ordered source set")
	}
	for i, raw := range ordered {
		item, ok := raw.(map[string]any)
		want := f.sources[i]
		if !ok || item["assignment_id"] != want.AssignmentID || item["checkpoint_id"] != want.CheckpointID ||
			item["maximum_challenge_lifetime"] != float64(want.MaximumChallengeLifetime) ||
			item["maximum_proof_age"] != float64(want.MaximumProofAge) || item["maximum_renewal_term"] != float64(want.MaximumRenewalTerm) {
			t.Fatal("review scope changed source order, pins or policy", raw)
		}
	}
	stringsInScope := make(map[string]bool)
	var collect func(any)
	collect = func(value any) {
		switch value := value.(type) {
		case string:
			stringsInScope[value] = true
		case []any:
			for _, element := range value {
				collect(element)
			}
		case map[string]any:
			for _, element := range value {
				collect(element)
			}
		}
	}
	collect(scope)
	for _, raw := range []string{f.inventoryPath, f.sourcesPath, f.sources[0].Journal, f.sources[0].Manifest,
		f.sources[0].Checkpoint, f.sources[0].InitialReceipt} {
		canonical, err := filepath.EvalSymlinks(raw)
		if err != nil || !stringsInScope[canonical] {
			t.Fatal("review omitted an effective canonical input path", raw, canonical, err, output.String())
		}
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(f.outPath))
	if err != nil || !stringsInScope[filepath.Join(parent, filepath.Base(f.outPath))] {
		t.Fatal("review omitted the concrete canonical output", err, output.String())
	}
	failure := errors.New("scope output unavailable")
	writer := &pruneLineageScopeFailWriter{err: failure}
	if err := runPruneOffline(t.Context(), f.args("review"), writer); !errors.Is(err, failure) || writer.writes < 2 {
		t.Fatal("review scope failure did not fail the invocation", err)
	}
	if _, err := os.Stat(f.outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed review output published evidence", err)
	}
	for _, journal := range f.journals {
		owner, err := journal.AcquireDecision()
		if err != nil {
			t.Fatal("failed review scope output retained source ownership", err)
		}
		_ = owner.Close()
	}
}

func TestPruneLineageCLIStrictSourceMetadata(t *testing.T) {
	f := newPruneLineageCLIFixture(t)
	original, _ := os.ReadFile(f.sourcesPath)
	first, _ := json.Marshal(f.sources[0])
	for name, encoded := range map[string][]byte{
		"null-list": []byte("null"), "object-list": []byte("{}"), "empty": []byte("[]"), "trailing": append(bytes.Clone(original), []byte(" []")...),
		"unknown-key":      bytes.Replace(original, []byte(`"journal":`), []byte(`"unknown":"x","journal":`), 1),
		"wrong-case":       bytes.Replace(original, []byte(`"journal":`), []byte(`"Journal":`), 1),
		"duplicate-key":    bytes.Replace(original, []byte(`"journal":`), []byte(`"journal":"x","journal":`), 1),
		"null-path":        bytes.Replace(original, []byte(`"manifest":"`), []byte(`"manifest":null,"ignored":"`), 1),
		"missing-source":   append(append([]byte("["), first...), ']'),
		"duplicate-source": []byte("[" + string(first) + "," + string(first) + "]"),
		"bytes":            bytes.Repeat([]byte{' '}, (256<<10)+1),
		"count":            []byte("[" + strings.TrimSuffix(strings.Repeat(string(first)+",", 65), ",") + "]"),
	} {
		t.Run(name, func(t *testing.T) {
			writePruneCLIFile(t, f.sourcesPath, encoded)
			if err := runPruneOffline(t.Context(), f.args("review"), io.Discard); err == nil {
				t.Fatal("malformed source metadata accepted")
			}
		})
	}
	for _, field := range []string{"assignment_id", "journal", "checkpoint", "checkpoint_id", "manifest", "initial_receipt", "maximum_challenge_lifetime", "maximum_proof_age", "maximum_renewal_term"} {
		for _, variant := range []string{"missing", "null", "wrong-type"} {
			t.Run(field+"/"+variant, func(t *testing.T) {
				var changed []map[string]json.RawMessage
				_ = json.Unmarshal(original, &changed)
				switch variant {
				case "missing":
					delete(changed[0], field)
				case "null":
					changed[0][field] = json.RawMessage("null")
				case "wrong-type":
					changed[0][field] = json.RawMessage(`{}`)
				}
				encoded, _ := json.Marshal(changed)
				writePruneCLIFile(t, f.sourcesPath, encoded)
				if err := runPruneOffline(t.Context(), f.args("review"), io.Discard); err == nil {
					t.Fatal("missing/null/wrong-type source field accepted")
				}
			})
		}
	}
	writePruneCLIFile(t, f.sourcesPath, original)
	if _, err := os.Stat(f.outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source metadata rejection published an artifact", err)
	}
}

func TestPruneLineageCLIReviewBindsScopeAndRefusesStaleSources(t *testing.T) {
	f := newPruneLineageCLIFixture(t)
	review := f.review(t)
	original := append([]pruneLineageCLISource(nil), f.sources...)
	for _, name := range []string{"review-id", "out", "checkpoint-pin", "policy", "initial", "assignment", "checkpoint-file", "manifest-file", "receipt-file"} {
		t.Run(name, func(t *testing.T) {
			f.sources = append([]pruneLineageCLISource(nil), original...)
			args := append(f.args("extract"), "--expected-review-id", review["review_id"])
			switch name {
			case "review-id":
				args = pruneCLISet(args, "expected-review-id", pruneCLIHash(99).String())
			case "out":
				args = pruneCLISet(args, "out", filepath.Join(filepath.Dir(f.outPath), "changed.omple"))
			case "checkpoint-pin":
				f.sources[0].CheckpointID = pruneCLIHash(99).String()
			case "policy":
				f.sources[0].MaximumProofAge++
			case "initial":
				f.sources[0].InitialReceipt = f.sources[1].InitialReceipt
			case "assignment":
				f.sources[0].AssignmentID = pruneCLIHash(99).String()
			case "checkpoint-file":
				f.sources[0].Checkpoint = f.sources[1].Checkpoint
			case "manifest-file":
				// Identical manifest bytes at a new path still change reviewed scope.
				path := filepath.Join(filepath.Dir(f.sourcesPath), "copied-manifest")
				encoded, _ := os.ReadFile(f.sources[0].Manifest)
				writePruneCLIFile(t, path, encoded)
				f.sources[0].Manifest = path
			case "receipt-file":
				path := filepath.Join(filepath.Dir(f.sourcesPath), "copied-receipt")
				encoded, _ := os.ReadFile(f.sources[0].InitialReceipt)
				writePruneCLIFile(t, path, encoded)
				f.sources[0].InitialReceipt = path
			}
			f.writeSources(t)
			if err := runPruneOffline(t.Context(), args, io.Discard); err == nil {
				t.Fatal("changed source/review scope published evidence")
			}
			if _, err := os.Stat(f.outPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected changed scope left an output", err)
			}
		})
	}
	f.sources = original
	f.writeSources(t)
	// A layout-only change still invalidates the reviewed exact checkpoint.
	writePruneCLIFile(t, filepath.Join(f.sources[0].Journal, "unexpected"), []byte("stale source"))
	if err := runPruneOffline(t.Context(), append(f.args("extract"), "--expected-review-id", review["review_id"]), io.Discard); err == nil {
		t.Fatal("stale source tree passed the old review")
	}
}

func TestPruneLineageCLIRejectsUnsafePlacementAndArtifacts(t *testing.T) {
	f := newPruneLineageCLIFixture(t)
	for _, name := range []string{"missing-parent", "input-parent", "source-parent", "output-input-hardlink", "output-symlink", "sources-symlink", "checkpoint-symlink", "manifest-directory", "missing-receipt", "bad-checkpoint", "oversize-manifest"} {
		t.Run(name, func(t *testing.T) {
			args := f.args("review")
			var cleanup func()
			switch name {
			case "missing-parent":
				args = pruneCLISet(args, "out", filepath.Join(f.root, "missing", "out"))
			case "input-parent":
				args = pruneCLISet(args, "out", filepath.Join(filepath.Dir(f.inventoryPath), "out"))
			case "source-parent":
				args = pruneCLISet(args, "out", filepath.Join(f.sources[0].Journal, "out"))
			case "output-input-hardlink":
				if err := os.Link(f.inventoryPath, f.outPath); err != nil {
					t.Fatal(err)
				}
				cleanup = func() { _ = os.Remove(f.outPath) }
			case "output-symlink":
				if err := os.Symlink(f.inventoryPath, f.outPath); err != nil {
					t.Fatal(err)
				}
				cleanup = func() { _ = os.Remove(f.outPath) }
			case "sources-symlink":
				path := filepath.Join(f.root, "sources-alias")
				if err := os.Symlink(f.sourcesPath, path); err != nil {
					t.Fatal(err)
				}
				args = pruneCLISet(args, "sources", path)
			case "checkpoint-symlink", "manifest-directory", "missing-receipt", "bad-checkpoint", "oversize-manifest":
				original := append([]pruneLineageCLISource(nil), f.sources...)
				path := filepath.Join(filepath.Dir(f.sourcesPath), name)
				switch name {
				case "checkpoint-symlink":
					if err := os.Symlink(f.sources[0].Checkpoint, path); err != nil {
						t.Fatal(err)
					}
					f.sources[0].Checkpoint = path
				case "manifest-directory":
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
					f.sources[0].Manifest = path
				case "missing-receipt":
					f.sources[0].InitialReceipt = path
				case "bad-checkpoint":
					writePruneCLIFile(t, path, []byte{1})
					f.sources[0].Checkpoint = path
				case "oversize-manifest":
					writePruneCLIFile(t, path, make([]byte, workarchive.MaximumManifestBytes+1))
					f.sources[0].Manifest = path
				}
				f.writeSources(t)
				cleanup = func() { f.sources = original; f.writeSources(t) }
			}
			if cleanup != nil {
				defer cleanup()
			}
			before := pruneLineageTree(t, f.sources[0].Journal)
			if err := runPruneOffline(t.Context(), args, io.Discard); err == nil {
				t.Fatal("unsafe artifact or placement accepted")
			}
			assertPruneLineageTree(t, f.sources[0].Journal, before)
		})
	}
}

func TestPruneLineageCLIOutputFailureAndCancelledOwnership(t *testing.T) {
	f := newPruneLineageCLIFixture(t)
	failure := errors.New("output unavailable")
	before := pruneLineageTree(t, f.root)
	if err := runPruneOffline(t.Context(), f.args("review"), pruneFailWriter{failure}); !errors.Is(err, failure) {
		t.Fatal("review concealed output failure", err)
	}
	assertPruneLineageTree(t, f.root, before)
	review := f.review(t)
	args := append(f.args("extract"), "--expected-review-id", review["review_id"])
	if err := runPruneOffline(t.Context(), args, pruneFailWriter{failure}); !errors.Is(err, failure) {
		t.Fatal("published extraction concealed output failure", err)
	}
	encoded, err := os.ReadFile(f.outPath)
	if err != nil || !bytes.Equal(encoded, f.evidenceBytes) {
		t.Fatal("failed output erased or changed published evidence", err)
	}
	if err := runPruneOffline(t.Context(), f.args("verify"), io.Discard); err != nil {
		t.Fatal("publication could not be independently verified after output failure", err)
	}
	for _, journal := range f.journals {
		owner, err := journal.AcquireDecision()
		if err != nil {
			t.Fatal("stdout cleanup retained a source lock", err)
		}
		_ = owner.Close()
	}
	if err := os.Remove(f.outPath); err != nil {
		t.Fatal(err)
	}
	// Hold the lexically later path so a cancelled invocation also releases
	// any source it already acquired before reaching this one.
	index := 0
	if f.sources[0].Journal < f.sources[1].Journal {
		index = 1
	}
	owner, err := f.journals[index].AcquireDecision()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runPruneOffline(ctx, args, io.Discard) }()
	select {
	case err := <-done:
		t.Fatal("extraction ignored an owned journal", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled extraction lost cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("source lock wait ignored cancellation")
	}
	_ = owner.Close()
	for _, journal := range f.journals {
		owner, err := journal.AcquireDecision()
		if err != nil {
			t.Fatal("cancelled extraction leaked source ownership", err)
		}
		_ = owner.Close()
	}
	if _, err := os.Stat(f.outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled extraction published evidence", err)
	}
	if !reflect.DeepEqual(before, pruneLineageTree(t, f.root)) {
		t.Fatal("output failure/cancellation changed source files")
	}
}
