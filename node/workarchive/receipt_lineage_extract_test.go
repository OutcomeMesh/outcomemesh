package workarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func receiptLineageExtractionFixture(t testing.TB, entries int, incarnation byte) (CustodyReceiptLineageSource, *CustodyJournal, CustodyReceiptLineage) {
	t.Helper()
	lineage, assignment, _ := receiptLineageFixture(t)
	assignment.IncarnationID = types.DomainHash("test/lineage-extraction/incarnation", []byte{incarnation})
	lineage.AssignmentID, _ = assignment.ID()
	manifest, err := DecodeManifest(lineage.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	journal, _, err := OpenOrCreateCustodyJournal(filepath.Join(t.TempDir(), "journal"), manifest, lineage.InitialReceipt, lineage.Policy)
	if err != nil {
		t.Fatal(err)
	}
	selected := lineage.InitialReceipt
	for _, encoded := range lineage.Entries[:entries] {
		entry, err := DecodeCustodyJournalEntry(encoded)
		if err != nil {
			t.Fatal(err)
		}
		written, created, err := journal.Append(entry.Record)
		if err != nil || !created {
			t.Fatal("fixture append", created, err)
		}
		actual, _ := written.CanonicalBytes()
		if !bytes.Equal(actual, encoded) {
			t.Fatal("fixture changed canonical entry")
		}
		selected = entry.Record.RenewedReceipt
	}
	lineage.Entries = lineage.Entries[:entries]
	checkpoint, err := CaptureCustodyCheckpoint(journal.path, "", manifest, lineage.InitialReceipt, lineage.Policy)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := checkpoint.ID()
	return CustodyReceiptLineageSource{JournalPath: journal.path, Checkpoint: checkpoint, CheckpointID: id,
		Assignment: assignment, AssignmentID: lineage.AssignmentID, Manifest: lineage.Manifest,
		InitialReceipt: lineage.InitialReceipt, Policy: lineage.Policy, SelectedReceipt: selected}, journal, lineage
}

func refreshReceiptLineageSource(t testing.TB, source *CustodyReceiptLineageSource) {
	t.Helper()
	manifest, err := DecodeManifest(source.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	source.Checkpoint, err = CaptureCustodyCheckpoint(source.JournalPath, "", manifest, source.InitialReceipt, source.Policy)
	if err != nil {
		t.Fatal(err)
	}
	source.CheckpointID, _ = source.Checkpoint.ID()
}

// Unlike the production checkpoint walker this snapshot also records malformed
// source layouts, so a rejected extraction cannot silently repair them.
func receiptLineageSourceTree(t testing.TB, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += ":" + target
		} else if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			hash := sha256.New()
			_, readErr := io.Copy(hash, file)
			closeErr := file.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return err
			}
			value += fmt.Sprintf(":%x", hash.Sum(nil))
		}
		result[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReceiptLineageExtractionMixedPrefixesAndDetachedBuffers(t *testing.T) {
	empty, _, initial := receiptLineageExtractionFixture(t, 0, 1)
	renewed, journal, history := receiptLineageExtractionFixture(t, 2, 2)
	// A losing, canonical same-slot body and a duplicate winning body must not
	// turn the selected prefix into every file discovered in the journal.
	fixture := newCustodyRecordFixture(t)
	sibling := CustodyJournalEntry{Version: CustodyJournalEntryVersion0, Sequence: 1,
		PreviousReceipt: fixture.receipt, Record: fixture.buildRecord(t, 142, 1_003)}
	encoded, _ := sibling.CanonicalBytes()
	id, _ := sibling.ID()
	writeCheckpointTestFile(t, filepath.Join(journal.activePath(), custodyJournalBodyName(id)), encoded)
	if changed, err := journal.Rotate(); err != nil || !changed {
		t.Fatal("fixture rotation", changed, err)
	}
	first, _ := DecodeCustodyJournalEntry(history.Entries[0])
	firstID, _ := first.ID()
	writeCheckpointTestFile(t, filepath.Join(journal.activePath(), custodyJournalBodyName(firstID)), history.Entries[0])
	refreshReceiptLineageSource(t, &renewed)
	sources := []CustodyReceiptLineageSource{renewed, empty}
	want := []CustodyReceiptLineage{history, initial}
	before := []map[string]string{receiptLineageSourceTree(t, renewed.JournalPath), receiptLineageSourceTree(t, empty.JournalPath)}
	got, err := ExtractCustodyReceiptLineages(t.Context(), sources)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("extraction lost order or exact winning history", err)
	}
	for i, source := range sources {
		if err := VerifyCustodyReceiptLineage(t.Context(), got[i], source.Assignment, source.AssignmentID, source.SelectedReceipt); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before[i], receiptLineageSourceTree(t, source.JournalPath)) {
			t.Fatal("extraction changed a source tree")
		}
	}
	got[0].Manifest[0] ^= 1
	got[0].Entries[0][0] ^= 1
	got[0].Policy.TrustedAuditors[0][0] ^= 1
	if !reflect.DeepEqual(sources[0].Manifest, want[0].Manifest) || !reflect.DeepEqual(sources[0].Policy, want[0].Policy) {
		t.Fatal("result aliases caller inputs")
	}
	again, err := ExtractCustodyReceiptLineages(t.Context(), sources)
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("result mutation reached retained journal or another result", err)
	}
}

func TestReceiptLineageExtractionRejectsScopeBeforeFilesystem(t *testing.T) {
	source, _, _ := receiptLineageExtractionFixture(t, 1, 3)
	for _, mode := range []string{"checkpoint-pin", "zero-checkpoint-pin", "assignment-pin", "zero-assignment-pin", "assignment", "manifest", "initial", "policy", "auditors", "selected", "artifact-checkpoint", "version"} {
		t.Run(mode, func(t *testing.T) {
			bad := source
			bad.JournalPath = filepath.Join(t.TempDir(), "never-created")
			switch mode {
			case "checkpoint-pin":
				bad.CheckpointID[0] ^= 1
			case "zero-checkpoint-pin":
				bad.CheckpointID = types.Hash{}
			case "assignment-pin":
				bad.AssignmentID[0] ^= 1
			case "zero-assignment-pin":
				bad.AssignmentID = types.Hash{}
			case "assignment":
				bad.Assignment.IncarnationID[0] ^= 1
			case "manifest":
				bad.Manifest = []byte{0}
			case "initial":
				bad.InitialReceipt = source.SelectedReceipt
			case "policy":
				bad.Policy.MaximumProofAge++
			case "auditors":
				bad.Policy.TrustedAuditors = nil
			case "selected":
				bad.SelectedReceipt = source.InitialReceipt
			case "artifact-checkpoint":
				bad.Checkpoint.Artifacts = bad.Checkpoint.Journal
				bad.CheckpointID, _ = bad.Checkpoint.ID()
			case "version":
				bad.Checkpoint.Version++
			}
			got, err := ExtractCustodyReceiptLineages(t.Context(), []CustodyReceiptLineageSource{bad})
			if got != nil || !errors.Is(err, ErrReceiptLineage) || errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid scope reached filesystem or returned evidence", err)
			}
			if _, err := os.Lstat(bad.JournalPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid scope created a source", err)
			}
		})
	}
	for _, sources := range [][]CustodyReceiptLineageSource{nil, make([]CustodyReceiptLineageSource, MaximumReplicas+1), {source, source}} {
		if got, err := ExtractCustodyReceiptLineages(t.Context(), sources); got != nil || !errors.Is(err, ErrReceiptLineage) {
			t.Fatal("invalid source set accepted", err)
		}
	}
	if got, err := ExtractCustodyReceiptLineages(nil, []CustodyReceiptLineageSource{source}); got != nil || !errors.Is(err, ErrReceiptLineage) {
		t.Fatal("nil context accepted", err)
	}
}

func TestReceiptLineageExtractionRejectsChangedSourcesWithoutRepair(t *testing.T) {
	source, _, history := receiptLineageExtractionFixture(t, 2, 4)
	first, _ := DecodeCustodyJournalEntry(history.Entries[0])
	firstID, _ := first.ID()
	for _, mode := range []string{"missing-lock", "missing-body", "missing-slot", "corrupt-body", "truncated-header", "missing-active", "symlink-lock", "symlink-body"} {
		t.Run(mode, func(t *testing.T) {
			bad := source
			bad.JournalPath = filepath.Join(t.TempDir(), "copy")
			copyCheckpointTestTree(t, source.JournalPath, bad.JournalPath)
			journal := &CustodyJournal{path: bad.JournalPath}
			body := filepath.Join(journal.activePath(), custodyJournalBodyName(firstID))
			remove := func(path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing-lock":
				remove(filepath.Join(bad.JournalPath, custodyJournalLockName))
			case "missing-body":
				remove(body)
			case "missing-slot":
				remove(filepath.Join(journal.slotBucketPath(1), custodyJournalSlotName(1)))
			case "corrupt-body":
				writeCheckpointTestFile(t, body, []byte("not a canonical body"))
			case "truncated-header":
				writeCheckpointTestFile(t, filepath.Join(bad.JournalPath, custodyJournalHeaderName), []byte{0})
			case "missing-active":
				if err := os.Rename(journal.activePath(), filepath.Join(journal.segmentsPath(), "segment-11111111111111111111111111111111")); err != nil {
					t.Fatal(err)
				}
			case "symlink-lock":
				path := filepath.Join(bad.JournalPath, custodyJournalLockName)
				remove(path)
				if err := os.Symlink(filepath.Join(source.JournalPath, custodyJournalLockName), path); err != nil {
					t.Fatal(err)
				}
			case "symlink-body":
				remove(body)
				if err := os.Symlink(filepath.Join((&CustodyJournal{path: source.JournalPath}).activePath(), custodyJournalBodyName(firstID)), body); err != nil {
					t.Fatal(err)
				}
			}
			before := receiptLineageSourceTree(t, bad.JournalPath)
			if got, err := ExtractCustodyReceiptLineages(t.Context(), []CustodyReceiptLineageSource{bad}); got != nil || !errors.Is(err, ErrReceiptLineage) {
				t.Fatal("changed source was accepted", err)
			}
			if !reflect.DeepEqual(before, receiptLineageSourceTree(t, bad.JournalPath)) {
				t.Fatal("failed extraction changed or repaired its source")
			}
		})
	}
	for _, kind := range []string{"missing", "symlink", "nested"} {
		t.Run(kind, func(t *testing.T) {
			bad := source
			bad.JournalPath = filepath.Join(t.TempDir(), "candidate")
			if kind == "symlink" {
				if err := os.Symlink(source.JournalPath, bad.JournalPath); err != nil {
					t.Fatal(err)
				}
			} else if kind == "nested" {
				bad.JournalPath = filepath.Join(source.JournalPath, "nested")
			}
			if got, err := ExtractCustodyReceiptLineages(t.Context(), []CustodyReceiptLineageSource{bad}); got != nil || !errors.Is(err, ErrReceiptLineage) {
				t.Fatal("invalid source path accepted", err)
			}
			if kind == "missing" || kind == "nested" {
				if _, err := os.Lstat(bad.JournalPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("extraction created a missing directory", err)
				}
			}
		})
	}
}

func TestReceiptLineageExtractionRejectsStaleCheckpointAndLockAliases(t *testing.T) {
	for _, change := range []string{"append", "rotate", "pending"} {
		t.Run(change, func(t *testing.T) {
			source, journal, _ := receiptLineageExtractionFixture(t, 1, 5)
			switch change {
			case "append":
				all, _, _ := receiptLineageFixture(t)
				entry, _ := DecodeCustodyJournalEntry(all.Entries[1])
				if _, _, err := journal.Append(entry.Record); err != nil {
					t.Fatal(err)
				}
			case "rotate":
				if _, err := journal.Rotate(); err != nil {
					t.Fatal(err)
				}
			case "pending":
				writeCheckpointTestFile(t, filepath.Join(journal.path, custodyJournalPendingName, ".outcomemesh-custody-journal-abandoned"), []byte{1})
			}
			before := receiptLineageSourceTree(t, source.JournalPath)
			if got, err := ExtractCustodyReceiptLineages(t.Context(), []CustodyReceiptLineageSource{source}); got != nil || !errors.Is(err, ErrReceiptLineage) {
				t.Fatal("changed head or evidence tree reused old checkpoint", err)
			}
			if !reflect.DeepEqual(before, receiptLineageSourceTree(t, source.JournalPath)) {
				t.Fatal("stale checkpoint rejection changed source history")
			}
		})
	}
	left, _, _ := receiptLineageExtractionFixture(t, 1, 6)
	right, _, _ := receiptLineageExtractionFixture(t, 1, 7)
	for _, kind := range []string{"same-root", "ancestor-alias"} {
		t.Run(kind, func(t *testing.T) {
			alias := left
			alias.Assignment.IncarnationID[0] ^= 1
			alias.AssignmentID, _ = alias.Assignment.ID()
			if kind == "ancestor-alias" {
				parent := filepath.Join(t.TempDir(), "parent-alias")
				if err := os.Symlink(filepath.Dir(left.JournalPath), parent); err != nil {
					t.Fatal(err)
				}
				alias.JournalPath = filepath.Join(parent, filepath.Base(left.JournalPath))
			}
			before := receiptLineageSourceTree(t, left.JournalPath)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if got, err := ExtractCustodyReceiptLineages(ctx, []CustodyReceiptLineageSource{left, alias}); got != nil || !errors.Is(err, ErrReceiptLineage) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("overlapping canonical roots were not rejected before acquisition", err)
			}
			if !reflect.DeepEqual(before, receiptLineageSourceTree(t, left.JournalPath)) {
				t.Fatal("overlap rejection changed source tree")
			}
		})
	}
	lockPath := filepath.Join(right.JournalPath, custodyJournalLockName)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(left.JournalPath, custodyJournalLockName), lockPath); err != nil {
		t.Fatal(err)
	}
	before := []map[string]string{receiptLineageSourceTree(t, left.JournalPath), receiptLineageSourceTree(t, right.JournalPath)}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if got, err := ExtractCustodyReceiptLineages(ctx, []CustodyReceiptLineageSource{left, right}); got != nil || !errors.Is(err, ErrReceiptLineage) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shared lock inode was not rejected before acquisition", err)
	}
	for i, source := range []CustodyReceiptLineageSource{left, right} {
		if !reflect.DeepEqual(before[i], receiptLineageSourceTree(t, source.JournalPath)) {
			t.Fatal("alias rejection modified a source")
		}
	}
}

func TestReceiptLineageExtractionAggregateEntryPreflightAndCancellation(t *testing.T) {
	left, _, _ := receiptLineageExtractionFixture(t, 1, 8)
	right, _, _ := receiptLineageExtractionFixture(t, 1, 9)
	for _, sizes := range [][2]uint64{{MaximumReceiptLineageEntries + 1, 1}, {MaximumReceiptLineageEntries / 2, MaximumReceiptLineageEntries/2 + 1}} {
		sources := []CustodyReceiptLineageSource{left, right}
		for i := range sources {
			sources[i].Checkpoint.Sequence = sizes[i]
			sources[i].CheckpointID, _ = sources[i].Checkpoint.ID()
		}
		lock, err := acquireCustodyEvidenceLock(left.JournalPath, custodyJournalLockName, false)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		called := false
		got, err := extractCustodyReceiptLineages(ctx, sources, receiptLineageExtractHooks{at: func(string) error { called = true; return nil }})
		cancel()
		_ = lock.Close()
		if got != nil || !errors.Is(err, ErrReceiptLineage) || errors.Is(err, context.DeadlineExceeded) || called {
			t.Fatal("aggregate entry budget was not checked before source locks/copy", err)
		}
	}
	// Cancel while the last source is externally locked. An earlier acquired
	// source lock must be released too, not retained after the failed batch.
	sources := []CustodyReceiptLineageSource{left, right}
	sort.Slice(sources, func(i, j int) bool { return sources[i].JournalPath < sources[j].JournalPath })
	lock, err := acquireCustodyEvidenceLock(sources[1].JournalPath, custodyJournalLockName, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		got, err := ExtractCustodyReceiptLineages(ctx, sources)
		if got != nil {
			t.Error("cancelled extraction returned evidence")
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatal("extraction ignored external source lock", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost its cause", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lock wait ignored cancellation")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		held, err := acquireCustodyEvidenceLockContext(ctx, source.JournalPath, custodyJournalLockName, false)
		cancel()
		if err != nil {
			t.Fatal("failed batch leaked a source lock", err)
		}
		_ = held.Close()
	}
}

func TestReceiptLineageExtractionHoldsAllSourcesThroughCopy(t *testing.T) {
	for _, operation := range []string{"append", "rotate", "retire"} {
		t.Run(operation, func(t *testing.T) {
			left, _, leftWant := receiptLineageExtractionFixture(t, 0, 10)
			right, writer, rightWant := receiptLineageExtractionFixture(t, 1, 11)
			var next CustodyJournalEntry
			if operation == "append" {
				all, _, _ := receiptLineageFixture(t)
				next, _ = DecodeCustodyJournalEntry(all.Entries[1])
			}
			sources := []CustodyReceiptLineageSource{right, left}
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			type result struct {
				lineages []CustodyReceiptLineage
				err      error
			}
			done := make(chan result, 1)
			go func() {
				got, err := extractCustodyReceiptLineages(t.Context(), sources, receiptLineageExtractHooks{at: func(at string) error {
					if at == "before-body-copy" {
						close(reached)
						<-release
					}
					return nil
				}})
				done <- result{got, err}
			}()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("extractor did not reach copy barrier")
			}
			for _, source := range sources {
				file, err := os.OpenFile(filepath.Join(source.JournalPath, custodyJournalLockName), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				locked, err := tryLockCustodyJournalFile(file)
				_ = file.Close()
				if err != nil || locked {
					t.Fatal("extractor released source before body copies", err)
				}
			}
			changed := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "append":
					_, _, err = writer.Append(next.Record)
				case "rotate":
					_, err = writer.Rotate()
				case "retire":
					var lock *os.File
					lock, err = acquireCustodyEvidenceLock(writer.path, custodyJournalLockName, false)
					if err == nil {
						marker := CustodyParticipantRetirement{ProposalID: types.Hash{1}, Before: right.Checkpoint, DecidedAt: 30_001}
						encoded, _ := marker.CanonicalBytes()
						err = os.WriteFile(filepath.Join(writer.path, custodyRetirementFileName), encoded, 0o600)
						_ = lock.Close()
					}
				}
				changed <- err
			}()
			select {
			case err := <-changed:
				t.Fatal("writer crossed extraction copy barrier", err)
			case <-time.After(30 * time.Millisecond):
			}
			unblock()
			var extracted result
			select {
			case extracted = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("extractor did not release source locks")
			}
			if extracted.err != nil || !reflect.DeepEqual(extracted.lineages, []CustodyReceiptLineage{rightWant, leftWant}) {
				t.Fatal("extraction changed reviewed history", extracted.err)
			}
			select {
			case err := <-changed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not resume after extraction")
			}
		})
	}
}

func TestReceiptLineageExtractionRetiredHistoryAndCopyCancellation(t *testing.T) {
	source, journal, want := receiptLineageExtractionFixture(t, 2, 12)
	marker := CustodyParticipantRetirement{ProposalID: types.Hash{2}, Before: source.Checkpoint, DecidedAt: 30_001}
	encoded, _ := marker.CanonicalBytes()
	writeCheckpointTestFile(t, filepath.Join(source.JournalPath, custodyRetirementFileName), encoded)
	refreshReceiptLineageSource(t, &source)
	before := receiptLineageSourceTree(t, source.JournalPath)
	if got, err := ExtractCustodyReceiptLineages(t.Context(), []CustodyReceiptLineageSource{source}); err != nil || !reflect.DeepEqual(got, []CustodyReceiptLineage{want}) {
		t.Fatal("retired valid history was treated as live permission", err)
	}
	if _, err := journal.AcquireDecision(); !errors.Is(err, ErrCustodyJournalRetired) {
		t.Fatal("historical extraction reactivated retired source", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	got, err := extractCustodyReceiptLineages(ctx, []CustodyReceiptLineageSource{source}, receiptLineageExtractHooks{at: func(at string) error {
		if at == "before-body-copy" {
			cancel()
		}
		return nil
	}})
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation at copy boundary returned evidence", err)
	}
	if !reflect.DeepEqual(before, receiptLineageSourceTree(t, source.JournalPath)) {
		t.Fatal("historical extraction or cancellation changed retirement evidence")
	}
}
