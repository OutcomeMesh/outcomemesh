package workarchive

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodyCheckpointColdCopyPreservesPendingEvidence(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := t.TempDir()
	journalPath, artifacts := filepath.Join(root, "journal"), filepath.Join(root, "artifacts")
	journal, _, err := OpenOrCreateCustodyJournal(journalPath, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	firstRecord, _ := fixture.record.CanonicalBytes()
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000001", "record.omcr"), firstRecord)
	oldCheckpoint, err := CaptureCustodyCheckpoint(journalPath, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	oldCopy := filepath.Join(t.TempDir(), "old-copy")
	copyCheckpointTestTree(t, root, oldCopy)

	// A valid next response body exists without a slot; its challenge is already
	// durable at the auditor. Head alone cannot distinguish this from oldCopy.
	next := nextCustodyJournalRecord(t, fixture, fixture.record.RenewedReceipt, 144, 1_004, 1_005, 30_000)
	mustPanicCustodyJournal(t, func() {
		_, _, _ = journal.append(next, custodyJournalHooks{afterBody: panicCustodyJournalHook})
	})
	challenge, _ := next.Challenge.CanonicalBytes()
	nextRecord, _ := next.CanonicalBytes()
	cycle := "cycle-00000000000000000002"
	writeCheckpointTestFile(t, filepath.Join(artifacts, cycle, "challenge.omcc"), challenge)
	writeCheckpointTestFile(t, filepath.Join(artifacts, cycle, "record.omcr"), nextRecord)
	writeCheckpointTestFile(t, filepath.Join(artifacts, cycle, ".outcomemesh-work-artifact-partial"), []byte{1, 2, 3})
	writeCheckpointTestFile(t, filepath.Join(journalPath, "pending", ".outcomemesh-custody-journal-empty"), nil)
	writeCheckpointTestFile(t, filepath.Join(journalPath, "pending", ".outcomemesh-custody-journal-partial"), []byte{4, 5})
	checkpoint, err := CaptureCustodyCheckpoint(journalPath, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := checkpoint.ID()
	if checkpoint.Sequence != 1 || checkpoint.HeadEntryID != oldCheckpoint.HeadEntryID || checkpoint == oldCheckpoint {
		t.Fatal("checkpoint did not preserve pending evidence separately from the head")
	}
	verify := func(j, a string) error {
		return VerifyCustodyCheckpoint(checkpoint, id, j, a, fixture.manifest, fixture.receipt, fixture.policy)
	}
	if err := verify(filepath.Join(oldCopy, "journal"), filepath.Join(oldCopy, "artifacts")); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatalf("same-head older backup accepted: %v", err)
	}
	oldID, _ := oldCheckpoint.ID()
	if err := VerifyCustodyCheckpoint(oldCheckpoint, oldID, filepath.Join(oldCopy, "journal"), filepath.Join(oldCopy, "artifacts"), fixture.manifest, fixture.receipt, fixture.policy); err != nil {
		t.Fatalf("older copy is not a valid baseline: %v", err)
	}
	if err := VerifyCustodyCheckpoint(oldCheckpoint, id, filepath.Join(oldCopy, "journal"), filepath.Join(oldCopy, "artifacts"), fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatal("replacing both backup and checkpoint bypassed the independent pin")
	}

	orphans, err := os.ReadDir(journal.activePath())
	if err != nil || len(orphans) != 1 {
		t.Fatalf("orphan inventory: %v %v", orphans, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(string, string) error
	}{
		{name: "exact copy"},
		{name: "lost signed request", mutate: func(_, a string) error { return os.Remove(filepath.Join(a, cycle, "challenge.omcc")) }},
		{name: "changed signed request", mutate: func(_, a string) error {
			return os.WriteFile(filepath.Join(a, cycle, "challenge.omcc"), []byte("different"), 0o600)
		}},
		{name: "lost pending record", mutate: func(_, a string) error { return os.Remove(filepath.Join(a, cycle, "record.omcr")) }},
		{name: "lost orphan", mutate: func(j, _ string) error { return os.Remove(filepath.Join(j, "objects", "active", orphans[0].Name())) }},
		{name: "lost empty temporary", mutate: func(j, _ string) error {
			return os.Remove(filepath.Join(j, "pending", ".outcomemesh-custody-journal-empty"))
		}},
		{name: "lost partial artifact", mutate: func(_, a string) error {
			return os.Remove(filepath.Join(a, cycle, ".outcomemesh-work-artifact-partial"))
		}},
		{name: "unrepaired missing active", mutate: func(j, _ string) error {
			return os.Rename(filepath.Join(j, "objects", "active"), filepath.Join(j, "objects", "segments", "segment-11111111111111111111111111111111"))
		}},
		{name: "missing artifact lock", mutate: func(_, a string) error { return os.Remove(filepath.Join(a, custodyArtifactsLockName)) }},
		{name: "missing journal lock", mutate: func(j, _ string) error { return os.Remove(filepath.Join(j, custodyJournalLockName)) }},
		{name: "truncated header", mutate: func(j, _ string) error {
			return os.WriteFile(filepath.Join(j, custodyJournalHeaderName), []byte{1}, 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyRoot := filepath.Join(t.TempDir(), "copy")
			copyCheckpointTestTree(t, root, copyRoot)
			j, a := filepath.Join(copyRoot, "journal"), filepath.Join(copyRoot, "artifacts")
			if test.mutate != nil {
				if err := test.mutate(j, a); err != nil {
					t.Fatal(err)
				}
			}
			before, err := digestCustodyEvidenceTree(a, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			if err != nil {
				t.Fatal(err)
			}
			journalBefore, err := digestCustodyEvidenceTree(j, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			if err != nil {
				t.Fatal(err)
			}
			err = verify(j, a)
			if (err == nil) != (test.mutate == nil) {
				t.Fatalf("verification error=%v", err)
			}
			after, _ := digestCustodyEvidenceTree(a, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			journalAfter, _ := digestCustodyEvidenceTree(j, MaximumCustodyJournalBytes, MaximumCustodyJournalPaths)
			if before != after || journalBefore != journalAfter {
				t.Fatal("verification modified the copy")
			}
		})
	}
	// A replica checkpoint is deliberately a different inventory contract.
	if err := verify(journalPath, ""); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatal("auditor verification omitted its artifact tree")
	}
}

func TestCustodyCheckpointRejectsValidOlderHeadAndWrongTrust(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := CaptureCustodyCheckpoint(root, "", fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Sequence != 0 || !checkpoint.HeadEntryID.IsZero() {
		t.Fatal("nonempty genesis checkpoint")
	}
	copyRoot := filepath.Join(t.TempDir(), "copy")
	copyCheckpointTestTree(t, root, copyRoot)
	if _, _, err := journal.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	newCheckpoint, err := CaptureCustodyCheckpoint(root, "", fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	newID, _ := newCheckpoint.ID()
	if err := VerifyCustodyCheckpoint(newCheckpoint, newID, copyRoot, "", fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatal("valid older prefix accepted")
	}
	oldID, _ := checkpoint.ID()
	if err := VerifyCustodyCheckpoint(checkpoint, oldID, root, "", fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatal("newer head accepted as exact copy")
	}
	policy := fixture.policy
	policy.MaximumProofAge++
	if _, err := CaptureCustodyCheckpoint(root, "", fixture.manifest, fixture.receipt, policy); err == nil {
		t.Fatal("changed policy accepted")
	}
	if _, err := CaptureCustodyCheckpoint(root, "", fixture.manifest, fixture.record.RenewedReceipt, fixture.policy); err == nil {
		t.Fatal("changed initial receipt accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := VerifyCustodyCheckpoint(newCheckpoint, types.Hash{}, missing, "", fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatal("zero pin accepted")
	}
	if _, err := CaptureCustodyCheckpoint(missing, "", fixture.manifest, fixture.receipt, fixture.policy); err == nil {
		t.Fatal("missing journal initialized")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("checkpoint created a journal")
	}
}

func TestCustodyCheckpointWaitsForArtifactAndJournalWriters(t *testing.T) {
	for _, lockKind := range []string{"artifacts", "journal"} {
		t.Run(lockKind, func(t *testing.T) {
			fixture := newCustodyRecordFixture(t)
			root := t.TempDir()
			j, a := filepath.Join(root, "journal"), filepath.Join(root, "artifacts")
			journal, _, err := OpenOrCreateCustodyJournal(j, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			artifactLock, err := AcquireCustodyArtifacts(a)
			if err != nil {
				t.Fatal(err)
			}
			lock := artifactLock
			if lockKind == "journal" {
				if err := artifactLock.Close(); err != nil {
					t.Fatal(err)
				}
				lock, err = acquireCustodyJournalLock(j)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer lock.Close()
			type result struct {
				checkpoint CustodyCheckpoint
				err        error
			}
			done := make(chan result, 1)
			go func() {
				checkpoint, err := CaptureCustodyCheckpoint(j, a, fixture.manifest, fixture.receipt, fixture.policy)
				done <- result{checkpoint, err}
			}()
			select {
			case result := <-done:
				t.Fatalf("checkpoint bypassed %s lock: %v", lockKind, result.err)
			case <-time.After(75 * time.Millisecond):
			}
			if lockKind == "artifacts" {
				challenge, _ := fixture.record.Challenge.CanonicalBytes()
				writeCheckpointTestFile(t, filepath.Join(a, "cycle-00000000000000000001", "challenge.omcc"), challenge)
				if _, _, err := journal.Append(fixture.record); err != nil {
					t.Fatal(err)
				}
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-done:
				if result.err != nil {
					t.Fatal(result.err)
				}
				if lockKind == "artifacts" && (result.checkpoint.Sequence != 1 || result.checkpoint.Artifacts.Bytes == 0) {
					t.Fatal("checkpoint mixed pre/post-publication state")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("checkpoint did not acquire released lock")
			}
		})
	}
}

func TestCustodyCheckpointTreeBoundsAndCanonicalOrder(t *testing.T) {
	left, right := t.TempDir(), t.TempDir()
	writeCheckpointTestFile(t, filepath.Join(left, "b"), []byte("two"))
	writeCheckpointTestFile(t, filepath.Join(left, "a"), []byte("one"))
	writeCheckpointTestFile(t, filepath.Join(right, "a"), []byte("one"))
	writeCheckpointTestFile(t, filepath.Join(right, "b"), []byte("two"))
	l, err := digestCustodyEvidenceTree(left, 6, 3)
	if err != nil {
		t.Fatal(err)
	}
	const wantTreeID = "24507ab2f516ea22cdf56a447418c79791d2eaa0469921d4ed32864be84e4a5b"
	if l.ID.String() != wantTreeID {
		t.Fatalf("tree golden ID = %s", l.ID)
	}
	r, err := digestCustodyEvidenceTree(right, 6, 3)
	if err != nil || l != r || l.Bytes != 6 || l.Paths != 3 {
		t.Fatalf("noncanonical tree: %v", err)
	}
	for _, bounds := range [][2]uint64{{5, 3}, {6, 2}, {6, 0}} {
		if _, err := digestCustodyEvidenceTree(left, bounds[0], bounds[1]); err == nil {
			t.Fatalf("exceeded bounds %v", bounds)
		}
	}
	if err := os.Link(filepath.Join(left, "a"), filepath.Join(left, "c")); err != nil {
		t.Fatal(err)
	}
	hardlinked, err := digestCustodyEvidenceTree(left, 9, 4)
	if err != nil || hardlinked.Bytes != 9 || hardlinked.Paths != 4 {
		t.Fatalf("hardlink not charged: %+v %v", hardlinked, err)
	}
	if err := os.Mkdir(filepath.Join(right, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	r, err = digestCustodyEvidenceTree(right, 6, 4)
	if err != nil || r.ID == l.ID {
		t.Fatal("empty directory omitted")
	}
	if err := os.MkdirAll(filepath.Join(right, "empty", "too", "many", "levels"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := digestCustodyEvidenceTree(right, 6, 10); err == nil {
		t.Fatal("excess depth accepted")
	}
	for _, target := range []string{filepath.Join(left, "a"), left} {
		root := t.TempDir()
		if err := os.Symlink(target, filepath.Join(root, "alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := digestCustodyEvidenceTree(root, 20, 10); err == nil {
			t.Fatal("symlink followed")
		}
		if _, err := digestCustodyEvidenceTree(filepath.Join(root, "alias"), 20, 10); err == nil {
			t.Fatal("symlink root followed")
		}
	}
}

func TestCustodyCheckpointCanonicalEncoding(t *testing.T) {
	checkpoint := checkpointGoldenFixture()
	encoded, err := checkpoint.CanonicalBytes()
	if err != nil || len(encoded) != MaximumCustodyCheckpointBytes {
		t.Fatalf("encoding: %v", err)
	}
	decoded, err := DecodeCustodyCheckpoint(encoded)
	if err != nil || decoded != checkpoint {
		t.Fatalf("round trip: %v", err)
	}
	for size := 0; size < len(encoded); size++ {
		if _, err := DecodeCustodyCheckpoint(encoded[:size]); err == nil {
			t.Fatalf("truncation %d accepted", size)
		}
	}
	if _, err := DecodeCustodyCheckpoint(append(encoded, 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	for _, offset := range []int{0, 8, 9} {
		changed := bytes.Clone(encoded)
		changed[offset] ^= 1
		if _, err := DecodeCustodyCheckpoint(changed); err == nil {
			t.Fatalf("unknown magic/version at %d accepted", offset)
		}
	}
	id, _ := checkpoint.ID()
	// Fixed synthetic inputs avoid filesystem names, signing times, and fixture
	// randomness becoming part of this format's compatibility gate.
	const want = "d0bd4b43b76f9694fff41dbcc69d03066d72a37fba96ed5e65e02fcaad415776"
	if id.String() != want {
		t.Fatalf("checkpoint golden ID = %s", id)
	}
}

func TestCustodyCheckpointRejectsInvalidShape(t *testing.T) {
	for _, mutate := range []func(*CustodyCheckpoint){
		func(c *CustodyCheckpoint) { c.HeaderID = types.Hash{} },
		func(c *CustodyCheckpoint) { c.ReceiptID = types.Hash{} },
		func(c *CustodyCheckpoint) { c.Sequence = 0 },
		func(c *CustodyCheckpoint) { c.HeadEntryID = types.Hash{} },
		func(c *CustodyCheckpoint) { c.Journal.ID = types.Hash{} },
		func(c *CustodyCheckpoint) { c.Journal.Paths = 0 },
		func(c *CustodyCheckpoint) { c.Journal.Paths = MaximumCustodyJournalPaths + 1 },
		func(c *CustodyCheckpoint) { c.Journal.Bytes = MaximumCustodyJournalBytes + 1 },
		func(c *CustodyCheckpoint) { c.Artifacts.ID = types.Hash{} },
		func(c *CustodyCheckpoint) { c.Artifacts.Paths = 0 },
		func(c *CustodyCheckpoint) { c.Artifacts.Paths = MaximumCustodyJournalPaths + 1 },
		func(c *CustodyCheckpoint) { c.Artifacts.Bytes = MaximumCustodyJournalBytes + 1 },
	} {
		checkpoint := checkpointGoldenFixture()
		mutate(&checkpoint)
		if _, err := checkpoint.CanonicalBytes(); !errors.Is(err, ErrCustodyCheckpoint) {
			t.Fatal("invalid shape encoded")
		}
		if _, err := checkpoint.ID(); !errors.Is(err, ErrCustodyCheckpoint) {
			t.Fatal("invalid shape hashed")
		}
	}
}

func TestCustodyEvidencePathsRejectCaseAlias(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, strings.ToUpper("journal"))
	original, err := os.Stat(journal)
	if err != nil {
		t.Fatal(err)
	}
	aliased, err := os.Stat(alias)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("case-sensitive filesystem")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(original, aliased) {
		t.Skip("distinct case-sensitive paths")
	}
	for _, path := range []string{alias, filepath.Join(alias, "not-created", "checkpoint.omccp")} {
		if !CustodyEvidencePathsOverlap(journal, path) || !CustodyEvidencePathsOverlap(path, journal) {
			t.Fatalf("case alias hid overlapping evidence paths: %s", path)
		}
	}
}

func checkpointGoldenFixture() CustodyCheckpoint {
	return CustodyCheckpoint{
		Version: CustodyCheckpointVersion0, HeaderID: types.Hash{1}, Sequence: 2,
		HeadEntryID: types.Hash{3}, ReceiptID: types.Hash{4},
		Journal:   CustodyCheckpointTree{ID: types.Hash{5}, Bytes: 6, Paths: 7},
		Artifacts: CustodyCheckpointTree{ID: types.Hash{8}, Bytes: 9, Paths: 10},
	}
}

func FuzzDecodeCustodyCheckpointNeverPanics(f *testing.F) {
	encoded, _ := checkpointGoldenFixture().CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		checkpoint, err := DecodeCustodyCheckpoint(input)
		if err != nil {
			return
		}
		canonical, err := checkpoint.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, input) {
			t.Fatal("decoder accepted noncanonical checkpoint")
		}
	})
}

func writeCheckpointTestFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyCheckpointTestTree(t testing.TB, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
}
