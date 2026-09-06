package workarchive

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodyBackupPublishesIndependentExactCopies(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	for _, sourceArtifacts := range []string{artifacts, ""} {
		t.Run(map[bool]string{true: "auditor", false: "replica"}[sourceArtifacts != ""], func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "new-parent", "backup")
			expected, err := CaptureCustodyCheckpoint(journal.path, sourceArtifacts, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, created, err := CreateCustodyBackup(context.Background(), destination, journal.path, sourceArtifacts, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil || !created || checkpoint != expected {
				t.Fatalf("backup created=%t checkpoint=%+v err=%v", created, checkpoint, err)
			}
			id, _ := checkpoint.ID()
			verified, err := VerifyCustodyBackup(destination, id, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil || verified != expected {
				t.Fatalf("backup verify: %v", err)
			}
			copyJournal, copyArtifacts := custodyBackupEvidencePaths(destination, sourceArtifacts != "")
			assertIndependentCustodyCopy(t, journal.path, copyJournal)
			if copyArtifacts != "" {
				assertIndependentCustodyCopy(t, artifacts, copyArtifacts)
			}
			if again, created, err := CreateCustodyBackup(context.Background(), destination, journal.path, sourceArtifacts, fixture.manifest, fixture.receipt, fixture.policy); err != nil || created || again != checkpoint {
				t.Fatalf("identical retry: created=%t err=%v", created, err)
			}
			if _, err := VerifyCustodyBackup(destination, types.Hash{77}, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
				t.Fatalf("wrong pin accepted: %v", err)
			}
			if _, err := VerifyCustodyBackup(destination, types.Hash{}, fixture.manifest, fixture.receipt, fixture.policy); err == nil {
				t.Fatal("zero pin accepted")
			}
			// A journal temp file has no authority, but still belongs to the exact
			// inventory. Modifying the backup cannot mutate its source inode.
			pending := filepath.Join(copyJournal, "pending", ".outcomemesh-custody-journal-partial")
			if err := os.WriteFile(pending, []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCustodyBackup(destination, id, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
				t.Fatalf("corrupt backup accepted: %v", err)
			}
			actual, err := CaptureCustodyCheckpoint(journal.path, sourceArtifacts, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil || actual != expected {
				t.Fatalf("copy mutation changed source: %v", err)
			}
		})
	}
}

func TestCustodyBackupDoesNotOverwriteExistingOrIncompleteDestinations(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	destination := filepath.Join(t.TempDir(), "backup")
	checkpoint, _, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := checkpoint.ID()
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000002", "another-pending-file"), []byte("new intent"))
	if _, _, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyCheckpointMismatch) {
		t.Fatalf("old backup presented as current: %v", err)
	}
	if got, err := VerifyCustodyBackup(destination, id, fixture.manifest, fixture.receipt, fixture.policy); err != nil || got != checkpoint {
		t.Fatalf("old backup was changed: %v", err)
	}
	for _, kind := range []string{"empty", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "existing")
			var err error
			switch kind {
			case "empty":
				err = os.Mkdir(path, 0o700)
			case "file":
				err = os.WriteFile(path, []byte("keep me"), 0o600)
			case "symlink":
				err = os.Symlink(destination, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(path)
			if _, _, err := CreateCustodyBackup(context.Background(), path, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); err == nil {
				t.Fatal("existing destination adopted")
			}
			after, _ := os.Lstat(path)
			if !sameCustodyEvidenceFile(before, after) {
				t.Fatal("existing destination changed")
			}
		})
	}
}

func TestCustodyBackupFailuresCannotPublishCompletion(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	for _, boundary := range []string{"journal", "copy", "before-commit", "corrupt-copy", "cancel", "after-commit"} {
		t.Run(boundary, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "backup")
			fault := errors.New("injected backup failure")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hooks := custodyBackupHooks{}
			switch boundary {
			case "journal":
				hooks.afterJournalCopy = func() error { return fault }
			case "copy":
				hooks.afterCopy = func() error { return fault }
			case "before-commit":
				hooks.beforeCommit = func() error { return fault }
			case "after-commit":
				hooks.afterCommit = func() error { return fault }
			case "cancel":
				hooks.beforeCommit = func() error { cancel(); return nil }
			case "corrupt-copy":
				hooks.afterCopy = func() error {
					return os.WriteFile(filepath.Join(destination, "journal", custodyJournalHeaderName), []byte("corrupt"), 0o600)
				}
			}
			checkpoint, created, err := createCustodyBackup(ctx, destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy, hooks)
			if err == nil {
				t.Fatal("injected failure ignored")
			}
			if boundary == "after-commit" {
				id, _ := checkpoint.ID()
				if !created {
					t.Fatal("lost committed result")
				}
				if _, err := VerifyCustodyBackup(destination, id, fixture.manifest, fixture.receipt, fixture.policy); err != nil {
					t.Fatal(err)
				}
				if _, created, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); err != nil || created {
					t.Fatalf("post-commit retry: %v", err)
				}
				return
			}
			if created {
				t.Fatal("failed backup marked created")
			}
			if _, err := os.Lstat(filepath.Join(destination, custodyBackupCheckpointName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completion appeared after failure: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(destination, "journal", custodyJournalHeaderName)); err != nil {
				t.Fatal("incomplete files were deleted")
			}
			if _, err := VerifyCustodyBackup(destination, types.Hash{1}, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupIncomplete) {
				t.Fatalf("incomplete backup accepted: %v", err)
			}
			if _, _, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, ErrCustodyBackupIncomplete) {
				t.Fatalf("incomplete destination resumed: %v", err)
			}
		})
	}
}

func TestCustodyBackupWaitsForEntireAuditorCycle(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	lock, err := AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	destination := filepath.Join(t.TempDir(), "backup")
	done := make(chan error, 1)
	go func() {
		_, _, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("backup bypassed artifact lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("backup created before source was locked")
	}
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000002", "new-request"), []byte("signed intent"))
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backup did not resume after writer released lock")
	}
	if got, err := os.ReadFile(filepath.Join(destination, "artifacts", "cycle-00000000000000000002", "new-request")); err != nil || string(got) != "signed intent" {
		t.Fatalf("backup omitted final intent: %v", err)
	}
}

func TestCustodyBackupRejectsSourceAliasesAndMissingLocks(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(journal.path, alias); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{journal.path, artifacts, filepath.Dir(journal.path), filepath.Join(alias, "backup"), filepath.Join(artifacts, "backup")} {
		if _, _, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); err == nil {
			t.Fatalf("overlapping backup accepted: %s", destination)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	destination := filepath.Join(t.TempDir(), "backup")
	if _, _, err := CreateCustodyBackup(ctx, destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled backup: %v", err)
	}
	if err := os.Remove(filepath.Join(artifacts, custodyArtifactsLockName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreateCustodyBackup(context.Background(), destination, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy); err == nil {
		t.Fatal("missing source lock recreated")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid source created backup")
	}
	if _, err := os.Lstat(filepath.Join(artifacts, custodyArtifactsLockName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing source lock repaired")
	}
}

func TestCustodyBackupLayoutAndCommitMarker(t *testing.T) {
	fixture, journal, artifacts := custodyBackupTestEvidence(t)
	root := filepath.Join(t.TempDir(), "backup")
	checkpoint, _, err := CreateCustodyBackup(context.Background(), root, journal.path, artifacts, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := checkpoint.ID()
	for _, test := range []struct {
		name   string
		valid  bool
		mutate func(string) error
	}{
		{name: "abandoned marker temp", valid: true, mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, ".outcomemesh-custody-journal-abandoned"), []byte{1}, 0o600)
		}},
		{name: "missing marker", mutate: func(root string) error { return os.Remove(filepath.Join(root, custodyBackupCheckpointName)) }},
		{name: "wrong marker", mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, custodyBackupCheckpointName), bytes.Repeat([]byte{1}, MaximumCustodyCheckpointBytes), 0o600)
		}},
		{name: "unknown root file", mutate: func(root string) error { return os.WriteFile(filepath.Join(root, "untracked"), nil, 0o600) }},
		{name: "oversized marker temp", mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, ".outcomemesh-custody-journal-abandoned"), make([]byte, MaximumCustodyCheckpointBytes+1), 0o600)
		}},
		{name: "missing bundle lock", mutate: func(root string) error { return os.Remove(filepath.Join(root, custodyBackupLockName)) }},
		{name: "extra root paths", mutate: func(root string) error {
			for _, name := range []string{".outcomemesh-custody-journal-one", ".outcomemesh-custody-journal-two"} {
				if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
					return err
				}
			}
			return nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyRoot := filepath.Join(t.TempDir(), "copy")
			copyCheckpointTestTree(t, root, copyRoot)
			if err := test.mutate(copyRoot); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir(copyRoot)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCustodyBackup(copyRoot, id, fixture.manifest, fixture.receipt, fixture.policy); (err == nil) != test.valid {
				t.Fatalf("layout error=%v want_valid=%t", err, test.valid)
			}
			after, err := os.ReadDir(copyRoot)
			if err != nil || len(before) != len(after) {
				t.Fatal("verification changed root layout")
			}
		})
	}
}

func TestCustodyEvidenceCopyChecksBudgetAndCancellation(t *testing.T) {
	source := t.TempDir()
	writeCheckpointTestFile(t, filepath.Join(source, "payload"), bytes.Repeat([]byte{17}, 64*1024))
	for _, limits := range [][2]uint64{{1024, 2}, {64 * 1024, 1}} {
		destination := filepath.Join(t.TempDir(), "copy")
		if _, err := walkCustodyEvidenceTree(context.Background(), source, destination, limits[0], limits[1]); err == nil {
			t.Fatalf("copy exceeded limits: %v", limits)
		}
		if _, err := os.Lstat(filepath.Join(destination, "payload")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("over-budget payload was published: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	reader := custodyEvidenceContextReader{ctx: ctx, reader: bytes.NewReader([]byte{1, 2})}
	buffer := make([]byte, 1)
	if n, err := reader.Read(buffer); err != nil || n != 1 {
		t.Fatalf("initial read: %d %v", n, err)
	}
	cancel()
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("copy ignored cancellation: %d %v", n, err)
	}
}

func custodyBackupTestEvidence(t testing.TB) (custodyRecordFixture, *CustodyJournal, string) {
	t.Helper()
	fixture := newCustodyRecordFixture(t)
	root := t.TempDir()
	journal, _, err := OpenOrCreateCustodyJournal(filepath.Join(root, "journal"), fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Rotate(); err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(root, "artifacts")
	lock, err := AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	challenge, _ := fixture.record.Challenge.CanonicalBytes()
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000001", "challenge.omcc"), challenge)
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000002", ".outcomemesh-work-artifact-empty"), nil)
	writeCheckpointTestFile(t, filepath.Join(journal.path, "pending", ".outcomemesh-custody-journal-partial"), []byte{1, 2, 3})
	if err := os.Link(filepath.Join(journal.path, "pending", ".outcomemesh-custody-journal-partial"), filepath.Join(journal.path, "pending", ".outcomemesh-custody-journal-hardlink")); err != nil {
		t.Fatal(err)
	}
	return fixture, journal, artifacts
}

func assertIndependentCustodyCopy(t testing.TB, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		copyPath := filepath.Join(destination, relative)
		copyInfo, err := os.Lstat(copyPath)
		if err != nil {
			return err
		}
		if os.SameFile(info, copyInfo) {
			t.Fatalf("copy shares source inode: %s", path)
		}
		if entry.IsDir() {
			if copyInfo.Mode().Perm() != 0o700 {
				t.Fatalf("directory mode: %s", copyInfo.Mode())
			}
			return nil
		}
		if copyInfo.Mode().Perm() != 0o600 {
			t.Fatalf("file mode: %s", copyInfo.Mode())
		}
		original, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		copied, err := os.ReadFile(copyPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(original, copied) {
			t.Fatalf("copy differs: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
