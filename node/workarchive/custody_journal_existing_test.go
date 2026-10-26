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

func TestOpenExistingCustodyJournalReplaysWithoutMutationAndDetachesConfiguration(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	writer, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writer.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Rotate(); err != nil {
		t.Fatal(err)
	}
	want, err := writer.State()
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotExistingCustodyTree(t, root)
	manifestBytes, _ := fixture.manifest.CanonicalBytes()
	manifest, _ := DecodeManifest(manifestBytes)
	policy := fixture.policy
	policy.TrustedAuditors = append(policy.TrustedAuditors[:0:0], policy.TrustedAuditors...)
	limits := CustodyJournalLimits{MaximumBytes: 2 * MaximumCustodyJournalHeaderBytes, MaximumPaths: 9}
	journal, got, err := OpenExistingCustodyJournalWithLimits(context.Background(), root, manifest, fixture.receipt, policy, limits)
	if err != nil || journal == nil || got != want || journal.limits != limits {
		t.Fatalf("existing journal state=%+v expected=%+v error=%v", got, want, err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || journal.Directory() != canonical {
		t.Fatalf("existing directory=%q expected=%q error=%v", journal.Directory(), canonical, err)
	}
	manifest.Chunks[0].ID = types.Hash{}
	policy.TrustedAuditors[0] = [32]byte{}
	if state, err := journal.State(); err != nil || state != want {
		t.Fatalf("caller mutation changed journal state=%+v error=%v", state, err)
	}
	assertExistingCustodyTreeUnchanged(t, root, before)
	if fixture.store.Directory() == "" || (*ObjectStore)(nil).Directory() != "" || (*CustodyJournal)(nil).Directory() != "" {
		t.Fatal("placement accessors returned invalid paths")
	}
}

func TestOpenExistingCustodyJournalRejectsMissingDamagedRetiredAndHistoricalWithoutMutation(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	for _, name := range []string{
		"missing root", "empty root", "missing lock", "nonempty lock", "symlink lock",
		"missing header", "corrupt header", "missing active directory", "wrong policy pin",
		"retirement marker", "historical header", "symlink root",
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "journal")
			policy := fixture.policy
			if name == "empty root" {
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if name != "missing root" {
				journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "missing lock", "symlink lock":
					mustExistingCustodyRemove(t, filepath.Join(root, custodyJournalLockName))
					if name == "symlink lock" {
						other := filepath.Join(parent, "other.lock")
						mustExistingCustodyWrite(t, other, nil)
						if err := os.Symlink(other, filepath.Join(root, custodyJournalLockName)); err != nil {
							t.Fatal(err)
						}
					}
				case "nonempty lock":
					mustExistingCustodyWrite(t, filepath.Join(root, custodyJournalLockName), []byte{1})
				case "missing header":
					mustExistingCustodyRemove(t, filepath.Join(root, custodyJournalHeaderName))
				case "corrupt header":
					mustExistingCustodyWrite(t, filepath.Join(root, custodyJournalHeaderName), []byte("bad header"))
				case "missing active directory":
					mustExistingCustodyRemove(t, journal.activePath())
				case "wrong policy pin":
					policy.MaximumProofAge++
				case "retirement marker":
					mustExistingCustodyWrite(t, filepath.Join(root, custodyRetirementFileName), []byte("untrusted marker"))
				case "historical header":
					header := journal.header
					header.Version = CustodyJournalHeaderHistoricalVersion1
					header.HistoricalTransferID = types.DomainHash("test/existing-historical")
					encoded, err := header.CanonicalBytes()
					if err != nil {
						t.Fatal(err)
					}
					mustExistingCustodyWrite(t, filepath.Join(root, custodyJournalHeaderName), encoded)
				case "symlink root":
					realRoot := filepath.Join(parent, "real-journal")
					if err := os.Rename(root, realRoot); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(realRoot, root); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := snapshotExistingCustodyTree(t, parent)
			journal, state, err := OpenExistingCustodyJournalWithLimits(context.Background(), root,
				fixture.manifest, fixture.receipt, policy, DefaultCustodyJournalLimits())
			if err == nil || journal != nil || state != (CustodyJournalState{}) {
				t.Fatalf("invalid existing root accepted journal=%v state=%+v error=%v", journal, state, err)
			}
			if name == "historical header" && !errors.Is(err, ErrCustodyJournalHistoricalOnly) {
				t.Fatalf("historical header error=%v", err)
			}
			assertExistingCustodyTreeUnchanged(t, parent, before)
		})
	}
}

func TestOpenExistingCustodyJournalCancellationWhileWaitingForOriginalLock(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	root := filepath.Join(t.TempDir(), "journal")
	journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := journal.AcquireDecision()
	if err != nil {
		t.Fatal(err)
	}
	defer decision.Close()
	before := snapshotExistingCustodyTree(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	opened, _, err := OpenExistingCustodyJournalWithLimits(ctx, root, fixture.manifest, fixture.receipt, fixture.policy, DefaultCustodyJournalLimits())
	if !errors.Is(err, context.DeadlineExceeded) || opened != nil {
		t.Fatalf("busy existing journal cancellation error=%v", err)
	}
	assertExistingCustodyTreeUnchanged(t, root, before)
	if _, _, err := OpenExistingCustodyJournalWithLimits(nil, root, fixture.manifest, fixture.receipt, fixture.policy, DefaultCustodyJournalLimits()); !errors.Is(err, ErrCustodyJournal) {
		t.Fatalf("nil context error=%v", err)
	}
}

type existingCustodyTreeEntry struct {
	info os.FileInfo
	data []byte
}

func snapshotExistingCustodyTree(t testing.TB, root string) map[string]existingCustodyTreeEntry {
	t.Helper()
	entries := make(map[string]existingCustodyTreeEntry)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode().IsRegular() {
			data, err = os.ReadFile(path)
		} else if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = os.Readlink(path)
			data = []byte(target)
		}
		entries[path] = existingCustodyTreeEntry{info: info, data: data}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func assertExistingCustodyTreeUnchanged(t testing.TB, root string, before map[string]existingCustodyTreeEntry) {
	t.Helper()
	after := snapshotExistingCustodyTree(t, root)
	if len(after) != len(before) {
		t.Fatalf("existing journal changed path count: before=%d after=%d", len(before), len(after))
	}
	for path, old := range before {
		current, exists := after[path]
		if !exists || !os.SameFile(old.info, current.info) || old.info.Mode() != current.info.Mode() ||
			!old.info.ModTime().Equal(current.info.ModTime()) || !bytes.Equal(old.data, current.data) {
			t.Fatalf("existing journal changed %q", path)
		}
	}
}

func mustExistingCustodyRemove(t testing.TB, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func mustExistingCustodyWrite(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
