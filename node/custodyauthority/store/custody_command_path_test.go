package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// EvalSymlinks preserves the spelling of real path components. On the usual
// macOS volume, two differently cased spellings can name the same directory.
func custodyCommandCaseAlias(t testing.TB, root string) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("requires a macOS case-insensitive volume")
	}
	base := filepath.Base(root)
	aliasBase := strings.ToUpper(base)
	if aliasBase == base {
		aliasBase = strings.ToLower(base)
	}
	if aliasBase == base {
		t.Fatal("fixture root has no alternate-case spelling", root)
	}
	alias := filepath.Join(filepath.Dir(root), aliasBase)
	before, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(alias)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("test volume is case-sensitive")
	}
	if err != nil || !os.SameFile(before, other) {
		t.Fatalf("alternate-case path did not identify the existing root: %v", err)
	}
	return alias
}

func custodyCommandPathTrees(t testing.TB, roots []string) []map[string]string {
	t.Helper()
	trees := make([]map[string]string, len(roots))
	for i, root := range roots {
		trees[i] = bootstrapTree(t, root)
	}
	return trees
}

func TestManagedCustodyCommandRejectsCaseAliasMetadataPlacement(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires a macOS case-insensitive volume")
	}
	f := newManagedAuditFixture(t)
	owner := f.serve.archive.f.coordinator
	scope := managedCommandApplyTestScope(f)
	roots := []string{owner.authority.path, owner.journal.path, f.config.JournalPath}
	before := custodyCommandPathTrees(t, roots)
	b, err := f.config.Admission.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []struct {
		root, directory string
	}{
		{owner.authority.path, entriesName},
		{owner.journal.path, intentsName},
	} {
		t.Run(filepath.Base(selected.root), func(t *testing.T) {
			alias := custodyCommandCaseAlias(t, selected.root)
			// This is an existing valid admission, not an unknown extra file.
			// Only its alternate-case placement differs from the protected root.
			metadata := filepath.Join(alias, selected.directory, entryName(f.config.Admission.Command.ExpectedSequence+1))
			_, err := openManagedCustodyCommandSource(t.Context(), owner, scope, f.config.IntentPath, f.config.JournalPath,
				f.config.JournalLimits, []managedCustodyCommandArtifact{{path: metadata, bytes: b, maximum: custodyauthority.MaximumEntryBytes}})
			if !errors.Is(err, ErrManagedCustodyCommand) {
				t.Fatal("accepted protected-root metadata through a case alias", err)
			}
		})
	}
	if got := custodyCommandPathTrees(t, roots); !reflect.DeepEqual(got, before) {
		t.Fatal("rejected metadata placement changed protected root paths or bytes")
	}
}

func TestManagedCustodyCaptureRejectsCaseAliasOutputPlacement(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires a macOS case-insensitive volume")
	}
	f := newManagedAuditFixture(t)
	if _, _, err := f.journal.Append(f.answer(t)); err != nil {
		t.Fatal(err)
	}
	config := managedCommandApplyCaptureConfig(t, f)
	if err := f.serve.archive.f.coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	service := managedCommandApplyCaptureOpen(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{config.AuthorityPath, config.AuthorityPinsPath, config.JournalPath}
	before := custodyCommandPathTrees(t, roots)
	for _, root := range roots {
		t.Run(filepath.Base(root), func(t *testing.T) {
			alias := custodyCommandCaseAlias(t, root)
			output := filepath.Join(alias, "rejected-terminal.omcat")
			if _, err := service.CaptureToFile(t.Context(), id, output); !errors.Is(err, ErrManagedCustodyCommand) {
				t.Fatal("published into a protected root through a case alias", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "rejected-terminal.omcat")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected capture left an output in the protected root", err)
			}
		})
	}
	if got := custodyCommandPathTrees(t, roots); !reflect.DeepEqual(got, before) {
		t.Fatal("rejected capture changed protected root paths or bytes")
	}
	if _, err := service.Review(t.Context()); err != nil {
		t.Fatal("rejected output placement poisoned the original owner or source", err)
	}
	if _, _, err := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), config.JournalPath, config.Scope.Manifest,
		config.Scope.InitialReceipt, config.Scope.CustodyPolicy, config.JournalLimits); err != nil {
		t.Fatal("rejected output placement damaged the source", err)
	}
}
