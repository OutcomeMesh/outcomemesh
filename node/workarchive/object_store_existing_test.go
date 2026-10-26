package workarchive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenExistingObjectStoreVerifiesWithoutMutation(t *testing.T) {
	f := newCustodyRecordFixture(t)
	before := snapshotExistingCustodyTree(t, f.store.Directory())
	opened, err := OpenExistingObjectStore(f.store.Directory(), DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	missing, err := opened.Missing(f.manifest)
	if err != nil || len(missing) != 0 {
		t.Fatal("existing objects unavailable", missing, err)
	}
	wantObjects, wantBytes, err := f.store.Usage()
	if err != nil {
		t.Fatal(err)
	}
	objects, bytes, err := opened.Usage()
	if err != nil || objects != wantObjects || bytes != wantBytes {
		t.Fatal("existing usage mismatch", objects, bytes, err)
	}
	assertExistingCustodyTreeUnchanged(t, f.store.Directory(), before)
}

func TestOpenExistingObjectStoreRejectsWithoutRepair(t *testing.T) {
	for _, name := range []string{"missing", "regular-file", "symlink", "unknown-file", "invalid-object", "cancelled", "nil-context", "invalid-policy"} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "objects")
			if name == "regular-file" {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if name != "missing" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			policy := DefaultObjectStorePolicy()
			switch name {
			case "symlink":
				real := filepath.Join(parent, "real")
				if err := os.Rename(path, real); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, path); err != nil {
					t.Fatal(err)
				}
			case "unknown-file":
				if err := os.WriteFile(filepath.Join(path, "partial.tmp"), []byte{1}, 0o600); err != nil {
					t.Fatal(err)
				}
			case "invalid-object":
				f := newCustodyRecordFixture(t)
				if err := os.WriteFile(filepath.Join(path, objectFileName(f.manifest.Chunks[0].ID)), []byte{1}, 0o600); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			case "invalid-policy":
				policy.MaximumObjects = 0
			}
			before := snapshotExistingCustodyTree(t, parent)
			opened, err := OpenExistingObjectStoreContext(ctx, path, policy)
			if err == nil || opened != nil {
				t.Fatal("invalid existing store opened", opened, err)
			}
			if name == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation", err)
			}
			assertExistingCustodyTreeUnchanged(t, parent, before)
		})
	}
}
