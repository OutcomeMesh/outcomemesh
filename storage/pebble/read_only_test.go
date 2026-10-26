package pebblestore

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/storage"
)

func readOnlySourceTree(t testing.TB, path string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(path, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(path, name)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode().IsRegular():
			body, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			result[relative] = fmt.Sprintf("%v:%x", info.Mode(), sha256.Sum256(body))
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(name)
			if err != nil {
				return err
			}
			result[relative] = "link:" + target
		default:
			result[relative] = info.Mode().String()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestOpenExistingReadOnlyPreservesSourceAndRejectsCommit(t *testing.T) {
	document := testGenesis()
	parent := t.TempDir()
	path := filepath.Join(parent, "ledger")
	writer, err := Open(path, document)
	if err != nil {
		t.Fatal(err)
	}
	genesisTip, mined, postState := prepareBlockForStore(t, writer, document)
	wantTip, err := writer.Commit(genesisTip, mined, postState)
	if err != nil {
		t.Fatal(err)
	}
	wantHistory, _, err := writer.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	before := readOnlySourceTree(t, parent)
	reader, err := OpenExistingReadOnly(path, document, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	tip, err := reader.Tip()
	if err != nil || !storage.EqualTips(tip, wantTip) {
		t.Fatal("read-only source changed tip", err)
	}
	snapshot, err := reader.Snapshot()
	if err != nil || snapshot.Root() != postState.Root() {
		t.Fatal("read-only source changed active state", err)
	}
	genesisState, err := reader.SnapshotAt(genesisTip.ID)
	if err != nil || genesisState.Root() != genesisTip.StateRoot {
		t.Fatal("read-only source lost historical activation base", err)
	}
	stored, err := reader.BlockByID(wantTip.ID)
	if err != nil || !bytes.Equal(stored.CanonicalBytes(), mined.CanonicalBytes()) {
		t.Fatal("read-only source changed block bytes", err)
	}
	history, _, err := reader.HistoryUsage()
	if err != nil || history != wantHistory {
		t.Fatal("read-only source changed logical history", err)
	}
	if other, err := OpenExistingReadOnly(path, document, DefaultPolicy()); err == nil {
		_ = other.Close()
		t.Fatal("read-only open lost exclusive source lock")
	}
	parentTip, next, nextState := prepareBlockForStore(t, reader, document)
	reader.commitHook = func(commitStage) error { t.Fatal("read-only Commit reached write path"); return nil }
	if _, err := reader.Commit(parentTip, next, nextState); !errors.Is(err, pebble.ErrReadOnly) {
		t.Fatal("read-only handle allowed commit", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if after := readOnlySourceTree(t, parent); !reflect.DeepEqual(before, after) {
		t.Fatal("opening/reading/rejected commit changed source files")
	}
	writer, err = Open(path, document)
	if err != nil {
		t.Fatal("source lock did not release", err)
	}
	defer writer.Close()
	if _, err := writer.Commit(parentTip, next, nextState); err != nil {
		t.Fatal("existing read-write behavior changed", err)
	}
}

func TestOpenExistingReadOnlyRejectsWithoutBootstrap(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "lock-only", "lockless", "nonempty-lock", "symlink-lock", "symlink-root", "genesis-mismatch", "missing-genesis", "missing-schema", "missing-both", "bad-schema", "bad-tip", "bad-state", "invalid-document", "invalid-policy"} {
		t.Run(mode, func(t *testing.T) {
			document := testGenesis()
			policy := DefaultPolicy()
			parent := t.TempDir()
			path := filepath.Join(parent, "ledger")
			switch mode {
			case "missing":
			case "empty", "lock-only":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if mode == "lock-only" {
					if err := os.WriteFile(filepath.Join(path, "LOCK"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			default:
				writer, err := Open(path, document)
				if err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if mode == "missing-genesis" || mode == "missing-schema" || mode == "missing-both" || mode == "bad-schema" || mode == "bad-tip" || mode == "bad-state" {
					db, err := pebble.Open(path, &pebble.Options{FormatMajorVersion: pebble.FormatNewest})
					if err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "missing-genesis", "missing-both":
						err = db.Delete(keyGenesis, pebble.Sync)
					case "missing-schema":
						err = db.Delete(keySchema, pebble.Sync)
					case "bad-schema":
						err = db.Set(keySchema, []byte{0, 99}, pebble.Sync)
					case "bad-tip":
						err = db.Set(keyTip, []byte{0}, pebble.Sync)
					case "bad-state":
						resource := document.Allocations[0]
						resource.Amount++
						err = db.Set(resourceKey(resource.ID), resource.CanonicalBytes(), pebble.Sync)
					}
					if mode == "missing-both" && err == nil {
						err = db.Delete(keySchema, pebble.Sync)
					}
					if err := errors.Join(err, db.Close()); err != nil {
						t.Fatal(err)
					}
				}
				switch mode {
				case "lockless":
					if err := os.Remove(filepath.Join(path, "LOCK")); err != nil {
						t.Fatal(err)
					}
				case "nonempty-lock":
					if err := os.WriteFile(filepath.Join(path, "LOCK"), []byte("must be preserved"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "symlink-lock":
					if err := os.Remove(filepath.Join(path, "LOCK")); err != nil {
						t.Fatal(err)
					}
					target := filepath.Join(parent, "other-lock")
					if err := os.WriteFile(target, nil, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, filepath.Join(path, "LOCK")); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				case "symlink-root":
					link := filepath.Join(parent, "alias")
					if err := os.Symlink(path, link); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
					path = link
				case "genesis-mismatch":
					document.NetworkID++
				case "invalid-document":
					document.NetworkID = 0
				case "invalid-policy":
					policy.MaxHistoryBytes = 0
				}
			}
			before := readOnlySourceTree(t, parent)
			reader, err := OpenExistingReadOnly(path, document, policy)
			if err == nil {
				_ = reader.Close()
				t.Fatal("invalid source opened", mode)
			}
			if reader != nil {
				t.Fatal("failed source returned a handle")
			}
			if after := readOnlySourceTree(t, parent); !reflect.DeepEqual(before, after) {
				t.Fatal("failed read-only open changed source names or bytes", mode)
			}
		})
	}
}
