package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImmutableArtifactRetryConfirmsExistingInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	expected := []byte("exact immutable output")
	writePruneCLIFile(t, path, expected)
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("existing inode fsync failed")
	var retained *os.File
	err = syncExactRegularArtifact(path, expected, func(file *os.File) error {
		retained = file
		opened, err := file.Stat()
		if err != nil || !os.SameFile(original, opened) {
			t.Fatal("confirmation synced the wrong inode", err)
		}
		return fault
	})
	if !errors.Is(err, fault) || retained == nil {
		t.Fatal("lost existing-file sync failure", err)
	}
	if _, err := retained.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("sync failure leaked the existing file", err)
	}
	if err := publishImmutableArtifact(path, expected); err != nil {
		t.Fatal("exact retry failed", err)
	}
	after, err := os.Stat(path)
	got, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || !os.SameFile(original, after) || !bytes.Equal(got, expected) {
		t.Fatal("exact publication retry replaced the retained file", err, readErr)
	}
	// Checked Close must not be lost even if the file was successfully synced.
	err = syncExactRegularArtifact(path, expected, func(file *os.File) error {
		if err := file.Sync(); err != nil {
			return err
		}
		return file.Close()
	})
	if !errors.Is(err, os.ErrClosed) {
		t.Fatal("lost close error", err)
	}
}

func TestImmutableArtifactConfirmationRejectsChangedOrWrongFiles(t *testing.T) {
	for _, kind := range []string{"conflict", "oversize", "empty", "symlink", "directory", "replaced"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "artifact")
			expected := []byte("immutable")
			switch kind {
			case "conflict":
				writePruneCLIFile(t, path, []byte("different"))
			case "oversize":
				writePruneCLIFile(t, path, append(append([]byte(nil), expected...), 0))
			case "empty":
				writePruneCLIFile(t, path, nil)
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(root, "original")
				writePruneCLIFile(t, target, expected)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				writePruneCLIFile(t, path, expected)
			}
			synced := false
			err := syncExactRegularArtifact(path, expected, func(file *os.File) error {
				synced = true
				if kind != "replaced" {
					t.Fatal("invalid bytes reached durability confirmation")
				}
				if err := file.Sync(); err != nil {
					return err
				}
				// Preserve the old inode; an identical replacement is still not
				// the inode whose successful Sync was just observed.
				if err := os.Rename(path, filepath.Join(root, "preserved")); err != nil {
					return err
				}
				writePruneCLIFile(t, path, expected)
				return nil
			})
			if err == nil || synced != (kind == "replaced") {
				t.Fatal("invalid artifact confirmation succeeded", err, synced)
			}
		})
	}
}
