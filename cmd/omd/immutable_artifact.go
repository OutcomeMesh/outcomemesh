package main

import (
	"bytes"
	"errors"
	"io"
	"os"
)

// Confirm the exact existing inode before publication retry reports success.
// Directory fsync alone cannot establish durability of a matching file that
// was originally written by a different publisher. The optional sync function
// is a package-private fault seam; production always uses the file's Sync.
func syncExactRegularArtifact(path string, expected []byte, syncFile func(*os.File) error) (err error) {
	if path == "" || len(expected) == 0 {
		return errors.New("invalid immutable artifact")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(expected)) {
		return errors.New("immutable artifact is not an exact bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return errors.Join(errors.New("immutable artifact changed while opening"), err)
	}
	current, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil || !bytes.Equal(current, expected) {
		return errors.Join(errors.New("immutable artifact conflict"), err)
	}
	if syncFile == nil {
		syncFile = (*os.File).Sync
	}
	if err := syncFile(file); err != nil {
		return err
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || !currentInfo.Mode().IsRegular() || !os.SameFile(opened, currentInfo) || currentInfo.Size() != opened.Size() {
		return errors.Join(errors.New("immutable artifact changed while confirming"), err)
	}
	return nil
}
