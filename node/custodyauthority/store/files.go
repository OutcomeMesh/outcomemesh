package store

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func storePath(path string) (string, error) {
	if path == "" {
		return "", ErrStore
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() {
		return "", errors.Join(ErrStore, err)
	}
	return path, nil
}

func boundedNames(path string, limit int) ([]string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() {
		return nil, errors.Join(ErrStore, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(ErrStore, err)
	}
	entries, err := file.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, custodyauthority.ErrLimit
	}
	sort.Strings(entries)
	return entries, nil
}

func inspectLayout(path string, lock *os.File) (map[string]os.FileInfo, error) {
	names, err := boundedNames(path, 5)
	if err != nil {
		return nil, err
	}
	if len(names) != 5 {
		return nil, ErrStore
	}
	kinds := map[string]bool{assignmentName: false, readyName: false, lockName: false, entriesName: true, pendingName: true, "": true}
	identity := make(map[string]os.FileInfo, len(kinds))
	for _, name := range append(names, "") {
		isDir, ok := kinds[name]
		if !ok {
			return nil, ErrStore
		}
		info, err := os.Lstat(filepath.Join(path, name))
		if err != nil || (isDir && !info.IsDir()) || (!isDir && !info.Mode().IsRegular()) {
			return nil, errors.Join(ErrStore, err)
		}
		identity[name] = info
	}
	opened, err := lock.Stat()
	if err != nil || !os.SameFile(opened, identity[lockName]) || opened.Size() != 0 {
		return nil, errors.Join(ErrStore, err)
	}
	return identity, nil
}

func inspectPending(path string) (int, error) {
	names, err := boundedNames(filepath.Join(path, pendingName), MaximumPendingFiles)
	if err != nil {
		return 0, err
	}
	for _, name := range names {
		suffix, ok := strings.CutPrefix(name, "entry-")
		if !ok || len(suffix) == 0 || len(suffix) > 20 || strings.Trim(suffix, "0123456789") != "" {
			return 0, ErrStore
		}
		info, err := os.Lstat(filepath.Join(path, pendingName, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() > custodyauthority.MaximumEntryBytes {
			return 0, errors.Join(ErrStore, err)
		}
	}
	return len(names), nil
}

func readRegular(path string, maximum int) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > int64(maximum) {
		return nil, errors.Join(ErrStore, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(ErrStore, err)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) || !current.Mode().IsRegular() ||
		len(encoded) != int(before.Size()) || current.Size() != before.Size() {
		return nil, errors.Join(ErrStore, err)
	}
	return encoded, nil
}

func writeExclusive(path string, encoded []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return writeAndSync(file, encoded, storeHooks{})
}

func writeAndSync(file *os.File, encoded []byte, hooks storeHooks) (err error) {
	defer func() { err = errors.Join(err, file.Close()) }()
	n, err := file.Write(encoded)
	if err != nil {
		return err
	}
	if n != len(encoded) {
		return io.ErrShortWrite
	}
	if err := hooks.reach("before-file-sync"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return hooks.reach("file-synced")
}

func syncPath(path string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return file.Sync()
}

func syncDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return errors.Join(ErrStore, err)
	}
	return syncPath(path)
}

func openLock(path string, create bool) (_ *os.File, err error) {
	root, err := os.Lstat(path)
	if err != nil || !root.IsDir() {
		return nil, errors.Join(ErrStore, err)
	}
	lockPath := filepath.Join(path, lockName)
	flags := os.O_RDWR
	var before os.FileInfo
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	} else {
		before, err = os.Lstat(lockPath)
		if err != nil || !before.Mode().IsRegular() || before.Size() != 0 {
			return nil, errors.Join(ErrStore, err)
		}
	}
	file, err := os.OpenFile(lockPath, flags, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	locked, err := tryLock(file)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrBusy
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(lockPath)
	if err != nil || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(opened, current) ||
		(before != nil && !os.SameFile(before, opened)) {
		return nil, errors.Join(ErrStore, err)
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	return file, nil
}
