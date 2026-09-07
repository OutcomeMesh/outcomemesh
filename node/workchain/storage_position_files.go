package workchain

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maximumPositionPending = 128

func positionNames(path string, limit int) ([]string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	names, err := file.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > limit {
		return nil, ErrStoragePinLimit
	}
	sort.Strings(names)
	return names, nil
}

func readPositionFile(path string, maximum int) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > int64(maximum) {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || !after.Mode().IsRegular() || after.Size() != before.Size() || len(encoded) != int(before.Size()) {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	return encoded, nil
}

func syncPositionFile(path string) (err error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > positionRecordMaximum {
		return errors.Join(ErrStoragePosition, err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.Join(ErrStoragePosition, err)
	}
	return file.Sync()
}

func openPositionLock(path string, create bool) (_ *os.File, err error) {
	root, err := os.Lstat(path)
	if err != nil || !root.IsDir() {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	name := filepath.Join(path, "positions.lock")
	flags := os.O_RDWR
	var before os.FileInfo
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	} else {
		before, err = os.Lstat(name)
		if err != nil || !before.Mode().IsRegular() || before.Size() != 0 {
			return nil, errors.Join(ErrStoragePosition, err)
		}
	}
	file, err := os.OpenFile(name, flags, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	locked, err := tryPositionLock(file)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrStoragePinBusy
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(opened, current) ||
		(before != nil && !os.SameFile(before, opened)) {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	return file, nil
}

func (p *storagePositionPins) layout() (map[string]os.FileInfo, error) {
	kinds := map[string]bool{"": true, "identity": false, "ready": false, "positions.lock": false, "intents": true, "confirmed": true, "pending": true}
	names, err := positionNames(p.path, len(kinds)-1)
	if err != nil || len(names) != len(kinds)-1 {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	result := make(map[string]os.FileInfo, len(kinds))
	for _, name := range append(names, "") {
		directory, ok := kinds[name]
		if !ok {
			return nil, ErrStoragePosition
		}
		info, err := os.Lstat(filepath.Join(p.path, name))
		if err != nil || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
			return nil, errors.Join(ErrStoragePosition, err)
		}
		result[name] = info
	}
	opened, err := p.lock.Stat()
	if err != nil || !os.SameFile(opened, result["positions.lock"]) || opened.Size() != 0 {
		return nil, errors.Join(ErrStoragePosition, err)
	}
	for _, name := range []string{"identity", "ready"} {
		encoded, err := readPositionFile(filepath.Join(p.path, name), positionRecordMaximum)
		if err != nil || !bytes.Equal(encoded, p.encodedIdentity) {
			return nil, errors.Join(ErrStoragePosition, err)
		}
	}
	if _, err := p.inspectPending(); err != nil {
		return nil, err
	}
	return result, nil
}

func (p *storagePositionPins) captureIdentity() error {
	identity, err := p.layout()
	if err != nil {
		return err
	}
	p.identity = identity
	return nil
}

func (p *storagePositionPins) checkIdentity() error {
	current, err := p.layout()
	if err != nil {
		return err
	}
	for name, before := range p.identity {
		if !os.SameFile(before, current[name]) {
			return ErrStoragePosition
		}
	}
	return nil
}

func (p *storagePositionPins) inspectPending() (int, error) {
	names, err := positionNames(filepath.Join(p.path, "pending"), maximumPositionPending)
	if err != nil {
		return 0, err
	}
	for _, name := range names {
		suffix, ok := strings.CutPrefix(name, "entry-")
		if !ok || len(suffix) == 0 || len(suffix) > 20 || strings.Trim(suffix, "0123456789") != "" {
			return 0, ErrStoragePosition
		}
		info, err := os.Lstat(filepath.Join(p.path, "pending", name))
		if err != nil || !info.Mode().IsRegular() || info.Size() > positionRecordMaximum {
			return 0, errors.Join(ErrStoragePosition, err)
		}
	}
	return len(names), nil
}

// Publish complete, synced bytes through a no-replace link. Only our own staging
// file is removed; interrupted staging files are bounded and never interpreted
// as intent or confirmation. A failed publication poisons its caller.
func (p *storagePositionPins) publish(relative string, encoded []byte, stage string) (err error) {
	if len(encoded) > positionRecordMaximum {
		return ErrStoragePosition
	}
	count, err := p.inspectPending()
	if err != nil {
		return err
	}
	if count >= maximumPositionPending {
		return ErrStoragePinLimit
	}
	if err := p.reach(stage + "-before-temp"); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Join(p.path, "pending"), "entry-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, temp.Close(), os.Remove(temp.Name())) }()
	if err := p.reach(stage + "-temp-created"); err != nil {
		return err
	}
	n, err := temp.Write(encoded)
	if err != nil {
		return err
	}
	if n != len(encoded) {
		return io.ErrShortWrite
	}
	if err := p.reach(stage + "-before-file-sync"); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := p.reach(stage + "-file-synced"); err != nil {
		return err
	}
	if err := os.Link(temp.Name(), filepath.Join(p.path, relative)); err != nil {
		return err
	}
	if err := p.reach(stage + "-linked"); err != nil {
		return err
	}
	if err := syncStorageDirectory(filepath.Dir(filepath.Join(p.path, relative))); err != nil {
		return err
	}
	return p.reach(stage + "-directory-synced")
}
