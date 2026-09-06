package workarchive

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

var ErrCustodyJournalBusy = errors.New("custody journal is busy; retry the operation")

// The lock inode is permanent. Closing the descriptor releases the kernel
// lock, including on process death; deleting it would permit split ownership.
func acquireCustodyJournalLock(root string) (*os.File, error) {
	if err := requireCustodyJournalDirectory(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, custodyJournalLockName)
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && (!info.Mode().IsRegular() || info.Size() != 0) {
		return nil, ErrCustodyJournal
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		locked, err := tryLockCustodyJournalFile(file)
		if err != nil {
			return nil, err
		}
		if locked {
			break
		}
		if !time.Now().Before(deadline) {
			return nil, ErrCustodyJournalBusy
		}
		time.Sleep(10 * time.Millisecond)
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || current.Size() != 0 ||
		!os.SameFile(opened, current) || (info != nil && !os.SameFile(info, opened)) {
		return nil, errors.Join(ErrCustodyJournal, err)
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := syncDirectory(root); err != nil {
		return nil, err
	}
	failed = false
	return file, nil
}
