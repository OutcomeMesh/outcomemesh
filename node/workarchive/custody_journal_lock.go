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
	return acquireCustodyEvidenceLock(root, custodyJournalLockName, true)
}

// AcquireCustodyArtifacts serializes the whole auditor invocation, including
// challenge publication before the journal append. Always acquire this lock
// before opening or locking its journal. Close releases it; never unlink it.
func AcquireCustodyArtifacts(root string) (*os.File, error) {
	if root == "" {
		return nil, ErrCustodyJournal
	}
	if err := makeCustodyJournalRoot(root); err != nil {
		return nil, err
	}
	return acquireCustodyEvidenceLock(root, custodyArtifactsLockName, true)
}

const custodyArtifactsLockName = "custody.lock"

func acquireCustodyEvidenceLock(root, name string, create bool) (*os.File, error) {
	if err := requireCustodyJournalDirectory(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, name)
	info, err := os.Lstat(path)
	if !create && err != nil {
		return nil, err
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && (!info.Mode().IsRegular() || info.Size() != 0) {
		return nil, ErrCustodyJournal
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	file, err := os.OpenFile(path, flags, 0o600)
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
