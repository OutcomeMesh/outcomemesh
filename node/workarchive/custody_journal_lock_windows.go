//go:build windows

package workarchive

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func tryLockCustodyJournalFile(file *os.File) (bool, error) {
	var overlap windows.Overlapped
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}
