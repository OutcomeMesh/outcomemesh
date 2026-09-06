//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package workarchive

import "os"

func tryLockCustodyJournalFile(*os.File) (bool, error) { return false, ErrCustodyJournal }
