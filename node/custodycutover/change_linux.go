//go:build linux

package custodycutover

import (
	"os"
	"syscall"
)

// Permanent lock files have no writes after creation. Unlike directory change
// time, their change time remains stable during ordinary open/flock/fsync and
// distinguishes an immediately recycled inode from its original lock.
func lockChangeIdentity(info os.FileInfo) (int64, int64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrPreparation
	}
	return s.Ctim.Sec, s.Ctim.Nsec, nil
}
