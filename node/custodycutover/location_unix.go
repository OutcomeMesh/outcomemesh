//go:build darwin || linux

package custodycutover

import (
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) (uint64, uint64, uint64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, ErrPreparation
	}
	return uint64(s.Dev), s.Ino, uint64(s.Uid), nil
}
